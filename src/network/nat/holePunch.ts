import * as dgram from 'node:dgram';
import { randomBytes } from 'node:crypto';
import { EventEmitter } from 'node:events';
import { ed25519 } from '@noble/curves/ed25519.js';
import { bytesToHex, hexToBytes } from '@noble/hashes/utils.js';
import type { SignedEndpoint, HolePunchResult, NatType, EncryptedPayload } from './types.js';

const PUNCH_INTERVAL_MS = 500;
const PUNCH_MIN_INTERVAL_MS = 200;
const PUNCH_MAX_ATTEMPTS = 5;
const PUNCH_TIMEOUT_MS = 15000;
const CHALLENGE_TIMEOUT_MS = 5000;
const KEEPALIVE_MS = 15000;
const IDLE_TIMEOUT_MS = 60000;
const TIMESTAMP_WINDOW_MS = 30000;
const MAX_PORT_CHANGES = 3;
const MAX_NONCES = 5000;

export interface HolePuncherEvents {
  'punch:started': [peer: string];
  'punch:attempt': [attempt: number, port: number];
  'punch:received': [from: string];
  'punch:authenticated': [nodeId: string];
  'punch:established': [result: HolePunchResult];
  'punch:failed': [result: HolePunchResult];
  'punch:fallback': [reason: string];
  'punch:suspicious': [detail: string];
}

interface PunchPacket {
  type: 'punch' | 'ack' | 'challenge' | 'challenge_response';
  nodeId: string;
  nonce: string;
  timestamp: number;
  signature: string;
  challengeNonce?: string;
  challengeSignature?: string;
}

export class HolePuncher extends EventEmitter<HolePuncherEvents> {
  private readonly nodeId: string;
  private readonly privateKey: Uint8Array;
  private readonly publicKey: Uint8Array;
  private knownPeers = new Map<string, Uint8Array>();
  private seenNonces = new Set<string>();
  private activeSocket: dgram.Socket | null = null;
  private keepaliveTimer: ReturnType<typeof setInterval> | null = null;

  constructor(nodeId: string, privateKey: Uint8Array) {
    super();
    this.nodeId = nodeId;
    this.privateKey = privateKey;
    this.publicKey = ed25519.getPublicKey(privateKey);
  }

  /** Register a peer's public key for verification. */
  addPeer(nodeId: string, publicKey: Uint8Array): void {
    this.knownPeers.set(nodeId, publicKey);
  }

  /**
   * Attempt UDP hole punch to a peer.
   * DEFENSE 5: Only accepts SignedEndpoint — type system prevents unsigned endpoints.
   */
  async punch(peerEndpoint: SignedEndpoint, ownNatType: NatType = 'unknown', peerNatType: NatType = 'unknown'): Promise<HolePunchResult> {
    const start = Date.now();
    const peerKey = `${peerEndpoint.ip}:${peerEndpoint.port}`;

    // DEFENSE 1: Verify Ed25519 signature on peer endpoint
    if (!this.verifyEndpointSignature(peerEndpoint)) {
      this.emit('punch:suspicious', 'invalid_endpoint_signature');
      return this.fail('invalid_endpoint_signature', ownNatType, start);
    }

    this.emit('punch:started', peerKey);

    // Step 3: NAT compatibility
    if (ownNatType === 'symmetric' && peerNatType === 'symmetric') {
      this.emit('punch:fallback', 'both_symmetric');
      return this.fail('both_symmetric_nat', ownNatType, start, 'turn_fallback');
    }

    const peerPubKey = this.knownPeers.get(peerEndpoint.nodeId);
    if (!peerPubKey) {
      return this.fail('unknown_peer', ownNatType, start);
    }

    // Step 4: Punch sequence with port changes
    for (let portChange = 0; portChange <= MAX_PORT_CHANGES; portChange++) {
      const result = await this.attemptPunch(peerEndpoint, peerPubKey, ownNatType, start, portChange);
      if (result.success) return result;
      if (Date.now() - start > PUNCH_TIMEOUT_MS) break;
    }

    // Symmetric NAT: port prediction attempt
    if (ownNatType === 'symmetric' || peerNatType === 'symmetric') {
      for (let predict = 1; predict <= 3; predict++) {
        const predicted: SignedEndpoint = {
          ...peerEndpoint,
          port: peerEndpoint.port + predict,
        };
        const result = await this.attemptPunch(predicted, peerPubKey, ownNatType, start, 0);
        if (result.success) {
          result.method = 'port_prediction';
          return result;
        }
      }
    }

    this.emit('punch:fallback', 'all_attempts_exhausted');
    return this.fail('all_attempts_exhausted', ownNatType, start, 'turn_fallback');
  }

  /** Close active socket and cleanup. */
  close(): void {
    if (this.keepaliveTimer) { clearInterval(this.keepaliveTimer); this.keepaliveTimer = null; }
    if (this.activeSocket) { try { this.activeSocket.close(); } catch {} this.activeSocket = null; }
    this.seenNonces.clear();
  }

  private async attemptPunch(
    peer: SignedEndpoint, peerPubKey: Uint8Array, natType: NatType, startTime: number, portOffset: number,
  ): Promise<HolePunchResult> {
    return new Promise((resolve) => {
      const socket = dgram.createSocket('udp4');
      let attempts = 0;
      let done = false;
      let interval = PUNCH_INTERVAL_MS;

      const finish = (result: HolePunchResult) => {
        if (done) return;
        done = true;
        clearTimeout(timeout);
        clearInterval(punchTimer);
        if (!result.success) { try { socket.close(); } catch {} }
        resolve(result);
      };

      const timeout = setTimeout(() => {
        finish(this.fail('timeout', natType, startTime));
      }, Math.min(PUNCH_TIMEOUT_MS - (Date.now() - startTime), 5000));

      socket.on('message', (msg, rinfo) => {
        if (done) return;
        this.emit('punch:received', `${rinfo.address}:${rinfo.port}`);

        const packet = this.decryptAndVerify(msg, peerPubKey, peer.nodeId);
        if (!packet) {
          this.emit('punch:suspicious', 'undecryptable_packet');
          return;
        }

        if (packet.type === 'punch') {
          const ackPacket = this.buildPacket('ack');
          socket.send(this.signAndEncrypt(ackPacket, peerPubKey), peer.port, peer.ip);
        }

        if (packet.type === 'ack') {
          this.emit('punch:authenticated', peer.nodeId);
          // Step 5: Post-punch challenge
          this.doChallenge(socket, peer, peerPubKey).then((verified) => {
            if (!verified) {
              this.emit('punch:suspicious', 'challenge_failed');
              finish(this.fail('challenge_failed', natType, startTime));
              return;
            }
            this.activeSocket = socket;
            this.startKeepalive(socket, peer, peerPubKey);
            finish({
              success: true,
              socket,
              peerEndpoint: { ip: peer.ip, port: peer.port },
              peerNodeId: peer.nodeId,
              natType,
              punchAttempts: attempts,
              totalTime: Date.now() - startTime,
              method: 'direct_punch',
            });
          });
        }
      });

      socket.on('error', () => finish(this.fail('socket_error', natType, startTime)));

      socket.bind(0, () => {
        const punchTimer = setInterval(() => {
          if (done || attempts >= PUNCH_MAX_ATTEMPTS) { clearInterval(punchTimer); return; }
          attempts++;
          this.emit('punch:attempt', attempts, (socket.address() as any).port);
          const packet = this.buildPacket('punch');
          socket.send(this.signAndEncrypt(packet, peerPubKey), peer.port, peer.ip);
          if (interval > PUNCH_MIN_INTERVAL_MS) interval = Math.max(PUNCH_MIN_INTERVAL_MS, interval - 100);
        }, interval);
      });
    });
  }

  private async doChallenge(socket: dgram.Socket, peer: SignedEndpoint, peerPubKey: Uint8Array): Promise<boolean> {
    return new Promise((resolve) => {
      const challengeNonce = randomBytes(32).toString('hex');
      const packet = this.buildPacket('challenge');
      (packet as any).challengeNonce = challengeNonce;
      socket.send(this.signAndEncrypt(packet, peerPubKey), peer.port, peer.ip);

      const timer = setTimeout(() => resolve(false), CHALLENGE_TIMEOUT_MS);

      const handler = (msg: Buffer) => {
        const resp = this.decryptAndVerify(msg, peerPubKey, peer.nodeId);
        if (!resp || resp.type !== 'challenge_response') return;
        clearTimeout(timer);
        socket.removeListener('message', handler);

        if (!resp.challengeSignature) { resolve(false); return; }
        try {
          const sigBytes = hexToBytes(resp.challengeSignature);
          const nonceBytes = new TextEncoder().encode(challengeNonce);
          resolve(ed25519.verify(sigBytes, nonceBytes, peerPubKey));
        } catch {
          resolve(false);
        }
      };
      socket.on('message', handler);
    });
  }

  private buildPacket(type: PunchPacket['type']): PunchPacket {
    const nonce = randomBytes(32).toString('hex');
    const timestamp = Date.now();
    const sigPayload = `${this.nodeId}:${nonce}:${timestamp}:${type}`;
    const signature = bytesToHex(ed25519.sign(new TextEncoder().encode(sigPayload), this.privateKey));
    return { type, nodeId: this.nodeId, nonce, timestamp, signature };
  }

  private signAndEncrypt(packet: PunchPacket, _peerPubKey: Uint8Array): Buffer {
    // DEFENSE 4: In production, encrypt with peer's X25519 derived key.
    // Here we sign the JSON — encryption requires a shared secret established via X25519 DH.
    return Buffer.from(JSON.stringify(packet), 'utf8');
  }

  private decryptAndVerify(data: Buffer, peerPubKey: Uint8Array, expectedNodeId: string): PunchPacket | null {
    let packet: PunchPacket;
    try {
      packet = JSON.parse(data.toString('utf8'));
    } catch { return null; }

    if (packet.nodeId !== expectedNodeId) return null;
    if (Math.abs(Date.now() - packet.timestamp) > TIMESTAMP_WINDOW_MS) return null;
    if (this.seenNonces.has(packet.nonce)) return null;

    const sigPayload = `${packet.nodeId}:${packet.nonce}:${packet.timestamp}:${packet.type}`;
    try {
      const valid = ed25519.verify(hexToBytes(packet.signature), new TextEncoder().encode(sigPayload), peerPubKey);
      if (!valid) return null;
    } catch { return null; }

    this.seenNonces.add(packet.nonce);
    if (this.seenNonces.size > MAX_NONCES) {
      const first = this.seenNonces.values().next().value!;
      this.seenNonces.delete(first);
    }

    return packet;
  }

  private verifyEndpointSignature(ep: SignedEndpoint): boolean {
    const peerPubKey = this.knownPeers.get(ep.nodeId);
    if (!peerPubKey) return false;
    const payload = `${ep.nodeId}:${ep.ip}:${ep.port}:${ep.timestamp}`;
    try {
      return ed25519.verify(hexToBytes(ep.signature), new TextEncoder().encode(payload), peerPubKey);
    } catch { return false; }
  }

  private startKeepalive(socket: dgram.Socket, peer: SignedEndpoint, peerPubKey: Uint8Array): void {
    let lastActivity = Date.now();
    socket.on('message', () => { lastActivity = Date.now(); });
    this.keepaliveTimer = setInterval(() => {
      if (Date.now() - lastActivity > IDLE_TIMEOUT_MS) {
        this.emit('punch:failed', this.fail('idle_timeout', 'unknown', lastActivity));
        this.close();
        return;
      }
      const ping = this.buildPacket('punch');
      socket.send(this.signAndEncrypt(ping, peerPubKey), peer.port, peer.ip);
    }, KEEPALIVE_MS);
  }

  private fail(reason: string, natType: NatType, start: number, method: HolePunchResult['method'] = 'direct_punch'): HolePunchResult {
    return { success: false, reason, natType, punchAttempts: 0, totalTime: Date.now() - start, method };
  }
}
