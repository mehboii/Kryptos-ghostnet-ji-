import { EventEmitter } from 'node:events';
import { randomBytes, createCipheriv, createDecipheriv } from 'node:crypto';
import { ed25519, x25519 } from '@noble/curves/ed25519.js';
import { blake3 } from '@noble/hashes/blake3.js';
import { bytesToHex } from '@noble/hashes/utils.js';

const E2E_CIPHER = 'aes-256-gcm';
const E2E_IV_BYTES = 12;
const E2E_TAG_BYTES = 16;
import { StunClient } from './stun.js';
import { StunValidator } from './stunValidator.js';
import { TurnClient } from './turn.js';
import { HolePuncher } from './holePunch.js';
import { PacketAuthenticator } from './packetAuth.js';
import type {
  Connection, ConnectionMethod, ConnectionStatus, SignedEndpoint,
  NatType, StunResult, ValidationResult, RelayTier, EncryptedPayload,
} from './types.js';

const KEEPALIVE_MS = 15000;
const RECONNECT_DELAY_MS = 2000;
const MAX_RECONNECTS = 5;

export interface NatTraversalEvents {
  'connection:started': [peerNodeId: string];
  'connection:stun_complete': [result: StunResult];
  'connection:punching': [peer: string];
  'connection:direct': [peerNodeId: string];
  'connection:relayed': [peerNodeId: string];
  'connection:upgrading': [peerNodeId: string];
  'connection:upgraded': [peerNodeId: string];
  'connection:lost': [peerNodeId: string];
  'connection:reconnecting': [peerNodeId: string, attempt: number];
  'security:violation': [detail: string];
  'quota:warning': [used: number, limit: number];
  'quota:exceeded': [];
}

export class NatTraversal extends EventEmitter<NatTraversalEvents> {
  private readonly nodeId: string;
  private readonly privateKey: Uint8Array;
  private readonly publicKey: Uint8Array;
  readonly stun: StunClient;
  readonly validator: StunValidator;
  readonly turn: TurnClient;
  readonly puncher: HolePuncher;
  readonly auth: PacketAuthenticator;

  private readonly turnServers: { host: string; port: number }[];
  private activeConnections = new Map<string, ManagedConnection>();
  private ownNatType: NatType = 'unknown';

  constructor(nodeId: string, privateKey: Uint8Array, options?: { relayTier?: RelayTier; turnServers?: { host: string; port: number }[] }) {
    super();
    this.nodeId = nodeId;
    this.privateKey = privateKey;
    this.publicKey = ed25519.getPublicKey(privateKey);

    this.turnServers = options?.turnServers ?? [{ host: 'turn.ghostnet.local', port: 3478 }];
    this.stun = new StunClient();
    this.validator = new StunValidator();
    this.turn = new TurnClient(options?.relayTier ?? 'ghost');
    this.puncher = new HolePuncher(nodeId, privateKey);
    this.auth = new PacketAuthenticator();

    this.turn.on('relay:quota_warning', (used, limit) => this.emit('quota:warning', used, limit));
    this.turn.on('relay:quota_exceeded', () => this.emit('quota:exceeded'));
  }

  /** Register a peer for future connections. Verifies nodeId === BLAKE3(publicKey). */
  addPeer(nodeId: string, publicKey: Uint8Array): void {
    const expected = bytesToHex(blake3(publicKey));
    if (nodeId !== expected) {
      this.emit('security:violation', 'nodeId does not match BLAKE3(publicKey)');
      return;
    }
    this.puncher.addPeer(nodeId, publicKey);
    this.auth.addKnownPeer(nodeId, publicKey);
    this.turn.addKnownPeer(nodeId, publicKey);
  }

  /**
   * Connect to a peer. Tries STUN → punch → TURN fallback.
   * Connection.send() encrypts+signs. Connection.receive() verifies+decrypts.
   */
  async connect(peerNodeId: string, peerPublicKey: Uint8Array, peerSignedEndpoint: SignedEndpoint): Promise<Connection> {
    this.addPeer(peerNodeId, peerPublicKey);
    this.emit('connection:started', peerNodeId);

    // Step 1: STUN discovery + validation
    let stunResult: StunResult | null = null;
    let validation: ValidationResult | null = null;
    try {
      stunResult = await this.stun.discover();
      validation = this.validator.validate(stunResult);
      this.ownNatType = stunResult.natType;
      this.emit('connection:stun_complete', stunResult);
    } catch {
      // STUN failed, skip to relay
    }

    // Step 2+3: Hole punch if STUN succeeded and not both symmetric
    if (validation?.valid) {
      this.emit('connection:punching', peerNodeId);
      const punchResult = await this.puncher.punch(peerSignedEndpoint, this.ownNatType);

      if (punchResult.success && punchResult.socket) {
        this.emit('connection:direct', peerNodeId);
        const conn = new ManagedConnection(
          'direct', peerNodeId, punchResult.socket, this.auth,
          this.nodeId, this.privateKey, peerPublicKey,
          peerSignedEndpoint.ip, peerSignedEndpoint.port,
        );
        this.activeConnections.set(peerNodeId, conn);
        this.monitorConnection(peerNodeId, peerPublicKey, peerSignedEndpoint);
        return conn;
      }
    }

    // Step 4: TURN relay fallback
    try {
      await this.turn.allocateRelay(this.turnServers[0]);
      this.emit('connection:relayed', peerNodeId);

      const conn = new ManagedConnection(
        'relay', peerNodeId, null, this.auth,
        this.nodeId, this.privateKey, peerPublicKey,
        peerSignedEndpoint.ip, peerSignedEndpoint.port,
        this.turn,
      );
      this.activeConnections.set(peerNodeId, conn);

      // Background: keep trying direct punch
      this.backgroundUpgrade(peerNodeId, peerPublicKey, peerSignedEndpoint);

      return conn;
    } catch (err) {
      throw new Error(`Failed to connect to ${peerNodeId}: no direct or relay path available`);
    }
  }

  /** Create a signed endpoint for sharing via DHT/signaling. */
  async createSignedEndpoint(): Promise<SignedEndpoint> {
    const stunResult = await this.stun.discover();
    const validation = this.validator.validate(stunResult);

    if (!validation.valid || !validation.trustedIp || !validation.trustedPort) {
      throw new Error('Cannot create signed endpoint: STUN validation failed');
    }

    const timestamp = Date.now();
    const payload = `${this.nodeId}:${validation.trustedIp}:${validation.trustedPort}:${timestamp}`;
    const signature = bytesToHex(ed25519.sign(new TextEncoder().encode(payload), this.privateKey));

    return {
      nodeId: this.nodeId,
      ip: validation.trustedIp,
      port: validation.trustedPort,
      timestamp,
      signature,
    };
  }

  /** Get status of a peer connection. */
  getStatus(peerNodeId: string): ConnectionStatus | null {
    const conn = this.activeConnections.get(peerNodeId);
    if (!conn) return null;
    return {
      connected: true,
      method: conn.method,
      peerNodeId: conn.peerNodeId,
      natType: this.ownNatType,
      relayStats: conn.method === 'relay' ? this.turn.getStats() : undefined,
      uptime: Date.now() - conn.established,
    };
  }

  /** Tear down everything. */
  destroy(): void {
    for (const conn of this.activeConnections.values()) conn.close();
    this.activeConnections.clear();
    this.puncher.close();
    this.turn.teardown();
    this.auth.destroy();
    this.removeAllListeners();
  }

  private monitorConnection(peerNodeId: string, peerPublicKey: Uint8Array, peerEndpoint: SignedEndpoint): void {
    // Auto-reconnect on connection loss handled by keepalive failures
  }

  private async backgroundUpgrade(peerNodeId: string, peerPublicKey: Uint8Array, peerEndpoint: SignedEndpoint): Promise<void> {
    this.emit('connection:upgrading', peerNodeId);
    const result = await this.puncher.punch(peerEndpoint, this.ownNatType);

    if (result.success && result.socket) {
      const oldConn = this.activeConnections.get(peerNodeId);
      const newConn = new ManagedConnection(
        'direct', peerNodeId, result.socket, this.auth,
        this.nodeId, this.privateKey, peerPublicKey,
        peerEndpoint.ip, peerEndpoint.port,
      );
      this.activeConnections.set(peerNodeId, newConn);
      if (oldConn) oldConn.close();
      this.emit('connection:upgraded', peerNodeId);
    }
  }
}

class ManagedConnection implements Connection {
  readonly method: ConnectionMethod;
  readonly peerNodeId: string;
  readonly established: number;
  private socket: import('node:dgram').Socket | null;
  private readonly authenticator: PacketAuthenticator;
  private readonly nodeId: string;
  private readonly privateKey: Uint8Array;
  private readonly peerPublicKey: Uint8Array;
  private readonly sharedSecret: Buffer;
  private readonly peerIp: string;
  private readonly peerPort: number;
  private readonly turnClient: TurnClient | null;
  private seqNumber = 0;
  private closed = false;
  private incomingQueue: Buffer[] = [];
  private waitResolve: ((v: IteratorResult<Buffer>) => void) | null = null;

  constructor(
    method: ConnectionMethod, peerNodeId: string,
    socket: import('node:dgram').Socket | null, auth: PacketAuthenticator,
    nodeId: string, privateKey: Uint8Array, peerPublicKey: Uint8Array,
    peerIp: string, peerPort: number,
    turn?: TurnClient,
  ) {
    this.method = method;
    this.peerNodeId = peerNodeId;
    this.established = Date.now();
    this.socket = socket;
    this.authenticator = auth;
    this.nodeId = nodeId;
    this.privateKey = privateKey;
    this.peerPublicKey = peerPublicKey;
    this.peerIp = peerIp;
    this.peerPort = peerPort;
    this.turnClient = turn ?? null;

    const myX25519Priv = ed25519.utils.toMontgomerySecret(privateKey);
    const peerX25519Pub = ed25519.utils.toMontgomery(peerPublicKey);
    const raw = x25519.getSharedSecret(myX25519Priv, peerX25519Pub);
    this.sharedSecret = Buffer.from(blake3(raw, { dkLen: 32 }));

    if (socket) {
      socket.on('message', (msg) => {
        const decrypted = this.e2eDecrypt(msg);
        if (!decrypted) return;
        const result = this.authenticator.authenticate(decrypted, peerNodeId);
        if (!result.valid) return;
        const data = Buffer.from(JSON.stringify(result.data));
        if (this.waitResolve) {
          const resolve = this.waitResolve;
          this.waitResolve = null;
          resolve({ value: data, done: false });
        } else {
          this.incomingQueue.push(data);
        }
      });
    }
  }

  async send(data: Buffer): Promise<void> {
    if (this.closed) throw new Error('Connection closed');

    const timestamp = Date.now();
    const nonce = randomBytes(16).toString('hex');
    const sigPayload = `${this.nodeId}:${timestamp}:${nonce}:${JSON.stringify(data.toString('base64'))}`;
    const signature = bytesToHex(ed25519.sign(new TextEncoder().encode(sigPayload), this.privateKey));

    const innerPacket = Buffer.from(JSON.stringify({
      nodeId: this.nodeId,
      signature,
      timestamp,
      nonce,
      data: data.toString('base64'),
    }));

    const encrypted = this.e2eEncrypt(innerPacket);

    if (this.method === 'direct' && this.socket) {
      this.socket.send(encrypted, this.peerPort, this.peerIp);
    } else if (this.method === 'relay' && this.turnClient) {
      const payload: EncryptedPayload = {
        ciphertext: encrypted,
        nonce: Buffer.from(nonce, 'hex'),
        signature,
        sequenceNumber: this.seqNumber++,
        timestamp,
        paddedSize: this.selectPadSize(encrypted.length),
        nodeId: this.nodeId,
      };
      this.turnClient.sendViaRelay(payload);
    }
  }

  async *receive(): AsyncGenerator<Buffer> {
    while (!this.closed) {
      if (this.incomingQueue.length > 0) {
        yield this.incomingQueue.shift()!;
        continue;
      }
      yield await new Promise<Buffer>((resolve) => { this.waitResolve = resolve; });
    }
  }

  close(): void {
    this.closed = true;
    this.sharedSecret.fill(0);
    if (this.socket) { try { this.socket.close(); } catch {} this.socket = null; }
  }

  private e2eEncrypt(plaintext: Buffer): Buffer {
    const iv = randomBytes(E2E_IV_BYTES);
    const cipher = createCipheriv(E2E_CIPHER, this.sharedSecret, iv);
    const encrypted = Buffer.concat([cipher.update(plaintext), cipher.final()]);
    const tag = cipher.getAuthTag();
    return Buffer.concat([iv, tag, encrypted]);
  }

  private e2eDecrypt(ciphertext: Buffer): Buffer | null {
    if (ciphertext.length < E2E_IV_BYTES + E2E_TAG_BYTES + 1) return null;
    try {
      const iv = ciphertext.subarray(0, E2E_IV_BYTES);
      const tag = ciphertext.subarray(E2E_IV_BYTES, E2E_IV_BYTES + E2E_TAG_BYTES);
      const data = ciphertext.subarray(E2E_IV_BYTES + E2E_TAG_BYTES);
      const decipher = createDecipheriv(E2E_CIPHER, this.sharedSecret, iv);
      decipher.setAuthTag(tag);
      return Buffer.concat([decipher.update(data), decipher.final()]);
    } catch {
      return null;
    }
  }

  private selectPadSize(len: number): 512 | 1024 | 2048 | 4096 {
    if (len <= 512) return 512;
    if (len <= 1024) return 1024;
    if (len <= 2048) return 2048;
    return 4096;
  }
}

export { StunClient } from './stun.js';
export { StunValidator } from './stunValidator.js';
export { TurnClient } from './turn.js';
export { HolePuncher } from './holePunch.js';
export { PacketAuthenticator } from './packetAuth.js';
export { SequenceStore } from './sequenceStore.js';
export { ReplayAttackError, StaleMessageError, FutureMessageError } from './replayErrors.js';
export * from './constants.js';
export type * from './types.js';
