import * as dgram from 'node:dgram';
import { randomBytes } from 'node:crypto';
import { EventEmitter } from 'node:events';
import { ed25519 } from '@noble/curves/ed25519.js';
import { blake3 } from '@noble/hashes/blake3.js';
import { bytesToHex, hexToBytes } from '@noble/hashes/utils.js';
import type { MdnsAnnouncement, PeerEndpoint } from './types.js';

const MDNS_ADDRESS = '224.0.0.251';
const MDNS_PORT = 5353;
const SERVICE_NAME = '_kryptos._udp.local';
const ANNOUNCE_INTERVAL_MS = 10_000;
const CHALLENGE_TIMEOUT_MS = 3_000;
const NONCE_WINDOW_MS = 15_000;
const MAX_NONCES = 2_000;
const MAX_ANNOUNCEMENTS_PER_IP = 5;
const RATE_WINDOW_MS = 60_000;

export interface MdnsDiscoveryEvents {
  'mdns:discovered': [nodeId: string, endpoint: PeerEndpoint, publicKey: Uint8Array];
  'mdns:verified': [nodeId: string];
  'mdns:spoof_detected': [ip: string, reason: string];
  'mdns:rate_limited': [ip: string];
  'mdns:challenge_failed': [nodeId: string];
}

/**
 * mDNS-based local peer discovery with anti-spoofing hardening.
 *
 * DEFENSE: Spoofing — all announcements are Ed25519 signed, nodeId = BLAKE3(pubkey).
 * DEFENSE: Spoofing — mandatory challenge-response after discovery before trusting.
 * DEFENSE: Amplification — rate-limit announcements per source IP.
 * DEFENSE: Replay — nonce + timestamp freshness on every announcement.
 */
export class MdnsDiscovery extends EventEmitter<MdnsDiscoveryEvents> {
  private readonly nodeId: string;
  private readonly privateKey: Uint8Array;
  private readonly publicKey: Uint8Array;
  private readonly listenPort: number;
  private socket: dgram.Socket | null = null;
  private announceTimer: ReturnType<typeof setInterval> | null = null;
  private readonly seenNonces = new Set<string>();
  private readonly ipRateMap = new Map<string, { count: number; windowStart: number }>();
  private readonly verifiedPeers = new Set<string>();
  private readonly pendingChallenges = new Map<string, {
    token: string;
    nodeId: string;
    publicKey: Uint8Array;
    endpoint: PeerEndpoint;
    timer: ReturnType<typeof setTimeout>;
  }>();

  constructor(nodeId: string, privateKey: Uint8Array, listenPort: number) {
    super();
    this.nodeId = nodeId;
    this.privateKey = privateKey;
    this.publicKey = ed25519.getPublicKey(privateKey);
    this.listenPort = listenPort;
  }

  /** Start mDNS listener and begin announcing. */
  async start(): Promise<void> {
    return new Promise((resolve, reject) => {
      this.socket = dgram.createSocket({ type: 'udp4', reuseAddr: true });

      this.socket.on('message', (msg, rinfo) => {
        if (rinfo.address === '127.0.0.1') return;
        this.handleMessage(msg, rinfo);
      });

      this.socket.on('error', reject);

      this.socket.bind(MDNS_PORT, () => {
        try {
          this.socket!.addMembership(MDNS_ADDRESS);
        } catch {
          // May fail if no multicast interface available
        }
        this.announceTimer = setInterval(() => this.announce(), ANNOUNCE_INTERVAL_MS);
        this.announce();
        resolve();
      });
    });
  }

  /** Stop mDNS. */
  stop(): void {
    if (this.announceTimer) { clearInterval(this.announceTimer); this.announceTimer = null; }
    for (const pending of this.pendingChallenges.values()) clearTimeout(pending.timer);
    this.pendingChallenges.clear();
    this.seenNonces.clear();
    this.ipRateMap.clear();
    this.verifiedPeers.clear();
    if (this.socket) {
      try { this.socket.dropMembership(MDNS_ADDRESS); } catch {}
      try { this.socket.close(); } catch {}
      this.socket = null;
    }
    this.removeAllListeners();
  }

  /** Check if a peer has been challenge-verified. */
  isVerified(nodeId: string): boolean {
    return this.verifiedPeers.has(nodeId);
  }

  private announce(): void {
    if (!this.socket) return;

    const announcement: MdnsAnnouncement = {
      nodeId: this.nodeId,
      publicKey: bytesToHex(this.publicKey),
      port: this.listenPort,
      timestamp: Date.now(),
      nonce: bytesToHex(randomBytes(16)),
      signature: '',
    };

    const sigPayload = this.announcementSigPayload(announcement);
    announcement.signature = bytesToHex(
      ed25519.sign(new TextEncoder().encode(sigPayload), this.privateKey),
    );

    const packet = Buffer.from(JSON.stringify({
      service: SERVICE_NAME,
      ...announcement,
    }), 'utf8');

    this.socket.send(packet, MDNS_PORT, MDNS_ADDRESS);
  }

  private handleMessage(raw: Buffer, rinfo: dgram.RemoteInfo): void {
    if (raw.length > 2048) return;

    let parsed: any;
    try { parsed = JSON.parse(raw.toString('utf8')); } catch { return; }
    if (parsed.service !== SERVICE_NAME) return;

    if (parsed.challengeToken) {
      this.handleChallengeResponse(parsed, rinfo);
      return;
    }

    const ann: MdnsAnnouncement = parsed;
    if (!ann.nodeId || !ann.signature || !ann.publicKey || !ann.nonce || !ann.timestamp) return;
    if (ann.nodeId === this.nodeId) return;

    // DEFENSE: Rate limiting per IP
    if (!this.checkRate(rinfo.address)) {
      this.emit('mdns:rate_limited', rinfo.address);
      return;
    }

    // DEFENSE: Timestamp freshness
    if (Math.abs(Date.now() - ann.timestamp) > NONCE_WINDOW_MS) return;

    // DEFENSE: Replay
    if (this.seenNonces.has(ann.nonce)) return;

    // DEFENSE: nodeId = BLAKE3(publicKey) — prevent ID spoofing
    let pubKeyBytes: Uint8Array;
    try { pubKeyBytes = hexToBytes(ann.publicKey); } catch { return; }
    const expectedNodeId = bytesToHex(blake3(pubKeyBytes));
    if (ann.nodeId !== expectedNodeId) {
      this.emit('mdns:spoof_detected', rinfo.address, 'nodeId_mismatch');
      return;
    }

    // DEFENSE: Ed25519 signature verification BEFORE trusting
    const sigPayload = this.announcementSigPayload(ann);
    try {
      const valid = ed25519.verify(
        hexToBytes(ann.signature),
        new TextEncoder().encode(sigPayload),
        pubKeyBytes,
      );
      if (!valid) {
        this.emit('mdns:spoof_detected', rinfo.address, 'invalid_signature');
        return;
      }
    } catch {
      this.emit('mdns:spoof_detected', rinfo.address, 'signature_parse_error');
      return;
    }

    this.seenNonces.add(ann.nonce);
    if (this.seenNonces.size > MAX_NONCES) {
      const first = this.seenNonces.values().next().value!;
      this.seenNonces.delete(first);
    }

    const endpoint: PeerEndpoint = {
      ip: rinfo.address, port: ann.port, transport: 'internet', verified: false,
    };

    this.emit('mdns:discovered', ann.nodeId, endpoint, pubKeyBytes);

    // DEFENSE: Challenge-response — don't trust until peer proves key ownership
    this.sendChallenge(ann.nodeId, pubKeyBytes, endpoint);
  }

  /**
   * Send a challenge to a discovered peer.
   * DEFENSE: Proves the responder actually holds the private key for the announced publicKey.
   */
  private sendChallenge(peerNodeId: string, peerPublicKey: Uint8Array, endpoint: PeerEndpoint): void {
    if (this.verifiedPeers.has(peerNodeId)) return;
    if (this.pendingChallenges.has(peerNodeId)) return;

    const token = bytesToHex(randomBytes(32));

    const timer = setTimeout(() => {
      this.pendingChallenges.delete(peerNodeId);
      this.emit('mdns:challenge_failed', peerNodeId);
    }, CHALLENGE_TIMEOUT_MS);

    this.pendingChallenges.set(peerNodeId, {
      token, nodeId: peerNodeId, publicKey: peerPublicKey, endpoint, timer,
    });

    const challenge = {
      service: SERVICE_NAME,
      type: 'challenge',
      challengeToken: token,
      fromNodeId: this.nodeId,
      timestamp: Date.now(),
      nonce: bytesToHex(randomBytes(16)),
      signature: '',
    };

    const sigPayload = `challenge:${this.nodeId}:${token}:${challenge.timestamp}:${challenge.nonce}`;
    challenge.signature = bytesToHex(
      ed25519.sign(new TextEncoder().encode(sigPayload), this.privateKey),
    );

    if (this.socket) {
      const buf = Buffer.from(JSON.stringify(challenge), 'utf8');
      this.socket.send(buf, endpoint.port, endpoint.ip);
    }
  }

  private handleChallengeResponse(parsed: any, rinfo: dgram.RemoteInfo): void {
    if (parsed.type === 'challenge' && parsed.fromNodeId && parsed.challengeToken) {
      // Respond to someone else's challenge
      const responseToken = parsed.challengeToken;
      const responseSig = bytesToHex(
        ed25519.sign(new TextEncoder().encode(responseToken), this.privateKey),
      );

      const response = {
        service: SERVICE_NAME,
        type: 'challenge_response',
        challengeToken: responseToken,
        nodeId: this.nodeId,
        publicKey: bytesToHex(this.publicKey),
        responseSig,
        timestamp: Date.now(),
        nonce: bytesToHex(randomBytes(16)),
        signature: '',
      };

      const sigPayload = `challenge_response:${this.nodeId}:${responseToken}:${response.timestamp}:${response.nonce}`;
      response.signature = bytesToHex(
        ed25519.sign(new TextEncoder().encode(sigPayload), this.privateKey),
      );

      if (this.socket) {
        const buf = Buffer.from(JSON.stringify(response), 'utf8');
        this.socket.send(buf, rinfo.port, rinfo.address);
      }
      return;
    }

    if (parsed.type === 'challenge_response' && parsed.nodeId && parsed.responseSig) {
      const pending = this.pendingChallenges.get(parsed.nodeId);
      if (!pending) return;

      try {
        const valid = ed25519.verify(
          hexToBytes(parsed.responseSig),
          new TextEncoder().encode(pending.token),
          pending.publicKey,
        );

        clearTimeout(pending.timer);
        this.pendingChallenges.delete(parsed.nodeId);

        if (valid) {
          this.verifiedPeers.add(parsed.nodeId);
          this.emit('mdns:verified', parsed.nodeId);
        } else {
          this.emit('mdns:spoof_detected', rinfo.address, 'challenge_response_invalid');
        }
      } catch {
        this.emit('mdns:spoof_detected', rinfo.address, 'challenge_response_parse_error');
      }
    }
  }

  private checkRate(ip: string): boolean {
    const now = Date.now();

    if (this.ipRateMap.size > 500) {
      for (const [k, v] of this.ipRateMap) {
        if (now - v.windowStart > RATE_WINDOW_MS) this.ipRateMap.delete(k);
      }
    }

    const entry = this.ipRateMap.get(ip);
    if (!entry || now - entry.windowStart > RATE_WINDOW_MS) {
      this.ipRateMap.set(ip, { count: 1, windowStart: now });
      return true;
    }
    entry.count++;
    return entry.count <= MAX_ANNOUNCEMENTS_PER_IP;
  }

  private announcementSigPayload(ann: MdnsAnnouncement): string {
    return `mdns:${ann.nodeId}:${ann.port}:${ann.timestamp}:${ann.nonce}`;
  }
}
