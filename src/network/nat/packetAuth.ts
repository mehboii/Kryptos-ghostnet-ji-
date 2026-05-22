import { ed25519 } from '@noble/curves/ed25519.js';
import { hexToBytes } from '@noble/hashes/utils.js';
import type { AuthResult } from './types.js';

const TIMESTAMP_WINDOW_MS = 30000;
const NONCE_MAX = 10000;
const NONCE_TTL_MS = 60000;
const CLEANUP_INTERVAL_MS = 30000;

interface NonceEntry { nonce: string; expiresAt: number }

interface AuthStats {
  totalReceived: number;
  authenticated: number;
  rejected: number;
  rejectionReasons: Record<string, number>;
}

export class PacketAuthenticator {
  private knownPeers = new Map<string, Uint8Array>();
  private nonceSet = new Map<string, number>();
  private cleanupTimer: ReturnType<typeof setInterval>;
  private stats: AuthStats = { totalReceived: 0, authenticated: 0, rejected: 0, rejectionReasons: {} };

  constructor() {
    this.cleanupTimer = setInterval(() => this.evictNonces(), CLEANUP_INTERVAL_MS);
  }

  /**
   * Authenticate an inbound packet. 6-step mandatory flow.
   * On ANY failure: returns { valid: false } — caller MUST silently drop. No response.
   */
  authenticate(packet: Buffer, expectedPeerNodeId?: string): AuthResult {
    this.stats.totalReceived++;

    // Step 1: Parse (in production, decrypt first with own private key)
    let parsed: { nodeId: string; signature: string; timestamp: number; nonce: string; data: unknown };
    try {
      parsed = JSON.parse(packet.toString('utf8'));
    } catch {
      return this.reject('malformed_payload');
    }

    if (!parsed.nodeId || !parsed.signature || !parsed.timestamp || !parsed.nonce || parsed.data === undefined) {
      return this.reject('malformed_payload');
    }

    // Step 2: Peer identity check
    if (expectedPeerNodeId && parsed.nodeId !== expectedPeerNodeId) {
      return this.reject('unexpected_peer');
    }

    const peerPubKey = this.knownPeers.get(parsed.nodeId);
    if (!peerPubKey) {
      return this.reject('unknown_peer');
    }

    // Step 3: Ed25519 signature verification — BEFORE any payload processing
    const sigPayload = `${parsed.nodeId}:${parsed.timestamp}:${parsed.nonce}:${JSON.stringify(parsed.data)}`;
    try {
      const sigBytes = hexToBytes(parsed.signature);
      const valid = ed25519.verify(sigBytes, new TextEncoder().encode(sigPayload), peerPubKey);
      if (!valid) return this.reject('invalid_signature');
    } catch {
      return this.reject('invalid_signature');
    }

    // Step 4: Timestamp freshness
    if (Math.abs(Date.now() - parsed.timestamp) > TIMESTAMP_WINDOW_MS) {
      return this.reject('timestamp_expired');
    }

    // Step 5: Nonce replay check
    if (this.nonceSet.has(parsed.nonce)) {
      return this.reject('nonce_reused');
    }
    this.recordNonce(parsed.nonce);

    this.stats.authenticated++;
    return {
      valid: true,
      peerNodeId: parsed.nodeId,
      data: parsed.data,
      timestamp: parsed.timestamp,
    };
  }

  /** Register a known peer's public key. */
  addKnownPeer(nodeId: string, publicKey: Uint8Array): void {
    this.knownPeers.set(nodeId, publicKey);
  }

  /** Remove a known peer. */
  removeKnownPeer(nodeId: string): void {
    this.knownPeers.delete(nodeId);
  }

  /** Get authentication statistics for Signal Intelligence. */
  getStats(): Readonly<AuthStats> {
    return { ...this.stats, rejectionReasons: { ...this.stats.rejectionReasons } };
  }

  /** Number of known peers. */
  get peerCount(): number {
    return this.knownPeers.size;
  }

  /** Destroy: clear timers and state. */
  destroy(): void {
    clearInterval(this.cleanupTimer);
    this.nonceSet.clear();
    this.knownPeers.clear();
  }

  private reject(reason: string): AuthResult {
    this.stats.rejected++;
    this.stats.rejectionReasons[reason] = (this.stats.rejectionReasons[reason] ?? 0) + 1;
    return { valid: false, reason };
  }

  private recordNonce(nonce: string): void {
    if (this.nonceSet.size >= NONCE_MAX) this.evictNonces();
    if (this.nonceSet.size >= NONCE_MAX) {
      const oldest = this.nonceSet.keys().next().value!;
      this.nonceSet.delete(oldest);
    }
    this.nonceSet.set(nonce, Date.now() + NONCE_TTL_MS);
  }

  private evictNonces(): void {
    const now = Date.now();
    for (const [nonce, expiresAt] of this.nonceSet) {
      if (now >= expiresAt) this.nonceSet.delete(nonce);
    }
  }
}
