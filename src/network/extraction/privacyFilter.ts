import { blake3 } from '@noble/hashes/blake3.js';
import { bytesToHex } from '@noble/hashes/utils.js';
import type { ReconciledPeer } from './reconciliation.js';

export type PrivacyTier = 'stealth' | 'ghost' | 'phantom';

const TTL_STEALTH_MS = 60 * 60_000;
const TTL_GHOST_MS = 15 * 60_000;

export interface SafePeerRecord {
  nodeId: string;
  ipFingerprint: string;
  endpoint?: string;
  confidence: number;
  tier: PrivacyTier;
  expiresAt: number;
}

interface CacheEntry {
  record: SafePeerRecord;
  expiresAt: number;
}

export class PrivacyFilter {
  private readonly cache = new Map<string, CacheEntry>();

  /** Apply a Ghost Shield privacy tier to a reconciled peer, returning a sanitised record. */
  apply(peer: ReconciledPeer, tier: PrivacyTier): SafePeerRecord {
    this.evict();

    const now = Date.now();

    if (tier === 'phantom') {
      return {
        nodeId: peer.nodeId,
        ipFingerprint: 'redacted',
        endpoint: undefined,
        confidence: peer.confidence,
        tier,
        expiresAt: now,
      };
    }

    const fingerprint = this.fingerprint(peer.observed.ip);
    const expiresAt = now + (tier === 'stealth' ? TTL_STEALTH_MS : TTL_GHOST_MS);

    const record: SafePeerRecord = {
      nodeId: peer.nodeId,
      ipFingerprint: fingerprint,
      endpoint: tier === 'ghost' ? `${peer.observed.ip}:${peer.observed.port}` : undefined,
      confidence: peer.confidence,
      tier,
      expiresAt,
    };

    this.cache.set(peer.nodeId, { record, expiresAt });
    return record;
  }

  /** Look up a cached record by nodeId. Returns undefined if expired or absent. */
  lookup(nodeId: string): SafePeerRecord | undefined {
    const entry = this.cache.get(nodeId);
    if (!entry) return undefined;
    if (Date.now() >= entry.expiresAt) {
      this.cache.delete(nodeId);
      return undefined;
    }
    return entry.record;
  }

  /** Flush all cached records immediately. */
  clear(): void {
    this.cache.clear();
  }

  /** Return count of live (non-expired) cached records. */
  get size(): number {
    this.evict();
    return this.cache.size;
  }

  private fingerprint(ip: string): string {
    return bytesToHex(blake3(new TextEncoder().encode(ip)));
  }

  private evict(): void {
    const now = Date.now();
    for (const [key, entry] of this.cache) {
      if (now >= entry.expiresAt) this.cache.delete(key);
    }
  }
}
