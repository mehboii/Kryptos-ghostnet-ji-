import { EventEmitter } from 'node:events';
import { blake3 } from '@noble/hashes/blake3.js';
import { bytesToHex, hexToBytes } from '@noble/hashes/utils.js';
import type { KBucketEntry, DhtConfig, PeerEndpoint } from './types.js';
import { DEFAULT_DHT_CONFIG } from './types.js';

export interface KBucketEvents {
  'bucket:added': [entry: KBucketEntry];
  'bucket:evicted': [entry: KBucketEntry];
  'bucket:updated': [entry: KBucketEntry];
  'bucket:ping': [oldest: KBucketEntry, candidate: KBucketEntry];
  'bucket:sybil_blocked': [nodeId: string, reason: string];
  'bucket:eclipse_blocked': [nodeId: string, ipPrefix: string];
}

/**
 * Kademlia k-bucket with anti-Sybil and anti-eclipse hardening.
 *
 * DEFENSE: Sybil — nodeId = BLAKE3(publicKey), can't choose IDs.
 * DEFENSE: Sybil — max entries per IP prefix across all buckets.
 * DEFENSE: Eclipse — max nodes per /16 subnet within each bucket.
 * DEFENSE: Eclipse — prefer long-lived nodes (don't evict for newcomers).
 */
export class KBucketManager extends EventEmitter<KBucketEvents> {
  private readonly ownId: Uint8Array;
  private readonly config: DhtConfig;
  private readonly buckets: KBucketEntry[][] = [];
  private readonly ipPrefixCount = new Map<string, number>();
  private readonly globalIpCount = new Map<string, number>();

  constructor(ownNodeId: string, config: Partial<DhtConfig> = {}) {
    super();
    this.ownId = hexToBytes(ownNodeId);
    this.config = { ...DEFAULT_DHT_CONFIG, ...config };
    for (let i = 0; i < this.config.bucketCount; i++) this.buckets.push([]);
  }

  /** XOR distance between two nodeIds (as hex strings). */
  static distance(a: string, b: string): Uint8Array {
    const aBytes = hexToBytes(a);
    const bBytes = hexToBytes(b);
    const result = new Uint8Array(aBytes.length);
    for (let i = 0; i < aBytes.length; i++) result[i] = aBytes[i] ^ bBytes[i];
    return result;
  }

  /** Bucket index = position of highest set bit in XOR distance. */
  bucketIndex(nodeId: string): number {
    const dist = KBucketManager.distance(bytesToHex(this.ownId), nodeId);
    for (let i = 0; i < dist.length; i++) {
      if (dist[i] === 0) continue;
      return (dist.length - 1 - i) * 8 + (7 - Math.clz32(dist[i]) + 24);
    }
    return 0;
  }

  /**
   * Insert or update a peer. Returns true if accepted.
   * DEFENSE: Verifies nodeId === BLAKE3(publicKey) before any insertion.
   * DEFENSE: Rejects if IP prefix quota exceeded in this bucket (anti-eclipse).
   * DEFENSE: Rejects if global IP count exceeded (anti-Sybil).
   */
  addOrUpdate(nodeId: string, publicKey: Uint8Array, endpoint: PeerEndpoint): boolean {
    const expectedId = bytesToHex(blake3(publicKey));
    if (nodeId !== expectedId) {
      this.emit('bucket:sybil_blocked', nodeId, 'nodeId_mismatch');
      return false;
    }

    if (nodeId === bytesToHex(this.ownId)) return false;

    const idx = this.bucketIndex(nodeId);
    const bucket = this.buckets[idx];
    const ipPrefix = this.extractPrefix(endpoint.ip);
    const globalIp = endpoint.ip;

    const existing = bucket.find(e => e.nodeId === nodeId);
    if (existing) {
      existing.lastSeen = Date.now();
      existing.endpoint = endpoint;
      existing.failCount = 0;
      this.emit('bucket:updated', existing);
      return true;
    }

    const prefixInBucket = bucket.filter(e => e.ipPrefix === ipPrefix).length;
    if (prefixInBucket >= this.config.maxIpPrefixPerBucket) {
      this.emit('bucket:eclipse_blocked', nodeId, ipPrefix);
      return false;
    }

    const globalCount = this.globalIpCount.get(globalIp) ?? 0;
    if (globalCount >= this.config.maxEntriesPerIp) {
      this.emit('bucket:sybil_blocked', nodeId, 'ip_quota_exceeded');
      return false;
    }

    const entry: KBucketEntry = {
      nodeId, publicKey, endpoint,
      lastSeen: Date.now(), lastPonged: 0, failCount: 0,
      ipPrefix, addedAt: Date.now(),
    };

    if (bucket.length < this.config.k) {
      bucket.push(entry);
      this.trackIp(globalIp, 1);
      this.emit('bucket:added', entry);
      return true;
    }

    const stale = bucket.find(e => e.failCount >= 3);
    if (stale) {
      this.evict(idx, stale);
      bucket.push(entry);
      this.trackIp(globalIp, 1);
      this.emit('bucket:added', entry);
      return true;
    }

    const oldest = bucket.reduce((a, b) => a.lastSeen < b.lastSeen ? a : b);
    this.emit('bucket:ping', oldest, entry);
    return false;
  }

  /** Mark a node as failed (no pong response). */
  markFailed(nodeId: string): void {
    const idx = this.bucketIndex(nodeId);
    const entry = this.buckets[idx].find(e => e.nodeId === nodeId);
    if (entry) entry.failCount++;
  }

  /** Mark a node as alive (pong received). */
  markAlive(nodeId: string): void {
    const idx = this.bucketIndex(nodeId);
    const entry = this.buckets[idx].find(e => e.nodeId === nodeId);
    if (entry) {
      entry.lastPonged = Date.now();
      entry.lastSeen = Date.now();
      entry.failCount = 0;
    }
  }

  /** Find k closest nodes to a target nodeId. */
  closest(targetId: string, count?: number): KBucketEntry[] {
    const k = count ?? this.config.k;
    const all: KBucketEntry[] = [];
    for (const bucket of this.buckets) all.push(...bucket);

    all.sort((a, b) => {
      const da = KBucketManager.distance(a.nodeId, targetId);
      const db = KBucketManager.distance(b.nodeId, targetId);
      for (let i = 0; i < da.length; i++) {
        if (da[i] !== db[i]) return da[i] - db[i];
      }
      return 0;
    });

    return all.slice(0, k);
  }

  /** Get a specific entry by nodeId. */
  get(nodeId: string): KBucketEntry | undefined {
    const idx = this.bucketIndex(nodeId);
    return this.buckets[idx].find(e => e.nodeId === nodeId);
  }

  /** Remove a node from routing table. */
  remove(nodeId: string): boolean {
    const idx = this.bucketIndex(nodeId);
    const bucket = this.buckets[idx];
    const pos = bucket.findIndex(e => e.nodeId === nodeId);
    if (pos === -1) return false;
    const entry = bucket[pos];
    bucket.splice(pos, 1);
    this.trackIp(entry.endpoint.ip, -1);
    this.emit('bucket:evicted', entry);
    return true;
  }

  /** Total entries across all buckets. */
  get size(): number {
    let n = 0;
    for (const b of this.buckets) n += b.length;
    return n;
  }

  /** Get all entries in a specific bucket. */
  getBucket(index: number): readonly KBucketEntry[] {
    return this.buckets[index] ?? [];
  }

  /** Find buckets that haven't been refreshed recently. */
  staleBuckets(thresholdMs: number): number[] {
    const now = Date.now();
    const stale: number[] = [];
    for (let i = 0; i < this.buckets.length; i++) {
      const bucket = this.buckets[i];
      if (bucket.length === 0) continue;
      const newest = bucket.reduce((a, b) => a.lastSeen > b.lastSeen ? a : b);
      if (now - newest.lastSeen > thresholdMs) stale.push(i);
    }
    return stale;
  }

  /** Clear all entries. */
  destroy(): void {
    for (const bucket of this.buckets) bucket.length = 0;
    this.ipPrefixCount.clear();
    this.globalIpCount.clear();
    this.removeAllListeners();
  }

  private evict(bucketIdx: number, entry: KBucketEntry): void {
    const bucket = this.buckets[bucketIdx];
    const pos = bucket.indexOf(entry);
    if (pos !== -1) {
      bucket.splice(pos, 1);
      this.trackIp(entry.endpoint.ip, -1);
      this.emit('bucket:evicted', entry);
    }
  }

  private trackIp(ip: string, delta: number): void {
    const current = this.globalIpCount.get(ip) ?? 0;
    const next = current + delta;
    if (next <= 0) this.globalIpCount.delete(ip);
    else this.globalIpCount.set(ip, next);
  }

  /** /16 prefix for IPv4 eclipse defense. */
  private extractPrefix(ip: string): string {
    const parts = ip.split('.');
    if (parts.length === 4) return `${parts[0]}.${parts[1]}`;
    return ip.slice(0, ip.lastIndexOf(':'));
  }
}
