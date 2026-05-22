import { EventEmitter } from 'node:events';
import type { SafePeerRecord } from './privacyFilter.js';

const MAX_PEERS = 1000;
const CLEANUP_INTERVAL_MS = 60_000;

export interface PeerEvent {
  record: SafePeerRecord;
  timestamp: number;
}

export interface PeerRemovedEvent {
  nodeId: string;
  timestamp: number;
}

export interface PeerRegistryEvents {
  'peer:added': [event: PeerEvent];
  'peer:updated': [event: PeerEvent];
  'peer:removed': [event: PeerRemovedEvent];
  'peer:expired': [event: PeerRemovedEvent];
}

export class PeerRegistry extends EventEmitter<PeerRegistryEvents> {
  private readonly peers = new Map<string, SafePeerRecord>();
  private cleanupTimer: ReturnType<typeof setInterval> | null = null;

  constructor() {
    super();
    this.cleanupTimer = setInterval(() => this.cleanup(), CLEANUP_INTERVAL_MS);
  }

  /** Add or update a peer record. Evicts lowest-confidence peer if at capacity. */
  addPeer(record: SafePeerRecord): void {
    const exists = this.peers.has(record.nodeId);

    if (!exists && this.peers.size >= MAX_PEERS) {
      this.evictLowestConfidence();
    }

    this.peers.set(record.nodeId, record);
    const event: PeerEvent = { record, timestamp: Date.now() };
    this.emit(exists ? 'peer:updated' : 'peer:added', event);
  }

  /** Remove a peer by nodeId. */
  removePeer(nodeId: string): void {
    if (!this.peers.delete(nodeId)) return;
    this.emit('peer:removed', { nodeId, timestamp: Date.now() });
  }

  /** Look up a single peer by nodeId. */
  getPeer(nodeId: string): SafePeerRecord | null {
    return this.peers.get(nodeId) ?? null;
  }

  /** Return all peer records. */
  getAllPeers(): SafePeerRecord[] {
    return Array.from(this.peers.values());
  }

  /** Find all peers sharing an IP fingerprint (Sybil detection support). */
  getByFingerprint(ipFingerprint: string): SafePeerRecord[] {
    const results: SafePeerRecord[] = [];
    for (const record of this.peers.values()) {
      if (record.ipFingerprint === ipFingerprint) results.push(record);
    }
    return results;
  }

  /** Evict all peers whose TTL has expired. */
  cleanup(): void {
    const now = Date.now();
    for (const [nodeId, record] of this.peers) {
      if (now >= record.expiresAt) {
        this.peers.delete(nodeId);
        this.emit('peer:expired', { nodeId, timestamp: now });
      }
    }
  }

  /** Stop the cleanup timer, clear all peers, remove all listeners. */
  destroy(): void {
    if (this.cleanupTimer) {
      clearInterval(this.cleanupTimer);
      this.cleanupTimer = null;
    }
    this.peers.clear();
    this.removeAllListeners();
  }

  /** Current number of registered peers. */
  get size(): number {
    return this.peers.size;
  }

  private evictLowestConfidence(): void {
    let lowestId: string | null = null;
    let lowestConf = Infinity;
    for (const [nodeId, record] of this.peers) {
      if (record.confidence < lowestConf) {
        lowestConf = record.confidence;
        lowestId = nodeId;
      }
    }
    if (lowestId) this.removePeer(lowestId);
  }
}
