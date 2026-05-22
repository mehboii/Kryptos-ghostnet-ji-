import type { ObservedEndpoint } from './observer.js';
import type { ClaimedEndpoint } from './handshake.js';

const ROAMING_WINDOW_MS = 5 * 60_000;
const SYBIL_WINDOW_MS = 10 * 60_000;
const ROAMING_THRESHOLD = 3;
const SYBIL_THRESHOLD = 5;

export type ConnectionType = 'direct' | 'nat' | 'relay' | 'suspicious';

export interface ReconciledPeer {
  nodeId: string;
  observed: ObservedEndpoint;
  claimed: ClaimedEndpoint;
  natDetected: boolean;
  spoofingFlag: boolean;
  confidence: number;
  connectionType: ConnectionType;
  flags: string[];
}

interface TimestampedEntry {
  value: string;
  at: number;
}

const MAX_TRACKING_ENTRIES = 5_000;

/** Check whether an IPv4 address falls within RFC 1918 private ranges. */
export function isPrivateIp(ip: string): boolean {
  let normalized = ip;
  if (normalized.startsWith('::ffff:')) normalized = normalized.slice(7);
  const parts = normalized.split('.').map(Number);
  if (parts.length !== 4 || parts.some(p => isNaN(p) || p < 0 || p > 255)) return false;
  if (parts[0] === 10) return true;
  if (parts[0] === 172 && parts[1] >= 16 && parts[1] <= 31) return true;
  if (parts[0] === 192 && parts[1] === 168) return true;
  if (parts[0] === 127) return true;
  return false;
}

export class ReconciliationEngine {
  private readonly relayIps: Set<string>;
  private readonly nodeIpHistory = new Map<string, TimestampedEntry[]>();
  private readonly ipNodeHistory = new Map<string, TimestampedEntry[]>();

  constructor(relayIps: string[] = []) {
    this.relayIps = new Set(relayIps);
  }

  /** Compare an observed socket endpoint against a peer's claimed handshake data. */
  reconcile(observed: ObservedEndpoint, claimed: ClaimedEndpoint): ReconciledPeer {
    const flags: string[] = [];
    let connectionType: ConnectionType;
    let confidence: number;
    let natDetected = false;
    let spoofingFlag = false;

    // Decision tree
    if (!claimed.verified) {
      connectionType = 'suspicious';
      confidence = 0;
      spoofingFlag = true;
    } else if (this.relayIps.has(observed.ip)) {
      connectionType = 'relay';
      confidence = 60;
    } else if (observed.ip === claimed.claimedPublicIp) {
      connectionType = 'direct';
      confidence = 95;
    } else if (isPrivateIp(claimed.claimedLanIp)) {
      connectionType = 'nat';
      confidence = 75;
      natDetected = true;
    } else {
      connectionType = 'suspicious';
      confidence = 20;
      spoofingFlag = true;
    }

    // Historical tracking
    this.recordNodeIp(claimed.nodeId, observed.ip, observed.observedAt);
    this.recordIpNode(observed.ip, claimed.nodeId, observed.observedAt);

    if (this.isRoaming(claimed.nodeId, observed.observedAt)) {
      flags.push('roaming_or_compromised');
    }
    if (this.isSybil(observed.ip, observed.observedAt)) {
      flags.push('possible_sybil');
    }

    return {
      nodeId: claimed.nodeId,
      observed,
      claimed,
      natDetected,
      spoofingFlag,
      confidence,
      connectionType,
      flags,
    };
  }

  /** Total number of tracked keys across both maps. */
  get trackingSize(): number {
    return this.nodeIpHistory.size + this.ipNodeHistory.size;
  }

  /** Flush all tracking history. */
  clear(): void {
    this.nodeIpHistory.clear();
    this.ipNodeHistory.clear();
  }

  private recordNodeIp(nodeId: string, ip: string, at: number): void {
    const entries = this.nodeIpHistory.get(nodeId) ?? [];
    entries.push({ value: ip, at });
    this.nodeIpHistory.set(nodeId, this.pruneEntries(entries, at, ROAMING_WINDOW_MS));
    this.capMap(this.nodeIpHistory);
  }

  private recordIpNode(ip: string, nodeId: string, at: number): void {
    const entries = this.ipNodeHistory.get(ip) ?? [];
    entries.push({ value: nodeId, at });
    this.ipNodeHistory.set(ip, this.pruneEntries(entries, at, SYBIL_WINDOW_MS));
    this.capMap(this.ipNodeHistory);
  }

  private capMap(map: Map<string, TimestampedEntry[]>): void {
    if (map.size <= MAX_TRACKING_ENTRIES) return;
    const oldest = map.keys().next().value!;
    map.delete(oldest);
  }

  private isRoaming(nodeId: string, now: number): boolean {
    const entries = this.nodeIpHistory.get(nodeId);
    if (!entries) return false;
    const cutoff = now - ROAMING_WINDOW_MS;
    const uniqueIps = new Set(entries.filter(e => e.at >= cutoff).map(e => e.value));
    return uniqueIps.size >= ROAMING_THRESHOLD;
  }

  private isSybil(ip: string, now: number): boolean {
    const entries = this.ipNodeHistory.get(ip);
    if (!entries) return false;
    const cutoff = now - SYBIL_WINDOW_MS;
    const uniqueNodes = new Set(entries.filter(e => e.at >= cutoff).map(e => e.value));
    return uniqueNodes.size >= SYBIL_THRESHOLD;
  }

  private pruneEntries(entries: TimestampedEntry[], now: number, ttl: number): TimestampedEntry[] {
    const cutoff = now - ttl;
    return entries.filter(e => e.at >= cutoff);
  }
}
