import { EventEmitter } from 'node:events';
import type { Socket as TcpSocket } from 'node:net';
import type { RemoteInfo } from 'node:dgram';

import { SocketObserver } from './observer.js';
import { HandshakeParser } from './handshake.js';
import { ReconciliationEngine } from './reconciliation.js';
import { PrivacyFilter } from './privacyFilter.js';
import { PeerRegistry } from './registry.js';
import type { ObservedEndpoint } from './observer.js';
import type { ClaimedEndpoint, HandshakeMessage } from './handshake.js';
import type { ReconciledPeer } from './reconciliation.js';
import type { SafePeerRecord, PrivacyTier } from './privacyFilter.js';
import type { PeerEvent, PeerRemovedEvent } from './registry.js';

export type { ObservedEndpoint, ClaimedEndpoint, ReconciledPeer, SafePeerRecord, PrivacyTier };
export { SocketObserver, HandshakeParser, ReconciliationEngine, PrivacyFilter, PeerRegistry };

export interface IPv4ExtractorOptions {
  relayIps?: string[];
  defaultTier?: PrivacyTier;
}

export interface IPv4ExtractorEvents {
  'peer:added': [event: PeerEvent];
  'peer:updated': [event: PeerEvent];
  'peer:removed': [event: PeerRemovedEvent];
  'peer:expired': [event: PeerRemovedEvent];
}

/**
 * Unified pipeline wiring together socket observation, handshake verification,
 * NAT/spoof reconciliation, privacy filtering, and peer registration.
 *
 * @example
 * const extractor = new IPv4Extractor({ defaultTier: 'ghost' });
 * extractor.on('peer:added', (e) => console.log('New peer:', e.record.nodeId));
 * const record = extractor.processConnection(socket, handshakeMsg);
 */
export class IPv4Extractor extends EventEmitter<IPv4ExtractorEvents> {
  private readonly observer: SocketObserver;
  private readonly handshake: HandshakeParser;
  private readonly reconciliation: ReconciliationEngine;
  private readonly privacy: PrivacyFilter;
  private readonly registry: PeerRegistry;
  private readonly defaultTier: PrivacyTier;

  constructor(options: IPv4ExtractorOptions = {}) {
    super();
    this.defaultTier = options.defaultTier ?? 'stealth';
    this.observer = new SocketObserver();
    this.handshake = new HandshakeParser();
    this.reconciliation = new ReconciliationEngine(options.relayIps);
    this.privacy = new PrivacyFilter();
    this.registry = new PeerRegistry();

    for (const event of ['peer:added', 'peer:updated', 'peer:removed', 'peer:expired'] as const) {
      this.registry.on(event, (payload: PeerEvent | PeerRemovedEvent) => {
        this.emit(event, payload as any);
      });
    }
  }

  /**
   * Run the full extraction pipeline for a TCP socket or UDP remote info.
   * Returns null if the observed endpoint could not be extracted.
   */
  processConnection(
    socket: TcpSocket | RemoteInfo,
    handshakeMessage: Buffer | HandshakeMessage,
    tier?: PrivacyTier,
  ): SafePeerRecord | null {
    const observed = this.extractEndpoint(socket);
    if (!observed) return null;

    const claimed = this.handshake.parse(handshakeMessage);
    const reconciled = this.reconciliation.reconcile(observed, claimed);
    const record = this.privacy.apply(reconciled, tier ?? this.defaultTier);
    this.registry.addPeer(record);
    return record;
  }

  /** Look up a peer by nodeId. */
  getPeer(nodeId: string): SafePeerRecord | null {
    return this.registry.getPeer(nodeId);
  }

  /** Return all registered peers. */
  getAllPeers(): SafePeerRecord[] {
    return this.registry.getAllPeers();
  }

  /** Tear down the entire pipeline: timers, caches, listeners. */
  destroy(): void {
    this.registry.destroy();
    this.privacy.clear();
    this.reconciliation.clear();
    this.observer.clear();
    this.removeAllListeners();
  }

  private extractEndpoint(socket: TcpSocket | RemoteInfo): ObservedEndpoint | null {
    if (this.isRemoteInfo(socket)) {
      if (!socket.address || socket.family === 'IPv6') return null;
      let ip = socket.address;
      if (ip.startsWith('::ffff:')) ip = ip.slice(7);
      return { ip, port: socket.port, family: 'IPv4', observedAt: Date.now() };
    }
    return this.observer.observeTcp(socket);
  }

  private isRemoteInfo(value: TcpSocket | RemoteInfo): value is RemoteInfo {
    return 'address' in value && 'family' in value && 'size' in value;
  }
}
