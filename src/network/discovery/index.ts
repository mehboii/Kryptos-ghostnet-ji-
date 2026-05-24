import { EventEmitter } from 'node:events';
import { ed25519 } from '@noble/curves/ed25519.js';
import { blake3 } from '@noble/hashes/blake3.js';
import { bytesToHex } from '@noble/hashes/utils.js';
import { DhtNode } from './dht.js';
import { MdnsDiscovery } from './mdns.js';
import { BootstrapClient } from './bootstrap.js';
import { generatePoW } from './proofOfWork.js';
import { KBucketManager } from './kBucket.js';
import type {
  TransportMode, DiscoveryPeer, BootstrapNode,
  DhtConfig, PeerEndpoint,
} from './types.js';
import { DEFAULT_DHT_CONFIG } from './types.js';

const MAX_ENDPOINTS_PER_PEER = 5;
const MAX_DISCOVERED_PEERS = 2_000;

export interface PeerDiscoveryEvents {
  'discovery:peer_found': [peer: DiscoveryPeer];
  'discovery:peer_verified': [nodeId: string];
  'discovery:peer_lost': [nodeId: string];
  'discovery:mode_changed': [mode: TransportMode];
  'discovery:bootstrap_complete': [peerCount: number];
  'discovery:dht_joined': [];
  'discovery:mdns_started': [];
  'discovery:security_event': [type: string, detail: string];
}

export interface DiscoveryOptions {
  transport?: TransportMode;
  dhtConfig?: Partial<DhtConfig>;
  bootstrapNodes?: BootstrapNode[];
  dhtPort?: number;
  servicePort?: number;
  enableMdns?: boolean;
  enableDht?: boolean;
}

const DEFAULT_BOOTSTRAP_NODES: BootstrapNode[] = [
  {
    host: 'bootstrap1.ghostnet.local',
    port: 6881,
    publicKeyHex: '0000000000000000000000000000000000000000000000000000000000000000',
    name: 'ghostnet-bootstrap-1',
  },
  {
    host: 'bootstrap2.ghostnet.local',
    port: 6881,
    publicKeyHex: '0000000000000000000000000000000000000000000000000000000000000000',
    name: 'ghostnet-bootstrap-2',
  },
  {
    host: 'bootstrap3.ghostnet.local',
    port: 6881,
    publicKeyHex: '0000000000000000000000000000000000000000000000000000000000000000',
    name: 'ghostnet-bootstrap-3',
  },
];

/**
 * Unified peer discovery orchestrator.
 *
 * Default transport: internet (DHT + mDNS + bootstrap nodes).
 * Optional: BLE mesh (user must explicitly enable).
 *
 * Security guarantees:
 * - All peer identities verified: nodeId = BLAKE3(publicKey)
 * - All messages signed with Ed25519
 * - DHT hardened against Sybil (PoW + IP quotas) and eclipse (/16 diversity)
 * - mDNS hardened against spoofing (challenge-response + signatures)
 * - Bootstrap nodes hardened against compromise (pinned keys + cross-validation)
 */
export class PeerDiscovery extends EventEmitter<PeerDiscoveryEvents> {
  private readonly nodeId: string;
  private readonly privateKey: Uint8Array;
  private readonly publicKey: Uint8Array;
  private transport: TransportMode;
  private dht: DhtNode | null = null;
  private mdns: MdnsDiscovery | null = null;
  private bootstrap: BootstrapClient;
  private readonly discoveredPeers = new Map<string, DiscoveryPeer>();
  private readonly options: Required<DiscoveryOptions>;
  private started = false;
  private bleCallback: ((peer: DiscoveryPeer) => void) | null = null;

  constructor(nodeId: string, privateKey: Uint8Array, options: DiscoveryOptions = {}) {
    super();
    this.nodeId = nodeId;
    this.privateKey = privateKey;
    this.publicKey = ed25519.getPublicKey(privateKey);

    this.options = {
      transport: options.transport ?? 'internet',
      dhtConfig: options.dhtConfig ?? {},
      bootstrapNodes: options.bootstrapNodes ?? DEFAULT_BOOTSTRAP_NODES,
      dhtPort: options.dhtPort ?? 0,
      servicePort: options.servicePort ?? 0,
      enableMdns: options.enableMdns ?? true,
      enableDht: options.enableDht ?? true,
    };

    this.transport = this.options.transport;
    this.bootstrap = new BootstrapClient(nodeId, privateKey, this.options.bootstrapNodes);

    this.bootstrap.on('bootstrap:compromised', (server, reason) => {
      this.emit('discovery:security_event', 'bootstrap_compromised', `${server}: ${reason}`);
    });
    this.bootstrap.on('bootstrap:poisoned_routing', (server, reason) => {
      this.emit('discovery:security_event', 'poisoned_routing', `${server}: ${reason}`);
    });
  }

  /** Start discovery on the current transport mode. */
  async start(): Promise<void> {
    if (this.started) return;
    this.started = true;

    if (this.transport === 'internet') {
      await this.startInternet();
    }
  }

  /**
   * Switch transport mode at runtime.
   * BLE is opt-in — user must explicitly request it.
   */
  async switchTransport(mode: TransportMode): Promise<void> {
    if (mode === this.transport) return;

    const previousTransport = this.transport;
    await this.stopCurrentTransport();

    for (const [nodeId, peer] of this.discoveredPeers) {
      if (peer.discoveredVia === previousTransport ||
          (previousTransport === 'internet' && (peer.discoveredVia === 'dht' || peer.discoveredVia === 'mdns' || peer.discoveredVia === 'bootstrap'))) {
        this.discoveredPeers.delete(nodeId);
        this.emit('discovery:peer_lost', nodeId);
      }
    }

    this.transport = mode;
    this.emit('discovery:mode_changed', mode);

    if (mode === 'internet' && this.started) {
      await this.startInternet();
    }
  }

  /** Register a BLE discovery callback for when BLE mode is active. */
  onBleDiscovery(callback: (peer: DiscoveryPeer) => void): void {
    this.bleCallback = callback;
  }

  /**
   * Feed a peer discovered via BLE into the registry.
   * DEFENSE: Same nodeId = BLAKE3(publicKey) verification applies to BLE peers.
   */
  addBlePeer(nodeId: string, publicKey: Uint8Array, bleEndpoint: PeerEndpoint): boolean {
    const expectedId = bytesToHex(blake3(publicKey));
    if (nodeId !== expectedId) {
      this.emit('discovery:security_event', 'ble_identity_mismatch', 'nodeId does not match BLAKE3(publicKey)');
      return false;
    }

    const peer: DiscoveryPeer = {
      nodeId, publicKey,
      endpoints: [bleEndpoint],
      discoveredVia: 'ble',
      discoveredAt: Date.now(),
      lastVerified: Date.now(),
      trustScore: 70,
    };

    this.discoveredPeers.set(nodeId, peer);
    this.emit('discovery:peer_found', peer);
    return true;
  }

  /** Manually add a peer (e.g., from QR code or direct entry). */
  addManualPeer(nodeId: string, publicKey: Uint8Array, endpoint: PeerEndpoint): boolean {
    const expectedId = bytesToHex(blake3(publicKey));
    if (nodeId !== expectedId) {
      this.emit('discovery:security_event', 'manual_identity_mismatch', 'nodeId does not match BLAKE3(publicKey)');
      return false;
    }

    const peer: DiscoveryPeer = {
      nodeId, publicKey,
      endpoints: [endpoint],
      discoveredVia: 'manual',
      discoveredAt: Date.now(),
      lastVerified: Date.now(),
      trustScore: 90,
    };

    this.discoveredPeers.set(nodeId, peer);
    this.emit('discovery:peer_found', peer);

    if (this.dht) {
      this.dht.buckets.addOrUpdate(nodeId, publicKey, endpoint);
    }

    return true;
  }

  /** Get all discovered peers. */
  getPeers(): DiscoveryPeer[] {
    return Array.from(this.discoveredPeers.values());
  }

  /** Get a specific peer. */
  getPeer(nodeId: string): DiscoveryPeer | undefined {
    return this.discoveredPeers.get(nodeId);
  }

  /** Find peers close to a target in DHT space. */
  async findPeers(targetNodeId: string): Promise<DiscoveryPeer[]> {
    if (!this.dht) return [];

    const entries = await this.dht.findNode(targetNodeId);
    return entries
      .map(e => this.discoveredPeers.get(e.nodeId))
      .filter((p): p is DiscoveryPeer => p !== undefined);
  }

  /** Current transport mode. */
  get currentTransport(): TransportMode { return this.transport; }

  /** Total known peers. */
  get peerCount(): number { return this.discoveredPeers.size; }

  /** Shut down all discovery mechanisms. */
  async destroy(): Promise<void> {
    this.started = false;
    await this.stopCurrentTransport();
    this.discoveredPeers.clear();
    this.removeAllListeners();
  }

  private async startInternet(): Promise<void> {
    // Phase 1: Bootstrap — contact pinned nodes for initial peers
    const seedPeers = await this.bootstrap.discover();
    this.emit('discovery:bootstrap_complete', seedPeers.length);

    for (const seed of seedPeers) {
      this.registerPeer(seed.nodeId, seed.publicKey, {
        ip: seed.ip, port: seed.port, transport: 'internet', verified: false,
      }, 'bootstrap');
    }

    // Phase 2: DHT — join with PoW, build routing table
    if (this.options.enableDht) {
      this.dht = new DhtNode(this.nodeId, this.privateKey, this.options.dhtConfig);

      this.dht.on('dht:peer_found', (nid, endpoint) => {
        const existing = this.dht!.buckets.get(nid);
        if (existing) {
          this.registerPeer(nid, existing.publicKey, endpoint, 'dht');
        }
      });

      this.dht.on('dht:sybil_rejected', (nid, reason) => {
        this.emit('discovery:security_event', 'dht_sybil', `${nid.slice(0, 8)}...: ${reason}`);
      });

      this.dht.on('dht:eclipse_rejected', (nid, reason) => {
        this.emit('discovery:security_event', 'dht_eclipse', `${nid.slice(0, 8)}...: ${reason}`);
      });

      const dhtPort = await this.dht.listen(this.options.dhtPort);

      if (seedPeers.length > 0) {
        const pow = generatePoW(this.nodeId, this.options.dhtConfig?.powDifficulty ?? DEFAULT_DHT_CONFIG.powDifficulty);
        await this.dht.join(seedPeers, pow);
        this.emit('discovery:dht_joined');
      }
    }

    // Phase 3: mDNS — local network discovery with challenge-response
    if (this.options.enableMdns) {
      const servicePort = this.options.servicePort || (this.dht ? (this.dht as any).port : 0);
      this.mdns = new MdnsDiscovery(this.nodeId, this.privateKey, servicePort);

      this.mdns.on('mdns:discovered', (nid, endpoint, publicKey) => {
        this.registerPeer(nid, publicKey, endpoint, 'mdns');
      });

      this.mdns.on('mdns:verified', (nid) => {
        const peer = this.discoveredPeers.get(nid);
        if (peer) {
          peer.lastVerified = Date.now();
          peer.trustScore = Math.min(100, peer.trustScore + 20);
        }
        this.emit('discovery:peer_verified', nid);
      });

      this.mdns.on('mdns:spoof_detected', (ip, reason) => {
        this.emit('discovery:security_event', 'mdns_spoof', `${reason}`);
      });

      try {
        await this.mdns.start();
        this.emit('discovery:mdns_started');
      } catch {
        // mDNS may not be available (no multicast support)
        this.mdns = null;
      }
    }
  }

  private async stopCurrentTransport(): Promise<void> {
    if (this.dht) { this.dht.destroy(); this.dht = null; }
    if (this.mdns) { this.mdns.stop(); this.mdns = null; }
  }

  private registerPeer(
    nodeId: string, publicKey: Uint8Array,
    endpoint: PeerEndpoint, source: DiscoveryPeer['discoveredVia'],
  ): void {
    const existing = this.discoveredPeers.get(nodeId);
    if (existing) {
      const hasEndpoint = existing.endpoints.some(
        e => e.ip === endpoint.ip && e.port === endpoint.port,
      );
      if (!hasEndpoint && existing.endpoints.length < MAX_ENDPOINTS_PER_PEER) {
        existing.endpoints.push(endpoint);
      }
      existing.lastVerified = Date.now();
      return;
    }

    if (this.discoveredPeers.size >= MAX_DISCOVERED_PEERS) return;

    const peer: DiscoveryPeer = {
      nodeId, publicKey,
      endpoints: [endpoint],
      discoveredVia: source,
      discoveredAt: Date.now(),
      lastVerified: Date.now(),
      trustScore: source === 'bootstrap' ? 80 : source === 'dht' ? 60 : source === 'mdns' ? 50 : 40,
    };

    this.discoveredPeers.set(nodeId, peer);
    this.emit('discovery:peer_found', peer);
  }
}

export { DhtNode } from './dht.js';
export { MdnsDiscovery } from './mdns.js';
export { BootstrapClient } from './bootstrap.js';
export { KBucketManager } from './kBucket.js';
export { generatePoW, verifyPoW } from './proofOfWork.js';
export type * from './types.js';
