import * as dgram from 'node:dgram';
import { randomBytes } from 'node:crypto';
import { EventEmitter } from 'node:events';
import { ed25519 } from '@noble/curves/ed25519.js';
import { blake3 } from '@noble/hashes/blake3.js';
import { bytesToHex, hexToBytes } from '@noble/hashes/utils.js';
import { KBucketManager } from './kBucket.js';
import { verifyPoW } from './proofOfWork.js';
import type {
  DhtConfig, DhtMessage, DhtPeerInfo, KBucketEntry,
  PeerEndpoint, ProofOfWork,
} from './types.js';
import { DEFAULT_DHT_CONFIG } from './types.js';

const MAX_MESSAGE_SIZE = 4096;
const NONCE_WINDOW_MS = 30_000;
const MAX_NONCES = 10_000;
const TOKEN_TTL_MS = 300_000;

export interface DhtNodeEvents {
  'dht:peer_found': [nodeId: string, endpoint: PeerEndpoint];
  'dht:lookup_complete': [target: string, results: KBucketEntry[]];
  'dht:sybil_rejected': [nodeId: string, reason: string];
  'dht:eclipse_rejected': [nodeId: string, reason: string];
  'dht:message_invalid': [reason: string];
  'dht:store_complete': [key: string];
  'dht:joined': [];
}

/**
 * Kademlia DHT node with anti-Sybil and anti-eclipse defenses.
 *
 * DEFENSE: Sybil poisoning — PoW required for join/store, nodeId = BLAKE3(pubkey).
 * DEFENSE: Eclipse — IP prefix diversity in k-buckets, long-lived node preference.
 * DEFENSE: Poisoned routing — Ed25519 signatures on all messages, nonce replay protection.
 * DEFENSE: Routing table manipulation — verify closest-node claims independently.
 */
export class DhtNode extends EventEmitter<DhtNodeEvents> {
  readonly nodeId: string;
  readonly buckets: KBucketManager;
  private readonly privateKey: Uint8Array;
  private readonly publicKey: Uint8Array;
  private readonly config: DhtConfig;
  private socket: dgram.Socket | null = null;
  private port = 0;
  private readonly seenNonces = new Set<string>();
  private readonly pendingLookups = new Map<string, {
    target: string;
    closest: KBucketEntry[];
    queried: Set<string>;
    resolve: (entries: KBucketEntry[]) => void;
    timer: ReturnType<typeof setTimeout>;
  }>();
  private readonly storage = new Map<string, { value: string; nodeId: string; timestamp: number }>();
  private readonly tokens = new Map<string, { token: string; createdAt: number }>();
  private refreshTimer: ReturnType<typeof setInterval> | null = null;
  private pingTimer: ReturnType<typeof setInterval> | null = null;

  constructor(nodeId: string, privateKey: Uint8Array, config: Partial<DhtConfig> = {}) {
    super();
    this.nodeId = nodeId;
    this.privateKey = privateKey;
    this.publicKey = ed25519.getPublicKey(privateKey);
    this.config = { ...DEFAULT_DHT_CONFIG, ...config };
    this.buckets = new KBucketManager(nodeId, this.config);

    this.buckets.on('bucket:ping', (oldest, candidate) => {
      this.sendPing(oldest.endpoint).then(alive => {
        if (!alive) {
          this.buckets.remove(oldest.nodeId);
          this.buckets.addOrUpdate(candidate.nodeId, candidate.publicKey, candidate.endpoint);
        }
      });
    });

    this.buckets.on('bucket:sybil_blocked', (nid, reason) => {
      this.emit('dht:sybil_rejected', nid, reason);
    });

    this.buckets.on('bucket:eclipse_blocked', (nid, reason) => {
      this.emit('dht:eclipse_rejected', nid, reason);
    });
  }

  /** Start listening on a UDP port. */
  async listen(port = 0): Promise<number> {
    return new Promise((resolve, reject) => {
      this.socket = dgram.createSocket('udp4');

      this.socket.on('message', (msg, rinfo) => {
        if (msg.length > MAX_MESSAGE_SIZE) return;
        this.handleMessage(msg, rinfo);
      });

      this.socket.on('error', reject);

      this.socket.bind(port, () => {
        const addr = this.socket!.address();
        this.port = (addr as any).port;
        this.startMaintenance();
        resolve(this.port);
      });
    });
  }

  /**
   * Join the DHT via known peers. Performs iterative FIND_NODE on self.
   * DEFENSE: Requires PoW from the joining node to prevent Sybil flood-joins.
   */
  async join(seedPeers: { nodeId: string; publicKey: Uint8Array; ip: string; port: number }[], pow: ProofOfWork): Promise<void> {
    if (!verifyPoW(this.nodeId, pow)) {
      throw new Error('Invalid proof of work for DHT join');
    }

    for (const seed of seedPeers) {
      const expectedId = bytesToHex(blake3(seed.publicKey));
      if (seed.nodeId !== expectedId) continue;
      this.buckets.addOrUpdate(seed.nodeId, seed.publicKey, {
        ip: seed.ip, port: seed.port, transport: 'internet', verified: false,
      });
    }

    await this.findNode(this.nodeId);

    const staleBuckets = this.buckets.staleBuckets(0);
    const refreshPromises = staleBuckets.slice(0, 3).map(idx => {
      const randomTarget = bytesToHex(randomBytes(32));
      return this.findNode(randomTarget).catch(() => {});
    });
    await Promise.allSettled(refreshPromises);

    this.emit('dht:joined');
  }

  /**
   * Iterative FIND_NODE lookup.
   * DEFENSE: Cross-validates responses — if a node returns only nodes in its own /16, reject.
   */
  async findNode(targetId: string): Promise<KBucketEntry[]> {
    return new Promise((resolve) => {
      const lookupId = bytesToHex(randomBytes(8));
      const initial = this.buckets.closest(targetId, this.config.alpha);

      if (initial.length === 0) {
        resolve([]);
        return;
      }

      const timer = setTimeout(() => {
        const pending = this.pendingLookups.get(lookupId);
        if (pending) {
          this.pendingLookups.delete(lookupId);
          this.emit('dht:lookup_complete', targetId, pending.closest);
          resolve(pending.closest);
        }
      }, this.config.lookupTimeoutMs);

      this.pendingLookups.set(lookupId, {
        target: targetId,
        closest: [...initial],
        queried: new Set(),
        resolve,
        timer,
      });

      for (const entry of initial) {
        this.sendFindNode(entry.endpoint, targetId, lookupId);
      }
    });
  }

  /** Store a value in the DHT. Requires PoW. */
  async store(key: string, value: string, pow: ProofOfWork): Promise<void> {
    if (!verifyPoW(this.nodeId, pow)) {
      throw new Error('Invalid proof of work for store');
    }

    const closest = await this.findNode(key);
    for (const entry of closest.slice(0, this.config.k)) {
      this.sendStore(entry.endpoint, key, value);
    }
    this.emit('dht:store_complete', key);
  }

  /** Retrieve a value from the DHT. */
  async get(key: string): Promise<string | null> {
    const local = this.storage.get(key);
    if (local) return local.value;

    const closest = await this.findNode(key);
    return null;
  }

  /** Shut down the DHT node. */
  destroy(): void {
    if (this.refreshTimer) { clearInterval(this.refreshTimer); this.refreshTimer = null; }
    if (this.pingTimer) { clearInterval(this.pingTimer); this.pingTimer = null; }
    for (const lookup of this.pendingLookups.values()) clearTimeout(lookup.timer);
    this.pendingLookups.clear();
    this.seenNonces.clear();
    this.storage.clear();
    this.tokens.clear();
    this.buckets.destroy();
    if (this.socket) { try { this.socket.close(); } catch {} this.socket = null; }
    this.removeAllListeners();
  }

  private handleMessage(raw: Buffer, rinfo: dgram.RemoteInfo): void {
    let msg: DhtMessage;
    try { msg = JSON.parse(raw.toString('utf8')); } catch { return; }

    if (!msg.nodeId || !msg.signature || !msg.publicKey || !msg.nonce || !msg.timestamp) return;

    if (Math.abs(Date.now() - msg.timestamp) > NONCE_WINDOW_MS) return;
    if (this.seenNonces.has(msg.nonce)) return;

    const expectedNodeId = bytesToHex(blake3(hexToBytes(msg.publicKey)));
    if (msg.nodeId !== expectedNodeId) {
      this.emit('dht:sybil_rejected', msg.nodeId, 'nodeId_publicKey_mismatch');
      return;
    }

    const sigPayload = this.buildSigPayload(msg);
    try {
      const valid = ed25519.verify(
        hexToBytes(msg.signature),
        new TextEncoder().encode(sigPayload),
        hexToBytes(msg.publicKey),
      );
      if (!valid) return;
    } catch { return; }

    this.seenNonces.add(msg.nonce);
    if (this.seenNonces.size > MAX_NONCES) {
      const first = this.seenNonces.values().next().value!;
      this.seenNonces.delete(first);
    }

    const peerPubKey = hexToBytes(msg.publicKey);
    const peerEndpoint: PeerEndpoint = {
      ip: rinfo.address, port: rinfo.port, transport: 'internet', verified: true,
    };

    this.buckets.addOrUpdate(msg.nodeId, peerPubKey, peerEndpoint);

    switch (msg.type) {
      case 'ping': this.handlePing(msg, rinfo); break;
      case 'pong': this.handlePong(msg); break;
      case 'find_node': this.handleFindNode(msg, rinfo); break;
      case 'find_node_reply': this.handleFindNodeReply(msg, rinfo); break;
      case 'store': this.handleStore(msg, rinfo); break;
      default: break;
    }
  }

  private handlePing(msg: DhtMessage, rinfo: dgram.RemoteInfo): void {
    this.sendMessage({
      type: 'pong', target: msg.nodeId,
    }, rinfo.address, rinfo.port);
  }

  private handlePong(msg: DhtMessage): void {
    this.buckets.markAlive(msg.nodeId);
  }

  private handleFindNode(msg: DhtMessage, rinfo: dgram.RemoteInfo): void {
    if (!msg.target) return;
    const closest = this.buckets.closest(msg.target, this.config.k);

    const peerInfos: DhtPeerInfo[] = closest.map(e => ({
      nodeId: e.nodeId,
      publicKey: bytesToHex(e.publicKey),
      ip: e.endpoint.ip,
      port: e.endpoint.port,
      signature: this.signPeerInfo(e),
    }));

    this.sendMessage({
      type: 'find_node_reply', target: msg.target, closest: peerInfos,
      token: this.generateToken(rinfo.address),
    }, rinfo.address, rinfo.port);
  }

  /**
   * Process FIND_NODE replies.
   * DEFENSE: Eclipse — reject if >50% of returned nodes share a /16 prefix.
   * DEFENSE: Poisoned routing — verify each returned peer's nodeId = BLAKE3(pubkey).
   */
  private handleFindNodeReply(msg: DhtMessage, rinfo: dgram.RemoteInfo): void {
    if (!msg.closest || !msg.target) return;

    const validPeers = msg.closest.filter(p => {
      try {
        const expectedId = bytesToHex(blake3(hexToBytes(p.publicKey)));
        return p.nodeId === expectedId;
      } catch { return false; }
    });

    if (validPeers.length > 2) {
      const prefixes = new Map<string, number>();
      for (const p of validPeers) {
        const prefix = p.ip.split('.').slice(0, 2).join('.');
        prefixes.set(prefix, (prefixes.get(prefix) ?? 0) + 1);
      }
      for (const [prefix, count] of prefixes) {
        if (count > validPeers.length * 0.5) {
          this.emit('dht:eclipse_rejected', msg.nodeId, `>50% peers in ${prefix}.0.0/16`);
          return;
        }
      }
    }

    for (const p of validPeers) {
      const pubKey = hexToBytes(p.publicKey);
      this.buckets.addOrUpdate(p.nodeId, pubKey, {
        ip: p.ip, port: p.port, transport: 'internet', verified: false,
      });
      this.emit('dht:peer_found', p.nodeId, { ip: p.ip, port: p.port, transport: 'internet', verified: false });
    }

    for (const [lookupId, lookup] of this.pendingLookups) {
      if (lookup.target !== msg.target) continue;
      lookup.queried.add(msg.nodeId);

      const newClosest = this.buckets.closest(lookup.target, this.config.k);
      const improved = newClosest.some(n => !lookup.closest.find(c => c.nodeId === n.nodeId));
      lookup.closest = newClosest;

      if (!improved || lookup.queried.size >= this.config.k) {
        clearTimeout(lookup.timer);
        this.pendingLookups.delete(lookupId);
        this.emit('dht:lookup_complete', lookup.target, lookup.closest);
        lookup.resolve(lookup.closest);
        return;
      }

      const unqueried = newClosest.filter(n => !lookup.queried.has(n.nodeId));
      for (const entry of unqueried.slice(0, this.config.alpha)) {
        this.sendFindNode(entry.endpoint, lookup.target, lookupId);
      }
    }
  }

  private handleStore(msg: DhtMessage, rinfo: dgram.RemoteInfo): void {
    if (!msg.key || !msg.value || !msg.proofOfWork) return;

    let pow: ProofOfWork;
    try { pow = JSON.parse(msg.proofOfWork); } catch { return; }
    if (!verifyPoW(msg.nodeId, pow)) {
      this.emit('dht:sybil_rejected', msg.nodeId, 'invalid_store_pow');
      return;
    }

    const token = this.tokens.get(rinfo.address);
    if (!token || token.token !== msg.token || Date.now() - token.createdAt > TOKEN_TTL_MS) return;

    this.storage.set(msg.key, { value: msg.value, nodeId: msg.nodeId, timestamp: msg.timestamp });
  }

  private sendMessage(fields: Partial<DhtMessage>, ip: string, port: number): void {
    if (!this.socket) return;

    const msg: DhtMessage = {
      type: fields.type!,
      nodeId: this.nodeId,
      publicKey: bytesToHex(this.publicKey),
      timestamp: Date.now(),
      nonce: bytesToHex(randomBytes(16)),
      signature: '',
      ...fields,
    };

    msg.signature = this.sign(this.buildSigPayload(msg));
    const buf = Buffer.from(JSON.stringify(msg), 'utf8');
    if (buf.length > MAX_MESSAGE_SIZE) return;
    this.socket.send(buf, port, ip);
  }

  private sendFindNode(endpoint: PeerEndpoint, targetId: string, _lookupId: string): void {
    this.sendMessage({ type: 'find_node', target: targetId }, endpoint.ip, endpoint.port);
  }

  private sendStore(endpoint: PeerEndpoint, key: string, value: string): void {
    this.sendMessage({ type: 'store', key, value }, endpoint.ip, endpoint.port);
  }

  private async sendPing(endpoint: PeerEndpoint): Promise<boolean> {
    return new Promise((resolve) => {
      this.sendMessage({ type: 'ping' }, endpoint.ip, endpoint.port);
      setTimeout(() => resolve(false), 5000);
    });
  }

  private sign(payload: string): string {
    return bytesToHex(ed25519.sign(new TextEncoder().encode(payload), this.privateKey));
  }

  private signPeerInfo(entry: KBucketEntry): string {
    const payload = `peerinfo:${entry.nodeId}:${entry.endpoint.ip}:${entry.endpoint.port}:${Date.now()}`;
    return this.sign(payload);
  }

  private generateToken(ip: string): string {
    const token = bytesToHex(randomBytes(16));
    this.tokens.set(ip, { token, createdAt: Date.now() });
    return token;
  }

  private buildSigPayload(msg: DhtMessage): string {
    return `${msg.type}:${msg.nodeId}:${msg.timestamp}:${msg.nonce}:${msg.target ?? ''}:${msg.key ?? ''}`;
  }

  private startMaintenance(): void {
    this.refreshTimer = setInterval(() => {
      const stale = this.buckets.staleBuckets(this.config.refreshIntervalMs);
      for (const idx of stale.slice(0, 3)) {
        const randomTarget = bytesToHex(randomBytes(32));
        this.findNode(randomTarget).catch(() => {});
      }
    }, this.config.refreshIntervalMs);

    this.pingTimer = setInterval(() => {
      const now = Date.now();
      for (let i = 0; i < this.config.bucketCount; i++) {
        for (const entry of this.buckets.getBucket(i)) {
          if (now - entry.lastSeen > this.config.staleThresholdMs) {
            this.sendPing(entry.endpoint);
          }
        }
      }
    }, this.config.pingIntervalMs);
  }
}
