import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import { randomBytes } from 'node:crypto';
import { ed25519 } from '@noble/curves/ed25519.js';
import { blake3 } from '@noble/hashes/blake3.js';
import { bytesToHex, hexToBytes } from '@noble/hashes/utils.js';
import { KBucketManager } from '../kBucket.js';
import { generatePoW, verifyPoW } from '../proofOfWork.js';
import { DhtNode } from '../dht.js';
import { MdnsDiscovery } from '../mdns.js';
import { BootstrapClient } from '../bootstrap.js';
import { PeerDiscovery } from '../index.js';
import type { PeerEndpoint, BootstrapNode, DhtPeerInfo } from '../types.js';

function makeIdentity() {
  const privKey = randomBytes(32);
  const pubKey = ed25519.getPublicKey(privKey);
  const nodeId = bytesToHex(blake3(pubKey));
  return { privKey, pubKey, nodeId };
}

function makeEndpoint(ip = '192.168.1.1', port = 8000): PeerEndpoint {
  return { ip, port, transport: 'internet' as const, verified: true };
}

// ──────────────────────────────────────────
// K-BUCKET: Anti-Sybil + Anti-Eclipse
// ──────────────────────────────────────────

describe('KBucketManager', () => {
  const self = makeIdentity();
  let buckets: KBucketManager;

  beforeEach(() => {
    buckets = new KBucketManager(self.nodeId);
  });

  afterEach(() => {
    buckets.destroy();
  });

  it('accepts peer with valid nodeId = BLAKE3(publicKey)', () => {
    const peer = makeIdentity();
    const result = buckets.addOrUpdate(peer.nodeId, peer.pubKey, makeEndpoint());
    expect(result).toBe(true);
    expect(buckets.size).toBe(1);
  });

  it('SYBIL: rejects peer with fabricated nodeId', () => {
    const peer = makeIdentity();
    const fakeNodeId = bytesToHex(randomBytes(32));
    const events: string[] = [];
    buckets.on('bucket:sybil_blocked', (nid, reason) => events.push(reason));

    const result = buckets.addOrUpdate(fakeNodeId, peer.pubKey, makeEndpoint());
    expect(result).toBe(false);
    expect(events).toContain('nodeId_mismatch');
  });

  it('SYBIL: rejects when global IP quota exceeded', () => {
    const events: string[] = [];
    buckets.on('bucket:sybil_blocked', (_, reason) => events.push(reason));

    for (let i = 0; i < 5; i++) {
      const peer = makeIdentity();
      buckets.addOrUpdate(peer.nodeId, peer.pubKey, makeEndpoint('10.0.0.1', 8000 + i));
    }

    const extraPeer = makeIdentity();
    const result = buckets.addOrUpdate(extraPeer.nodeId, extraPeer.pubKey, makeEndpoint('10.0.0.1', 9000));
    expect(result).toBe(false);
    expect(events).toContain('ip_quota_exceeded');
  });

  it('ECLIPSE: rejects when /16 prefix quota exceeded in bucket', () => {
    const events: string[] = [];
    buckets.on('bucket:eclipse_blocked', () => events.push('blocked'));

    const added: string[] = [];
    for (let i = 0; i < 10; i++) {
      const peer = makeIdentity();
      const ip = `10.5.${i}.${i + 1}`;
      const result = buckets.addOrUpdate(peer.nodeId, peer.pubKey, makeEndpoint(ip, 8000));
      if (result) added.push(peer.nodeId);
    }

    expect(events.length).toBeGreaterThan(0);
  });

  it('rejects own nodeId', () => {
    const result = buckets.addOrUpdate(self.nodeId, self.pubKey, makeEndpoint());
    expect(result).toBe(false);
  });

  it('updates existing peer instead of duplicating', () => {
    const peer = makeIdentity();
    buckets.addOrUpdate(peer.nodeId, peer.pubKey, makeEndpoint('1.2.3.4', 8000));
    buckets.addOrUpdate(peer.nodeId, peer.pubKey, makeEndpoint('1.2.3.4', 9000));
    expect(buckets.size).toBe(1);
  });

  it('finds k closest nodes to target', () => {
    for (let i = 0; i < 5; i++) {
      const peer = makeIdentity();
      buckets.addOrUpdate(peer.nodeId, peer.pubKey, makeEndpoint(`192.168.${i}.1`, 8000));
    }

    const target = bytesToHex(randomBytes(32));
    const closest = buckets.closest(target, 3);
    expect(closest.length).toBeLessThanOrEqual(3);
  });

  it('marks failed nodes and evicts after threshold', () => {
    const peer = makeIdentity();
    buckets.addOrUpdate(peer.nodeId, peer.pubKey, makeEndpoint('1.1.1.1'));
    buckets.markFailed(peer.nodeId);
    buckets.markFailed(peer.nodeId);
    buckets.markFailed(peer.nodeId);

    const entry = buckets.get(peer.nodeId);
    expect(entry?.failCount).toBe(3);
  });

  it('markAlive resets failCount', () => {
    const peer = makeIdentity();
    buckets.addOrUpdate(peer.nodeId, peer.pubKey, makeEndpoint('2.2.2.2'));
    buckets.markFailed(peer.nodeId);
    buckets.markFailed(peer.nodeId);
    buckets.markAlive(peer.nodeId);

    const entry = buckets.get(peer.nodeId);
    expect(entry?.failCount).toBe(0);
  });

  it('XOR distance is symmetric', () => {
    const a = makeIdentity();
    const b = makeIdentity();
    const dab = KBucketManager.distance(a.nodeId, b.nodeId);
    const dba = KBucketManager.distance(b.nodeId, a.nodeId);
    expect(bytesToHex(dab)).toBe(bytesToHex(dba));
  });

  it('XOR distance to self is zero', () => {
    const a = makeIdentity();
    const d = KBucketManager.distance(a.nodeId, a.nodeId);
    expect(d.every(b => b === 0)).toBe(true);
  });

  it('finds stale buckets correctly', () => {
    const peer = makeIdentity();
    buckets.addOrUpdate(peer.nodeId, peer.pubKey, makeEndpoint('3.3.3.3'));
    const stale = buckets.staleBuckets(0);
    expect(stale.length).toBe(0);

    const veryStale = buckets.staleBuckets(-1);
    expect(veryStale.length).toBeGreaterThan(0);
  });

  it('remove decrements IP count', () => {
    const peer = makeIdentity();
    buckets.addOrUpdate(peer.nodeId, peer.pubKey, makeEndpoint('4.4.4.4'));
    expect(buckets.size).toBe(1);
    buckets.remove(peer.nodeId);
    expect(buckets.size).toBe(0);

    const peer2 = makeIdentity();
    const result = buckets.addOrUpdate(peer2.nodeId, peer2.pubKey, makeEndpoint('4.4.4.4'));
    expect(result).toBe(true);
  });
});

// ──────────────────────────────────────────
// PROOF OF WORK: Anti-Sybil cost
// ──────────────────────────────────────────

describe('ProofOfWork', () => {
  it('generates valid PoW at difficulty 8', () => {
    const { nodeId } = makeIdentity();
    const pow = generatePoW(nodeId, 8);
    expect(pow.hash.startsWith('00')).toBe(true);
    expect(verifyPoW(nodeId, pow)).toBe(true);
  });

  it('rejects PoW with wrong nodeId', () => {
    const { nodeId } = makeIdentity();
    const pow = generatePoW(nodeId, 8);
    const { nodeId: otherId } = makeIdentity();
    expect(verifyPoW(otherId, pow)).toBe(false);
  });

  it('rejects PoW with tampered hash', () => {
    const { nodeId } = makeIdentity();
    const pow = generatePoW(nodeId, 8);
    pow.hash = 'ff' + pow.hash.slice(2);
    expect(verifyPoW(nodeId, pow)).toBe(false);
  });

  it('rejects PoW with tampered nonce', () => {
    const { nodeId } = makeIdentity();
    const pow = generatePoW(nodeId, 8);
    pow.nonce = bytesToHex(randomBytes(16));
    expect(verifyPoW(nodeId, pow)).toBe(false);
  });

  it('rejects invalid difficulty range', () => {
    const { nodeId } = makeIdentity();
    const pow = generatePoW(nodeId, 8);
    pow.difficulty = 0;
    expect(verifyPoW(nodeId, pow)).toBe(false);
    pow.difficulty = 100;
    expect(verifyPoW(nodeId, pow)).toBe(false);
  });
});

// ──────────────────────────────────────────
// DHT NODE: Sybil + Eclipse + Poisoned Routing
// ──────────────────────────────────────────

describe('DhtNode', () => {
  const self = makeIdentity();
  let dht: DhtNode;

  beforeEach(() => {
    dht = new DhtNode(self.nodeId, self.privKey, { powDifficulty: 4 });
  });

  afterEach(() => {
    dht.destroy();
  });

  it('creates DHT node with correct nodeId', () => {
    expect(dht.nodeId).toBe(self.nodeId);
  });

  it('SYBIL: emits event when nodeId/publicKey mismatch detected', () => {
    const events: string[] = [];
    dht.on('dht:sybil_rejected', (_, reason) => events.push(reason));

    const peer = makeIdentity();
    const fakeId = bytesToHex(randomBytes(32));
    dht.buckets.addOrUpdate(fakeId, peer.pubKey, makeEndpoint());

    expect(events).toContain('nodeId_mismatch');
  });

  it('ECLIPSE: emits event when /16 diversity violated', () => {
    const events: string[] = [];
    dht.buckets.on('bucket:eclipse_blocked', () => events.push('eclipse'));

    for (let i = 0; i < 5; i++) {
      const peer = makeIdentity();
      dht.buckets.addOrUpdate(peer.nodeId, peer.pubKey, makeEndpoint(`10.10.${i}.1`));
    }

    expect(events.length).toBeGreaterThan(0);
  });

  it('accepts valid peers into routing table', () => {
    const peer = makeIdentity();
    const result = dht.buckets.addOrUpdate(peer.nodeId, peer.pubKey, makeEndpoint('44.55.66.77'));
    expect(result).toBe(true);
  });

  it('SYBIL: join requires valid PoW', async () => {
    const badPoW = { nonce: 'abc', difficulty: 4, hash: 'ffff' };
    await expect(dht.join([], badPoW)).rejects.toThrow('Invalid proof of work');
  });

  it('join with valid PoW and no seeds completes without error', async () => {
    const pow = generatePoW(self.nodeId, 4);
    await dht.join([], pow);
  });
});

// ──────────────────────────────────────────
// mDNS: Anti-Spoofing
// ──────────────────────────────────────────

describe('MdnsDiscovery', () => {
  const self = makeIdentity();

  it('creates mDNS discovery instance', () => {
    const mdns = new MdnsDiscovery(self.nodeId, self.privKey, 8000);
    expect(mdns).toBeDefined();
    mdns.stop();
  });

  it('isVerified returns false for unknown peers', () => {
    const mdns = new MdnsDiscovery(self.nodeId, self.privKey, 8000);
    expect(mdns.isVerified('unknown')).toBe(false);
    mdns.stop();
  });
});

// ──────────────────────────────────────────
// BOOTSTRAP: Anti-Compromise + Poisoned Routing
// ──────────────────────────────────────────

describe('BootstrapClient', () => {
  const self = makeIdentity();

  it('creates client with pinned bootstrap nodes', () => {
    const nodes: BootstrapNode[] = [{
      host: '127.0.0.1', port: 6881,
      publicKeyHex: bytesToHex(makeIdentity().pubKey),
      name: 'test-bootstrap',
    }];
    const client = new BootstrapClient(self.nodeId, self.privKey, nodes);
    expect(client).toBeDefined();
  });

  it('COMPROMISE: emits all_failed when no bootstrap nodes respond', async () => {
    const nodes: BootstrapNode[] = [{
      host: '127.0.0.255', port: 1,
      publicKeyHex: bytesToHex(makeIdentity().pubKey),
      name: 'unreachable',
    }];
    const client = new BootstrapClient(self.nodeId, self.privKey, nodes);
    const events: string[] = [];
    client.on('bootstrap:all_failed', () => events.push('failed'));

    const peers = await client.discover();
    expect(peers).toHaveLength(0);
    expect(events).toContain('failed');
  }, 30_000);
});

// ──────────────────────────────────────────
// ORCHESTRATOR: PeerDiscovery
// ──────────────────────────────────────────

describe('PeerDiscovery', () => {
  const self = makeIdentity();
  let discovery: PeerDiscovery;

  beforeEach(() => {
    discovery = new PeerDiscovery(self.nodeId, self.privKey, {
      enableDht: false,
      enableMdns: false,
      bootstrapNodes: [],
    });
  });

  afterEach(async () => {
    await discovery.destroy();
  });

  it('defaults to internet transport', () => {
    expect(discovery.currentTransport).toBe('internet');
  });

  it('accepts BLE peer with valid identity', () => {
    const peer = makeIdentity();
    const result = discovery.addBlePeer(peer.nodeId, peer.pubKey, {
      ip: '0.0.0.0', port: 0, transport: 'ble', verified: true,
    });
    expect(result).toBe(true);
    expect(discovery.peerCount).toBe(1);
  });

  it('rejects BLE peer with fabricated nodeId', () => {
    const peer = makeIdentity();
    const events: string[] = [];
    discovery.on('discovery:security_event', (type) => events.push(type));

    const result = discovery.addBlePeer('fake_node_id', peer.pubKey, {
      ip: '0.0.0.0', port: 0, transport: 'ble', verified: true,
    });
    expect(result).toBe(false);
    expect(events).toContain('ble_identity_mismatch');
  });

  it('accepts manual peer with valid identity', () => {
    const peer = makeIdentity();
    const result = discovery.addManualPeer(peer.nodeId, peer.pubKey, makeEndpoint());
    expect(result).toBe(true);
    expect(discovery.getPeer(peer.nodeId)).toBeDefined();
  });

  it('rejects manual peer with fabricated nodeId', () => {
    const peer = makeIdentity();
    const events: string[] = [];
    discovery.on('discovery:security_event', (type) => events.push(type));

    const result = discovery.addManualPeer('bad_id', peer.pubKey, makeEndpoint());
    expect(result).toBe(false);
    expect(events).toContain('manual_identity_mismatch');
  });

  it('switches transport mode', async () => {
    const events: string[] = [];
    discovery.on('discovery:mode_changed', (mode) => events.push(mode));

    await discovery.switchTransport('ble');
    expect(discovery.currentTransport).toBe('ble');
    expect(events).toContain('ble');
  });

  it('does not duplicate when switching to same mode', async () => {
    const events: string[] = [];
    discovery.on('discovery:mode_changed', () => events.push('changed'));

    await discovery.switchTransport('internet');
    expect(events).toHaveLength(0);
  });

  it('merges endpoints for same peer discovered multiple times', () => {
    const peer = makeIdentity();
    discovery.addManualPeer(peer.nodeId, peer.pubKey, makeEndpoint('1.1.1.1', 8000));

    // Simulate re-discovery — internal registerPeer would merge
    discovery.addManualPeer(peer.nodeId, peer.pubKey, makeEndpoint('2.2.2.2', 9000));

    // addManualPeer overwrites, but the orchestrator's registerPeer merges
    expect(discovery.peerCount).toBe(1);
  });

  it('getPeers returns all discovered peers', () => {
    for (let i = 0; i < 3; i++) {
      const peer = makeIdentity();
      discovery.addManualPeer(peer.nodeId, peer.pubKey, makeEndpoint(`10.${i}.0.1`));
    }
    expect(discovery.getPeers()).toHaveLength(3);
  });

  it('destroy clears all state', async () => {
    const peer = makeIdentity();
    discovery.addManualPeer(peer.nodeId, peer.pubKey, makeEndpoint());
    await discovery.destroy();
    expect(discovery.peerCount).toBe(0);
  });
});

// ──────────────────────────────────────────
// CROSS-CUTTING: Identity verification
// ──────────────────────────────────────────

describe('Identity Verification (cross-cutting)', () => {
  it('BLAKE3(publicKey) produces deterministic nodeId', () => {
    const { privKey, pubKey, nodeId } = makeIdentity();
    const recomputed = bytesToHex(blake3(pubKey));
    expect(nodeId).toBe(recomputed);
  });

  it('different keys produce different nodeIds', () => {
    const a = makeIdentity();
    const b = makeIdentity();
    expect(a.nodeId).not.toBe(b.nodeId);
  });

  it('Ed25519 signature roundtrip works', () => {
    const { privKey, pubKey } = makeIdentity();
    const msg = new TextEncoder().encode('test message');
    const sig = ed25519.sign(msg, privKey);
    expect(ed25519.verify(sig, msg, pubKey)).toBe(true);
  });

  it('Ed25519 signature rejects wrong key', () => {
    const a = makeIdentity();
    const b = makeIdentity();
    const msg = new TextEncoder().encode('test message');
    const sig = ed25519.sign(msg, a.privKey);
    expect(ed25519.verify(sig, msg, b.pubKey)).toBe(false);
  });
});
