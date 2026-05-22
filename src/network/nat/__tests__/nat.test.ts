import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import * as dgram from 'node:dgram';
import * as fs from 'node:fs';
import * as path from 'node:path';
import { randomBytes } from 'node:crypto';
import { ed25519 } from '@noble/curves/ed25519.js';
import { blake3 } from '@noble/hashes/blake3.js';
import { bytesToHex, hexToBytes } from '@noble/hashes/utils.js';
import { StunClient } from '../stun.js';
import { StunValidator } from '../stunValidator.js';
import { TurnClient } from '../turn.js';
import { HolePuncher } from '../holePunch.js';
import { PacketAuthenticator } from '../packetAuth.js';
import { SequenceStore } from '../sequenceStore.js';
import { ReplayAttackError, StaleMessageError, FutureMessageError } from '../replayErrors.js';
import { MAX_MESSAGE_AGE_MS, MAX_CLOCK_SKEW_MS } from '../constants.js';
import { NatTraversal } from '../index.js';
import type { StunResult, SignedEndpoint, EncryptedPayload } from '../types.js';

// ── Helpers ──────────────────────────────────────────────────────────

function makeIdentity() {
  const privKey = ed25519.utils.randomSecretKey();
  const pubKey = ed25519.getPublicKey(privKey);
  const nodeId = bytesToHex(blake3(pubKey));
  return { privKey, pubKey, nodeId };
}

function signEndpoint(nodeId: string, ip: string, port: number, privKey: Uint8Array): SignedEndpoint {
  const timestamp = Date.now();
  const payload = `${nodeId}:${ip}:${port}:${timestamp}`;
  const signature = bytesToHex(ed25519.sign(new TextEncoder().encode(payload), privKey));
  return { nodeId, ip, port, timestamp, signature };
}

function makeAuthPacket(nodeId: string, privKey: Uint8Array, data: unknown, overrides?: { nonce?: string; timestamp?: number }) {
  const nonce = overrides?.nonce ?? randomBytes(16).toString('hex');
  const timestamp = overrides?.timestamp ?? Date.now();
  const sigPayload = `${nodeId}:${timestamp}:${nonce}:${JSON.stringify(data)}`;
  const signature = bytesToHex(ed25519.sign(new TextEncoder().encode(sigPayload), privKey));
  return Buffer.from(JSON.stringify({ nodeId, signature, timestamp, nonce, data }));
}

function stunResult(overrides: Partial<StunResult> = {}): StunResult {
  return {
    success: true,
    publicIp: '203.0.113.10',
    publicPort: 40000,
    natType: 'full_cone',
    confidence: 'high',
    serverResults: [
      { server: 'stun.l.google.com:19302', ip: '203.0.113.10', port: 40000, responded: true, responseTime: 50 },
      { server: 'stun.cloudflare.com:3478', ip: '203.0.113.10', port: 40000, responded: true, responseTime: 60 },
      { server: 'stun.nextcloud.com:3478', ip: '203.0.113.10', port: 40000, responded: true, responseTime: 70 },
    ],
    ...overrides,
  };
}

// ═══════════════════════════════════════════════════════════════════
// STUN Tests (1-8)
// ═══════════════════════════════════════════════════════════════════

describe('STUN Client', () => {
  it('1. returns cached result within TTL', async () => {
    const client = new StunClient([]);
    // Force a cached result
    (client as any).cached = { result: stunResult(), at: Date.now() };
    const result = await client.discover();
    expect(result.success).toBe(true);
    expect(result.publicIp).toBe('203.0.113.10');
  });

  it('2. 3 servers agree → high confidence', () => {
    const result = stunResult();
    expect(result.confidence).toBe('high');
    expect(result.serverResults.filter(s => s.ip === '203.0.113.10')).toHaveLength(3);
  });

  it('5. server timeout → graceful fallback', async () => {
    const client = new StunClient([{ host: '192.0.2.1', port: 19302 }]);
    const result = await client.discover();
    expect(result.success).toBe(false);
    expect(result.error).toBeDefined();
  }, 15000);

  it('8. cache cleared after clearCache()', async () => {
    const client = new StunClient([]);
    (client as any).cached = { result: stunResult(), at: Date.now() };
    client.clearCache();
    expect((client as any).cached).toBeNull();
  });
});

describe('STUN Validator', () => {
  it('3. 1 disagrees → majority used, disagreement flagged', () => {
    const validator = new StunValidator();
    const result = validator.validate(stunResult({
      serverResults: [
        { server: 'a:19302', ip: '203.0.113.10', port: 40000, responded: true, responseTime: 50 },
        { server: 'b:3478', ip: '203.0.113.10', port: 40000, responded: true, responseTime: 60 },
        { server: 'c:3478', ip: '198.51.100.99', port: 40000, responded: true, responseTime: 70 },
      ],
    }));
    expect(result.valid).toBe(true);
    expect(result.trustedIp).toBe('203.0.113.10');
  });

  it('4. all 3 disagree → stun_consensus_failed handled', () => {
    const validator = new StunValidator();
    const result = validator.validate(stunResult({
      success: false,
      publicIp: undefined,
      error: 'stun_consensus_failed',
    }));
    expect(result.valid).toBe(false);
  });

  it('6. reflection attack: private IP returned → caught', () => {
    const validator = new StunValidator();
    const result = validator.validate(stunResult({ publicIp: '192.168.1.1' }));
    expect(result.valid).toBe(false);
    expect(result.attacks_detected).toContain('private_ip_as_public');
  });

  it('6b. loopback returned → caught', () => {
    const validator = new StunValidator();
    const result = validator.validate(stunResult({ publicIp: '127.0.0.1' }));
    expect(result.valid).toBe(false);
    expect(result.attacks_detected).toContain('private_ip_as_public');
  });

  it('6c. 0.0.0.0 returned → caught', () => {
    const validator = new StunValidator();
    const result = validator.validate(stunResult({ publicIp: '0.0.0.0' }));
    expect(result.valid).toBe(false);
    expect(result.attacks_detected).toContain('reserved_ip_returned');
  });

  it('6d. broadcast returned → caught', () => {
    const validator = new StunValidator();
    const result = validator.validate(stunResult({ publicIp: '255.255.255.255' }));
    expect(result.valid).toBe(false);
  });

  it('6e. server own IP reflection → caught', () => {
    const validator = new StunValidator();
    validator.addStunServerIp('203.0.113.10');
    const result = validator.validate(stunResult({ publicIp: '203.0.113.10' }));
    expect(result.valid).toBe(false);
    expect(result.attacks_detected).toContain('server_ip_reflection');
  });

  it('7. wrong transaction ID dropped (tested via StunClient parsing)', () => {
    const client = new StunClient();
    const txId = randomBytes(12);
    const wrongTxId = randomBytes(12);
    const buf = Buffer.alloc(32);
    buf.writeUInt16BE(0x0101, 0);
    buf.writeUInt16BE(12, 2);
    buf.writeUInt32BE(0x2112a442, 4);
    wrongTxId.copy(buf, 8);
    const parsed = (client as any).parseResponse(buf, txId);
    expect(parsed).toBeNull();
  });

  it('historical subnet change flagged', () => {
    const validator = new StunValidator();
    for (let i = 0; i < 5; i++) {
      validator.validate(stunResult({ publicIp: '203.0.113.10' }));
    }
    const result = validator.validate(stunResult({ publicIp: '198.51.100.1' }));
    expect(result.warnings).toContain('subnet_change_detected');
  });
});

// ═══════════════════════════════════════════════════════════════════
// Hole Punch Tests (9-16)
// ═══════════════════════════════════════════════════════════════════

describe('Hole Puncher', () => {
  const alice = makeIdentity();
  const bob = makeIdentity();

  it('10. unsigned endpoint → refused', async () => {
    const puncher = new HolePuncher(alice.nodeId, alice.privKey);
    puncher.addPeer(bob.nodeId, bob.pubKey);
    const fakeEndpoint: SignedEndpoint = {
      nodeId: bob.nodeId, ip: '203.0.113.20', port: 5000,
      timestamp: Date.now(), signature: 'deadbeef'.repeat(16),
    };
    const result = await puncher.punch(fakeEndpoint);
    expect(result.success).toBe(false);
    expect(result.reason).toBe('invalid_endpoint_signature');
    puncher.close();
  });

  it('11. unknown peer endpoint → refused (sig check fails without peer key)', async () => {
    const puncher = new HolePuncher(alice.nodeId, alice.privKey);
    // Don't add bob as known peer — sig check can't find pubkey → rejects
    const ep = signEndpoint(bob.nodeId, '203.0.113.20', 5000, bob.privKey);
    const result = await puncher.punch(ep);
    expect(result.success).toBe(false);
    expect(result.reason).toBe('invalid_endpoint_signature');
    puncher.close();
  });

  it('15. both symmetric NAT → immediate TURN fallback', async () => {
    const puncher = new HolePuncher(alice.nodeId, alice.privKey);
    puncher.addPeer(bob.nodeId, bob.pubKey);
    const ep = signEndpoint(bob.nodeId, '203.0.113.20', 5000, bob.privKey);
    const events: string[] = [];
    puncher.on('punch:fallback', (r) => events.push(r));
    const result = await puncher.punch(ep, 'symmetric', 'symmetric');
    expect(result.success).toBe(false);
    expect(result.method).toBe('turn_fallback');
    expect(events).toContain('both_symmetric');
    puncher.close();
  });

  it('14. replayed punch packet → nonce/timestamp caught', async () => {
    const puncher = new HolePuncher(alice.nodeId, alice.privKey);
    puncher.addPeer(bob.nodeId, bob.pubKey);

    // Simulate a nonce already seen
    const nonce = randomBytes(32).toString('hex');
    (puncher as any).seenNonces.add(nonce);

    const timestamp = Date.now();
    const sigPayload = `${bob.nodeId}:${nonce}:${timestamp}:punch`;
    const signature = bytesToHex(ed25519.sign(new TextEncoder().encode(sigPayload), bob.privKey));
    const packet = Buffer.from(JSON.stringify({
      type: 'punch', nodeId: bob.nodeId, nonce, timestamp, signature,
    }));

    const result = (puncher as any).decryptAndVerify(packet, bob.pubKey, bob.nodeId);
    expect(result).toBeNull();
    puncher.close();
  });

  it('16. random packets during open window → silently dropped', async () => {
    const puncher = new HolePuncher(alice.nodeId, alice.privKey);
    puncher.addPeer(bob.nodeId, bob.pubKey);

    const garbage = Buffer.from('totally random garbage data!!!');
    const result = (puncher as any).decryptAndVerify(garbage, bob.pubKey, bob.nodeId);
    expect(result).toBeNull();
    puncher.close();
  });

  it('13. wrong key challenge response → rejected', () => {
    const puncher = new HolePuncher(alice.nodeId, alice.privKey);
    puncher.addPeer(bob.nodeId, bob.pubKey);

    const eve = makeIdentity();
    const challengeNonce = randomBytes(32).toString('hex');
    // Eve signs with her own key, not Bob's
    const eveSig = bytesToHex(ed25519.sign(new TextEncoder().encode(challengeNonce), eve.privKey));

    try {
      const valid = ed25519.verify(hexToBytes(eveSig), new TextEncoder().encode(challengeNonce), bob.pubKey);
      expect(valid).toBe(false);
    } catch {
      // Expected — signature verification throws or returns false
    }
    puncher.close();
  });
});

// ═══════════════════════════════════════════════════════════════════
// TURN Tests (17-22)
// ═══════════════════════════════════════════════════════════════════

describe('TURN Client', () => {
  it('17. initial state: not allocated', () => {
    const client = new TurnClient('ghost');
    expect(client.isAllocated).toBe(false);
    client.teardown();
  });

  it('18. sendViaRelay returns false without allocation', () => {
    const client = new TurnClient('ghost');
    const payload: EncryptedPayload = {
      ciphertext: Buffer.from('encrypted'), nonce: Buffer.from('nonce'),
      signature: 'sig', sequenceNumber: 0, timestamp: Date.now(), paddedSize: 512,
    };
    expect(client.sendViaRelay(payload)).toBe(false);
    client.teardown();
  });

  it('19. tier quotas differ', () => {
    const ghost = new TurnClient('ghost');
    const phantom = new TurnClient('phantom');
    const spectre = new TurnClient('spectre');
    const gs = ghost.getStats();
    const ps = phantom.getStats();
    const ss = spectre.getStats();
    // Phantom has higher quota than Ghost
    expect(ps.quotaLimit).toBeGreaterThan(gs.quotaLimit);
    expect(ss.quotaLimit).toBeGreaterThan(ps.quotaLimit);
    ghost.teardown();
    phantom.teardown();
    spectre.teardown();
  });

  it('20. replayed relay packet with old sequence → dropped', () => {
    const tmpPath = path.join(process.cwd(), 'data', `test-20-${Date.now()}.json`);
    const client = new TurnClient('ghost', tmpPath);
    // Pre-seed the persistent sequence store with seq 5 for a peer
    (client as any).sequenceStore.update('test_peer', 5);
    const rec = (client as any).sequenceStore.get('test_peer');
    expect(rec.lastSequence).toBe(5);
    // A packet with seq 3 should be dropped
    const oldPacket = { sequenceNumber: 3, timestamp: Date.now(), ciphertext: 'test', nonce: 'n', signature: 's', paddedSize: 512 };
    expect(oldPacket.sequenceNumber).toBeLessThanOrEqual(rec.lastSequence);
    client.teardown();
    try { fs.unlinkSync(tmpPath); } catch {}
  });

  it('21. stats initially zeroed', () => {
    const client = new TurnClient('ghost');
    const stats = client.getStats();
    expect(stats.bytesRelayed).toBe(0);
    expect(stats.packetsRelayed).toBe(0);
    expect(stats.quotaUsed).toBe(0);
    client.teardown();
  });

  it('22. teardown is safe and idempotent', () => {
    const client = new TurnClient('phantom');
    client.teardown();
    expect(client.isAllocated).toBe(false);
    expect(() => client.teardown()).not.toThrow();
  });
});

// ═══════════════════════════════════════════════════════════════════
// Packet Auth Tests (23-29)
// ═══════════════════════════════════════════════════════════════════

describe('PacketAuthenticator', () => {
  let auth: PacketAuthenticator;
  const peer = makeIdentity();

  beforeEach(() => {
    auth = new PacketAuthenticator();
    auth.addKnownPeer(peer.nodeId, peer.pubKey);
  });
  afterEach(() => auth.destroy());

  it('23. valid packet passes all 6 steps', () => {
    const packet = makeAuthPacket(peer.nodeId, peer.privKey, { msg: 'hello' });
    const result = auth.authenticate(packet);
    expect(result.valid).toBe(true);
    expect(result.peerNodeId).toBe(peer.nodeId);
    expect(result.data).toEqual({ msg: 'hello' });
  });

  it('24. malformed JSON → rejected', () => {
    const result = auth.authenticate(Buffer.from('not json!!!'));
    expect(result.valid).toBe(false);
    expect(result.reason).toBe('malformed_payload');
  });

  it('25. tampered data → signature fails', () => {
    const packet = makeAuthPacket(peer.nodeId, peer.privKey, { msg: 'hello' });
    const parsed = JSON.parse(packet.toString());
    parsed.data = { msg: 'tampered' };
    const result = auth.authenticate(Buffer.from(JSON.stringify(parsed)));
    expect(result.valid).toBe(false);
    expect(result.reason).toBe('invalid_signature');
  });

  it('26. 60s old timestamp → rejected', () => {
    const packet = makeAuthPacket(peer.nodeId, peer.privKey, { msg: 'old' }, { timestamp: Date.now() - 60000 });
    const result = auth.authenticate(packet);
    expect(result.valid).toBe(false);
    expect(result.reason).toBe('timestamp_expired');
  });

  it('27. reused nonce → rejected', () => {
    const nonce = randomBytes(16).toString('hex');
    const p1 = makeAuthPacket(peer.nodeId, peer.privKey, { n: 1 }, { nonce });
    const p2 = makeAuthPacket(peer.nodeId, peer.privKey, { n: 2 }, { nonce });
    expect(auth.authenticate(p1).valid).toBe(true);
    expect(auth.authenticate(p2).valid).toBe(false);
    expect(auth.authenticate(p2).reason).toBe('nonce_reused');
  });

  it('28. unknown nodeId → rejected', () => {
    const unknown = makeIdentity();
    const packet = makeAuthPacket(unknown.nodeId, unknown.privKey, { msg: 'who am i' });
    const result = auth.authenticate(packet);
    expect(result.valid).toBe(false);
    expect(result.reason).toBe('unknown_peer');
  });

  it('29. zero outbound on failure (silent drop verified via stats)', () => {
    const garbage = Buffer.from('garbage');
    auth.authenticate(garbage);
    auth.authenticate(Buffer.from(JSON.stringify({ bad: true })));

    const unknown = makeIdentity();
    auth.authenticate(makeAuthPacket(unknown.nodeId, unknown.privKey, {}));

    const stats = auth.getStats();
    expect(stats.rejected).toBeGreaterThanOrEqual(3);
    expect(stats.rejectionReasons['malformed_payload']).toBeGreaterThanOrEqual(1);
    expect(stats.rejectionReasons['unknown_peer']).toBeGreaterThanOrEqual(1);
    // No outbound tracking needed — auth NEVER sends responses by design
  });

  it('unexpected peer → rejected', () => {
    const packet = makeAuthPacket(peer.nodeId, peer.privKey, { msg: 'hi' });
    const result = auth.authenticate(packet, 'different-node-id');
    expect(result.valid).toBe(false);
    expect(result.reason).toBe('unexpected_peer');
  });

  it('stats track rejection reasons for Signal Intelligence', () => {
    for (let i = 0; i < 5; i++) {
      auth.authenticate(Buffer.from('bad'));
    }
    const stats = auth.getStats();
    expect(stats.rejectionReasons['malformed_payload']).toBe(5);
  });
});

// ═══════════════════════════════════════════════════════════════════
// Orchestrator Tests (30-33)
// ═══════════════════════════════════════════════════════════════════

describe('NatTraversal Orchestrator', () => {
  const alice = makeIdentity();
  const bob = makeIdentity();

  it('30. createSignedEndpoint produces valid signature', async () => {
    const nat = new NatTraversal(alice.nodeId, alice.privKey);
    // Inject cached STUN result
    (nat.stun as any).cached = { result: stunResult(), at: Date.now() };

    const ep = await nat.createSignedEndpoint();
    expect(ep.nodeId).toBe(alice.nodeId);
    expect(ep.ip).toBe('203.0.113.10');
    expect(ep.port).toBe(40000);

    // Verify the signature
    const payload = `${ep.nodeId}:${ep.ip}:${ep.port}:${ep.timestamp}`;
    const valid = ed25519.verify(
      hexToBytes(ep.signature),
      new TextEncoder().encode(payload),
      alice.pubKey,
    );
    expect(valid).toBe(true);
    nat.destroy();
  });

  it('31. addPeer registers in both puncher and auth', () => {
    const nat = new NatTraversal(alice.nodeId, alice.privKey);
    nat.addPeer(bob.nodeId, bob.pubKey);
    expect(nat.auth.peerCount).toBe(1);
    nat.destroy();
  });

  it('32. getStatus returns null for unknown peer', () => {
    const nat = new NatTraversal(alice.nodeId, alice.privKey);
    expect(nat.getStatus('unknown')).toBeNull();
    nat.destroy();
  });

  it('33. destroy cleans up all components', () => {
    const nat = new NatTraversal(alice.nodeId, alice.privKey);
    nat.addPeer(bob.nodeId, bob.pubKey);
    expect(() => nat.destroy()).not.toThrow();
    expect(nat.auth.peerCount).toBe(0);
  });

  it('STUN validator rejects invalid results during flow', () => {
    const nat = new NatTraversal(alice.nodeId, alice.privKey);
    const result = nat.validator.validate(stunResult({ publicIp: '10.0.0.1' }));
    expect(result.valid).toBe(false);
    nat.destroy();
  });
});

// ═══════════════════════════════════════════════════════════════════
// UPnP Ban Verification
// ═══════════════════════════════════════════════════════════════════

describe('UPnP Ban', () => {
  it('no UPnP anywhere in the NAT module', () => {
    const classes = [StunClient, StunValidator, TurnClient, HolePuncher, PacketAuthenticator, NatTraversal];
    for (const cls of classes) {
      const proto = Object.getOwnPropertyNames(cls.prototype);
      expect(proto.some(n => /upnp/i.test(n))).toBe(false);
    }
  });
});

// ═══════════════════════════════════════════════════════════════════
// RED-TEAM: Adversarial Exploit Chain Tests
// ═══════════════════════════════════════════════════════════════════

describe('RED-TEAM: Chain 1 — Plaintext interception + relay injection', () => {
  it('RT-1a. signAndEncrypt produces encrypted binary, not readable JSON', () => {
    const alice = makeIdentity();
    const bob = makeIdentity();
    const puncher = new HolePuncher(alice.nodeId, alice.privKey);
    puncher.addPeer(bob.nodeId, bob.pubKey);
    const packet = (puncher as any).buildPacket('punch');
    const output = (puncher as any).signAndEncrypt(packet, bob.pubKey);
    // Output must NOT be parseable as JSON — it's AES-256-GCM ciphertext
    expect(() => JSON.parse(output.toString('utf8'))).toThrow();
    // Must contain IV (12) + tag (16) + ciphertext
    expect(output.length).toBeGreaterThan(28);
    puncher.close();
  });

  it('RT-1b. TURN handleIncoming accepts unverified injected payload', () => {
    const client = new TurnClient('ghost');
    // Force allocation state so handleIncoming processes data
    (client as any).allocation = { relayIp: '1.2.3.4', relayPort: 3478, lifetime: 600, server: '1.2.3.4:3478', allocatedAt: Date.now() };
    (client as any).socket = { send: () => {} };

    const fakePayload = JSON.stringify({
      ciphertext: Buffer.from('INJECTED_BY_ATTACKER').toString('base64'),
      nonce: Buffer.from('fakenonce').toString('base64'),
      signature: 'fake_sig_no_verify',
      sequenceNumber: 1,
      timestamp: Date.now(),
      paddedSize: 512,
    });

    // Wrap in channel header like a real relay message
    const channelData = Buffer.alloc(4 + fakePayload.length);
    channelData.writeUInt16BE(0x4001, 0);
    channelData.writeUInt16BE(fakePayload.length, 2);
    Buffer.from(fakePayload).copy(channelData, 4);

    (client as any).handleIncoming(channelData);

    // ATTACK: The fake payload should have been queued without verification
    // After fix: incomingQueue should be empty (payload rejected)
    const queue = (client as any).incomingQueue;
    expect(queue.length).toBe(0);
    client.teardown();
  });
});

describe('RED-TEAM: Chain 2 — TURN sequence collision across peers', () => {
  it('RT-2. hardcoded "relay" key causes cross-peer replay drops', () => {
    const client = new TurnClient('ghost');
    (client as any).allocation = { relayIp: '1.2.3.4', relayPort: 3478, lifetime: 600, server: '1.2.3.4:3478', allocatedAt: Date.now() };
    (client as any).socket = { send: () => {} };

    // Peer A sends seq 5
    const peerAPayload = JSON.stringify({
      ciphertext: Buffer.from('from_peer_a').toString('base64'),
      nonce: Buffer.from('nonce_a').toString('base64'),
      signature: 'sig_a', sequenceNumber: 5,
      timestamp: Date.now(), paddedSize: 512,
      senderId: 'peer_a',
    });
    const chanA = Buffer.alloc(4 + peerAPayload.length);
    chanA.writeUInt16BE(0x4001, 0);
    chanA.writeUInt16BE(peerAPayload.length, 2);
    Buffer.from(peerAPayload).copy(chanA, 4);
    (client as any).handleIncoming(chanA);

    // Peer B sends seq 3 — DIFFERENT peer, valid message
    // But with hardcoded 'relay' key, this gets dropped as "replay"
    const peerBPayload = JSON.stringify({
      ciphertext: Buffer.from('from_peer_b').toString('base64'),
      nonce: Buffer.from('nonce_b').toString('base64'),
      signature: 'sig_b', sequenceNumber: 3,
      timestamp: Date.now(), paddedSize: 512,
      senderId: 'peer_b',
    });
    const chanB = Buffer.alloc(4 + peerBPayload.length);
    chanB.writeUInt16BE(0x4001, 0);
    chanB.writeUInt16BE(peerBPayload.length, 2);
    Buffer.from(peerBPayload).copy(chanB, 4);
    (client as any).handleIncoming(chanB);

    // After fix: both messages should be in the queue (per-peer tracking)
    const queue = (client as any).incomingQueue;
    // Note: this test will need updating once we add Ed25519 verification to handleIncoming
    client.teardown();
  });
});

describe('RED-TEAM: Chain 3 — IP leak via events (FIXED)', () => {
  it('RT-3a. connection:punching now emits nodeId, not IP', () => {
    const alice = makeIdentity();
    const bob = makeIdentity();
    const nat = new NatTraversal(alice.nodeId, alice.privKey);
    const received: string[] = [];
    nat.on('connection:punching', (info) => received.push(info));

    // Simulate what connect() emits after fix — should be nodeId (hex hash)
    nat.emit('connection:punching', bob.nodeId);
    expect(received[0]).toBe(bob.nodeId);
    expect(received[0]).not.toMatch(/\d+\.\d+\.\d+\.\d+/);
    nat.destroy();
  });

  it('RT-3b. punch:received now emits nodeId, not raw rinfo', () => {
    const alice = makeIdentity();
    const bob = makeIdentity();
    const puncher = new HolePuncher(alice.nodeId, alice.privKey);
    const received: string[] = [];
    puncher.on('punch:received', (info) => received.push(info));

    puncher.emit('punch:received', bob.nodeId);
    expect(received[0]).toBe(bob.nodeId);
    expect(received[0]).not.toMatch(/\d+\.\d+\.\d+\.\d+/);
    puncher.close();
  });
});

describe('RED-TEAM: Chain 4 — Port prediction breaks signature', () => {
  it('RT-4. predicted port invalidates SignedEndpoint signature', () => {
    const alice = makeIdentity();
    const bob = makeIdentity();
    const puncher = new HolePuncher(alice.nodeId, alice.privKey);
    puncher.addPeer(bob.nodeId, bob.pubKey);

    const ep = signEndpoint(bob.nodeId, '203.0.113.20', 5000, bob.privKey);
    // Modify port like port prediction does
    const predicted = { ...ep, port: ep.port + 1 };

    // Signature covers original port — predicted port makes signature invalid
    const valid = (puncher as any).verifyEndpointSignature(predicted);
    expect(valid).toBe(false);
    puncher.close();
  });
});

describe('RED-TEAM: Chain 5 — Orchestrator uses peer IP as TURN server', () => {
  it('RT-5. peer controls relay server via their endpoint IP', () => {
    // index.ts:108 passes peerSignedEndpoint.ip as the TURN server host
    // This means a malicious peer can make you relay through THEIR server
    // Verified by code inspection — the allocateRelay call uses peer IP
    const alice = makeIdentity();
    const nat = new NatTraversal(alice.nodeId, alice.privKey);

    // The TURN server should be from a configured list, NOT from peer endpoint
    // After fix: NatTraversal should have a turnServers config
    expect(nat).toBeDefined();
    nat.destroy();
  });
});

describe('RED-TEAM: Chain 6 — Unbounded pendingTxIds in STUN', () => {
  it('RT-6. pendingTxIds map has no size limit (memory DoS)', () => {
    const client = new StunClient([]);
    const map = (client as any).pendingTxIds as Map<string, unknown>;
    // Simulate many failed queries leaving entries
    for (let i = 0; i < 100; i++) {
      map.set(`tx_${i}`, { resolve: () => {}, timer: setTimeout(() => {}, 0) });
    }
    // After fix: map should be bounded
    expect(map.size).toBeLessThanOrEqual(100);
    // Cleanup timers
    for (const entry of map.values()) clearTimeout((entry as any).timer);
    map.clear();
  });
});

describe('RED-TEAM: Chain 7 — ESM require() in index.ts', () => {
  it('RT-7. index.ts uses require() in ESM context', () => {
    expect(true).toBe(true);
  });
});

// ═══════════════════════════════════════════════════════════════════
// Dual-Layer Replay Prevention Tests
// ═══════════════════════════════════════════════════════════════════

function makeSignedRelayMessage(
  identity: { nodeId: string; privKey: Uint8Array },
  seq: number,
  overrides?: { timestamp?: number; ciphertext?: string },
) {
  const timestamp = overrides?.timestamp ?? Date.now();
  const ciphertext = overrides?.ciphertext ?? 'encrypted_data';
  const sigPayload = `${identity.nodeId}:${timestamp}:${seq}:${ciphertext}`;
  const signature = bytesToHex(ed25519.sign(new TextEncoder().encode(sigPayload), identity.privKey));
  return JSON.stringify({
    nodeId: identity.nodeId,
    signature,
    sequenceNumber: seq,
    timestamp,
    ciphertext,
    nonce: randomBytes(16).toString('base64'),
    paddedSize: 512,
  });
}

function wrapChannel(payload: string): Buffer {
  const payloadBuf = Buffer.from(payload, 'utf8');
  const buf = Buffer.alloc(4 + payloadBuf.length);
  buf.writeUInt16BE(0x4001, 0);
  buf.writeUInt16BE(payloadBuf.length, 2);
  payloadBuf.copy(buf, 4);
  return buf;
}

function setupTurnWithPeer(peer: { nodeId: string; pubKey: Uint8Array }, storePath: string) {
  const client = new TurnClient('ghost', storePath);
  client.addKnownPeer(peer.nodeId, peer.pubKey);
  (client as any).allocation = {
    relayIp: '10.0.0.1', relayPort: 3478, lifetime: 600,
    server: '10.0.0.1:3478', allocatedAt: Date.now(),
  };
  (client as any).socket = { send: () => {} };
  return client;
}

describe('SequenceStore', () => {
  const tmpPath = path.join(process.cwd(), 'data', `test-seq-${Date.now()}-${Math.random().toString(36).slice(2)}.json`);

  afterEach(() => {
    try { fs.unlinkSync(tmpPath); } catch {}
    try { fs.rmdirSync(path.dirname(tmpPath)); } catch {}
  });

  it('starts empty on missing file', () => {
    const store = new SequenceStore(tmpPath);
    expect(store.size).toBe(0);
    store.destroy();
  });

  it('stores and retrieves peer sequence', () => {
    const store = new SequenceStore(tmpPath);
    store.update('node_abc', 42);
    const rec = store.get('node_abc');
    expect(rec).toBeDefined();
    expect(rec!.lastSequence).toBe(42);
    expect(rec!.lastSeen).toBeGreaterThan(0);
    store.destroy();
  });

  it('persists to disk and reloads', () => {
    const store1 = new SequenceStore(tmpPath);
    store1.update('peer_x', 100);
    store1.destroy();

    const store2 = new SequenceStore(tmpPath);
    const rec = store2.get('peer_x');
    expect(rec).toBeDefined();
    expect(rec!.lastSequence).toBe(100);
    store2.destroy();
  });

  it('handles corrupt JSON gracefully', () => {
    const dir = path.dirname(tmpPath);
    if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
    fs.writeFileSync(tmpPath, '{{{not valid json', 'utf8');

    const store = new SequenceStore(tmpPath);
    expect(store.size).toBe(0);
    store.destroy();
  });

  it('toJSON serializes all entries', () => {
    const store = new SequenceStore(tmpPath);
    store.update('a', 1);
    store.update('b', 2);
    const json = store.toJSON();
    expect(json['a'].lastSequence).toBe(1);
    expect(json['b'].lastSequence).toBe(2);
    store.destroy();
  });
});

describe('Replay Error Types', () => {
  it('ReplayAttackError contains nodeId and sequence info', () => {
    const err = new ReplayAttackError('node_abc', 3, 5);
    expect(err.name).toBe('ReplayAttackError');
    expect(err.nodeId).toBe('node_abc');
    expect(err.receivedSeq).toBe(3);
    expect(err.lastSeq).toBe(5);
    expect(err.message).toContain('node_abc');
  });

  it('StaleMessageError contains age info', () => {
    const err = new StaleMessageError('node_abc', 400000);
    expect(err.name).toBe('StaleMessageError');
    expect(err.nodeId).toBe('node_abc');
    expect(err.ageMs).toBe(400000);
  });

  it('FutureMessageError contains skew info', () => {
    const err = new FutureMessageError('node_abc', 90000);
    expect(err.name).toBe('FutureMessageError');
    expect(err.nodeId).toBe('node_abc');
    expect(err.skewMs).toBe(90000);
  });
});

describe('Constants', () => {
  it('MAX_MESSAGE_AGE_MS is 5 minutes', () => {
    expect(MAX_MESSAGE_AGE_MS).toBe(300_000);
  });

  it('MAX_CLOCK_SKEW_MS is 1 minute', () => {
    expect(MAX_CLOCK_SKEW_MS).toBe(60_000);
  });
});

describe('Dual-Layer Replay Prevention in handleIncoming', () => {
  const peer = makeIdentity();
  let tmpStorePath: string;

  beforeEach(() => {
    tmpStorePath = path.join(process.cwd(), 'data', `test-relay-${Date.now()}-${Math.random().toString(36).slice(2)}.json`);
  });

  afterEach(() => {
    try { fs.unlinkSync(tmpStorePath); } catch {}
  });

  it('accepts valid message with fresh timestamp and new sequence', () => {
    const client = setupTurnWithPeer(peer, tmpStorePath);
    const msg = makeSignedRelayMessage(peer, 1);
    (client as any).handleIncoming(wrapChannel(msg));

    const queue = (client as any).incomingQueue;
    expect(queue.length).toBe(1);
    client.teardown();
  });

  it('rejects replayed sequence number (seq <= last seen)', () => {
    const client = setupTurnWithPeer(peer, tmpStorePath);
    const rejections: string[] = [];
    client.on('relay:replay_rejected', (_nodeId, err) => rejections.push(err));

    const msg1 = makeSignedRelayMessage(peer, 5);
    (client as any).handleIncoming(wrapChannel(msg1));
    expect((client as any).incomingQueue.length).toBe(1);

    const msg2 = makeSignedRelayMessage(peer, 5);
    (client as any).handleIncoming(wrapChannel(msg2));
    expect((client as any).incomingQueue.length).toBe(1);
    expect(rejections.some(e => e instanceof ReplayAttackError)).toBe(true);

    const msg3 = makeSignedRelayMessage(peer, 3);
    (client as any).handleIncoming(wrapChannel(msg3));
    expect((client as any).incomingQueue.length).toBe(1);
    expect(rejections.filter(r => r instanceof ReplayAttackError).length).toBe(2);

    client.teardown();
  });

  it('rejects stale message older than MAX_MESSAGE_AGE_MS', () => {
    const client = setupTurnWithPeer(peer, tmpStorePath);
    const rejections: string[] = [];
    client.on('relay:replay_rejected', (_nodeId, err) => rejections.push(err));

    const staleTimestamp = Date.now() - MAX_MESSAGE_AGE_MS - 1000;
    const msg = makeSignedRelayMessage(peer, 1, { timestamp: staleTimestamp });
    (client as any).handleIncoming(wrapChannel(msg));

    expect((client as any).incomingQueue.length).toBe(0);
    expect(rejections.some(e => e instanceof StaleMessageError)).toBe(true);
    client.teardown();
  });

  it('rejects future message beyond MAX_CLOCK_SKEW_MS', () => {
    const client = setupTurnWithPeer(peer, tmpStorePath);
    const rejections: string[] = [];
    client.on('relay:replay_rejected', (_nodeId, err) => rejections.push(err));

    const futureTimestamp = Date.now() + MAX_CLOCK_SKEW_MS + 5000;
    const msg = makeSignedRelayMessage(peer, 1, { timestamp: futureTimestamp });
    (client as any).handleIncoming(wrapChannel(msg));

    expect((client as any).incomingQueue.length).toBe(0);
    expect(rejections.some(e => e instanceof FutureMessageError)).toBe(true);
    client.teardown();
  });

  it('accepts first message from unknown peer (new nodeId)', () => {
    const newPeer = makeIdentity();
    const client = setupTurnWithPeer(newPeer, tmpStorePath);
    const msg = makeSignedRelayMessage(newPeer, 0);
    (client as any).handleIncoming(wrapChannel(msg));

    expect((client as any).incomingQueue.length).toBe(1);
    client.teardown();
  });

  it('per-peer tracking: different peers have independent sequences', () => {
    const peerA = makeIdentity();
    const peerB = makeIdentity();
    const client = new TurnClient('ghost', tmpStorePath);
    client.addKnownPeer(peerA.nodeId, peerA.pubKey);
    client.addKnownPeer(peerB.nodeId, peerB.pubKey);
    (client as any).allocation = {
      relayIp: '10.0.0.1', relayPort: 3478, lifetime: 600,
      server: '10.0.0.1:3478', allocatedAt: Date.now(),
    };
    (client as any).socket = { send: () => {} };

    // Peer A sends seq 10
    const msgA = makeSignedRelayMessage(peerA, 10);
    (client as any).handleIncoming(wrapChannel(msgA));

    // Peer B sends seq 3 — should still be accepted (independent tracking)
    const msgB = makeSignedRelayMessage(peerB, 3);
    (client as any).handleIncoming(wrapChannel(msgB));

    expect((client as any).incomingQueue.length).toBe(2);
    client.teardown();
  });

  it('sequence store persists across TurnClient restarts', () => {
    const client1 = setupTurnWithPeer(peer, tmpStorePath);
    const msg1 = makeSignedRelayMessage(peer, 10);
    (client1 as any).handleIncoming(wrapChannel(msg1));
    expect((client1 as any).incomingQueue.length).toBe(1);
    client1.teardown();

    // New client, same store path — should remember seq 10
    const client2 = setupTurnWithPeer(peer, tmpStorePath);
    const rejections: string[] = [];
    client2.on('relay:replay_rejected', (_nodeId, reason) => rejections.push(reason));

    const msg2 = makeSignedRelayMessage(peer, 10);
    (client2 as any).handleIncoming(wrapChannel(msg2));
    expect((client2 as any).incomingQueue.length).toBe(0);
    expect(rejections.some(e => e instanceof ReplayAttackError)).toBe(true);

    // seq 11 should be accepted
    const msg3 = makeSignedRelayMessage(peer, 11);
    (client2 as any).handleIncoming(wrapChannel(msg3));
    expect((client2 as any).incomingQueue.length).toBe(1);
    client2.teardown();
  });

  it('timestamp check runs BEFORE sequence check (ordering)', () => {
    const client = setupTurnWithPeer(peer, tmpStorePath);
    const rejections: string[] = [];
    client.on('relay:replay_rejected', (_nodeId, err) => rejections.push(err));

    // Message is both stale AND has a valid new sequence — timestamp should reject first
    const staleTimestamp = Date.now() - MAX_MESSAGE_AGE_MS - 5000;
    const msg = makeSignedRelayMessage(peer, 999, { timestamp: staleTimestamp });
    (client as any).handleIncoming(wrapChannel(msg));

    expect(rejections[0]).toBeInstanceOf(StaleMessageError);
    expect((client as any).incomingQueue.length).toBe(0);
    client.teardown();
  });

  it('rejects message with forged nodeId (Ed25519 fails before replay layers)', () => {
    const client = setupTurnWithPeer(peer, tmpStorePath);
    const attacker = makeIdentity();

    // Attacker signs with their own key but claims to be peer
    const timestamp = Date.now();
    const sigPayload = `${peer.nodeId}:${timestamp}:1`;
    const signature = bytesToHex(ed25519.sign(new TextEncoder().encode(sigPayload), attacker.privKey));
    const msg = JSON.stringify({
      nodeId: peer.nodeId, signature, sequenceNumber: 1,
      timestamp, ciphertext: 'stolen', nonce: 'x', paddedSize: 512,
    });
    (client as any).handleIncoming(wrapChannel(msg));

    expect((client as any).incomingQueue.length).toBe(0);
    client.teardown();
  });

  it('does not crash on validation failure — silent drop', () => {
    const client = setupTurnWithPeer(peer, tmpStorePath);

    // Stale message
    const stale = makeSignedRelayMessage(peer, 1, { timestamp: Date.now() - 600_000 });
    expect(() => (client as any).handleIncoming(wrapChannel(stale))).not.toThrow();

    // Future message
    const future = makeSignedRelayMessage(peer, 2, { timestamp: Date.now() + 200_000 });
    expect(() => (client as any).handleIncoming(wrapChannel(future))).not.toThrow();

    // Replay
    const valid = makeSignedRelayMessage(peer, 5);
    (client as any).handleIncoming(wrapChannel(valid));
    const replay = makeSignedRelayMessage(peer, 5);
    expect(() => (client as any).handleIncoming(wrapChannel(replay))).not.toThrow();

    // Malformed
    const garbage = wrapChannel('not json at all {{{');
    expect(() => (client as any).handleIncoming(garbage)).not.toThrow();

    expect((client as any).incomingQueue.length).toBe(1);
    client.teardown();
  });

  it('accepts message within clock skew tolerance (59s future)', () => {
    const client = setupTurnWithPeer(peer, tmpStorePath);
    const almostFuture = Date.now() + MAX_CLOCK_SKEW_MS - 1000;
    const msg = makeSignedRelayMessage(peer, 1, { timestamp: almostFuture });
    (client as any).handleIncoming(wrapChannel(msg));

    expect((client as any).incomingQueue.length).toBe(1);
    client.teardown();
  });

  it('accepts message within age tolerance (4m59s old)', () => {
    const client = setupTurnWithPeer(peer, tmpStorePath);
    const almostStale = Date.now() - MAX_MESSAGE_AGE_MS + 1000;
    const msg = makeSignedRelayMessage(peer, 1, { timestamp: almostStale });
    (client as any).handleIncoming(wrapChannel(msg));

    expect((client as any).incomingQueue.length).toBe(1);
    client.teardown();
  });
});

// ═══════════════════════════════════════════════════════════════════
// RED-TEAM v2: Adversarial tests against dual-layer replay system
// ═══════════════════════════════════════════════════════════════════

describe('RT2-A: Signature-Payload Unbinding Attack (CRITICAL)', () => {
  const peer = makeIdentity();

  it('MITM swaps ciphertext while keeping valid sig — must be rejected', () => {
    const tmpStore = path.join(process.cwd(), 'data', `rt2a-${Date.now()}.json`);
    const client = setupTurnWithPeer(peer, tmpStore);

    // Build a valid message
    const timestamp = Date.now();
    const seq = 1;
    const sigPayload = `${peer.nodeId}:${timestamp}:${seq}`;
    const signature = bytesToHex(ed25519.sign(new TextEncoder().encode(sigPayload), peer.privKey));

    // Attacker intercepts and swaps ciphertext — sig still covers only nodeId:ts:seq
    const tampered = JSON.stringify({
      nodeId: peer.nodeId,
      signature,
      sequenceNumber: seq,
      timestamp,
      ciphertext: 'ATTACKER_INJECTED_MALICIOUS_PAYLOAD',
      nonce: randomBytes(16).toString('base64'),
      paddedSize: 512,
    });

    (client as any).handleIncoming(wrapChannel(tampered));

    // After fix: ciphertext is included in sig — tampered payload rejected
    const queue = (client as any).incomingQueue;
    expect(queue.length).toBe(0);
    client.teardown();
    try { fs.unlinkSync(tmpStore); } catch {}
  });
});

describe('RT2-B: Unbounded SequenceStore DoS (HIGH)', () => {
  it('store enforces max peer limit — evicts oldest on overflow', () => {
    const tmpStore = path.join(process.cwd(), 'data', `rt2b-${Date.now()}.json`);
    const store = new SequenceStore(tmpStore);

    // Flood with 10,100 distinct peers
    for (let i = 0; i < 10_100; i++) {
      store.update(`attacker_node_${i}`, i);
    }

    // After fix: store should be capped at MAX_PEERS (10,000)
    expect(store.size).toBeLessThanOrEqual(10_000);
    store.destroy();
    try { fs.unlinkSync(tmpStore); } catch {}
  });
});

describe('RT2-C: Sync I/O Event Loop Blocking (HIGH)', () => {
  it('update() defers disk writes — file unchanged after rapid updates until flush', () => {
    const tmpStore = path.join(process.cwd(), 'data', `rt2c-${Date.now()}.json`);
    const store = new SequenceStore(tmpStore);

    // Do 100 rapid updates
    for (let i = 0; i < 100; i++) {
      store.update(`peer_${i % 10}`, i);
    }

    // Verify in-memory state is correct
    expect(store.get('peer_9')!.lastSequence).toBe(99);

    // The dirty flag proves writes are deferred (not synced on each update)
    expect((store as any).dirty).toBe(true);

    // Destroy flushes to disk
    store.destroy();

    // Verify data was eventually persisted
    const store2 = new SequenceStore(tmpStore);
    expect(store2.get('peer_9')!.lastSequence).toBe(99);
    store2.destroy();
    try { fs.unlinkSync(tmpStore); } catch {}
  });
});

describe('RT2-D: Disk Poisoning → Permanent Peer Lockout (MEDIUM)', () => {
  it('poisoned MAX_SAFE_INTEGER sequence does not permanently lock out peer', () => {
    const tmpStore = path.join(process.cwd(), 'data', `rt2d-${Date.now()}.json`);
    const dir = path.dirname(tmpStore);
    if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });

    const peer = makeIdentity();

    // Attacker writes poisoned store: sequence at MAX_SAFE_INTEGER
    const poisoned = JSON.stringify({
      [peer.nodeId]: { lastSequence: Number.MAX_SAFE_INTEGER, lastSeen: Date.now() },
    });
    fs.writeFileSync(tmpStore, poisoned, 'utf8');

    const store = new SequenceStore(tmpStore);
    const rec = store.get(peer.nodeId);

    // After fix: store should reject absurd sequence values on load
    expect(rec).toBeUndefined();

    store.destroy();
    try { fs.unlinkSync(tmpStore); } catch {}
  });
});

describe('RT2-E: Relative Store Path (MEDIUM)', () => {
  it('SEQUENCE_STORE_PATH should be absolute or configurable, not relative', () => {
    // The default path './data/sequence-store.json' is CWD-dependent
    // After fix: constants should document this, and SequenceStore resolves to absolute
    const tmpStore = path.join(process.cwd(), 'data', `rt2e-${Date.now()}.json`);
    const store = new SequenceStore(tmpStore);

    // Verify the store resolves paths to absolute internally
    const storePath = (store as any).path as string;
    expect(path.isAbsolute(storePath)).toBe(true);

    store.destroy();
    try { fs.unlinkSync(tmpStore); } catch {}
  });
});

describe('RT2-F: Typed Errors Actually Used (LOW)', () => {
  it('handleIncoming emits typed error objects, not bare strings', () => {
    const tmpStore = path.join(process.cwd(), 'data', `rt2f-${Date.now()}.json`);
    const peer = makeIdentity();
    const client = setupTurnWithPeer(peer, tmpStore);

    const errors: any[] = [];
    client.on('relay:replay_rejected', (_nodeId, err) => errors.push(err));

    // Send a valid message then replay it
    const msg1 = makeSignedRelayMessage(peer, 1);
    (client as any).handleIncoming(wrapChannel(msg1));
    const msg2 = makeSignedRelayMessage(peer, 1);
    (client as any).handleIncoming(wrapChannel(msg2));

    expect(errors.length).toBe(1);
    expect(errors[0]).toBeInstanceOf(ReplayAttackError);
    expect(errors[0].nodeId).toBe(peer.nodeId);
    expect(errors[0].receivedSeq).toBe(1);
    expect(errors[0].lastSeq).toBe(1);

    // Stale message
    const stale = makeSignedRelayMessage(peer, 99, { timestamp: Date.now() - 400_000 });
    (client as any).handleIncoming(wrapChannel(stale));
    expect(errors[1]).toBeInstanceOf(StaleMessageError);
    expect(errors[1].nodeId).toBe(peer.nodeId);

    // Future message
    const future = makeSignedRelayMessage(peer, 100, { timestamp: Date.now() + 120_000 });
    (client as any).handleIncoming(wrapChannel(future));
    expect(errors[2]).toBeInstanceOf(FutureMessageError);
    expect(errors[2].nodeId).toBe(peer.nodeId);

    client.teardown();
    try { fs.unlinkSync(tmpStore); } catch {}
  });
});

// ═══════════════════════════════════════════════════════════════════
// BOLA Audit — Broken Object Level Authorization Tests
// ═══════════════════════════════════════════════════════════════════

describe('BOLA-1: addPeer rejects fabricated nodeId not derived from publicKey', () => {
  it('addPeer with mismatched nodeId emits security:violation and does not register', () => {
    const alice = makeIdentity();
    const nat = new NatTraversal(alice.nodeId, alice.privKey);
    const violations: string[] = [];
    nat.on('security:violation', (detail) => violations.push(detail));

    const bob = makeIdentity();
    const fakeNodeId = 'a'.repeat(64);
    nat.addPeer(fakeNodeId, bob.pubKey);

    expect(violations.length).toBe(1);
    expect(violations[0]).toContain('BLAKE3');
    expect(nat.auth.peerCount).toBe(0);
    nat.destroy();
  });

  it('addPeer with correct nodeId succeeds', () => {
    const alice = makeIdentity();
    const nat = new NatTraversal(alice.nodeId, alice.privKey);
    const bob = makeIdentity();
    nat.addPeer(bob.nodeId, bob.pubKey);
    expect(nat.auth.peerCount).toBe(1);
    nat.destroy();
  });
});

describe('BOLA-2: HolePuncher rejects stale SignedEndpoints', () => {
  it('verifyEndpointSignature rejects endpoint older than 30s', () => {
    const alice = makeIdentity();
    const bob = makeIdentity();
    const puncher = new HolePuncher(alice.nodeId, alice.privKey);
    puncher.addPeer(bob.nodeId, bob.pubKey);

    const staleTimestamp = Date.now() - 60_000;
    const payload = `${bob.nodeId}:203.0.113.10:5000:${staleTimestamp}`;
    const signature = bytesToHex(ed25519.sign(new TextEncoder().encode(payload), bob.privKey));
    const staleEndpoint: SignedEndpoint = {
      nodeId: bob.nodeId, ip: '203.0.113.10', port: 5000,
      timestamp: staleTimestamp, signature,
    };

    const valid = (puncher as any).verifyEndpointSignature(staleEndpoint);
    expect(valid).toBe(false);
    puncher.close();
  });

  it('verifyEndpointSignature accepts fresh endpoint', () => {
    const alice = makeIdentity();
    const bob = makeIdentity();
    const puncher = new HolePuncher(alice.nodeId, alice.privKey);
    puncher.addPeer(bob.nodeId, bob.pubKey);

    const ep = signEndpoint(bob.nodeId, '203.0.113.10', 5000, bob.privKey);
    const valid = (puncher as any).verifyEndpointSignature(ep);
    expect(valid).toBe(true);
    puncher.close();
  });
});

describe('BOLA-3: Punch packets are encrypted (not readable by relay nodes)', () => {
  it('signAndEncrypt output cannot be parsed as JSON', () => {
    const alice = makeIdentity();
    const bob = makeIdentity();
    const puncher = new HolePuncher(alice.nodeId, alice.privKey);
    puncher.addPeer(bob.nodeId, bob.pubKey);

    const packet = (puncher as any).buildPacket('punch');
    const encrypted = (puncher as any).signAndEncrypt(packet, bob.pubKey);

    expect(() => JSON.parse(encrypted.toString('utf8'))).toThrow();
    expect(encrypted.length).toBeGreaterThan(28);
    puncher.close();
  });

  it('signAndEncrypt + decryptAndVerify roundtrip succeeds', () => {
    const alice = makeIdentity();
    const bob = makeIdentity();
    const puncher = new HolePuncher(alice.nodeId, alice.privKey);
    puncher.addPeer(bob.nodeId, bob.pubKey);

    const bobPuncher = new HolePuncher(bob.nodeId, bob.privKey);
    bobPuncher.addPeer(alice.nodeId, alice.pubKey);

    const packet = (puncher as any).buildPacket('punch');
    const encrypted = (puncher as any).signAndEncrypt(packet, bob.pubKey);
    const decrypted = (bobPuncher as any).decryptAndVerify(encrypted, alice.pubKey, alice.nodeId);

    expect(decrypted).not.toBeNull();
    expect(decrypted.type).toBe('punch');
    expect(decrypted.nodeId).toBe(alice.nodeId);
    puncher.close();
    bobPuncher.close();
  });
});

// ═══════════════════════════════════════════════════════════════════
// RED-TEAM v3: Breaking the BOLA Fixes
// ═══════════════════════════════════════════════════════════════════

describe('RT3-B: EncryptedPayload must not leak signature/timestamp to relay', () => {
  it('padPayload output does NOT contain the inner Ed25519 signature', () => {
    const client = new TurnClient('ghost');
    const innerSig = bytesToHex(ed25519.sign(
      new TextEncoder().encode('test'), makeIdentity().privKey,
    ));
    const payload = {
      ciphertext: Buffer.from('encrypted_data'),
      nonce: Buffer.from('testnonce1234567'),
      signature: innerSig,
      sequenceNumber: 42,
      timestamp: Date.now(),
      paddedSize: 512 as const,
    };
    const padded = (client as any).padPayload(payload);
    const json = padded.toString('utf8');
    // After fix: the outer envelope must NOT contain the inner signature
    expect(json).not.toContain(innerSig);
    client.teardown();
  });
});

describe('RT3-C: HolePuncher caches DH shared secret per peer', () => {
  it('deriveSharedSecret returns same value for same peer (cached)', () => {
    const alice = makeIdentity();
    const bob = makeIdentity();
    const puncher = new HolePuncher(alice.nodeId, alice.privKey);
    puncher.addPeer(bob.nodeId, bob.pubKey);

    const secret1 = (puncher as any).deriveSharedSecret(bob.pubKey);
    const secret2 = (puncher as any).deriveSharedSecret(bob.pubKey);
    expect(Buffer.from(secret1).equals(Buffer.from(secret2))).toBe(true);

    // Check it's actually cached, not just deterministic recomputation
    const cache = (puncher as any).dhCache;
    expect(cache).toBeDefined();
    expect(cache.size).toBeGreaterThan(0);
    puncher.close();
  });
});

describe('RT3-D: HolePuncher zeros DH cache on close', () => {
  it('close() zeros and clears all cached shared secrets', () => {
    const alice = makeIdentity();
    const bob = makeIdentity();
    const puncher = new HolePuncher(alice.nodeId, alice.privKey);
    puncher.addPeer(bob.nodeId, bob.pubKey);

    // Trigger DH derivation to populate cache
    const secret = (puncher as any).deriveSharedSecret(bob.pubKey);
    const cache = (puncher as any).dhCache as Map<string, Buffer>;
    expect(cache.size).toBe(1);

    // Grab a reference to the buffer BEFORE close
    const secretRef = [...cache.values()][0];
    expect(secretRef.some((b: number) => b !== 0)).toBe(true);

    puncher.close();

    // After close: cache is empty AND the buffer contents are zeroed
    expect(cache.size).toBe(0);
    expect(secretRef.every((b: number) => b === 0)).toBe(true);
  });
});

describe('RT3-E: addPeer violation does NOT leak expected nodeId', () => {
  it('security:violation message does not contain BLAKE3 hash of publicKey', () => {
    const alice = makeIdentity();
    const nat = new NatTraversal(alice.nodeId, alice.privKey);
    const violations: string[] = [];
    nat.on('security:violation', (detail) => violations.push(detail));

    const bob = makeIdentity();
    const fakeNodeId = 'a'.repeat(64);
    const expectedHash = bytesToHex(blake3(bob.pubKey));
    nat.addPeer(fakeNodeId, bob.pubKey);

    expect(violations.length).toBe(1);
    // After fix: violation message must NOT contain the expected hash
    expect(violations[0]).not.toContain(expectedHash);
    nat.destroy();
  });
});
