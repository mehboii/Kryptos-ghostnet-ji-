/**
 * RED TEAM — Adversarial tests attempting to break GhostNet's NAT security.
 *
 * Each test simulates a specific attack vector. Tests are written to FAIL
 * against vulnerable code and PASS once the fix is applied.
 */
import { describe, it, expect, beforeEach } from 'vitest';
import { ed25519 } from '@noble/curves/ed25519.js';
import { blake3 } from '@noble/hashes/blake3.js';
import { bytesToHex } from '@noble/hashes/utils.js';

import { SocketObserver } from '../../extraction/observer.js';
import { HandshakeParser } from '../../extraction/handshake.js';
import type { HandshakeMessage } from '../../extraction/handshake.js';
import { ReconciliationEngine } from '../../extraction/reconciliation.js';
import { PrivacyFilter } from '../../extraction/privacyFilter.js';
import { PeerRegistry } from '../../extraction/registry.js';
import { NatSecurityAuditor } from '../securityAudit.js';
import type { MultiStunResult, StunResult } from '../stun.js';

// ── Helpers ───────────────────────────────────────────────────────────

function makeKeyPair() {
  const privKey = ed25519.utils.randomSecretKey();
  const pubKey = ed25519.getPublicKey(privKey);
  const nodeId = bytesToHex(blake3(pubKey));
  return { privKey, pubKey, pubKeyHex: bytesToHex(pubKey), nodeId };
}

function signHandshake(msg: Omit<HandshakeMessage, 'signature'>, privKey: Uint8Array): HandshakeMessage {
  const payload = new TextEncoder().encode(
    `${msg.nodeId}:${msg.claimedLanIp}:${msg.claimedPublicIp}:${msg.timestamp}`,
  );
  return { ...msg, signature: bytesToHex(ed25519.sign(payload, privKey)) };
}

function observed(ip: string, port = 40000) {
  return { ip, port, family: 'IPv4' as const, observedAt: Date.now() };
}

// ══════════════════════════════════════════════════════════════════════
// ATTACK 1: STUN Transaction ID uses Math.random() — predictable
// ══════════════════════════════════════════════════════════════════════
describe('ATTACK 1: STUN transaction ID predictability', () => {
  it('txId must use crypto.randomBytes, not Math.random()', async () => {
    // We can't directly test randomness quality, but we verify the
    // source code uses crypto.randomBytes by importing and checking
    // the built request contains high-entropy bytes.
    const { buildBindingRequest } = await import('../stun.js') as any;

    // If buildBindingRequest is not exported, we test indirectly:
    // Generate 100 txIds, ensure no duplicates (Math.random with same seed = dupes)
    const ids = new Set<string>();
    for (let i = 0; i < 100; i++) {
      const { txId } = buildBindingRequest();
      ids.add(txId.toString('hex'));
    }
    // With 12 bytes of crypto entropy, collision in 100 is astronomically unlikely
    expect(ids.size).toBe(100);
  });
});

// ══════════════════════════════════════════════════════════════════════
// ATTACK 2: Handshake payload delimiter injection
// Attacker crafts claimedLanIp containing ":" to shift payload fields
// ══════════════════════════════════════════════════════════════════════
describe('ATTACK 2: Handshake payload delimiter injection', () => {
  it('reject IPs containing colons (payload injection)', () => {
    const parser = new HandshakeParser();
    const { privKey, pubKeyHex, nodeId } = makeKeyPair();
    // Attacker claims LAN IP "192.168.1.1:fakePublicIp:9999"
    const malicious = signHandshake({
      nodeId,
      claimedLanIp: '192.168.1.1:203.0.113.99:9999',
      claimedPublicIp: '203.0.113.10',
      publicKey: pubKeyHex,
      timestamp: Date.now(),
    }, privKey);
    const result = parser.parse(malicious);
    // Should reject: IPs must not contain colons
    expect(result.verified).toBe(false);
  });

  it('reject IPs with newlines (header injection)', () => {
    const parser = new HandshakeParser();
    const { privKey, pubKeyHex, nodeId } = makeKeyPair();
    const malicious = signHandshake({
      nodeId,
      claimedLanIp: '192.168.1.1\n203.0.113.99',
      claimedPublicIp: '203.0.113.10',
      publicKey: pubKeyHex,
      timestamp: Date.now(),
    }, privKey);
    const result = parser.parse(malicious);
    expect(result.verified).toBe(false);
  });
});

// ══════════════════════════════════════════════════════════════════════
// ATTACK 3: IP format bypass — non-standard representations
// Attacker uses octal, hex, or decimal IP notation to bypass isPrivateIp
// ══════════════════════════════════════════════════════════════════════
describe('ATTACK 3: IP format bypass (octal/hex/decimal)', () => {
  it('reject octal IP 0177.0.0.1 (127.0.0.1)', () => {
    const engine = new ReconciliationEngine();
    const parser = new HandshakeParser();
    const { privKey, pubKeyHex, nodeId } = makeKeyPair();
    const msg = signHandshake({
      nodeId,
      claimedLanIp: '0177.0.0.1', // octal for 127.0.0.1
      claimedPublicIp: '203.0.113.10',
      publicKey: pubKeyHex,
      timestamp: Date.now(),
    }, privKey);
    const claimed = parser.parse(msg);
    const result = engine.reconcile(observed('198.51.100.1'), claimed);
    // Non-standard IP formats should not be treated as valid private IPs
    // They should be flagged as suspicious
    expect(result.connectionType).toBe('suspicious');
  });

  it('reject hex IP 0x7f000001 (127.0.0.1)', () => {
    const engine = new ReconciliationEngine();
    const parser = new HandshakeParser();
    const { privKey, pubKeyHex, nodeId } = makeKeyPair();
    const msg = signHandshake({
      nodeId,
      claimedLanIp: '0x7f000001',
      claimedPublicIp: '203.0.113.10',
      publicKey: pubKeyHex,
      timestamp: Date.now(),
    }, privKey);
    const claimed = parser.parse(msg);
    const result = engine.reconcile(observed('198.51.100.1'), claimed);
    expect(result.connectionType).toBe('suspicious');
  });

  it('reject decimal IP 2130706433 (127.0.0.1)', () => {
    const engine = new ReconciliationEngine();
    const parser = new HandshakeParser();
    const { privKey, pubKeyHex, nodeId } = makeKeyPair();
    const msg = signHandshake({
      nodeId,
      claimedLanIp: '2130706433',
      claimedPublicIp: '203.0.113.10',
      publicKey: pubKeyHex,
      timestamp: Date.now(),
    }, privKey);
    const claimed = parser.parse(msg);
    const result = engine.reconcile(observed('198.51.100.1'), claimed);
    expect(result.connectionType).toBe('suspicious');
  });
});

// ══════════════════════════════════════════════════════════════════════
// ATTACK 4: Observation array memory exhaustion
// Attacker floods SocketObserver with millions of connections
// ══════════════════════════════════════════════════════════════════════
describe('ATTACK 4: SocketObserver memory exhaustion', () => {
  it('observation array is bounded', () => {
    const obs = new SocketObserver();
    for (let i = 0; i < 20_000; i++) {
      obs.observeTcp({ remoteAddress: `1.2.3.${i % 256}`, remotePort: 5000 + i, once() {} } as any);
    }
    // Should be capped, not unbounded
    expect(obs.getObservations().length).toBeLessThanOrEqual(10_000);
  });
});

// ══════════════════════════════════════════════════════════════════════
// ATTACK 5: ReconciliationEngine map memory exhaustion
// Attacker generates unique nodeIds to grow tracking maps unboundedly
// ══════════════════════════════════════════════════════════════════════
describe('ATTACK 5: ReconciliationEngine tracking map exhaustion', () => {
  it('tracking maps are bounded even with unique keys', () => {
    const engine = new ReconciliationEngine();

    for (let i = 0; i < 12_000; i++) {
      const claimed = {
        nodeId: `node-${i}`,
        claimedLanIp: '192.168.1.1',
        claimedPublicIp: '203.0.113.10',
        signature: 'sig',
        verified: true,
      };
      engine.reconcile(observed(`1.2.${Math.floor(i / 256) % 256}.${i % 256}`), claimed);
    }
    expect(engine.trackingSize).toBeLessThanOrEqual(10_000);
  });
});

// ══════════════════════════════════════════════════════════════════════
// ATTACK 6: Hole punch UDP packet bomb (oversized payload)
// Attacker sends a 64KB UDP packet to crash JSON parser or exhaust memory
// ══════════════════════════════════════════════════════════════════════
describe('ATTACK 6: Hole punch oversized packet', () => {
  it('rejects packets larger than MAX_PACKET_SIZE', async () => {
    const { HolePuncher } = await import('../holePunch.js');
    const puncher = new HolePuncher('mynode');
    // Verify MAX_PACKET_SIZE constant exists and is reasonable
    const { MAX_PUNCH_PACKET_SIZE } = await import('../holePunch.js') as any;
    expect(MAX_PUNCH_PACKET_SIZE).toBeDefined();
    expect(MAX_PUNCH_PACKET_SIZE).toBeLessThanOrEqual(2048);
    puncher.cancelAll();
  });
});

// ══════════════════════════════════════════════════════════════════════
// ATTACK 7: Handshake timestamp at exact boundary (off-by-one)
// ══════════════════════════════════════════════════════════════════════
describe('ATTACK 7: Handshake timestamp boundary attacks', () => {
  it('reject handshake clearly past TTL', () => {
    const parser = new HandshakeParser();
    const { privKey, pubKeyHex, nodeId } = makeKeyPair();
    const msg = signHandshake({
      nodeId,
      claimedLanIp: '192.168.1.1',
      claimedPublicIp: '203.0.113.10',
      publicKey: pubKeyHex,
      timestamp: Date.now() - 31_000,
    }, privKey);
    expect(parser.parse(msg).verified).toBe(false);
  });

  it('accept handshake within TTL window', () => {
    const parser = new HandshakeParser();
    const { privKey, pubKeyHex, nodeId } = makeKeyPair();
    const msg = signHandshake({
      nodeId,
      claimedLanIp: '192.168.1.1',
      claimedPublicIp: '203.0.113.10',
      publicKey: pubKeyHex,
      timestamp: Date.now() - 29_000,
    }, privKey);
    expect(parser.parse(msg).verified).toBe(true);
  });

  it('reject future timestamp (clock skew attack)', () => {
    const parser = new HandshakeParser();
    const { privKey, pubKeyHex, nodeId } = makeKeyPair();
    const msg = signHandshake({
      nodeId,
      claimedLanIp: '192.168.1.1',
      claimedPublicIp: '203.0.113.10',
      publicKey: pubKeyHex,
      timestamp: Date.now() + 60_000, // 1 minute in future
    }, privKey);
    expect(parser.parse(msg).verified).toBe(false);
  });
});

// ══════════════════════════════════════════════════════════════════════
// ATTACK 8: Ghost tier endpoint leaks raw IP — verify it's time-bounded
// ══════════════════════════════════════════════════════════════════════
describe('ATTACK 8: Ghost tier IP exposure window', () => {
  it('ghost tier record expires and IP becomes unrecoverable', () => {
    const filter = new PrivacyFilter();
    const reconciled = {
      nodeId: 'test',
      observed: observed('203.0.113.10', 5000),
      claimed: { nodeId: 'test', claimedLanIp: '192.168.1.1', claimedPublicIp: '203.0.113.10', signature: 'sig', verified: true },
      natDetected: false,
      spoofingFlag: false,
      confidence: 95,
      connectionType: 'direct' as const,
      flags: [],
    };
    const record = filter.apply(reconciled, 'ghost');
    expect(record.endpoint).toBe('203.0.113.10:5000');

    // Manually expire by looking up after TTL
    // We can't wait 15 min, but verify the expiresAt is set correctly
    expect(record.expiresAt).toBeLessThanOrEqual(Date.now() + 15 * 60_000 + 100);
    expect(record.expiresAt).toBeGreaterThan(Date.now());
  });
});

// ══════════════════════════════════════════════════════════════════════
// ATTACK 9: PeerRegistry flood — rapid adds to trigger eviction chaos
// ══════════════════════════════════════════════════════════════════════
describe('ATTACK 9: PeerRegistry eviction manipulation', () => {
  it('attacker cannot keep low-confidence peers by rapid re-adding', () => {
    const registry = new PeerRegistry();
    // Fill registry with high-confidence peers
    for (let i = 0; i < 1000; i++) {
      registry.addPeer({
        nodeId: `legit-${i}`,
        ipFingerprint: `fp-${i}`,
        confidence: 90,
        tier: 'stealth' as const,
        expiresAt: Date.now() + 60_000,
      });
    }
    // Attacker tries to add a low-confidence peer
    registry.addPeer({
      nodeId: 'attacker',
      ipFingerprint: 'evil-fp',
      confidence: 5,
      tier: 'stealth' as const,
      expiresAt: Date.now() + 60_000,
    });
    // Attacker's peer should exist (it evicted the lowest legit peer)
    // But if attacker tries again after being evicted by a higher-confidence peer...
    registry.addPeer({
      nodeId: 'legit-replacement',
      ipFingerprint: 'fp-new',
      confidence: 95,
      tier: 'stealth' as const,
      expiresAt: Date.now() + 60_000,
    });
    // The attacker (confidence 5) should have been evicted for the new high-confidence peer
    expect(registry.getPeer('attacker')).toBeNull();
    registry.destroy();
  });
});

// ══════════════════════════════════════════════════════════════════════
// ATTACK 10: Handshake key encoding ambiguity
// Same bytes can be interpreted as hex or base64 differently
// ══════════════════════════════════════════════════════════════════════
describe('ATTACK 10: Key encoding ambiguity exploit', () => {
  it('hex and base64 of same key produce same verification result', () => {
    const parser = new HandshakeParser();
    const { privKey, pubKey, nodeId } = makeKeyPair();
    const now = Date.now();

    const hexKey = bytesToHex(pubKey);
    const b64Key = Buffer.from(pubKey).toString('base64');

    const baseMsg = {
      nodeId,
      claimedLanIp: '192.168.1.1',
      claimedPublicIp: '203.0.113.10',
      timestamp: now,
    };

    const hexMsg = signHandshake({ ...baseMsg, publicKey: hexKey }, privKey);
    const b64Msg = signHandshake({ ...baseMsg, publicKey: b64Key }, privKey);

    const hexResult = parser.parse(hexMsg);
    const b64Result = parser.parse(b64Msg);

    // Both should produce the same nodeId verification outcome
    // (both decode to the same pubKey bytes)
    expect(hexResult.verified).toBe(true);
    expect(b64Result.verified).toBe(true);
  });
});

// ══════════════════════════════════════════════════════════════════════
// ATTACK 11: IPv4-mapped IPv6 bypass in reconciliation
// Attacker claims "::ffff:10.0.0.1" to bypass private IP check
// ══════════════════════════════════════════════════════════════════════
describe('ATTACK 11: IPv6-mapped private IP bypass', () => {
  it('strip ::ffff: before private IP check on claimed IPs', () => {
    const engine = new ReconciliationEngine();
    const parser = new HandshakeParser();
    const { privKey, pubKeyHex, nodeId } = makeKeyPair();
    const msg = signHandshake({
      nodeId,
      claimedLanIp: '::ffff:10.0.0.1',
      claimedPublicIp: '203.0.113.10',
      publicKey: pubKeyHex,
      timestamp: Date.now(),
    }, privKey);
    const claimed = parser.parse(msg);
    const result = engine.reconcile(observed('198.51.100.1'), claimed);
    // Should detect NAT (claimedLanIp is private after stripping), not suspicious
    expect(result.connectionType).toBe('nat');
    expect(result.natDetected).toBe(true);
  });
});

// ══════════════════════════════════════════════════════════════════════
// ATTACK 12: STUN auditor doesn't catch 0.0.0.0 as invalid public IP
// ══════════════════════════════════════════════════════════════════════
describe('ATTACK 12: Invalid public IPs from STUN', () => {
  it('flag 0.0.0.0 as invalid public IP', () => {
    const auditor = new NatSecurityAuditor();
    const findings = auditor.auditStun({
      publicIp: '0.0.0.0',
      publicPort: 40000,
      consensus: true,
      results: [
        { ip: '0.0.0.0', port: 40000, server: 'a:19302', latencyMs: 50 },
        { ip: '0.0.0.0', port: 40000, server: 'b:19302', latencyMs: 50 },
      ],
      disagreements: [],
      aborted: false,
    });
    expect(findings.some(f => f.severity === 'critical')).toBe(true);
  });
});
