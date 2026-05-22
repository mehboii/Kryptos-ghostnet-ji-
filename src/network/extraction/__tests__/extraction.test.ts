import { describe, it, expect, beforeEach } from 'vitest';
import { ed25519 } from '@noble/curves/ed25519.js';
import { blake3 } from '@noble/hashes/blake3.js';
import { bytesToHex } from '@noble/hashes/utils.js';

import { SocketObserver } from '../observer.js';
import { HandshakeParser } from '../handshake.js';
import type { HandshakeMessage } from '../handshake.js';
import { ReconciliationEngine } from '../reconciliation.js';
import { PrivacyFilter } from '../privacyFilter.js';
import { PeerRegistry } from '../registry.js';
import type { ObservedEndpoint } from '../observer.js';

// ── Helpers ───────────────────────────────────────────────────────────

function makeKeyPair() {
  const privKey = ed25519.utils.randomSecretKey();
  const pubKey = ed25519.getPublicKey(privKey);
  const nodeId = bytesToHex(blake3(pubKey));
  return { privKey, pubKey, pubKeyHex: bytesToHex(pubKey), nodeId };
}

function makeHandshake(
  overrides: Partial<HandshakeMessage> & { privKey?: Uint8Array } = {},
): HandshakeMessage {
  const { privKey, pubKey, pubKeyHex, nodeId } = makeKeyPair();
  const msg: HandshakeMessage = {
    nodeId: overrides.nodeId ?? nodeId,
    claimedLanIp: overrides.claimedLanIp ?? '192.168.1.50',
    claimedPublicIp: overrides.claimedPublicIp ?? '203.0.113.10',
    publicKey: overrides.publicKey ?? pubKeyHex,
    signature: '', // filled below
    timestamp: overrides.timestamp ?? Date.now(),
  };
  const payload = new TextEncoder().encode(
    `${msg.nodeId}:${msg.claimedLanIp}:${msg.claimedPublicIp}:${msg.timestamp}`,
  );
  const key = overrides.privKey ?? privKey;
  msg.signature = overrides.signature ?? bytesToHex(ed25519.sign(payload, key));
  return msg;
}

function fakeSocket(ip: string, port: number) {
  return { remoteAddress: ip, remotePort: port, once() {} } as any;
}

function observed(ip: string, port = 40000): ObservedEndpoint {
  return { ip, port, family: 'IPv4', observedAt: Date.now() };
}

// ── Tests ─────────────────────────────────────────────────────────────

describe('SocketObserver', () => {
  it('extracts endpoint from TCP socket', () => {
    const obs = new SocketObserver();
    const result = obs.observeTcp(fakeSocket('203.0.113.10', 5000));
    expect(result).not.toBeNull();
    expect(result!.ip).toBe('203.0.113.10');
    expect(result!.port).toBe(5000);
    expect(result!.family).toBe('IPv4');
  });

  it('strips ::ffff: prefix', () => {
    const obs = new SocketObserver();
    const result = obs.observeTcp(fakeSocket('::ffff:10.0.0.1', 3000));
    expect(result!.ip).toBe('10.0.0.1');
  });

  it('returns null for undefined remoteAddress', () => {
    const obs = new SocketObserver();
    expect(obs.observeTcp(fakeSocket(undefined as any, 3000))).toBeNull();
  });
});

describe('HandshakeParser', () => {
  it('verifies a valid handshake', () => {
    const parser = new HandshakeParser();
    const msg = makeHandshake();
    const result = parser.parse(msg);
    expect(result.verified).toBe(true);
  });

  it('rejects expired handshake', () => {
    const parser = new HandshakeParser();
    const msg = makeHandshake({ timestamp: Date.now() - 60_000 });
    const result = parser.parse(msg);
    expect(result.verified).toBe(false);
  });

  it('rejects tampered signature', () => {
    const parser = new HandshakeParser();
    const msg = makeHandshake({ signature: 'aa'.repeat(64) });
    const result = parser.parse(msg);
    expect(result.verified).toBe(false);
  });

  it('parses from Buffer', () => {
    const parser = new HandshakeParser();
    const msg = makeHandshake();
    const buf = Buffer.from(JSON.stringify(msg));
    const result = parser.parse(buf);
    expect(result.verified).toBe(true);
  });
});

describe('ReconciliationEngine', () => {
  let engine: ReconciliationEngine;
  beforeEach(() => { engine = new ReconciliationEngine(['1.2.3.4']); });

  it('direct connection: IPs match', () => {
    const parser = new HandshakeParser();
    const msg = makeHandshake({ claimedPublicIp: '203.0.113.10' });
    const claimed = parser.parse(msg);
    const obs = observed('203.0.113.10');
    const result = engine.reconcile(obs, claimed);
    expect(result.connectionType).toBe('direct');
    expect(result.confidence).toBe(95);
    expect(result.natDetected).toBe(false);
  });

  it('NAT connection: different observed IP, private LAN', () => {
    const parser = new HandshakeParser();
    const msg = makeHandshake({ claimedLanIp: '192.168.1.50', claimedPublicIp: '203.0.113.10' });
    const claimed = parser.parse(msg);
    const obs = observed('198.51.100.5');
    const result = engine.reconcile(obs, claimed);
    expect(result.connectionType).toBe('nat');
    expect(result.confidence).toBe(75);
    expect(result.natDetected).toBe(true);
  });

  it('spoofing: unverified signature', () => {
    const parser = new HandshakeParser();
    const msg = makeHandshake({ signature: 'bb'.repeat(64) });
    const claimed = parser.parse(msg);
    const obs = observed('203.0.113.10');
    const result = engine.reconcile(obs, claimed);
    expect(result.connectionType).toBe('suspicious');
    expect(result.confidence).toBe(0);
    expect(result.spoofingFlag).toBe(true);
  });

  it('spoofing: public LAN IP mismatch', () => {
    const parser = new HandshakeParser();
    const msg = makeHandshake({ claimedLanIp: '8.8.8.8', claimedPublicIp: '203.0.113.10' });
    const claimed = parser.parse(msg);
    const obs = observed('198.51.100.99');
    const result = engine.reconcile(obs, claimed);
    expect(result.connectionType).toBe('suspicious');
    expect(result.spoofingFlag).toBe(true);
    expect(result.confidence).toBe(20);
  });

  it('relay connection', () => {
    const parser = new HandshakeParser();
    const msg = makeHandshake({ claimedPublicIp: '203.0.113.10' });
    const claimed = parser.parse(msg);
    const obs = observed('1.2.3.4');
    const result = engine.reconcile(obs, claimed);
    expect(result.connectionType).toBe('relay');
    expect(result.confidence).toBe(60);
  });

  it('sybil detection: 5 nodeIds from same IP', () => {
    const parser = new HandshakeParser();
    const now = Date.now();
    for (let i = 0; i < 5; i++) {
      const msg = makeHandshake({ claimedPublicIp: '10.0.0.' + i });
      const claimed = parser.parse(msg);
      engine.reconcile({ ip: '198.51.100.1', port: 4000 + i, family: 'IPv4', observedAt: now }, claimed);
    }
    const msg = makeHandshake({ claimedPublicIp: '10.0.0.99' });
    const claimed = parser.parse(msg);
    const result = engine.reconcile(
      { ip: '198.51.100.1', port: 5000, family: 'IPv4', observedAt: now },
      claimed,
    );
    expect(result.flags).toContain('possible_sybil');
  });

  it('roaming detection: same nodeId from 3 IPs', () => {
    const { privKey, pubKeyHex, nodeId } = makeKeyPair();
    const parser = new HandshakeParser();
    const now = Date.now();
    const ips = ['198.51.100.1', '198.51.100.2', '198.51.100.3'];
    for (const ip of ips) {
      const msg = makeHandshake({
        nodeId,
        publicKey: pubKeyHex,
        privKey,
        claimedPublicIp: '203.0.113.10',
        claimedLanIp: '192.168.1.50',
        timestamp: now,
      });
      const claimed = parser.parse(msg);
      engine.reconcile({ ip, port: 4000, family: 'IPv4', observedAt: now }, claimed);
    }
    const msg = makeHandshake({
      nodeId,
      publicKey: pubKeyHex,
      privKey,
      claimedPublicIp: '203.0.113.10',
      claimedLanIp: '192.168.1.50',
      timestamp: now,
    });
    const claimed = parser.parse(msg);
    const result = engine.reconcile(
      { ip: '198.51.100.4', port: 4000, family: 'IPv4', observedAt: now },
      claimed,
    );
    expect(result.flags).toContain('roaming_or_compromised');
  });
});

describe('PrivacyFilter', () => {
  it('stealth: no raw IP, fingerprint is BLAKE3 hash', () => {
    const filter = new PrivacyFilter();
    const engine = new ReconciliationEngine();
    const parser = new HandshakeParser();
    const msg = makeHandshake({ claimedPublicIp: '203.0.113.10' });
    const claimed = parser.parse(msg);
    const obs = observed('203.0.113.10');
    const reconciled = engine.reconcile(obs, claimed);
    const record = filter.apply(reconciled, 'stealth');

    expect(record.endpoint).toBeUndefined();
    expect(record.ipFingerprint).not.toBe('redacted');
    const expectedHash = bytesToHex(blake3(new TextEncoder().encode('203.0.113.10')));
    expect(record.ipFingerprint).toBe(expectedHash);
    expect(record.tier).toBe('stealth');
  });

  it('phantom: redacted fingerprint, no endpoint', () => {
    const filter = new PrivacyFilter();
    const engine = new ReconciliationEngine();
    const parser = new HandshakeParser();
    const msg = makeHandshake({ claimedPublicIp: '203.0.113.10' });
    const claimed = parser.parse(msg);
    const obs = observed('203.0.113.10');
    const reconciled = engine.reconcile(obs, claimed);
    const record = filter.apply(reconciled, 'phantom');

    expect(record.ipFingerprint).toBe('redacted');
    expect(record.endpoint).toBeUndefined();
    expect(record.tier).toBe('phantom');
  });

  it('ghost: has endpoint and fingerprint', () => {
    const filter = new PrivacyFilter();
    const engine = new ReconciliationEngine();
    const parser = new HandshakeParser();
    const msg = makeHandshake({ claimedPublicIp: '203.0.113.10' });
    const claimed = parser.parse(msg);
    const obs = observed('203.0.113.10', 5000);
    const reconciled = engine.reconcile(obs, claimed);
    const record = filter.apply(reconciled, 'ghost');

    expect(record.endpoint).toBe('203.0.113.10:5000');
    expect(record.ipFingerprint).not.toBe('redacted');
    expect(record.tier).toBe('ghost');
  });
});

describe('PeerRegistry', () => {
  it('emits peer:added and peer:updated', () => {
    const registry = new PeerRegistry();
    const events: string[] = [];
    registry.on('peer:added', () => events.push('added'));
    registry.on('peer:updated', () => events.push('updated'));

    const record = {
      nodeId: 'abc',
      ipFingerprint: 'hash1',
      confidence: 90,
      tier: 'stealth' as const,
      expiresAt: Date.now() + 60_000,
    };
    registry.addPeer(record);
    registry.addPeer({ ...record, confidence: 80 });

    expect(events).toEqual(['added', 'updated']);
    registry.destroy();
  });

  it('cleanup removes expired peers', async () => {
    const registry = new PeerRegistry();
    const expired: string[] = [];
    registry.on('peer:expired', (e) => expired.push(e.nodeId));

    registry.addPeer({
      nodeId: 'temp',
      ipFingerprint: 'hash',
      confidence: 50,
      tier: 'ghost' as const,
      expiresAt: Date.now() - 1,
    });

    registry.cleanup();
    expect(registry.getPeer('temp')).toBeNull();
    expect(expired).toContain('temp');
    registry.destroy();
  });

  it('evicts lowest confidence at capacity', () => {
    const registry = new PeerRegistry();
    for (let i = 0; i < 1000; i++) {
      registry.addPeer({
        nodeId: `node-${i}`,
        ipFingerprint: `fp-${i}`,
        confidence: i + 10,
        tier: 'stealth' as const,
        expiresAt: Date.now() + 60_000,
      });
    }
    registry.addPeer({
      nodeId: 'overflow',
      ipFingerprint: 'fp-new',
      confidence: 99,
      tier: 'stealth' as const,
      expiresAt: Date.now() + 60_000,
    });

    expect(registry.size).toBe(1000);
    expect(registry.getPeer('node-0')).toBeNull();
    expect(registry.getPeer('overflow')).not.toBeNull();
    registry.destroy();
  });
});
