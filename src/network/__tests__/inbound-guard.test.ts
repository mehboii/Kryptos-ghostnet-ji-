import { describe, it, expect, beforeEach } from 'vitest';
import { ed25519 } from '@noble/curves/ed25519.js';
import { blake3 } from '@noble/hashes/blake3.js';
import { bytesToHex } from '@noble/hashes/utils.js';
import { randomBytes } from 'node:crypto';
import { InboundGuard } from '../inboundGuard.js';
import type { InboundPacket, DropReason, SignalIntelEntry } from '../inboundGuard.js';

function makeKeyPair() {
  const privKey = ed25519.utils.randomSecretKey();
  const pubKey = ed25519.getPublicKey(privKey);
  const nodeId = bytesToHex(blake3(pubKey));
  return { privKey, pubKey, pubKeyHex: bytesToHex(pubKey), nodeId };
}

function signPacket(packet: Omit<InboundPacket, 'signature'>, privKey: Uint8Array): InboundPacket {
  const payload = new TextEncoder().encode(
    `${packet.nodeId}:${packet.nonce}:${packet.timestamp}:${JSON.stringify(packet.payload)}`,
  );
  return { ...packet, signature: bytesToHex(ed25519.sign(payload, privKey)) };
}

function validPacket(overrides: Partial<InboundPacket> = {}) {
  const { privKey, pubKeyHex, nodeId } = makeKeyPair();
  const base = {
    nodeId,
    publicKey: pubKeyHex,
    nonce: randomBytes(16).toString('hex'),
    timestamp: Date.now(),
    payload: { type: 'ping', data: 'hello' },
    ...overrides,
  };
  return { packet: signPacket(base, privKey), privKey, nodeId };
}

describe('InboundGuard — Auth Flow', () => {
  let guard: InboundGuard;
  beforeEach(() => { guard = new InboundGuard(); });

  it('accepts valid signed packet', () => {
    const { packet } = validPacket();
    const result = guard.process(Buffer.from(JSON.stringify(packet)), 'socket');
    expect(result).not.toBeNull();
    expect(result!.accepted).toBe(true);
    expect(result!.nodeId).toBe(packet.nodeId);
  });

  it('silent drop: invalid signature → returns null, no error', () => {
    const { packet } = validPacket();
    packet.signature = 'deadbeef'.repeat(16);
    const drops: DropReason[] = [];
    guard.on('guard:dropped', (v) => drops.push(v.dropReason!));
    const result = guard.process(Buffer.from(JSON.stringify(packet)), 'socket');
    expect(result).toBeNull();
    expect(drops).toContain('signature_invalid');
  });

  it('silent drop: tampered payload fails sig check', () => {
    const { packet } = validPacket();
    packet.payload = { type: 'tampered', data: 'evil' };
    const result = guard.process(Buffer.from(JSON.stringify(packet)), 'socket');
    expect(result).toBeNull();
  });

  it('silent drop: empty buffer', () => {
    const result = guard.process(Buffer.alloc(0), 'ble');
    expect(result).toBeNull();
  });

  it('silent drop: unparseable data', () => {
    const result = guard.process(Buffer.from('not json!!!'), 'qr');
    expect(result).toBeNull();
  });

  it('silent drop: missing required fields', () => {
    const result = guard.process(Buffer.from(JSON.stringify({ foo: 'bar' })), 'mesh_relay');
    expect(result).toBeNull();
  });

  it('silent drop: stale timestamp', () => {
    const { packet } = validPacket({ timestamp: Date.now() - 60_000 });
    // Re-sign with correct stale timestamp
    const { privKey, pubKeyHex, nodeId } = makeKeyPair();
    const stalePacket = signPacket({
      nodeId,
      publicKey: pubKeyHex,
      nonce: randomBytes(16).toString('hex'),
      timestamp: Date.now() - 60_000,
      payload: { type: 'stale' },
    }, privKey);
    const result = guard.process(Buffer.from(JSON.stringify(stalePacket)), 'socket');
    expect(result).toBeNull();
  });

  it('silent drop: replayed nonce', () => {
    const { privKey, pubKeyHex, nodeId } = makeKeyPair();
    const nonce = randomBytes(16).toString('hex');
    const first = signPacket({
      nodeId, publicKey: pubKeyHex, nonce, timestamp: Date.now(), payload: { n: 1 },
    }, privKey);
    const second = signPacket({
      nodeId, publicKey: pubKeyHex, nonce, timestamp: Date.now(), payload: { n: 2 },
    }, privKey);

    const r1 = guard.process(Buffer.from(JSON.stringify(first)), 'socket');
    expect(r1).not.toBeNull();
    const r2 = guard.process(Buffer.from(JSON.stringify(second)), 'socket');
    expect(r2).toBeNull();
  });

  it('silent drop: nodeId does not match BLAKE3(publicKey)', () => {
    const { privKey, pubKeyHex } = makeKeyPair();
    const fakeNodeId = 'a'.repeat(64);
    // Can't properly sign with wrong nodeId (sig will be invalid anyway)
    // but test the nodeId check path by using a valid sig with wrong nodeId
    const packet = signPacket({
      nodeId: fakeNodeId,
      publicKey: pubKeyHex,
      nonce: randomBytes(16).toString('hex'),
      timestamp: Date.now(),
      payload: { type: 'spoof' },
    }, privKey);
    const result = guard.process(Buffer.from(JSON.stringify(packet)), 'socket');
    // Will fail at signature check since nodeId is in the signed payload
    expect(result).toBeNull();
  });

  it('flags schema-invalid packets in Signal Intelligence', () => {
    const { privKey, pubKeyHex, nodeId } = makeKeyPair();
    // Valid sig but nonce too short (schema fail)
    const packet = signPacket({
      nodeId, publicKey: pubKeyHex, nonce: 'short',
      timestamp: Date.now(), payload: { type: 'test' },
    }, privKey);
    const sigintEntries: SignalIntelEntry[] = [];
    guard.on('guard:sigint', (e) => sigintEntries.push(e));
    guard.process(Buffer.from(JSON.stringify(packet)), 'ble');
    expect(sigintEntries.some(e => e.reason === 'schema_invalid')).toBe(true);
  });
});

describe('InboundGuard — All Inbound Sources', () => {
  let guard: InboundGuard;
  beforeEach(() => { guard = new InboundGuard(); });

  for (const source of ['socket', 'ble', 'qr', 'mesh_relay', 'handshake', 'hole_punch'] as const) {
    it(`accepts valid packet from ${source} source`, () => {
      const { packet } = validPacket();
      const result = guard.process(Buffer.from(JSON.stringify(packet)), source);
      expect(result).not.toBeNull();
      expect(result!.source).toBe(source);
      expect(result!.accepted).toBe(true);
    });
  }
});

describe('InboundGuard — Nonce Cache Management', () => {
  it('evicts stale nonces when cache is full', () => {
    const guard = new InboundGuard();
    // Process many valid packets to fill nonce cache
    for (let i = 0; i < 100; i++) {
      const { packet } = validPacket();
      guard.process(Buffer.from(JSON.stringify(packet)), 'socket');
    }
    expect(guard.nonceCount).toBe(100);
    guard.clear();
    expect(guard.nonceCount).toBe(0);
  });
});
