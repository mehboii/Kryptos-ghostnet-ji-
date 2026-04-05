/**
 * BLAKE3 Node Identity — Test Suite
 * ──────────────────────────────────
 *
 * Execute: node test-node-identity.js
 *
 * Tests cover:
 *   ✓ Key pair generation produces valid structure
 *   ✓ Node ID is deterministic (same key → same ID)
 *   ✓ Different keys produce different node IDs
 *   ✓ Node ID format validation (prefix + 64 hex chars)
 *   ✓ Node ID does NOT reveal the public key (one-way)
 *   ✓ Private key is NOT embedded in node ID
 *   ✓ Signing and verification round-trip
 *   ✓ Wrong key fails verification
 *   ✓ Tampered message fails verification
 *   ✓ Identity binding: verifyNodeId()
 *   ✓ Spoofed node ID detection
 *   ✓ Input validation (bad key formats)
 *   ✓ Collision resistance (bulk generation)
 *   ✓ Performance benchmark
 *   ✓ Hex and Uint8Array input interop
 */

import assert from 'assert';
import {
    generateNodeIdentity,
    getNodeId,
    signMessage,
    verifySignature,
    verifyNodeId,
    isValidNodeIdFormat,
    shortenNodeId,
    benchmarkNodeId,
    NODE_ID_PREFIX,
} from './auth/node-identity-blake3.js';

// ─── UTILITIES ──────────────────────────────────────────────────────────────

let passed = 0;
let failed = 0;
const failures = [];

async function test(name, fn) {
    try {
        await fn();
        passed++;
        console.log(`  ✅ ${name}`);
    } catch (err) {
        failed++;
        failures.push({ name, error: err.message });
        console.log(`  ❌ ${name}`);
        console.log(`     → ${err.message}`);
    }
}

// ─── TEST SUITE ─────────────────────────────────────────────────────────────

console.log('\n╔══════════════════════════════════════════════════╗');
console.log('║  GhostNet BLAKE3 Node Identity — Test Suite      ║');
console.log('╚══════════════════════════════════════════════════╝\n');

console.log('── Key pair generation ─────────────────────────────\n');

await test('generateNodeIdentity returns complete structure', async () => {
    const identity = generateNodeIdentity();
    assert.ok(identity.nodeId, 'nodeId present');
    assert.ok(identity.publicKey, 'publicKey present');
    assert.ok(identity.privateKey, 'privateKey present');
    assert.ok(identity.publicKeyBytes instanceof Uint8Array, 'publicKeyBytes is Uint8Array');
    assert.ok(identity.privateKeyBytes instanceof Uint8Array, 'privateKeyBytes is Uint8Array');
    assert.strictEqual(identity.publicKeyBytes.length, 32, 'publicKey is 32 bytes');
    assert.strictEqual(identity.privateKeyBytes.length, 32, 'privateKey is 32 bytes');
    assert.strictEqual(identity.algorithm, 'Ed25519');
    assert.strictEqual(identity.hashFunction, 'BLAKE3');
    assert.ok(identity.createdAt > 0, 'createdAt is positive timestamp');
});

await test('Public key hex is 64 characters', async () => {
    const identity = generateNodeIdentity();
    assert.strictEqual(identity.publicKey.length, 64);
    assert.ok(/^[0-9a-f]{64}$/.test(identity.publicKey));
});

await test('Private key hex is 64 characters', async () => {
    const identity = generateNodeIdentity();
    assert.strictEqual(identity.privateKey.length, 64);
    assert.ok(/^[0-9a-f]{64}$/.test(identity.privateKey));
});

await test('Each generation produces unique keys', async () => {
    const ids = new Set();
    for (let i = 0; i < 50; i++) {
        ids.add(generateNodeIdentity().nodeId);
    }
    assert.strictEqual(ids.size, 50, 'all 50 node IDs should be unique');
});

console.log('\n── Node ID derivation (getNodeId) ───────────────────\n');

await test('Node ID is deterministic (same key → same ID)', async () => {
    const identity = generateNodeIdentity();
    const id1 = getNodeId(identity.publicKeyBytes);
    const id2 = getNodeId(identity.publicKeyBytes);
    const id3 = getNodeId(identity.publicKey); // hex input
    assert.strictEqual(id1, id2, 'bytes → same ID');
    assert.strictEqual(id1, id3, 'hex → same ID');
    assert.strictEqual(id1, identity.nodeId, 'matches generateNodeIdentity output');
});

await test('Different keys produce different node IDs', async () => {
    const a = generateNodeIdentity();
    const b = generateNodeIdentity();
    assert.notStrictEqual(a.nodeId, b.nodeId);
    assert.notStrictEqual(a.publicKey, b.publicKey);
});

await test('Node ID has correct format: gn_ + 64 hex chars', async () => {
    const identity = generateNodeIdentity();
    assert.ok(identity.nodeId.startsWith(NODE_ID_PREFIX), 'starts with gn_');
    assert.strictEqual(identity.nodeId.length, 3 + 64, 'total length = 67');
    assert.ok(isValidNodeIdFormat(identity.nodeId), 'passes format validation');
});

await test('Accepts hex string input', async () => {
    const identity = generateNodeIdentity();
    const fromHex = getNodeId(identity.publicKey);
    const fromBytes = getNodeId(identity.publicKeyBytes);
    assert.strictEqual(fromHex, fromBytes, 'hex and bytes produce same ID');
});

console.log('\n── Security: one-way and no private key leakage ─────\n');

await test('Node ID does not contain the public key', async () => {
    const identity = generateNodeIdentity();
    const idHex = identity.nodeId.slice(NODE_ID_PREFIX.length);
    assert.notStrictEqual(idHex, identity.publicKey, 'node ID is not the raw public key');
});

await test('Node ID does not contain the private key', async () => {
    const identity = generateNodeIdentity();
    const idHex = identity.nodeId.slice(NODE_ID_PREFIX.length);
    assert.ok(!idHex.includes(identity.privateKey), 'private key not in node ID');
    assert.ok(!identity.nodeId.includes(identity.privateKey), 'private key not in full ID');
});

await test('Cannot reverse node ID to public key', async () => {
    // This is a design invariant check — BLAKE3 is a one-way function.
    // We can only verify the structural impossibility here.
    const identity = generateNodeIdentity();
    const idHex = identity.nodeId.slice(NODE_ID_PREFIX.length);
    // The hash output (32 bytes) has no algebraic relationship to the
    // 32-byte public key input. We verify they differ as a sanity check.
    assert.notStrictEqual(idHex, identity.publicKey);
});

console.log('\n── Signing and verification ──────────────────────────\n');

await test('Sign and verify round-trip', async () => {
    const identity = generateNodeIdentity();
    const message = 'Hello, GhostNet mesh!';
    const signature = signMessage(message, identity.privateKey);

    assert.ok(typeof signature === 'string', 'signature is hex string');
    assert.strictEqual(signature.length, 128, 'Ed25519 signature is 64 bytes (128 hex)');

    const valid = verifySignature(message, signature, identity.publicKey);
    assert.strictEqual(valid, true, 'signature should verify');
});

await test('Wrong private key → valid signature but wrong signer', async () => {
    const alice = generateNodeIdentity();
    const bob = generateNodeIdentity();
    const message = 'I am Alice';
    const signature = signMessage(message, alice.privateKey);

    // Verify with Alice's key → true
    assert.strictEqual(verifySignature(message, signature, alice.publicKey), true);
    // Verify with Bob's key → false
    assert.strictEqual(verifySignature(message, signature, bob.publicKey), false);
});

await test('Tampered message fails verification', async () => {
    const identity = generateNodeIdentity();
    const signature = signMessage('original message', identity.privateKey);
    const valid = verifySignature('tampered message', signature, identity.publicKey);
    assert.strictEqual(valid, false);
});

await test('Empty message can be signed and verified', async () => {
    const identity = generateNodeIdentity();
    const signature = signMessage('', identity.privateKey);
    assert.strictEqual(verifySignature('', signature, identity.publicKey), true);
    assert.strictEqual(verifySignature('x', signature, identity.publicKey), false);
});

await test('Binary message (Uint8Array) sign/verify', async () => {
    const identity = generateNodeIdentity();
    const msg = new Uint8Array([0x01, 0x02, 0x03, 0xff]);
    const signature = signMessage(msg, identity.privateKey);
    assert.strictEqual(verifySignature(msg, signature, identity.publicKey), true);
});

console.log('\n── Identity binding (verifyNodeId) ───────────────────\n');

await test('verifyNodeId confirms correct binding', async () => {
    const identity = generateNodeIdentity();
    assert.strictEqual(verifyNodeId(identity.nodeId, identity.publicKey), true);
    assert.strictEqual(verifyNodeId(identity.nodeId, identity.publicKeyBytes), true);
});

await test('verifyNodeId detects spoofed node ID', async () => {
    const alice = generateNodeIdentity();
    const bob = generateNodeIdentity();
    // Bob claims to be Alice
    assert.strictEqual(verifyNodeId(alice.nodeId, bob.publicKey), false);
});

await test('verifyNodeId rejects garbage input', async () => {
    assert.strictEqual(verifyNodeId('gn_invalid', 'not-a-key'), false);
    assert.strictEqual(verifyNodeId('', ''), false);
});

console.log('\n── Format validation ────────────────────────────────\n');

await test('isValidNodeIdFormat accepts valid IDs', async () => {
    const identity = generateNodeIdentity();
    assert.strictEqual(isValidNodeIdFormat(identity.nodeId), true);
});

await test('isValidNodeIdFormat rejects invalid formats', async () => {
    assert.strictEqual(isValidNodeIdFormat(''), false);
    assert.strictEqual(isValidNodeIdFormat('gn_'), false);
    assert.strictEqual(isValidNodeIdFormat('gn_abc'), false);
    assert.strictEqual(isValidNodeIdFormat('xx_' + 'a'.repeat(64)), false);
    assert.strictEqual(isValidNodeIdFormat('gn_' + 'g'.repeat(64)), false); // non-hex
    assert.strictEqual(isValidNodeIdFormat(null), false);
    assert.strictEqual(isValidNodeIdFormat(42), false);
});

await test('shortenNodeId produces readable output', async () => {
    const identity = generateNodeIdentity();
    const short = shortenNodeId(identity.nodeId);
    assert.ok(short.startsWith('gn_'), 'starts with prefix');
    assert.ok(short.includes('…'), 'contains ellipsis');
    assert.ok(short.length < identity.nodeId.length, 'shorter than original');
});

console.log('\n── Input validation edge cases ──────────────────────\n');

await test('getNodeId rejects wrong-length hex', async () => {
    assert.throws(() => getNodeId('abcdef'), /64 characters/);
});

await test('getNodeId rejects wrong-length bytes', async () => {
    assert.throws(() => getNodeId(new Uint8Array(16)), /32 bytes/);
});

await test('getNodeId rejects non-hex string', async () => {
    assert.throws(() => getNodeId('zz' + 'a'.repeat(62)), /64 characters/);
});

await test('getNodeId rejects invalid types', async () => {
    assert.throws(() => getNodeId(42), /Uint8Array or 64-char hex/);
    assert.throws(() => getNodeId(null), /Uint8Array or 64-char hex/);
});

await test('verifySignature returns false for corrupt input', async () => {
    assert.strictEqual(verifySignature('msg', 'bad-sig', 'bad-key'), false);
});

console.log('\n── Collision resistance (bulk generation) ────────────\n');

await test('1000 unique identities with no collisions', async () => {
    const nodeIds = new Set();
    const publicKeys = new Set();
    for (let i = 0; i < 1000; i++) {
        const identity = generateNodeIdentity();
        nodeIds.add(identity.nodeId);
        publicKeys.add(identity.publicKey);
    }
    assert.strictEqual(nodeIds.size, 1000, 'all node IDs unique');
    assert.strictEqual(publicKeys.size, 1000, 'all public keys unique');
});

console.log('\n── Performance benchmark ─────────────────────────────\n');

await test('BLAKE3 node ID derivation benchmark (10,000 iterations)', async () => {
    const result = benchmarkNodeId(10000);
    console.log(`     → Total: ${result.totalMs}ms | Avg: ${result.avgMicroseconds}μs | ${result.opsPerSecond.toLocaleString()} ops/sec`);
    // BLAKE3 should be under 10μs per derivation — generous threshold
    assert.ok(result.avgMicroseconds < 100, `avg ${result.avgMicroseconds}μs is too slow (threshold: 100μs)`);
});

await test('Full identity generation benchmark (1,000 iterations)', async () => {
    const start = performance.now();
    for (let i = 0; i < 1000; i++) {
        generateNodeIdentity();
    }
    const totalMs = performance.now() - start;
    const avgMs = totalMs / 1000;
    console.log(`     → Total: ${totalMs.toFixed(1)}ms | Avg: ${avgMs.toFixed(2)}ms/identity | ${Math.round(1000 / (totalMs / 1000)).toLocaleString()} identities/sec`);
    // Key generation + BLAKE3 should complete in under 5ms per identity
    assert.ok(avgMs < 10, `avg ${avgMs.toFixed(2)}ms is too slow (threshold: 10ms)`);
});

// ─── SUMMARY ────────────────────────────────────────────────────────────────

console.log('\n══════════════════════════════════════════════════════');
console.log(`  Results: ${passed} passed, ${failed} failed`);
if (failures.length > 0) {
    console.log('\n  Failures:');
    failures.forEach(f => console.log(`    ✗ ${f.name}: ${f.error}`));
}
console.log('══════════════════════════════════════════════════════\n');

process.exit(failed > 0 ? 1 : 0);
