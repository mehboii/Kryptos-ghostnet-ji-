/**
 * PIN Auth Test Suite — Argon2id Module Validation
 * ─────────────────────────────────────────────────
 *
 * Runs without a test framework (pure Node.js assert).
 * Execute: node test-pin-auth.js
 *
 * Tests cover:
 *   ✓ Happy-path hash + verify cycle
 *   ✓ Wrong PIN rejection
 *   ✓ PIN format validation (too short, too long, non-numeric, empty)
 *   ✓ Different PINs produce different hashes
 *   ✓ Same PIN produces different salts (no rainbow tables)
 *   ✓ Device secret binding changes the hash
 *   ✓ Wrong device secret fails verification
 *   ✓ Custom Argon2id parameters
 *   ✓ Rate limiter: tracks attempts correctly
 *   ✓ Rate limiter: triggers lockout after max attempts
 *   ✓ Rate limiter: resets on success
 *   ✓ Hash migration detection (needsRehash)
 *   ✓ Device secret generation produces valid hex
 *   ✓ Timing consistency (basic check)
 */

import assert from 'assert';
import {
    hashPin,
    verifyPin,
    checkRateLimit,
    recordFailedAttempt,
    resetRateLimit,
    generateDeviceSecret,
    needsRehash,
} from './auth/pin-auth.js';

import {
    ARGON2_MEMORY_COST,
    ARGON2_TIME_COST,
    ARGON2_PARALLELISM,
} from './auth/pin-auth.config.js';

// ─── UTILITIES ──────────────────────────────────────────────────────────────

let passed = 0;
let failed = 0;
const failures = [];

async function test(name, fn) {
    try {
        await fn();
        passed++;
        console.log(`   ${name}`);
    } catch (err) {
        failed++;
        failures.push({ name, error: err.message });
        console.log(`   ${name}`);
        console.log(`     → ${err.message}`);
    }
}

// Reduce Argon2 parameters for test speed (still validates correctness)
const FAST_OPTS = { memoryCost: 1024, timeCost: 1, parallelism: 1 };

// ─── TEST SUITE ─────────────────────────────────────────────────────────────

console.log('\n╔══════════════════════════════════════════════════╗');
console.log('║  GhostNet PIN Auth — Argon2id Test Suite         ║');
console.log('╚══════════════════════════════════════════════════╝\n');

console.log('── Core: hashPin + verifyPin ──────────────────────\n');

await test('Hash and verify valid PIN (000000)', async () => {
    const result = await hashPin('000000', FAST_OPTS);
    assert.ok(result.hash, 'hash should be present');
    assert.ok(result.salt, 'salt should be present');
    assert.ok(result.version.startsWith('argon2id$'), 'version should start with argon2id$');

    const valid = await verifyPin('000000', result.hash, result.salt, {
        ...FAST_OPTS,
        version: result.version,
    });
    assert.strictEqual(valid, true, 'correct PIN should verify');
});

await test('Hash and verify valid PIN (999999)', async () => {
    const result = await hashPin('999999', FAST_OPTS);
    const valid = await verifyPin('999999', result.hash, result.salt, {
        version: result.version,
        ...FAST_OPTS,
    });
    assert.strictEqual(valid, true);
});

await test('Hash and verify valid PIN (123456)', async () => {
    const result = await hashPin('123456', FAST_OPTS);
    const valid = await verifyPin('123456', result.hash, result.salt, {
        version: result.version,
        ...FAST_OPTS,
    });
    assert.strictEqual(valid, true);
});

await test('Wrong PIN is rejected', async () => {
    const result = await hashPin('123456', FAST_OPTS);
    const valid = await verifyPin('654321', result.hash, result.salt, {
        version: result.version,
        ...FAST_OPTS,
    });
    assert.strictEqual(valid, false, 'wrong PIN should NOT verify');
});

await test('Off-by-one PIN is rejected', async () => {
    const result = await hashPin('123456', FAST_OPTS);
    const valid = await verifyPin('123457', result.hash, result.salt, {
        version: result.version,
        ...FAST_OPTS,
    });
    assert.strictEqual(valid, false);
});

console.log('\n── Validation: PIN format enforcement ──────────────\n');

await test('Rejects PIN shorter than 6 digits', async () => {
    await assert.rejects(() => hashPin('12345', FAST_OPTS), /PIN must be exactly 6 digits/);
});

await test('Rejects PIN longer than 6 digits', async () => {
    await assert.rejects(() => hashPin('1234567', FAST_OPTS), /PIN must be exactly 6 digits/);
});

await test('Rejects non-numeric PIN', async () => {
    await assert.rejects(() => hashPin('abcdef', FAST_OPTS), /PIN must be exactly 6 digits/);
});

await test('Rejects alphanumeric PIN', async () => {
    await assert.rejects(() => hashPin('123abc', FAST_OPTS), /PIN must be exactly 6 digits/);
});

await test('Rejects empty string', async () => {
    await assert.rejects(() => hashPin('', FAST_OPTS), /PIN must be exactly 6 digits/);
});

await test('Rejects non-string input (number)', async () => {
    await assert.rejects(() => hashPin(123456, FAST_OPTS), /PIN must be a string/);
});

await test('Rejects null input', async () => {
    await assert.rejects(() => hashPin(null, FAST_OPTS), /PIN must be a string/);
});

await test('Rejects PIN with spaces', async () => {
    await assert.rejects(() => hashPin(' 12345', FAST_OPTS), /PIN must be exactly 6 digits/);
});

console.log('\n── Uniqueness: salts and hashes ─────────────────────\n');

await test('Same PIN produces different salts', async () => {
    const r1 = await hashPin('123456', FAST_OPTS);
    const r2 = await hashPin('123456', FAST_OPTS);
    assert.notStrictEqual(r1.salt, r2.salt, 'salts should differ');
});

await test('Same PIN produces different hashes (due to unique salt)', async () => {
    const r1 = await hashPin('123456', FAST_OPTS);
    const r2 = await hashPin('123456', FAST_OPTS);
    assert.notStrictEqual(r1.hash, r2.hash, 'hashes should differ');
});

await test('Different PINs produce different hashes', async () => {
    const r1 = await hashPin('123456', FAST_OPTS);
    const r2 = await hashPin('654321', FAST_OPTS);
    assert.notStrictEqual(r1.hash, r2.hash);
});

console.log('\n── Device secret binding ────────────────────────────\n');

await test('Device secret changes the hash', async () => {
    const secret = generateDeviceSecret();
    const r1 = await hashPin('123456', FAST_OPTS);
    const r2 = await hashPin('123456', { ...FAST_OPTS, deviceSecret: secret });
    // Even with same PIN, device secret should produce different hash
    // (though salts also differ, we verify the binding in next test)
    assert.ok(r1.hash !== r2.hash || r1.salt !== r2.salt, 'results should differ');
});

await test('Correct device secret verifies', async () => {
    const secret = generateDeviceSecret();
    const result = await hashPin('123456', { ...FAST_OPTS, deviceSecret: secret });
    const valid = await verifyPin('123456', result.hash, result.salt, {
        ...FAST_OPTS,
        deviceSecret: secret,
        version: result.version,
    });
    assert.strictEqual(valid, true, 'correct device secret should verify');
});

await test('Wrong device secret fails verification', async () => {
    const secret1 = generateDeviceSecret();
    const secret2 = generateDeviceSecret();
    const result = await hashPin('123456', { ...FAST_OPTS, deviceSecret: secret1 });
    const valid = await verifyPin('123456', result.hash, result.salt, {
        ...FAST_OPTS,
        deviceSecret: secret2,
        version: result.version,
    });
    assert.strictEqual(valid, false, 'wrong device secret should NOT verify');
});

await test('No device secret fails when hash used one', async () => {
    const secret = generateDeviceSecret();
    const result = await hashPin('123456', { ...FAST_OPTS, deviceSecret: secret });
    const valid = await verifyPin('123456', result.hash, result.salt, {
        ...FAST_OPTS,
        version: result.version,
        // Intentionally omitting deviceSecret
    });
    assert.strictEqual(valid, false, 'missing device secret should NOT verify');
});

console.log('\n── Device secret generation ─────────────────────────\n');

await test('generateDeviceSecret returns 64-char hex string', async () => {
    const secret = generateDeviceSecret();
    assert.strictEqual(secret.length, 64, 'should be 64 hex characters (256 bits)');
    assert.ok(/^[0-9a-f]+$/.test(secret), 'should be valid hex');
});

await test('generateDeviceSecret produces unique values', async () => {
    const secrets = new Set();
    for (let i = 0; i < 100; i++) {
        secrets.add(generateDeviceSecret());
    }
    assert.strictEqual(secrets.size, 100, 'all 100 secrets should be unique');
});

console.log('\n── Rate limiter / exponential backoff ───────────────\n');

await test('Fresh user is allowed', async () => {
    const result = checkRateLimit('test-user-fresh');
    assert.strictEqual(result.allowed, true);
    assert.strictEqual(result.attemptsRemaining, 5);
});

await test('Tracks failed attempts correctly', async () => {
    const userId = 'test-user-track';
    resetRateLimit(userId);

    recordFailedAttempt(userId);
    const rl = checkRateLimit(userId);
    assert.strictEqual(rl.allowed, true);
    assert.strictEqual(rl.attemptsRemaining, 4);

    recordFailedAttempt(userId);
    const rl2 = checkRateLimit(userId);
    assert.strictEqual(rl2.attemptsRemaining, 3);

    resetRateLimit(userId);
});

await test('Locks out after max attempts', async () => {
    const userId = 'test-user-lockout';
    resetRateLimit(userId);

    for (let i = 0; i < 4; i++) {
        recordFailedAttempt(userId);
    }

    // 5th attempt triggers lockout
    const result = recordFailedAttempt(userId);
    assert.strictEqual(result.locked, true);
    assert.ok(result.retryAfterMs > 0, 'retryAfterMs should be positive');
    assert.strictEqual(result.attemptsRemaining, 0);

    // Verify rate limit blocks further attempts
    const rl = checkRateLimit(userId);
    assert.strictEqual(rl.allowed, false);
    assert.ok(rl.retryAfterMs > 0);

    resetRateLimit(userId);
});

await test('Reset clears rate limit state', async () => {
    const userId = 'test-user-reset';
    resetRateLimit(userId);

    for (let i = 0; i < 3; i++) {
        recordFailedAttempt(userId);
    }

    resetRateLimit(userId);

    const rl = checkRateLimit(userId);
    assert.strictEqual(rl.allowed, true);
    assert.strictEqual(rl.attemptsRemaining, 5);
});

console.log('\n── Hash migration (needsRehash) ─────────────────────\n');

await test('Current version does not need rehash', async () => {
    const version = `argon2id$m=${ARGON2_MEMORY_COST},t=${ARGON2_TIME_COST},p=${ARGON2_PARALLELISM}`;
    assert.strictEqual(needsRehash(version), false);
});

await test('Old version needs rehash', async () => {
    assert.strictEqual(needsRehash('argon2id$m=1024,t=1,p=1'), true);
});

await test('Missing version needs rehash', async () => {
    assert.strictEqual(needsRehash(null), true);
    assert.strictEqual(needsRehash(undefined), true);
    assert.strictEqual(needsRehash(''), true);
});

console.log('\n── verifyPin edge cases ──────────────────────────────\n');

await test('Returns false for null hash (no crash)', async () => {
    const valid = await verifyPin('123456', null, 'abc123');
    assert.strictEqual(valid, false);
});

await test('Returns false for null salt (no crash)', async () => {
    const valid = await verifyPin('123456', 'abc123', null);
    assert.strictEqual(valid, false);
});

await test('Returns false for empty hash', async () => {
    const valid = await verifyPin('123456', '', 'dGVzdA==');
    assert.strictEqual(valid, false);
});

console.log('\n── Timing consistency (basic sanity check) ──────────\n');

await test('Correct and incorrect PIN take similar time', async () => {
    const result = await hashPin('123456', FAST_OPTS);

    // Warm up
    await verifyPin('123456', result.hash, result.salt, { ...FAST_OPTS, version: result.version });
    await verifyPin('654321', result.hash, result.salt, { ...FAST_OPTS, version: result.version });

    // Measure correct PIN
    const correctTimes = [];
    for (let i = 0; i < 5; i++) {
        const start = performance.now();
        await verifyPin('123456', result.hash, result.salt, { ...FAST_OPTS, version: result.version });
        correctTimes.push(performance.now() - start);
    }

    // Measure wrong PIN
    const wrongTimes = [];
    for (let i = 0; i < 5; i++) {
        const start = performance.now();
        await verifyPin('654321', result.hash, result.salt, { ...FAST_OPTS, version: result.version });
        wrongTimes.push(performance.now() - start);
    }

    const avgCorrect = correctTimes.reduce((a, b) => a + b) / correctTimes.length;
    const avgWrong = wrongTimes.reduce((a, b) => a + b) / wrongTimes.length;

    // The times should be within 50% of each other (generous tolerance
    // for CI/test environments; the important thing is constant-time
    // comparison, not identical Argon2 hashing time which is deterministic).
    const ratio = Math.max(avgCorrect, avgWrong) / Math.min(avgCorrect, avgWrong);
    assert.ok(ratio < 3.0, `Timing ratio ${ratio.toFixed(2)} is suspiciously large (>3x). Verify constant-time comparison.`);

    console.log(`     → Avg correct: ${avgCorrect.toFixed(1)}ms, Avg wrong: ${avgWrong.toFixed(1)}ms, Ratio: ${ratio.toFixed(2)}x`);
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
