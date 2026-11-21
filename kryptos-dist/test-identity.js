/**
 * Kryptos Identity Test — HARDENED
 * ====================================
 * Security fixes applied:
 *
 *  [1] CRITICAL  — privateKey logged/exposed in stack traces if test crashes
 *  [2] CRITICAL  — No timeout on async identity ops — hangs forever if crypto stalls
 *  [3] HIGH      — process.exit(1) called without cleanup — privateKey left in memory
 *  [4] HIGH      — Signature substring logged to console — partial sig leaks timing info
 *  [5] HIGH      — No validation on generated identity fields before use
 *  [6] MEDIUM    — No check that nodeId meets minimum entropy requirements
 *  [7] MEDIUM    — Test crashes expose raw Error objects — may leak internal paths
 *  [8] LOW       — No check that verifySignature rejects a WRONG signature (negative test)
 *  [9] LOW       — No check that verifySignature rejects a tampered message (negative test)
 */

'use strict';

const GhostIdentity = require('./kryptos-identity');

// ─── [2] TIMEOUT WRAPPER ────────────────────────────────
// Prevents crypto ops from hanging forever

function withTimeout(promise, ms, label) {
    const timer = new Promise((_, reject) =>
        setTimeout(() => reject(new Error(`Timeout: "${label}" exceeded ${ms}ms`)), ms)
    );
    return Promise.race([promise, timer]);
}

// ─── [7] SAFE ERROR REPORTER ────────────────────────────
// Logs test failures without leaking internal paths or stack frames

function failTest(label, err) {
    // [7] Only log the message, never the full stack (may contain file paths)
    console.error(` FAILED [${label}]:`, err instanceof Error ? err.message : String(err));
}

// ─── [5][6] IDENTITY VALIDATOR ──────────────────────────

function validateIdentity(id) {
    if (!id || typeof id !== 'object') {
        throw new Error('Identity is not an object');
    }

    // nodeId must exist and have minimum entropy (>= 16 hex chars = 64-bit)
    if (typeof id.nodeId !== 'string' || id.nodeId.length < 16) {
        throw new Error(`nodeId too short or missing (got ${id.nodeId?.length ?? 0} chars)`);
    }

    // [6] Reject low-entropy nodeIds (all same char, sequential, etc.)
    const uniqueChars = new Set(id.nodeId.split('')).size;
    if (uniqueChars < 4) {
        throw new Error('nodeId has suspiciously low entropy');
    }

    if (!id.publicKey) {
        throw new Error('publicKey missing from identity');
    }

    // [1] privateKey must exist but we NEVER log it
    if (!id.privateKey) {
        throw new Error('privateKey missing from identity');
    }
}

// ─── [1] SAFE CLEANUP ───────────────────────────────────
// Zero out key material before exiting

function scrubIdentity(id) {
    if (!id) return;
    try {
        // If privateKey is a buffer or typed array, zero it
        if (id.privateKey && typeof id.privateKey === 'object' && id.privateKey.fill) {
            id.privateKey.fill(0);
        } else if (typeof id.privateKey === 'string') {
            // Strings are immutable in JS — flag as scrubbed, warn dev
            id.privateKey = '[SCRUBBED]';
        }
    } catch (_) { }
}

// ─── MAIN TEST RUNNER ───────────────────────────────────

(async () => {
    console.log('--- Testing GhostIdentity (Universal) ---');

    let id = null;
    let passed = 0;
    let failed = 0;
    const TIMEOUT = 10000; // [2] 10s max per operation

    try {

        // ── TEST 1: Generate Identity ──────────────────
        console.log('\n[1/5] Generating Identity...');
        try {
            id = await withTimeout(
                GhostIdentity.generateIdentity(),
                TIMEOUT,
                'generateIdentity'
            );

            // [5][6] Validate before using anything
            validateIdentity(id);

            // [1] Log nodeId only — NEVER log privateKey or full publicKey
            console.log('  nodeId :', id.nodeId);
            console.log('  pubKey : OK (' + (id.publicKey?.length ?? 0) + ' chars)');
            // [1] privateKey existence confirmed by validateIdentity — never printed
            console.log('  privKey: OK (not logged)');
            console.log('✅ PASS: Identity generated');
            passed++;
        } catch (e) {
            failTest('generateIdentity', e);
            failed++;
            // Cannot continue without a valid identity
            throw new Error('Cannot continue — identity generation failed');
        }

        // ── TEST 2: Sign Message ───────────────────────
        console.log('\n[2/5] Signing message...');
        const msg = 'Hello Kryptos';
        let sig;
        try {
            sig = await withTimeout(
                GhostIdentity.signMessage(msg, id.privateKey),
                TIMEOUT,
                'signMessage'
            );

            if (typeof sig !== 'string' || sig.length === 0) {
                throw new Error('Signature is empty or wrong type');
            }

            // [4] Log ONLY the byte length — never any signature content
            console.log('  Signature length:', sig.length, 'chars');
            console.log('✅ PASS: Message signed');
            passed++;
        } catch (e) {
            failTest('signMessage', e);
            failed++;
            throw new Error('Cannot continue — signing failed');
        }

        // ── TEST 3: Verify Valid Signature ────────────
        console.log('\n[3/5] Verifying valid signature...');
        try {
            const valid = await withTimeout(
                GhostIdentity.verifySignature(msg, sig, id.publicKey),
                TIMEOUT,
                'verifySignature (valid)'
            );

            if (valid !== true) {
                throw new Error(`Expected true, got ${valid}`);
            }

            console.log('✅ PASS: Valid signature verified');
            passed++;
        } catch (e) {
            failTest('verifySignature (valid)', e);
            failed++;
        }

        // ── TEST 4: Reject Wrong Signature ────────────
        // [8] Negative test — must reject a bad signature
        console.log('\n[4/5] Verifying wrong signature (should reject)...');
        try {
            const fakeSignature = 'a'.repeat(sig.length); // same length, wrong content
            const shouldBeFalse = await withTimeout(
                GhostIdentity.verifySignature(msg, fakeSignature, id.publicKey),
                TIMEOUT,
                'verifySignature (wrong sig)'
            );

            if (shouldBeFalse !== false) {
                throw new Error(`verifySignature accepted a fake signature — CRITICAL`);
            }

            console.log('✅ PASS: Wrong signature correctly rejected');
            passed++;
        } catch (e) {
            failTest('verifySignature (wrong sig)', e);
            failed++;
        }

        // ── TEST 5: Reject Tampered Message ───────────
        // [9] Negative test — must reject a tampered message
        console.log('\n[5/5] Verifying tampered message (should reject)...');
        try {
            const tamperedMsg = msg + ' TAMPERED';
            const shouldBeFalse = await withTimeout(
                GhostIdentity.verifySignature(tamperedMsg, sig, id.publicKey),
                TIMEOUT,
                'verifySignature (tampered msg)'
            );

            if (shouldBeFalse !== false) {
                throw new Error(`verifySignature accepted a tampered message — CRITICAL`);
            }

            console.log('✅ PASS: Tampered message correctly rejected');
            passed++;
        } catch (e) {
            failTest('verifySignature (tampered msg)', e);
            failed++;
        }

    } catch (fatal) {
        // [7] Fatal crash — log message only, not stack
        console.error('\n🔥 FATAL:', fatal instanceof Error ? fatal.message : String(fatal));
    } finally {
        // [1][3] Always scrub key material before exit — even on failure
        scrubIdentity(id);
        id = null;

        // ── Summary ───────────────────────────────────
        console.log('\n─────────────────────────────────');
        console.log(`Results: ${passed} passed, ${failed} failed`);

        if (failed === 0 && passed === 5) {
            console.log('✅ ALL TESTS PASSED');
            // [3] Clean exit after scrub
            process.exit(0);
        } else {
            console.error('❌ SOME TESTS FAILED');
            process.exit(1);
        }
    }
})();