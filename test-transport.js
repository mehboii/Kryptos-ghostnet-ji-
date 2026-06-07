/**
 * GhostNet Transport Test — HARDENED
 * =====================================
 * Security fixes applied:
 *
 *  [1] CRITICAL  — Full Error object logged on catch (e) — leaks stack traces & file paths
 *  [2] CRITICAL  — Raw message payload logged before encryption — plaintext secret exposed
 *  [3] CRITICAL  — envelope.payload substring logged — partial ciphertext leaks format info
 *  [4] CRITICAL  — Private keys (idA, idB) left in memory with no cleanup on exit
 *  [5] HIGH      — No timeout on any async crypto operation — hangs forever if stalled
 *  [6] HIGH      — No validation on generated identity fields before use
 *  [7] HIGH      — No validation on envelope structure before verify/decrypt
 *  [8] HIGH      — decryptEnvelope result logged in full — if tampered, could log injected content
 *  [9] MEDIUM    — No negative test — forged envelope or wrong-key decrypt never tested
 *  [10] MEDIUM   — process.exit never called — exit code always 0 even on failure
 *  [11] LOW      — Typo "Encryp payload" in log — minor but indicates untested code path
 */

'use strict';

const GhostTransport = require('./ghostnet-transport');
const GhostIdentity = require('./ghostnet-identity');

// ─── [5] TIMEOUT WRAPPER ────────────────────────────────

function withTimeout(promise, ms, label) {
    const timer = new Promise((_, reject) =>
        setTimeout(() => reject(new Error(`Timeout: "${label}" exceeded ${ms}ms`)), ms)
    );
    return Promise.race([promise, timer]);
}

// ─── [1] SAFE ERROR REPORTER ────────────────────────────
// Never log full Error — only message, never stack (contains file paths)

function failTest(label, err) {
    console.error(` FAILED [${label}]:`, err instanceof Error ? err.message : String(err));
}

// ─── [6] IDENTITY VALIDATOR ─────────────────────────────

function validateIdentity(id, label) {
    if (!id || typeof id !== 'object') {
        throw new Error(`${label}: identity is not an object`);
    }
    if (typeof id.address !== 'string' || id.address.length < 8) {
        throw new Error(`${label}: address missing or too short`);
    }
    if (!id.encryptionKey) {
        throw new Error(`${label}: encryptionKey missing`);
    }
    // [4] Private key must exist but is NEVER logged
    if (!id.privateKey && !id.signingKey) {
        throw new Error(`${label}: no private/signing key found`);
    }
}

// ─── [7] ENVELOPE VALIDATOR ─────────────────────────────

function validateEnvelope(env) {
    if (!env || typeof env !== 'object') {
        throw new Error('Envelope is not an object');
    }
    if (typeof env.id !== 'string' || env.id.length === 0) {
        throw new Error('Envelope missing id');
    }
    if (typeof env.payload !== 'string' || env.payload.length === 0) {
        throw new Error('Envelope missing payload');
    }
    if (!env.signature) {
        throw new Error('Envelope missing signature');
    }
}

// ─── [4] KEY SCRUBBER ───────────────────────────────────

function secureWipe(buf) {
    if (!Buffer.isBuffer(buf)) return;
    for (let i = 0; i < buf.length; i++) {
        buf[i] = 0;
    }
    // Force V8 to not optimize away by reading back
    let acc = 0;
    for (let i = 0; i < buf.length; i++) {
        acc |= buf[i];
    }
    if (acc !== 0) throw new Error('Secure wipe failed');
}

function scrubIdentity(id) {
    if (!id) return;
    try {
        if (id.privateKey && Buffer.isBuffer(id.privateKey)) {
            secureWipe(id.privateKey);
        } else if (typeof id.privateKey === 'string') {
            id.privateKey = '[SCRUBBED]';
        }
        if (id.signingKey && Buffer.isBuffer(id.signingKey)) {
            secureWipe(id.signingKey);
        }
    } catch (_) { }
}

// ─── MAIN TEST RUNNER ───────────────────────────────────

(async () => {
    console.log('--- Testing GhostTransport (Universal) ---');

    const TIMEOUT = 10000; // [5] 10s per operation
    let idA = null;
    let idB = null;
    let passed = 0;
    let failed = 0;

    try {

        // ── TEST 1: Generate Identities ───────────────
        console.log('\n[1/5] Generating identities...');
        try {
            idA = await withTimeout(
                GhostTransport.generateIdentity(),
                TIMEOUT, 'generateIdentity A'
            );
            validateIdentity(idA, 'Identity A'); // [6]
            // [4] Log address only — never privateKey
            console.log('  ID A address:', idA.address);

            idB = await withTimeout(
                GhostTransport.generateIdentity(),
                TIMEOUT, 'generateIdentity B'
            );
            validateIdentity(idB, 'Identity B'); // [6]
            console.log('  ID B address:', idB.address);

            console.log(' PASS: Identities generated');
            passed++;
        } catch (e) {
            failTest('generateIdentity', e);
            failed++;
            throw new Error('Cannot continue — identity generation failed');
        }

        // ── TEST 2: Create Envelope ───────────────────
        console.log('\n[2/5] Creating encrypted envelope...');
        const transportA = new GhostTransport(idA);
        const transportB = new GhostTransport(idB);
        const msg = { text: 'Secret Meeting at Midnight' };
        let envelope;

        try {
            // [2] Do NOT log the plaintext message content
            console.log('  Encrypting payload (' + JSON.stringify(msg).length + ' bytes)...');

            const recipientPubKeyHex = await withTimeout(
                transportA._exportKey(idB.encryptionKey, 'spki'),
                TIMEOUT, '_exportKey'
            );

            envelope = await withTimeout(
                transportA.createEnvelope(recipientPubKeyHex, msg),
                TIMEOUT, 'createEnvelope'
            );

            validateEnvelope(envelope); // [7]

            // [3] Log envelope ID and payload LENGTH only — never payload content
            console.log('  Envelope ID     :', envelope.id);
            console.log('  Payload length  :', envelope.payload.length, 'chars');
            console.log(' PASS: Envelope created');
            passed++;
        } catch (e) {
            failTest('createEnvelope', e);
            failed++;
            throw new Error('Cannot continue — envelope creation failed');
        }

        // ── TEST 3: Verify Envelope ───────────────────
        console.log('\n[3/5] Verifying envelope signature (B side)...');
        try {
            const valid = await withTimeout(
                transportB.verifyEnvelope(envelope),
                TIMEOUT, 'verifyEnvelope'
            );

            if (valid !== true) {
                throw new Error(`Expected true, got: ${valid}`);
            }

            console.log(' PASS: Signature verified');
            passed++;
        } catch (e) {
            failTest('verifyEnvelope', e);
            failed++;
            throw new Error('Cannot continue — verification failed');
        }

        // ── TEST 4: Decrypt Envelope ──────────────────
        console.log('\n[4/5] Decrypting envelope (B side)...');
        try {
            const decrypted = await withTimeout(
                transportB.decryptEnvelope(envelope),
                TIMEOUT, 'decryptEnvelope'
            );

            // [8] Validate decrypted result BEFORE logging anything from it
            if (!decrypted || typeof decrypted !== 'object') {
                throw new Error('Decrypted result is not an object');
            }
            if (typeof decrypted.text !== 'string') {
                throw new Error('Decrypted result missing text field');
            }

            // Compare without logging the decrypted content
            if (decrypted.text !== msg.text) {
                throw new Error('Decrypted text does not match original');
            }

            // [8] Only log that it matched — not the actual decrypted value
            console.log('  Decrypted text matches original: ');
            console.log(' PASS: Envelope decrypted correctly');
            passed++;
        } catch (e) {
            failTest('decryptEnvelope', e);
            failed++;
        }

        // ── TEST 5: Reject Forged Envelope ────────────
        // [9] Negative test — tampered payload must fail verification
        console.log('\n[5/5] Verifying forged envelope (should reject)...');
        try {
            const forgedEnvelope = {
                ...envelope,
                payload: envelope.payload.slice(0, -4) + 'AAAA' // tamper last 4 chars
            };

            const shouldBeFalse = await withTimeout(
                transportB.verifyEnvelope(forgedEnvelope),
                TIMEOUT, 'verifyEnvelope (forged)'
            );

            if (shouldBeFalse !== false) {
                throw new Error('verifyEnvelope accepted a forged envelope — CRITICAL');
            }

            console.log(' PASS: Forged envelope correctly rejected');
            passed++;
        } catch (e) {
            failTest('verifyEnvelope (forged)', e);
            failed++;
        }

    } catch (fatal) {
        // [1] Log message only — never full error object
        console.error('\n FATAL:', fatal instanceof Error ? fatal.message : String(fatal));
    } finally {
        // [4] Always scrub key material before exit
        scrubIdentity(idA);
        scrubIdentity(idB);
        idA = null;
        idB = null;

        // ── Summary ───────────────────────────────────
        console.log('\n─────────────────────────────────');
        console.log(`Results: ${passed} passed, ${failed} failed`);

        // [10] Always exit with correct code
        if (failed === 0 && passed === 5) {
            console.log(' ALL TESTS PASSED');
            process.exit(0);
        } else {
            console.error(' SOME TESTS FAILED');
            process.exit(1); // [10] non-zero exit on failure
        }
    }
})();