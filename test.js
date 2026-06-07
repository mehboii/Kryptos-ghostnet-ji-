/**
 * GhostNet Identity Quick Test — HARDENED
 * ==========================================
 * Security fixes applied:
 *
 *  [1] CRITICAL  — node.publicKey printed raw — may expose sensitive key material
 *  [2] HIGH      — No try/catch — unhandled rejection leaks full stack trace & file paths
 *  [3] HIGH      — No validation on node before use — null/undefined silently passes
 *  [4] MEDIUM    — No timeout — hangs forever if createIdentity() stalls
 *  [5] MEDIUM    — process.exit never called — exit code always 0 even on failure
 */

'use strict';

const identity = require('./ghostnet-identity');

// ─── [4] TIMEOUT WRAPPER ────────────────────────────────

function withTimeout(promise, ms, label) {
    const timer = new Promise((_, reject) =>
        setTimeout(() => reject(new Error(`Timeout: "${label}" exceeded ${ms}ms`)), ms)
    );
    return Promise.race([promise, timer]);
}

// ─── MAIN ───────────────────────────────────────────────

(async () => {
    try { // [2] wrap everything — no unhandled rejections

        const node = await withTimeout(
            identity.createIdentity(),
            10000,
            'createIdentity'
        );

        // [3] Validate before use
        if (!node || typeof node !== 'object') {
            throw new Error('createIdentity() returned null or invalid object');
        }
        if (typeof node.id !== 'string' || node.id.length === 0) {
            throw new Error('node.id is missing or empty');
        }
        if (!node.publicKey) {
            throw new Error('node.publicKey is missing');
        }

        console.log('NODE ID:', node.id);

        // [1] Log public key LENGTH only — never the raw key value
        // Public keys are safe to share in principle, but logging raw
        // key objects/buffers risks accidentally printing adjacent private
        // key material depending on the identity implementation.
        const pubKeyLen = typeof node.publicKey === 'string'
            ? node.publicKey.length
            : (node.publicKey.byteLength ?? '?');

        console.log('PUBLIC KEY: OK (' + pubKeyLen + ' chars)');
        console.log(' Identity created successfully');

        process.exit(0); // [5] explicit success exit

    } catch (e) {
        // [2] Log message only — never full error object (leaks stack/paths)
        console.error(' FAILED:', e instanceof Error ? e.message : String(e));
        process.exit(1); // [5] non-zero on failure
    }
})();