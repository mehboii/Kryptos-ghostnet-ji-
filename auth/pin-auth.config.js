/**
 * PIN Auth Configuration — Argon2id Parameters
 * ──────────────────────────────────────────────
 *
 * SECURITY RATIONALE:
 *
 *   A 6-digit PIN has only 1,000,000 possible values (~19.9 bits of entropy).
 *   For comparison, a random 8-character alphanumeric password has ~47 bits.
 *   This means an attacker who obtains the hash + salt can enumerate every
 *   possible PIN in under 10^6 Argon2id evaluations.
 *
 *   Our defence strategy is LAYERED:
 *
 *   Layer 1 — COMPUTATIONAL COST (this config)
 *     Argon2id with ≥64 MiB memory and ≥3 iterations makes each guess
 *     expensive. At 64 MiB / 3 iterations a single evaluation takes ~200ms
 *     on modern hardware. Full keyspace: ~55 hours on one core.
 *     At 256 MiB / 4 iterations: ~800ms per guess → ~9 days single-core.
 *
 *   Layer 2 — SERVER-SIDE PEPPER (this config)
 *     A 256-bit secret HMAC key that is NEVER stored alongside the hash.
 *     Even if the database leaks, the attacker cannot evaluate guesses
 *     without the pepper. This converts a 19.9-bit PIN into a 275-bit
 *     input effectively (PIN + 256-bit pepper).
 *
 *   Layer 3 — RATE LIMITING (pin-auth.js)
 *     Online brute-force is throttled via per-user exponential backoff.
 *     After 5 failed attempts the account is locked for escalating periods.
 *
 *   Layer 4 — DEVICE BINDING (pin-auth.js)
 *     Optional: the PIN is HMAC'd with a device-bound secret before
 *     hashing. An attacker must possess both the hash AND the device
 *     secret to mount an offline attack.
 */

import crypto from 'crypto';

// ─── ARGON2ID TUNING ────────────────────────────────────────────────────────
// These follow OWASP recommendations for low-entropy secret hashing.
// Override via environment variables for different deployment targets
// (e.g., mobile with 64 MiB vs. server with 256 MiB).

/** Memory cost in KiB. Default: 65536 KiB = 64 MiB. Max recommended: 262144 KiB = 256 MiB. */
const ARGON2_MEMORY_COST = parseInt(process.env.ARGON2_MEMORY_COST_KIB, 10) || 65536;

/** Time cost (iterations). Higher = slower per guess. Minimum: 3. */
const ARGON2_TIME_COST = parseInt(process.env.ARGON2_TIME_COST, 10) || 3;

/** Parallelism lanes. Set to available cores, but ≤4 for mobile. */
const ARGON2_PARALLELISM = parseInt(process.env.ARGON2_PARALLELISM, 10) || 2;

/** Output hash length in bytes. 32 bytes = 256 bits. */
const ARGON2_HASH_LENGTH = 32;

/** Salt length in bytes. 16 bytes = 128 bits (NIST SP 800-132 minimum). */
const ARGON2_SALT_LENGTH = 16;

// ─── PEPPER (APPLICATION-LEVEL SECRET) ──────────────────────────────────────
//
// The pepper is a 256-bit HMAC key used to pre-process the PIN before
// Argon2id hashing. It MUST be:
//   1. Stored OUTSIDE the database (environment variable, HSM, or secrets manager).
//   2. NEVER logged, serialised, or included in error messages.
//   3. Rotated periodically (requires re-hashing all PINs on next login).
//
// Generate a new pepper:
//   node -e "console.log(require('crypto').randomBytes(32).toString('hex'))"
//
// In production, set PIN_AUTH_PEPPER via environment variable.
// The fallback generates a random pepper per process start (safe for dev, NOT for prod).

const PIN_AUTH_PEPPER = process.env.PIN_AUTH_PEPPER
    || (() => {
        const devPepper = crypto.randomBytes(32).toString('hex');
        if (process.env.NODE_ENV === 'production') {
            console.error(
                '╔══════════════════════════════════════════════════════════════╗\n' +
                '║  CRITICAL: PIN_AUTH_PEPPER is not set in production!        ║\n' +
                '║  Generate one:                                              ║\n' +
                '║  node -e "console.log(require(\'crypto\').randomBytes(32)     ║\n' +
                '║    .toString(\'hex\'))"                                       ║\n' +
                '║  Set it as PIN_AUTH_PEPPER in your environment.             ║\n' +
                '╚══════════════════════════════════════════════════════════════╝'
            );
        }
        return devPepper;
    })();

// ─── PIN CONSTRAINTS ────────────────────────────────────────────────────────
const PIN_LENGTH = 6;
const PIN_REGEX = /^\d{6}$/;

// ─── RATE LIMITING / LOCKOUT ────────────────────────────────────────────────
/** Maximum consecutive failed PIN attempts before lockout. */
const MAX_PIN_ATTEMPTS = 5;

/** Base lockout duration in seconds. Doubles on each subsequent lockout. */
const BASE_LOCKOUT_SECONDS = 60;

/** Maximum lockout duration (cap for exponential backoff). 1 hour. */
const MAX_LOCKOUT_SECONDS = 3600;

export {
    ARGON2_MEMORY_COST,
    ARGON2_TIME_COST,
    ARGON2_PARALLELISM,
    ARGON2_HASH_LENGTH,
    ARGON2_SALT_LENGTH,
    PIN_AUTH_PEPPER,
    PIN_LENGTH,
    PIN_REGEX,
    MAX_PIN_ATTEMPTS,
    BASE_LOCKOUT_SECONDS,
    MAX_LOCKOUT_SECONDS,
};
