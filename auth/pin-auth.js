/**
 * GhostNet PIN Authentication Module — Argon2id
 * ══════════════════════════════════════════════
 *
 * Production-ready 6-digit PIN hashing and verification using Argon2id
 * with layered defences against the inherently low entropy (~19.9 bits)
 * of a numeric PIN.
 *
 * THREAT MODEL:
 *   Attacker has obtained the database (hash + salt) but NOT the pepper.
 *   → Must brute-force 10^6 PINs × Argon2id cost per guess.
 *   → With pepper unknown, attack is infeasible regardless of PIN entropy.
 *
 *   Attacker has obtained both the database AND the pepper.
 *   → 10^6 guesses × ~200ms each (64 MiB) = ~55 hours single-core.
 *   → 10^6 guesses × ~800ms each (256 MiB) = ~9.2 days single-core.
 *   → GPU parallelism is limited by Argon2id's memory-hardness.
 *
 *   Attacker is making online guesses against the API.
 *   → Rate limiter allows 5 attempts, then exponential lockout.
 *   → Full keyspace online: 10^6 / 5 per minute = ~139 days minimum.
 *
 * ARCHITECTURE:
 *   PIN → HMAC(PIN, pepper) → HMAC(result, deviceSecret?) → Argon2id → hash
 *   Stored: { hash (base64), salt (base64), argon2Version }
 *   NOT stored: PIN, pepper, deviceSecret
 *
 * @module pin-auth
 */

import crypto from 'crypto';
import argon2 from 'argon2';

import {
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
} from './pin-auth.config.js';

// ─── INTERNAL: INPUT VALIDATION ─────────────────────────────────────────────

/**
 * Validate that a PIN is exactly 6 numeric digits.
 *
 * SECURITY: We reject any input that is not exactly 6 digits to prevent:
 *   - Injection of non-numeric characters that might alter hash behaviour.
 *   - Short PINs that would reduce the already-small keyspace further.
 *   - Long inputs that might cause excessive Argon2id memory allocation.
 *
 * @param {string} pin — Raw PIN input from user
 * @throws {Error} If PIN format is invalid
 */
function _validatePin(pin) {
    if (typeof pin !== 'string') {
        throw new Error(`PIN must be a string, got ${typeof pin}.`);
    }
    if (!PIN_REGEX.test(pin)) {
        throw new Error(`PIN must be exactly ${PIN_LENGTH} digits (0-9).`);
    }
}

// ─── INTERNAL: PEPPER APPLICATION ───────────────────────────────────────────

/**
 * Apply the server-side pepper to the PIN using HMAC-SHA256.
 *
 * WHY HMAC, NOT CONCATENATION:
 *   Simple concatenation (pepper + pin) is vulnerable to length-extension
 *   attacks on certain hash functions. HMAC is specifically designed to be
 *   a secure keyed-hash construction and is not susceptible to this class
 *   of attack.
 *
 * WHY PEPPER BEFORE ARGON2:
 *   Argon2id's input is the HMAC output (32 bytes = 256 bits of entropy),
 *   not the raw 6-digit PIN. Even if the attacker obtains the hash + salt
 *   from the database, they cannot evaluate Argon2id guesses without
 *   knowing the pepper. The PIN's low entropy becomes irrelevant.
 *
 * @param {string} pin — Validated 6-digit PIN
 * @returns {Buffer} — 32-byte HMAC digest
 */
function _applyPepper(pin) {
    return crypto
        .createHmac('sha256', Buffer.from(PIN_AUTH_PEPPER, 'hex'))
        .update(pin, 'utf8')
        .digest();
}

// ─── INTERNAL: DEVICE SECRET BINDING ────────────────────────────────────────

/**
 * Optionally bind a device-specific secret to the peppered PIN.
 *
 * USE CASE:
 *   On mobile, a hardware-backed keystore (Android Keystore / iOS Secure
 *   Enclave) can generate a 256-bit key that never leaves the device.
 *   By HMAC'ing the peppered PIN with this key, an attacker who steals
 *   the server database AND the pepper still cannot verify guesses without
 *   physical access to the specific device.
 *
 * IMPLEMENTATION:
 *   The device secret should be generated once during device registration
 *   and stored in the hardware keystore. It should NOT be stored in
 *   localStorage, SharedPreferences, or any software-accessible location.
 *
 *   If no device secret is provided, this step is a no-op and the peppered
 *   PIN is passed through unchanged.
 *
 * @param {Buffer} pepperedPin — Output of _applyPepper()
 * @param {string|null} deviceSecret — Hex-encoded device-bound key, or null
 * @returns {Buffer} — Final pre-hash input
 */
function _bindDeviceSecret(pepperedPin, deviceSecret) {
    if (!deviceSecret) return pepperedPin;

    return crypto
        .createHmac('sha256', Buffer.from(deviceSecret, 'hex'))
        .update(pepperedPin)
        .digest();
}

// ─── INTERNAL: MEMORY CLEARING ──────────────────────────────────────────────

/**
 * Best-effort zeroing of sensitive Buffers.
 *
 * CAVEAT:
 *   Node.js / V8 does not guarantee that Buffer.fill(0) will not be
 *   optimised away. In languages with explicit memory control (Rust, C),
 *   we would use `explicit_bzero()` or `zeroize`. In Node.js, this is
 *   defence-in-depth: it helps but is not a hard guarantee.
 *
 *   For critical deployments, consider running Argon2id in a WASM module
 *   with manual memory management, or in a native addon with explicit
 *   zeroing.
 *
 * @param {...Buffer} buffers — Buffers to zero out
 */
function _clearBuffers(...buffers) {
    for (const buf of buffers) {
        if (Buffer.isBuffer(buf)) {
            buf.fill(0);
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// PUBLIC API
// ═══════════════════════════════════════════════════════════════════════════

/**
 * Hash a 6-digit PIN using Argon2id with pepper and optional device binding.
 *
 * PIPELINE:
 *   1. Validate PIN format (exactly 6 digits).
 *   2. Generate a cryptographically secure random salt (16 bytes / 128 bits).
 *      ─ Each user/device gets a unique salt, preventing rainbow-table and
 *        multi-target attacks.
 *   3. Apply server-side pepper via HMAC-SHA256.
 *      ─ Converts the 19.9-bit PIN into a 256-bit keyed digest.
 *      ─ Pepper is stored outside the database (env var / HSM).
 *   4. Optionally bind a device secret via HMAC-SHA256.
 *      ─ Adds hardware-bound entropy; attacker needs physical device.
 *   5. Hash the result with Argon2id.
 *      ─ Memory-hard: resists GPU/ASIC parallelism.
 *      ─ Time-hard: configurable iteration count.
 *      ─ Hybrid (2id): resists both side-channel and GPU attacks.
 *   6. Zero sensitive intermediate buffers.
 *   7. Return the hash + salt for storage.
 *
 * @param {string} pin — Exactly 6 numeric digits
 * @param {object} [options]
 * @param {string} [options.deviceSecret] — Hex-encoded device-bound secret
 * @param {number} [options.memoryCost]   — Override memory cost (KiB)
 * @param {number} [options.timeCost]     — Override time cost (iterations)
 * @param {number} [options.parallelism]  — Override parallelism lanes
 * @returns {Promise<{hash: string, salt: string, version: string}>}
 *   hash  — Base64-encoded Argon2id output (raw, not the encoded string)
 *   salt  — Base64-encoded salt (must be stored alongside the hash)
 *   version — Algorithm identifier for future migration
 */
async function hashPin(pin, options = {}) {
    // ── Step 1: Validate ────────────────────────────────────────────────
    _validatePin(pin);

    // ── Step 2: Generate salt ───────────────────────────────────────────
    // CSPRNG salt ensures each hash is unique even for identical PINs.
    // 16 bytes exceeds the NIST SP 800-132 minimum of 128 bits.
    const salt = crypto.randomBytes(ARGON2_SALT_LENGTH);

    // ── Step 3: Apply pepper ────────────────────────────────────────────
    const pepperedPin = _applyPepper(pin);

    // ── Step 4: Bind device secret (optional) ───────────────────────────
    const finalInput = _bindDeviceSecret(pepperedPin, options.deviceSecret || null);

    // ── Step 5: Argon2id hash ───────────────────────────────────────────
    // We use argon2.hash() with `raw: true` to get the raw hash bytes,
    // then encode them ourselves. This avoids storing Argon2 parameters
    // in the encoded string format (we track them in `version` metadata).
    const hashBuffer = await argon2.hash(finalInput, {
        type: argon2.argon2id,               // Argon2id — hybrid mode
        salt,                                 // Unique per-user salt
        memoryCost: options.memoryCost || ARGON2_MEMORY_COST,
        timeCost: options.timeCost || ARGON2_TIME_COST,
        parallelism: options.parallelism || ARGON2_PARALLELISM,
        hashLength: ARGON2_HASH_LENGTH,       // 256-bit output
        raw: true,                            // Return raw Buffer, not encoded string
    });

    // ── Step 6: Clear sensitive intermediates ────────────────────────────
    _clearBuffers(pepperedPin, finalInput);

    // ── Step 7: Return storable result ──────────────────────────────────
    return {
        hash: hashBuffer.toString('base64'),
        salt: salt.toString('base64'),
        // Version string encodes the algorithm and parameters so we can
        // detect and migrate hashes if we change parameters in the future.
        version: `argon2id$m=${options.memoryCost || ARGON2_MEMORY_COST},t=${options.timeCost || ARGON2_TIME_COST},p=${options.parallelism || ARGON2_PARALLELISM}`,
    };
}

/**
 * Verify a 6-digit PIN against a stored Argon2id hash.
 *
 * SECURITY PROPERTIES:
 *   - Uses `crypto.timingSafeEqual()` for hash comparison.
 *     This prevents timing attacks where an attacker measures response
 *     times to determine how many bytes of the hash matched. Without
 *     constant-time comparison, the first differing byte causes an early
 *     return, leaking information about the correct hash.
 *
 *   - Never reveals whether the PIN, salt, or hash was incorrect.
 *     The caller should always return a generic "Invalid PIN" error.
 *
 *   - Clears sensitive intermediate buffers after use.
 *
 * @param {string} pin          — Candidate PIN (exactly 6 digits)
 * @param {string} storedHash   — Base64-encoded stored hash
 * @param {string} storedSalt   — Base64-encoded stored salt
 * @param {object} [options]
 * @param {string} [options.deviceSecret] — Hex-encoded device-bound secret
 * @param {string} [options.version]      — Version string from hashPin()
 * @returns {Promise<boolean>} — true if PIN matches, false otherwise
 */
async function verifyPin(pin, storedHash, storedSalt, options = {}) {
    // ── Validate ────────────────────────────────────────────────────────
    _validatePin(pin);

    if (!storedHash || !storedSalt) {
        // Return false (not throw) to prevent enumeration of which field
        // is missing. The caller sees only "verification failed".
        return false;
    }

    // ── Decode stored values ────────────────────────────────────────────
    const salt = Buffer.from(storedSalt, 'base64');
    const expectedHash = Buffer.from(storedHash, 'base64');

    // ── Parse version for parameters (future-proof migration) ───────────
    // Default to current config if no version string is provided.
    let memoryCost = ARGON2_MEMORY_COST;
    let timeCost = ARGON2_TIME_COST;
    let parallelism = ARGON2_PARALLELISM;

    if (options.version) {
        const paramMatch = options.version.match(/m=(\d+),t=(\d+),p=(\d+)/);
        if (paramMatch) {
            memoryCost = parseInt(paramMatch[1], 10);
            timeCost = parseInt(paramMatch[2], 10);
            parallelism = parseInt(paramMatch[3], 10);
        }
    }

    // ── Apply pepper + device binding ───────────────────────────────────
    const pepperedPin = _applyPepper(pin);
    const finalInput = _bindDeviceSecret(pepperedPin, options.deviceSecret || null);

    // ── Re-hash with same salt and parameters ───────────────────────────
    const candidateHash = await argon2.hash(finalInput, {
        type: argon2.argon2id,
        salt,
        memoryCost,
        timeCost,
        parallelism,
        hashLength: ARGON2_HASH_LENGTH,
        raw: true,
    });

    // ── Clear sensitive intermediates ────────────────────────────────────
    _clearBuffers(pepperedPin, finalInput);

    // ── Constant-time comparison ────────────────────────────────────────
    // CRITICAL: Do NOT use `===` or `Buffer.equals()` — they short-circuit
    // on the first differing byte, creating a timing side-channel.
    //
    // `crypto.timingSafeEqual` takes exactly the same time regardless of
    // where (or whether) the buffers differ.
    if (expectedHash.length !== candidateHash.length) {
        // Length mismatch means corrupted data. Still return false
        // without revealing which length was wrong.
        _clearBuffers(candidateHash);
        return false;
    }

    const match = crypto.timingSafeEqual(expectedHash, candidateHash);

    // ── Clear candidate hash ────────────────────────────────────────────
    _clearBuffers(candidateHash);

    return match;
}

// ═══════════════════════════════════════════════════════════════════════════
// RATE LIMITING / EXPONENTIAL BACKOFF
// ═══════════════════════════════════════════════════════════════════════════

/**
 * In-memory per-user rate limiter with exponential backoff.
 *
 * WHY IN-MEMORY:
 *   For single-server deployments, in-memory tracking is sufficient and
 *   avoids database round-trips on every PIN attempt. For multi-server
 *   deployments, replace this with a Redis-backed implementation.
 *
 * WHY EXPONENTIAL BACKOFF:
 *   Linear rate limiting (e.g., "5 per minute") allows a persistent
 *   attacker to enumerate ~7,200 PINs per day. Exponential backoff
 *   increases the lockout duration after each burst of failures:
 *     Burst 1: 5 attempts → 60s lockout
 *     Burst 2: 5 attempts → 120s lockout
 *     Burst 3: 5 attempts → 240s lockout
 *     ... capped at 3600s (1 hour)
 *
 *   This makes sustained online brute-force infeasible.
 *
 * DATA STRUCTURE:
 *   Map<userId, {
 *     attempts: number,         — Failed attempts in current window
 *     lockoutUntil: number,     — Timestamp (ms) until which user is locked
 *     lockoutCount: number,     — Number of times lockout has triggered
 *     lastAttempt: number,      — Timestamp of last attempt
 *   }>
 */
const _rateLimitStore = new Map();

/** Cleanup stale entries every 10 minutes to prevent memory leaks. */
const _CLEANUP_INTERVAL_MS = 10 * 60 * 1000;
const _ENTRY_TTL_MS = MAX_LOCKOUT_SECONDS * 1000 * 2; // Keep entries for 2× max lockout

setInterval(() => {
    const now = Date.now();
    for (const [key, entry] of _rateLimitStore) {
        if (now - entry.lastAttempt > _ENTRY_TTL_MS) {
            _rateLimitStore.delete(key);
        }
    }
}, _CLEANUP_INTERVAL_MS).unref(); // .unref() so this timer doesn't prevent process exit

/**
 * Check if a user is currently rate-limited.
 *
 * @param {string} userId — Unique user/device identifier
 * @returns {{ allowed: boolean, retryAfterMs?: number, attemptsRemaining?: number }}
 */
function checkRateLimit(userId) {
    const entry = _rateLimitStore.get(userId);
    if (!entry) {
        return { allowed: true, attemptsRemaining: MAX_PIN_ATTEMPTS };
    }

    const now = Date.now();

    // Check if currently locked out
    if (entry.lockoutUntil && now < entry.lockoutUntil) {
        return {
            allowed: false,
            retryAfterMs: entry.lockoutUntil - now,
            attemptsRemaining: 0,
        };
    }

    // Lockout expired — reset attempt counter but keep lockout history
    if (entry.lockoutUntil && now >= entry.lockoutUntil) {
        entry.attempts = 0;
        entry.lockoutUntil = null;
    }

    return {
        allowed: true,
        attemptsRemaining: MAX_PIN_ATTEMPTS - entry.attempts,
    };
}

/**
 * Record a failed PIN attempt. Triggers lockout after MAX_PIN_ATTEMPTS.
 *
 * @param {string} userId — Unique user/device identifier
 * @returns {{ locked: boolean, retryAfterMs?: number, attemptsRemaining: number }}
 */
function recordFailedAttempt(userId) {
    let entry = _rateLimitStore.get(userId);
    if (!entry) {
        entry = { attempts: 0, lockoutUntil: null, lockoutCount: 0, lastAttempt: 0 };
        _rateLimitStore.set(userId, entry);
    }

    entry.attempts += 1;
    entry.lastAttempt = Date.now();

    if (entry.attempts >= MAX_PIN_ATTEMPTS) {
        // Trigger lockout with exponential backoff
        entry.lockoutCount += 1;
        const lockoutSeconds = Math.min(
            BASE_LOCKOUT_SECONDS * Math.pow(2, entry.lockoutCount - 1),
            MAX_LOCKOUT_SECONDS
        );
        entry.lockoutUntil = Date.now() + (lockoutSeconds * 1000);

        return {
            locked: true,
            retryAfterMs: lockoutSeconds * 1000,
            attemptsRemaining: 0,
        };
    }

    return {
        locked: false,
        attemptsRemaining: MAX_PIN_ATTEMPTS - entry.attempts,
    };
}

/**
 * Reset rate limit state for a user (e.g., after successful verification).
 *
 * @param {string} userId — Unique user/device identifier
 */
function resetRateLimit(userId) {
    _rateLimitStore.delete(userId);
}

// ═══════════════════════════════════════════════════════════════════════════
// DEVICE SECRET GENERATION
// ═══════════════════════════════════════════════════════════════════════════

/**
 * Generate a new device-bound secret.
 *
 * In production, this should be stored in a hardware-backed keystore:
 *   - Android: Android Keystore (hardware-backed TEE/SE)
 *   - iOS: Secure Enclave via Keychain Services
 *   - Desktop: TPM 2.0 or OS credential manager
 *
 * For development/testing, this returns a random 256-bit hex string
 * that should be persisted securely on the device.
 *
 * SECURITY: The device secret MUST NOT be:
 *   - Stored in the database (defeats the purpose)
 *   - Stored in localStorage/SharedPreferences (extractable via XSS/root)
 *   - Derived from predictable device properties (MAC, IMEI — spoofable)
 *
 * @returns {string} — 64-character hex string (256 bits)
 */
function generateDeviceSecret() {
    return crypto.randomBytes(32).toString('hex');
}

// ═══════════════════════════════════════════════════════════════════════════
// HASH MIGRATION SUPPORT
// ═══════════════════════════════════════════════════════════════════════════

/**
 * Check if a stored hash needs re-hashing with updated parameters.
 *
 * WHY:
 *   As hardware improves, Argon2id parameters should be increased.
 *   This function checks if a stored hash was created with outdated
 *   parameters and signals that it should be re-hashed on next
 *   successful verification.
 *
 * @param {string} version — Version string from stored hash metadata
 * @returns {boolean} — true if hash should be re-created with current params
 */
function needsRehash(version) {
    if (!version) return true;

    const currentVersion = `argon2id$m=${ARGON2_MEMORY_COST},t=${ARGON2_TIME_COST},p=${ARGON2_PARALLELISM}`;
    return version !== currentVersion;
}

// ═══════════════════════════════════════════════════════════════════════════
// EXPORTS
// ═══════════════════════════════════════════════════════════════════════════

export {
    hashPin,
    verifyPin,
    checkRateLimit,
    recordFailedAttempt,
    resetRateLimit,
    generateDeviceSecret,
    needsRehash,
};
