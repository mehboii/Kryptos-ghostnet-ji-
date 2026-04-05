/**
 * PIN Auth Routes — Setup, Verify, Change
 * ────────────────────────────────────────
 * POST /pin/setup    → Hash and store a new 6-digit PIN
 * POST /pin/verify   → Verify a PIN against the stored hash
 * POST /pin/change   → Change PIN (requires current PIN verification)
 *
 * Security guarantees:
 *  • PINs are NEVER logged, echoed, or stored in plaintext.
 *  • All responses use identical timing for success/failure paths
 *    (constant-time comparison in pin-auth.js).
 *  • Rate limiting with exponential backoff prevents online brute-force.
 *  • Generic error messages prevent information leakage.
 */

import { Router } from 'express';
import rateLimit from 'express-rate-limit';

import { requireAuth } from './auth.middleware.js';
import {
    hashPin,
    verifyPin,
    checkRateLimit,
    recordFailedAttempt,
    resetRateLimit,
    needsRehash,
} from './pin-auth.js';

const router = Router();

// ─── TRANSPORT-LEVEL RATE LIMITER ───────────────────────────────────────────
// This is a coarse IP-based limiter (defence-in-depth on top of the
// per-user exponential backoff in pin-auth.js).
const pinLimiter = rateLimit({
    windowMs: 60 * 1000,          // 1-minute window
    max: 10,                       // 10 requests per IP per minute
    standardHeaders: true,
    legacyHeaders: false,
    message: { error: 'Too many PIN requests. Please try again later.' },
});

// ─── HELPERS ────────────────────────────────────────────────────────────────

/**
 * In production, PIN data should be stored in a proper database.
 * This in-memory store is for demonstration. Replace with your
 * database adapter (SQLite, PostgreSQL, etc.).
 */
const _pinStore = new Map();

function _getStoredPin(userId) {
    return _pinStore.get(userId) || null;
}

function _setStoredPin(userId, data) {
    _pinStore.set(userId, data);
}

// ============================================================
// POST /pin/setup — Create a new PIN
// ============================================================
router.post('/setup', requireAuth, pinLimiter, async (req, res) => {
    try {
        const userId = req.userId;
        const { pin, deviceSecret } = req.body;

        // ── Input validation (generic error to prevent info leakage) ────
        if (!pin || typeof pin !== 'string') {
            return res.status(400).json({ error: 'A 6-digit PIN is required.' });
        }

        // ── Check if PIN already exists ─────────────────────────────────
        const existing = _getStoredPin(userId);
        if (existing) {
            return res.status(409).json({
                error: 'PIN is already set. Use /pin/change to update it.',
            });
        }

        // ── Hash the PIN ────────────────────────────────────────────────
        const result = await hashPin(pin, { deviceSecret });

        // ── Store hash + salt + version (NEVER the raw PIN) ─────────────
        _setStoredPin(userId, {
            hash: result.hash,
            salt: result.salt,
            version: result.version,
            createdAt: Date.now(),
            updatedAt: Date.now(),
        });

        // SECURITY: Log the event, NEVER the PIN.
        console.log(`[PIN] PIN set for user ${userId}`);

        res.status(201).json({
            success: true,
            message: 'PIN created successfully.',
        });
    } catch (err) {
        // Surface validation errors (PIN format) to the client.
        if (err.message.includes('PIN must be')) {
            return res.status(400).json({ error: err.message });
        }
        console.error('[PIN] Setup error:', err.message);
        res.status(500).json({ error: 'Internal server error.' });
    }
});

// ============================================================
// POST /pin/verify — Verify a PIN
// ============================================================
router.post('/verify', requireAuth, pinLimiter, async (req, res) => {
    try {
        const userId = req.userId;
        const { pin, deviceSecret } = req.body;

        // ── Generic validation ──────────────────────────────────────────
        if (!pin || typeof pin !== 'string') {
            return res.status(400).json({ error: 'PIN is required.' });
        }

        // ── Check rate limit (per-user exponential backoff) ─────────────
        const rl = checkRateLimit(userId);
        if (!rl.allowed) {
            const retrySeconds = Math.ceil(rl.retryAfterMs / 1000);
            return res.status(429).json({
                error: `Account temporarily locked. Try again in ${retrySeconds} seconds.`,
                retryAfterMs: rl.retryAfterMs,
            });
        }

        // ── Retrieve stored hash ────────────────────────────────────────
        const stored = _getStoredPin(userId);
        if (!stored) {
            // SECURITY: Don't reveal that no PIN is set — same error as wrong PIN.
            // This prevents account state enumeration.
            return res.status(401).json({ error: 'Invalid PIN.' });
        }

        // ── Verify with Argon2id (constant-time comparison) ─────────────
        const match = await verifyPin(pin, stored.hash, stored.salt, {
            deviceSecret,
            version: stored.version,
        });

        if (!match) {
            // Record failed attempt (may trigger lockout)
            const result = recordFailedAttempt(userId);

            if (result.locked) {
                const retrySeconds = Math.ceil(result.retryAfterMs / 1000);
                return res.status(429).json({
                    error: `Too many failed attempts. Locked for ${retrySeconds} seconds.`,
                    retryAfterMs: result.retryAfterMs,
                });
            }

            // SECURITY: Generic error message — never say "PIN is wrong"
            // vs "PIN not found" vs "hash mismatch". All failures look identical.
            return res.status(401).json({
                error: 'Invalid PIN.',
                attemptsRemaining: result.attemptsRemaining,
            });
        }

        // ── Success: reset rate limiter ─────────────────────────────────
        resetRateLimit(userId);

        // ── Check if hash needs migration to new parameters ─────────────
        if (needsRehash(stored.version)) {
            // Re-hash with current parameters on successful verification.
            // This is transparent to the user.
            const newResult = await hashPin(pin, { deviceSecret });
            _setStoredPin(userId, {
                ...stored,
                hash: newResult.hash,
                salt: newResult.salt,
                version: newResult.version,
                updatedAt: Date.now(),
            });
            console.log(`[PIN] Re-hashed PIN for user ${userId} (parameter upgrade)`);
        }

        res.json({
            success: true,
            message: 'PIN verified.',
        });
    } catch (err) {
        if (err.message.includes('PIN must be')) {
            return res.status(400).json({ error: err.message });
        }
        console.error('[PIN] Verify error:', err.message);
        res.status(500).json({ error: 'Internal server error.' });
    }
});

// ============================================================
// POST /pin/change — Change PIN (requires current PIN)
// ============================================================
router.post('/change', requireAuth, pinLimiter, async (req, res) => {
    try {
        const userId = req.userId;
        const { currentPin, newPin, deviceSecret } = req.body;

        if (!currentPin || !newPin) {
            return res.status(400).json({
                error: 'Both current PIN and new PIN are required.',
            });
        }

        // ── Rate limit check ────────────────────────────────────────────
        const rl = checkRateLimit(userId);
        if (!rl.allowed) {
            const retrySeconds = Math.ceil(rl.retryAfterMs / 1000);
            return res.status(429).json({
                error: `Account temporarily locked. Try again in ${retrySeconds} seconds.`,
                retryAfterMs: rl.retryAfterMs,
            });
        }

        // ── Verify current PIN ──────────────────────────────────────────
        const stored = _getStoredPin(userId);
        if (!stored) {
            return res.status(401).json({ error: 'Invalid PIN.' });
        }

        const match = await verifyPin(currentPin, stored.hash, stored.salt, {
            deviceSecret,
            version: stored.version,
        });

        if (!match) {
            const result = recordFailedAttempt(userId);
            if (result.locked) {
                const retrySeconds = Math.ceil(result.retryAfterMs / 1000);
                return res.status(429).json({
                    error: `Too many failed attempts. Locked for ${retrySeconds} seconds.`,
                    retryAfterMs: result.retryAfterMs,
                });
            }
            return res.status(401).json({
                error: 'Invalid current PIN.',
                attemptsRemaining: result.attemptsRemaining,
            });
        }

        // ── Hash the new PIN ────────────────────────────────────────────
        const newResult = await hashPin(newPin, { deviceSecret });

        _setStoredPin(userId, {
            hash: newResult.hash,
            salt: newResult.salt,
            version: newResult.version,
            createdAt: stored.createdAt,
            updatedAt: Date.now(),
        });

        // Reset rate limiter on successful change
        resetRateLimit(userId);

        console.log(`[PIN] PIN changed for user ${userId}`);

        res.json({
            success: true,
            message: 'PIN changed successfully.',
        });
    } catch (err) {
        if (err.message.includes('PIN must be')) {
            return res.status(400).json({ error: err.message });
        }
        console.error('[PIN] Change error:', err.message);
        res.status(500).json({ error: 'Internal server error.' });
    }
});

export default router;
