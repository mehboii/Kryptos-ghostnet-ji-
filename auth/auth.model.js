/**
 * Auth User Model
 * ----------------
 * Thin persistence layer for authenticated users.
 * Uses a JSON file (auth-users.json) to match the project's
 * existing storage pattern.  Separates auth users from the
 * legacy users.json so existing functionality is untouched.
 *
 * Schema per user:
 *   { id, email, password_hash, verified, verify_code, verify_code_expires, created_at }
 *
 * NEVER stores plaintext passwords.
 * NEVER stores a separate salt field — bcrypt embeds it.
 */

import fs from 'fs';
import path from 'path';
import crypto from 'crypto';
import bcrypt from 'bcrypt';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const AUTH_USERS_FILE = path.join(__dirname, '..', 'auth-users.json');

// ---------------------------------------------------------------------------
// Bootstrap
// ---------------------------------------------------------------------------
let authUsers = [];

try {
    if (fs.existsSync(AUTH_USERS_FILE)) {
        authUsers = JSON.parse(fs.readFileSync(AUTH_USERS_FILE, 'utf-8'));
    } else {
        fs.writeFileSync(AUTH_USERS_FILE, '[]');
    }
} catch (e) {
    console.error('Auth user DB load error:', e);
    authUsers = [];
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

let _persistTimer = null;
function _persist() {
    if (_persistTimer) return;
    _persistTimer = setTimeout(() => {
        _persistTimer = null;
        fs.writeFile(AUTH_USERS_FILE, JSON.stringify(authUsers, null, 2), () => {});
    }, 500);
}

function generateId() {
    return 'auth_' + crypto.randomUUID();
}

// ---------------------------------------------------------------------------
// GhostCode Short Code Generation (GN-XXXX)
// ---------------------------------------------------------------------------
const SHORTCODE_CHARSET = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789'; // 32 chars, no 0/O/I/1
const SHORTCODE_REGEX = /^GN-[ABCDEFGHJKLMNPQRSTUVWXYZ23456789]{4,6}$/;

/**
 * Generate a unique GhostCode short code (GN-XXXX format).
 * Uses crypto.randomBytes for secure generation.
 * @param {number} length - Code length (4-6), default 4
 * @returns {string} e.g. "GN-X7K2"
 */
export function generateShortCode(length = 4) {
    const bytes = crypto.randomBytes(length);
    let code = 'GN-';
    for (let i = 0; i < length; i++) {
        code += SHORTCODE_CHARSET[bytes[i] % SHORTCODE_CHARSET.length];
    }
    return code;
}

/**
 * Generate a unique short code with collision checking.
 * Retries up to 10 times if a collision is found.
 * @returns {string} A unique GhostCode
 */
export function generateUniqueShortCode() {
    for (let attempt = 0; attempt < 10; attempt++) {
        const code = generateShortCode();
        if (!findByShortCode(code)) {
            return code;
        }
    }
    // Fallback to 5-char code if 4-char keeps colliding
    for (let attempt = 0; attempt < 10; attempt++) {
        const code = generateShortCode(5);
        if (!findByShortCode(code)) {
            return code;
        }
    }
    // Last resort: 6-char code
    return generateShortCode(6);
}

/**
 * Validate a short code format.
 * @param {string} code
 * @returns {boolean}
 */
export function isValidShortCode(code) {
    return SHORTCODE_REGEX.test(code);
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/**
 * Find a user by email (case-insensitive).
 * @param {string} email
 * @returns {object|undefined}
 */
export function findByEmail(email) {
    const normalised = email.trim().toLowerCase();
    return authUsers.find(u => u.email === normalised);
}

/**
 * Find a user by their GhostCode short code.
 * @param {string} shortCode e.g. "GN-X7K2"
 * @returns {object|undefined}
 */
export function findByShortCode(shortCode) {
    const upper = shortCode.toUpperCase();
    return authUsers.find(u => u.shortCode === upper);
}

/**
 * Find a user by id.
 * @param {string} id
 * @returns {object|undefined}
 */
export function findById(id) {
    return authUsers.find(u => u.id === id);
}

/**
 * Create a new auth user.
 * @param {{ email: string, password_hash: string }} data
 * @returns {object} The created user (without password_hash).
 */
export async function createUser({ email, password_hash }) {
    // Generate 6-digit verification code using CSPRNG
    const verifyCode = crypto.randomInt(100000, 999999).toString();

    // Hash the verification code before storing (like passwords)
    const verifyCodeHash = await bcrypt.hash(verifyCode, 10);

    // Generate unique GhostCode short code
    const shortCode = generateUniqueShortCode();

    const user = {
        id: generateId(),
        email: email.trim().toLowerCase(),
        password_hash,
        shortCode,
        verified: false,
        verify_code: verifyCodeHash,
        verify_code_expires: new Date(Date.now() + 10 * 60 * 1000).toISOString(), // 10 min
        created_at: new Date().toISOString(),
    };

    authUsers.push(user);
    _persist();

    // Return a safe copy without sensitive fields
    const { password_hash: _, verify_code: __, verify_code_expires: ___, ...safeUser } = user;
    return { ...safeUser, verifyCode }; // Include plaintext code so route can send it via email
}

/**
 * Return a user object without sensitive fields.
 * @param {object} user
 * @returns {object}
 */
export function sanitise(user) {
    if (!user) return null;
    const { password_hash, reset_token, reset_token_expires, verify_code, verify_code_expires, ...safe } = user;
    return safe;
}

/**
 * Bump a user's tokenVersion, invalidating all previously issued JWTs.
 * @param {string} userId
 * @returns {number} The new tokenVersion
 */
export function bumpTokenVersion(userId) {
    const user = authUsers.find(u => u.id === userId);
    if (!user) return -1;
    user.tokenVersion = (user.tokenVersion || 0) + 1;
    _persist();
    return user.tokenVersion;
}

/**
 * Update arbitrary fields on a user record.
 * @param {string} userId
 * @param {object} fields - key/value pairs to update
 * @returns {object|null} Updated user (sanitised) or null if not found
 */
const ALLOWED_UPDATE_FIELDS = new Set(['shortCode', 'displayName', 'avatar']);
export function updateUserFields(userId, fields) {
    const user = authUsers.find(u => u.id === userId);
    if (!user) return null;
    for (const [key, value] of Object.entries(fields)) {
        if (ALLOWED_UPDATE_FIELDS.has(key)) {
            user[key] = value;
        }
    }
    _persist();
    return sanitise(user);
}

/**
 * Verify a user's email with the 6-digit code.
 * @param {string} email
 * @param {string} code - The 6-digit verification code
 * @returns {{ success: boolean, error?: string, user?: object }}
 */
export async function verifyEmail(email, code) {
    const normalised = email.trim().toLowerCase();
    const user = authUsers.find(u => u.email === normalised);
    if (!user) return { success: false, error: 'User not found.' };

    if (user.verified) {
        return { success: true, user: sanitise(user), alreadyVerified: true };
    }

    // Check TTL first — clear expired codes
    if (!user.verify_code || !user.verify_code_expires || new Date(user.verify_code_expires) < new Date()) {
        // Clear expired code
        if (user.verify_code) {
            delete user.verify_code;
            delete user.verify_code_expires;
            _persist();
        }
        return { success: false, error: 'Verification code has expired. Please request a new one.' };
    }

    const attempts = user.verify_attempts || 0;
    if (attempts >= 5) {
        delete user.verify_code;
        delete user.verify_code_expires;
        delete user.verify_attempts;
        _persist();
        return { success: false, error: 'Too many failed attempts. Please request a new code.' };
    }

    // Compare submitted code against bcrypt hash (timing-safe)
    const match = await bcrypt.compare(code, user.verify_code);
    if (!match) {
        user.verify_attempts = attempts + 1;
        _persist();
        return { success: false, error: 'Invalid verification code.' };
    }

    // Mark verified and clear code
    user.verified = true;
    delete user.verify_code;
    delete user.verify_code_expires;
    delete user.verify_attempts;
    _persist();

    return { success: true, user: sanitise(user) };
}

/**
 * Generate a new verification code for a user.
 * @param {string} email
 * @returns {{ code: string, user: object }|null}
 */
export async function resendVerifyCode(email) {
    const normalised = email.trim().toLowerCase();
    const user = authUsers.find(u => u.email === normalised);
    if (!user) return null;

    if (user.verified) return { code: null, user: sanitise(user), alreadyVerified: true };

    const code = crypto.randomInt(100000, 999999).toString();
    user.verify_code = await bcrypt.hash(code, 10);
    user.verify_code_expires = new Date(Date.now() + 10 * 60 * 1000).toISOString();
    _persist();

    return { code, user: sanitise(user) };
}

/**
 * Generate and store a 6-digit reset code for the user.
 * Expires after 15 minutes.
 * @param {string} email
 * @returns {{ code: string, user: object }|null}
 */
export async function setResetToken(email) {
    const normalised = email.trim().toLowerCase();
    const user = authUsers.find(u => u.email === normalised);
    if (!user) return null;

    const code = crypto.randomInt(100000, 999999).toString();
    user.reset_token = await bcrypt.hash(code, 10);
    user.reset_token_expires = new Date(Date.now() + 15 * 60 * 1000).toISOString(); // 15 min
    _persist();

    return { code, user: sanitise(user) };
}

/**
 * Verify a reset token and update the password.
 * @param {string} email
 * @param {string} token - The 6-digit code
 * @param {string} newPasswordHash - The bcrypt hash of the new password
 * @returns {{ success: boolean, error?: string }}
 */
export async function resetPassword(email, token, newPasswordHash) {
    const normalised = email.trim().toLowerCase();
    const user = authUsers.find(u => u.email === normalised);
    if (!user) return { success: false, error: 'User not found.' };

    // Check TTL first — clear expired tokens
    if (!user.reset_token || !user.reset_token_expires || new Date(user.reset_token_expires) < new Date()) {
        if (user.reset_token) {
            delete user.reset_token;
            delete user.reset_token_expires;
            _persist();
        }
        return { success: false, error: 'Reset code has expired. Please request a new one.' };
    }

    const resetAttempts = user.reset_attempts || 0;
    if (resetAttempts >= 5) {
        delete user.reset_token;
        delete user.reset_token_expires;
        delete user.reset_attempts;
        _persist();
        return { success: false, error: 'Too many failed attempts. Please request a new reset code.' };
    }

    // Compare submitted token against bcrypt hash (timing-safe)
    const match = await bcrypt.compare(token, user.reset_token);
    if (!match) {
        user.reset_attempts = resetAttempts + 1;
        _persist();
        return { success: false, error: 'Invalid reset code.' };
    }

    // Update password, clear token, and bump tokenVersion to invalidate all existing JWTs
    user.password_hash = newPasswordHash;
    user.tokenVersion = (user.tokenVersion || 0) + 1;
    delete user.reset_token;
    delete user.reset_token_expires;
    delete user.reset_attempts;
    _persist();

    return { success: true };
}
