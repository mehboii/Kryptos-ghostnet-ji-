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

function _persist() {
    fs.writeFileSync(AUTH_USERS_FILE, JSON.stringify(authUsers, null, 2));
}

function generateId() {
    return 'auth_' + Date.now() + '_' + Math.random().toString(36).substring(2, 8);
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
export function createUser({ email, password_hash }) {
    // Generate 6-digit verification code
    const verifyCode = String(Math.floor(100000 + Math.random() * 900000));

    const user = {
        id: generateId(),
        email: email.trim().toLowerCase(),
        password_hash,
        verified: false,
        verify_code: verifyCode,
        verify_code_expires: new Date(Date.now() + 10 * 60 * 1000).toISOString(), // 10 min
        created_at: new Date().toISOString(),
    };

    authUsers.push(user);
    _persist();

    // Return a safe copy without sensitive fields
    const { password_hash: _, verify_code: __, verify_code_expires: ___, ...safeUser } = user;
    return { ...safeUser, verifyCode }; // Include code so route can send it via email
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
 * Verify a user's email with the 6-digit code.
 * @param {string} email
 * @param {string} code - The 6-digit verification code
 * @returns {{ success: boolean, error?: string, user?: object }}
 */
export function verifyEmail(email, code) {
    const normalised = email.trim().toLowerCase();
    const user = authUsers.find(u => u.email === normalised);
    if (!user) return { success: false, error: 'User not found.' };

    if (user.verified) {
        return { success: true, user: sanitise(user), alreadyVerified: true };
    }

    if (!user.verify_code || user.verify_code !== code) {
        return { success: false, error: 'Invalid verification code.' };
    }

    if (new Date(user.verify_code_expires) < new Date()) {
        return { success: false, error: 'Verification code has expired. Please request a new one.' };
    }

    // Mark verified and clear code
    user.verified = true;
    delete user.verify_code;
    delete user.verify_code_expires;
    _persist();

    return { success: true, user: sanitise(user) };
}

/**
 * Generate a new verification code for a user.
 * @param {string} email
 * @returns {{ code: string, user: object }|null}
 */
export function resendVerifyCode(email) {
    const normalised = email.trim().toLowerCase();
    const user = authUsers.find(u => u.email === normalised);
    if (!user) return null;

    if (user.verified) return { code: null, user: sanitise(user), alreadyVerified: true };

    const code = String(Math.floor(100000 + Math.random() * 900000));
    user.verify_code = code;
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
export function setResetToken(email) {
    const normalised = email.trim().toLowerCase();
    const user = authUsers.find(u => u.email === normalised);
    if (!user) return null;

    const code = String(Math.floor(100000 + Math.random() * 900000)); // 6-digit
    user.reset_token = code;
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
export function resetPassword(email, token, newPasswordHash) {
    const normalised = email.trim().toLowerCase();
    const user = authUsers.find(u => u.email === normalised);
    if (!user) return { success: false, error: 'User not found.' };

    if (!user.reset_token || user.reset_token !== token) {
        return { success: false, error: 'Invalid reset code.' };
    }

    if (new Date(user.reset_token_expires) < new Date()) {
        // Expired — clear it
        delete user.reset_token;
        delete user.reset_token_expires;
        _persist();
        return { success: false, error: 'Reset code has expired. Please request a new one.' };
    }

    // Update password and clear token
    user.password_hash = newPasswordHash;
    delete user.reset_token;
    delete user.reset_token_expires;
    _persist();

    return { success: true };
}
