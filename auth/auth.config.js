/**
 * Auth Configuration
 * ------------------
 * Centralised config for JWT and auth settings.
 * 
 * FUTURE: To switch to Auth0 / AWS Cognito, replace the JWT_SECRET
 * with your provider's public key / JWKS endpoint and update
 * auth.middleware.js to verify against it.  The rest of the app
 * only cares about `req.userId` — no other changes needed.
 */

import crypto from 'crypto';

const _envSecret = process.env.AUTH_JWT_SECRET;
const _isPlaceholder = !_envSecret || _envSecret.startsWith('CHANGE_ME');
if (_isPlaceholder && process.env.NODE_ENV === 'production') {
    console.error('FATAL: AUTH_JWT_SECRET is not set or is a placeholder. Refusing to start in production.');
    process.exit(1);
}
if (_isPlaceholder) {
    console.warn('  AUTH_JWT_SECRET not configured — using ephemeral random secret (dev only). Sessions will not survive restarts.');
}
const JWT_SECRET = _isPlaceholder
    ? crypto.randomBytes(64).toString('hex')
    : _envSecret;

const JWT_EXPIRES_IN = process.env.AUTH_JWT_EXPIRES_IN || '24h';

const BCRYPT_SALT_ROUNDS = parseInt(process.env.BCRYPT_SALT_ROUNDS, 10) || 12;

export {
    JWT_SECRET,
    JWT_EXPIRES_IN,
    BCRYPT_SALT_ROUNDS,
};
