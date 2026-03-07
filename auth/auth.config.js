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

// In production, set AUTH_JWT_SECRET via environment variable.
// The fallback generates a random secret per process start (safe for dev).
const JWT_SECRET = process.env.AUTH_JWT_SECRET
    || crypto.randomBytes(64).toString('hex');

const JWT_EXPIRES_IN = process.env.AUTH_JWT_EXPIRES_IN || '24h';

const BCRYPT_SALT_ROUNDS = 10;

export {
    JWT_SECRET,
    JWT_EXPIRES_IN,
    BCRYPT_SALT_ROUNDS,
};
