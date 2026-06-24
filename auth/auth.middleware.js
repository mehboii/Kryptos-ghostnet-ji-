/**
 * JWT Authentication Middleware
 * ------------------------------
 * Reads the Authorization header (Bearer TOKEN), verifies
 * the JWT, and attaches `req.userId` to the request.
 *
 * Also validates `tv` (tokenVersion) against the stored user
 * to ensure tokens issued before a logout/password-reset are
 * rejected.
 *
 * FUTURE: To switch to Auth0 / AWS Cognito, replace the
 * jwt.verify call with their SDK verification.  The rest
 * of the app only checks `req.userId`.
 */

import jwt from 'jsonwebtoken';
import { JWT_SECRET } from './auth.config.js';
import { findById } from './auth.model.js';

/**
 * Middleware that BLOCKS the request if the JWT is missing, invalid,
 * or has been revoked via tokenVersion bump (logout / password reset).
 * On success, sets `req.userId` from the token payload.
 */
export function requireAuth(req, res, next) {
    const authHeader = req.headers.authorization;

    if (!authHeader || !authHeader.startsWith('Bearer ')) {
        return res.status(401).json({ error: 'Authorization header missing or malformed. Expected: Bearer <token>' });
    }

    const token = authHeader.split(' ')[1];

    try {
        const decoded = jwt.verify(token, JWT_SECRET, { algorithms: ['HS256'] });
        req.userId = decoded.userId;

        // Validate tokenVersion — reject JWTs issued before logout/password-reset
        const user = findById(decoded.userId);
        if (user) {
            const currentTv = user.tokenVersion || 0;
            const tokenTv = decoded.tv ?? 0; // older tokens may lack tv
            if (tokenTv < currentTv) {
                return res.status(401).json({ error: 'Token revoked. Please log in again.' });
            }
        }

        next();
    } catch (err) {
        if (err.name === 'TokenExpiredError') {
            return res.status(401).json({ error: 'Token expired. Please log in again.' });
        }
        return res.status(401).json({ error: 'Invalid token.' });
    }
}
