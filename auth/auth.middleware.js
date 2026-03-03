/**
 * JWT Authentication Middleware
 * ------------------------------
 * Reads the Authorization header (Bearer TOKEN), verifies
 * the JWT, and attaches `req.userId` to the request.
 *
 * FUTURE: To switch to Auth0 / AWS Cognito, replace the
 * jwt.verify call with their SDK verification.  The rest
 * of the app only checks `req.userId`.
 */

import jwt from 'jsonwebtoken';
import { JWT_SECRET } from './auth.config.js';

/**
 * Middleware that BLOCKS the request if the JWT is missing or invalid.
 * On success, sets `req.userId` from the token payload.
 */
export function requireAuth(req, res, next) {
    const authHeader = req.headers.authorization;

    if (!authHeader || !authHeader.startsWith('Bearer ')) {
        return res.status(401).json({ error: 'Authorization header missing or malformed. Expected: Bearer <token>' });
    }

    const token = authHeader.split(' ')[1];

    try {
        const decoded = jwt.verify(token, JWT_SECRET);
        req.userId = decoded.userId;
        next();
    } catch (err) {
        if (err.name === 'TokenExpiredError') {
            return res.status(401).json({ error: 'Token expired. Please log in again.' });
        }
        return res.status(401).json({ error: 'Invalid token.' });
    }
}
