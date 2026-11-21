/**
 * Kryptos Messages Service (antigravity-network) — SECURITY HARDENED
 *
 * Fixes applied:
 *  [1] app.use(cors()) — wildcard CORS allowed any origin to access messages
 *      → Explicit origin allowlist from CORS_ALLOWED_ORIGINS env var
 *  [2] DELETE /cleanup had NO authentication — anyone could delete all messages
 *      → requireAuth middleware added; ttl validated with bounds
 *  [3] Math.random() used for message IDs — predictable/collision-prone
 *      → crypto.randomBytes for secure ID generation
 *  [4] JSON.parse(r.content) without try/catch — crashes on malformed data
 *      → Safe JSON parsing with fallback
 *  [5] No security headers — missing helmet/CSP/X-Frame-Options
 *      → Inline security headers added
 *  [6] No rate limiting — DoS-able
 *      → Per-IP rate limiter added
 *  [7] No body size limit — memory DoS via large payloads
 *      → express.json limit set to 64kb
 */

import express from 'express';
import sqlite3 from 'sqlite3';
import { open } from 'sqlite';
import cors from 'cors';
import crypto from 'crypto';
import { requireAuth } from '../../auth/auth.middleware.js';

const app = express();
const PORT = 8090;

// ─── [FIX 5] Security Headers ───────────────────────────────
app.use((req, res, next) => {
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('X-Frame-Options', 'DENY');
    res.setHeader('X-XSS-Protection', '0');
    res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
    res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains');
    res.setHeader('Permissions-Policy', 'camera=(), microphone=(), geolocation=()');
    next();
});

// ─── [FIX 6] Rate Limiting ──────────────────────────────────
const _rl = new Map();
const RL_WINDOW = 60000;
const RL_MAX = 100;
setInterval(() => {
    const now = Date.now();
    for (const [ip, e] of _rl) {
        if (now - e.start > RL_WINDOW * 2) _rl.delete(ip);
    }
}, RL_WINDOW).unref();

function rateLimiter(req, res, next) {
    const ip = req.ip || req.socket?.remoteAddress || 'unknown';
    const now = Date.now();
    const entry = _rl.get(ip);
    if (!entry || now - entry.start > RL_WINDOW) {
        _rl.set(ip, { count: 1, start: now });
        return next();
    }
    entry.count++;
    if (entry.count > RL_MAX) {
        return res.status(429).json({ error: 'Too many requests' });
    }
    next();
}

// Middleware
app.use(express.json({ limit: '64kb' })); // [FIX 7]
app.use(rateLimiter);

// [FIX 1] Explicit CORS allowlist
const ALLOWED_ORIGINS = (process.env.CORS_ALLOWED_ORIGINS || 'http://localhost:3000,http://127.0.0.1:3000')
    .split(',').map(o => o.trim()).filter(Boolean);

app.use(cors({
    origin: (origin, cb) => {
        if (!origin || ALLOWED_ORIGINS.includes(origin)) return cb(null, true);
        cb(new Error('CORS: origin not allowed'));
    },
    credentials: true,
}));

let db;

// Init DB
async function initDB() {
    db = await open({
        filename: './database.sqlite',
        driver: sqlite3.Database
    });

    // Enable WAL mode for better concurrent performance
    await db.exec('PRAGMA journal_mode=WAL');

    // Create Tables
    await db.exec(`
        CREATE TABLE IF NOT EXISTS users (
            id TEXT PRIMARY KEY,
            created_at INTEGER
        );

        CREATE TABLE IF NOT EXISTS messages (
            id TEXT PRIMARY KEY,
            user_id TEXT,
            content TEXT,
            timestamp INTEGER
        );
    `);

    console.log("SQLite Database Initialized (hardened)");
}

initDB().catch(console.error);

// --- ENDPOINTS ---

// 1. Save Message (authenticated, userId from token)
app.post('/message', requireAuth, async (req, res) => {
    const { content } = req.body;
    const userId = req.userId;

    if (!userId) {
        return res.status(401).json({ error: "Authentication required" });
    }
    if (!content || typeof content !== 'string' || content.length > 4096) {
        return res.status(400).json({ error: "Invalid content" });
    }

    try {
        // Ensure user exists (Upsert)
        await db.run(
            `INSERT OR IGNORE INTO users (id, created_at) VALUES (?, ?)`,
            userId, Date.now()
        );

        // [FIX 3] Secure ID generation with crypto
        const msgId = Date.now().toString(36) + crypto.randomBytes(8).toString('hex');
        const timestamp = Date.now();

        await db.run(
            `INSERT INTO messages (id, user_id, content, timestamp) VALUES (?, ?, ?, ?)`,
            msgId, userId, JSON.stringify(content), timestamp
        );

        res.json({ success: true, id: msgId });
    } catch (e) {
        console.error('Message save error:', e.message);
        res.status(500).json({ error: "Internal server error" });
    }
});

// 2. Get History (authenticated, scoped to caller)
app.get('/history', requireAuth, async (req, res) => {
    const userId = req.userId;
    if (!userId) {
        return res.status(401).json({ error: "Authentication required" });
    }
    try {
        const rows = await db.all(
            'SELECT * FROM messages WHERE user_id = ? ORDER BY timestamp ASC',
            userId
        );

        // [FIX 4] Safe JSON parsing with fallback
        const history = rows.map(r => {
            let content;
            try {
                content = JSON.parse(r.content);
            } catch {
                content = r.content;
            }
            return { ...r, content };
        });

        res.json(history);
    } catch (e) {
        console.error('History fetch error:', e.message);
        res.status(500).json({ error: "Internal server error" });
    }
});

// 3. Get Users (authenticated, minimal fields only)
app.get('/users', requireAuth, async (req, res) => {
    try {
        const users = await db.all('SELECT id FROM users');
        res.json(users.map(u => ({ id: u.id, displayName: u.id })));
    } catch (e) {
        console.error('Users fetch error:', e.message);
        res.status(500).json({ error: "Internal server error" });
    }
});

// [FIX 2] 4. Cleanup — NOW REQUIRES AUTHENTICATION + input validation
app.delete('/cleanup', requireAuth, async (req, res) => {
    const { ttl } = req.query; // Time to live in ms
    if (!ttl) return res.status(400).json({ error: "Missing ttl (ms)" });

    const parsed = parseInt(ttl, 10);
    if (!Number.isFinite(parsed) || parsed < 0 || parsed > 31536000000) {
        return res.status(400).json({ error: "ttl must be 0-31536000000 (1 year max)" });
    }
    const cutoff = Date.now() - parsed;

    try {
        const result = await db.run('DELETE FROM messages WHERE timestamp < ?', cutoff);
        res.json({ deleted: result.changes });
    } catch (e) {
        console.error('Cleanup error:', e.message);
        res.status(500).json({ error: "Internal server error" });
    }
});

const BIND_HOST = process.env.KRYPTOS_MESSAGES_HOST || '127.0.0.1';

app.listen(PORT, BIND_HOST, () => {
    console.log(`Message Service running on ${BIND_HOST}:${PORT} (hardened)`);
});
