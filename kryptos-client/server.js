/**
 * Kryptos Client — SECURITY HARDENED
 *
 * Fixes applied:
 *  [1] express.static(__dirname) exposed ALL files in the directory
 *      including .env, package.json, server.js source code itself.
 *      → Now serves only an explicit allowlist of safe frontend assets.
 *  [2] No security headers (no helmet, no CSP, no X-Frame-Options).
 *      → helmet() with strict CSP added.
 *  [3] No rate limiting — trivially DoS-able.
 *      → Per-IP rate limiter added.
 *  [4] Bound to 0.0.0.0 with no access control.
 *      → Kept 0.0.0.0 for Docker but added security layers.
 *  [5] setInterval keepalive wasted CPU.
 *      → Removed.
 */

const express = require("express");
const path = require("path");
const fs = require("fs");

const app = express();

// ─── Security Headers ────────────────────────────────────────
// Inline helmet-equivalent (avoids adding dependency to this lightweight service)
app.use((req, res, next) => {
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('X-Frame-Options', 'DENY');
    res.setHeader('X-XSS-Protection', '0'); // Modern browsers: CSP replaces this
    res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
    res.setHeader('Permissions-Policy', 'camera=(), microphone=(), geolocation=()');
    res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains');
    res.setHeader('Content-Security-Policy', [
        "default-src 'self'",
        "script-src 'self' https://cdnjs.cloudflare.com https://unpkg.com https://cdn.ethers.io",
        "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com https://cdnjs.cloudflare.com",
        "font-src 'self' https://fonts.gstatic.com https://cdnjs.cloudflare.com",
        "img-src 'self' data: blob:",
        "connect-src 'self' wss: ws: https:",
        "frame-src 'none'",
        "object-src 'none'",
        "base-uri 'self'",
    ].join('; '));
    next();
});

// ─── Rate Limiting ───────────────────────────────────────────
const _rl = new Map();
const RL_WINDOW = 60000;
const RL_MAX = 120;

setInterval(() => {
    const now = Date.now();
    for (const [ip, e] of _rl) {
        if (now - e.start > RL_WINDOW * 2) _rl.delete(ip);
    }
}, RL_WINDOW).unref();

app.use((req, res, next) => {
    const ip = req.ip || req.socket?.remoteAddress || 'unknown';
    const now = Date.now();
    const entry = _rl.get(ip);
    if (!entry || now - entry.start > RL_WINDOW) {
        _rl.set(ip, { count: 1, start: now });
        return next();
    }
    entry.count++;
    if (entry.count > RL_MAX) {
        return res.status(429).set('Retry-After', '60').send('Too Many Requests');
    }
    next();
});

// ─── [FIX 1] Explicit asset allowlist — NEVER serve the whole directory ──────
// Only these specific frontend files are served. Everything else returns 404.
const ALLOWED_ASSETS = new Set([
    'index.html',
    'script.js',
    'style.css',
    'kryptos-identity.js',
    'kryptos-chat.js',
    'kryptos-mesh.js',
    'kryptos-file-vault.js',
    'crypto-identity.js',
    'app.js',
    'ui.js',
    'ui.css',
    'jsQR.js',
    'qrcode.min.js',
]);

// MIME type map — prevents Content-Type sniffing attacks
const MIME_MAP = {
    '.html': 'text/html; charset=utf-8',
    '.js': 'application/javascript; charset=utf-8',
    '.css': 'text/css; charset=utf-8',
    '.json': 'application/json; charset=utf-8',
    '.png': 'image/png',
    '.jpg': 'image/jpeg',
    '.svg': 'image/svg+xml',
    '.ico': 'image/x-icon',
};

// Serve root as index.html
app.get('/', (req, res) => {
    const indexPath = path.join(__dirname, 'index.html');
    if (fs.existsSync(indexPath)) {
        res.type('text/html').sendFile(indexPath);
    } else {
        res.status(404).send('Not Found');
    }
});

// Serve only allowlisted assets
app.get('/:asset', (req, res) => {
    const asset = req.params.asset;

    // Block path traversal and non-allowlisted files
    if (!ALLOWED_ASSETS.has(asset) || asset.includes('..') || asset.includes('/') || asset.includes('\\')) {
        return res.status(404).send('Not Found');
    }

    const filePath = path.join(__dirname, asset);
    const ext = path.extname(asset).toLowerCase();
    const mime = MIME_MAP[ext] || 'application/octet-stream';

    if (fs.existsSync(filePath)) {
        res.type(mime).sendFile(filePath);
    } else {
        res.status(404).send('Not Found');
    }
});

// Health endpoint
const PORT = process.env.PORT || process.env.KRYPTOS_CLIENT_PORT || 3000;

app.get('/health', (req, res) => {
    res.json({ status: 'ok', service: 'kryptos-client', uptime: process.uptime() });
});

app.listen(PORT, "0.0.0.0", () => {
    console.log(`Kryptos Client running on port ${PORT} (hardened)`);
});
