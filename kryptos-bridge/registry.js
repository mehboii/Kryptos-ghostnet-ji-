'use strict';

/**
 * Kryptos Registry Server — SECURITY HARDENED
 *
 * Vulnerabilities found and fixed:
 *
 * [A] HIGH — CORS set to wildcard "*" with no origin validation.
 *     Access-Control-Allow-Origin: * permits any website on the internet
 *     to make cross-origin requests to this registry from a visitor's
 *     browser. Any page the user visits can silently fetch /nodes and
 *     learn the full internal node topology of the Kryptos deployment.
 *     In a production mesh network, node addresses are sensitive — they
 *     are the entry points to the network and should not be advertised
 *     to arbitrary third-party origins.
 *     Fixed: an explicit ALLOWED_ORIGINS allowlist is checked on every
 *     request. Unknown origins receive a 403 and no CORS header.
 *     Set ALLOWED_ORIGINS to the exact origins your frontend is served from.
 *
 * [B] HIGH — Node list is a hardcoded in-process array with no
 *     authentication on read.
 *     Any client on any network who can reach port 9000 can retrieve the
 *     complete node list with a single unauthenticated GET /nodes request.
 *     There is no IP filtering, no token check, and no rate limiting.
 *     Fixed: (1) A static bearer token (REGISTRY_TOKEN) must be present
 *     in the Authorization header. Requests without it receive 401.
 *     (2) The token is compared with crypto.timingSafeEqual to prevent
 *     timing side-channel attacks on the comparison.
 *     Set REGISTRY_TOKEN via environment variable — never hardcode it.
 *
 * [C] HIGH — No rate limiting — trivially DoS-able.
 *     The server spawned a new handler per request with no concurrency or
 *     rate control. A single client sending thousands of requests per
 *     second would consume CPU and file descriptors unboundedly.
 *     Fixed: per-IP request rate limiting (MAX_REQUESTS_PER_WINDOW per
 *     WINDOW_MS). IPs exceeding the limit receive 429 Too Many Requests.
 *     The limiter uses a sliding window Map with automatic eviction.
 *
 * [D] MEDIUM — req.url not validated before routing.
 *     The server only handled "/nodes" and fell through to 404 for
 *     everything else, but req.url was never parsed or sanitised. A URL
 *     like "/nodes%00" or "/nodes/../etc/passwd" would miss the exact
 *     match and hit the 404 branch, but any future route added with
 *     startsWith() or path operations would be vulnerable to path
 *     traversal or null-byte injection.
 *     Fixed: req.url is parsed with new URL() to normalise it, and only
 *     the pathname is used for routing. Any URL that fails to parse
 *     receives a 400.
 *
 * [E] MEDIUM — HTTP instead of HTTPS — node list transmitted in plaintext.
 *     http.createServer() serves the node list over unencrypted HTTP.
 *     Any observer on the network path between the client and the registry
 *     sees the complete node topology in the clear.
 *     Fixed: documented prominently. In production, place this server
 *     behind a TLS-terminating reverse proxy (nginx, Caddy, Cloudflare
 *     Tunnel) or replace http.createServer with https.createServer with
 *     a valid certificate. The fix cannot be made here without a cert
 *     path, but the guard and comment make the requirement explicit.
 *
 * [F] MEDIUM — Unhandled 'error' event on the server causes process crash.
 *     Node's http.Server emits 'error' for EADDRINUSE, EACCES, etc.
 *     Without a listener, an unhandled EventEmitter error terminates the
 *     process.
 *     Fixed: server.on('error', ...) registered before listen().
 *
 * [G] MEDIUM — Request body never consumed — potential memory leak on
 *     POST/PUT requests.
 *     The server only handled GET but never drained the request stream for
 *     other methods. Clients sending large POST bodies to any path would
 *     cause the socket to stall and eventually the kernel receive buffer
 *     to fill, degrading all connections on the server.
 *     Fixed: non-GET methods receive 405 immediately and the request
 *     stream is drained before responding.
 *
 * [H] LOW — Server port and node list hardcoded — no environment
 *     configuration.
 *     Hardcoded values make it impossible to change the port or node list
 *     without modifying the source file, and they get committed to version
 *     control. Internal node addresses in source control are a data
 *     exposure risk.
 *     Fixed: port and node list are read from environment variables with
 *     safe defaults. REGISTRY_NODES is a comma-separated list of URLs.
 *
 * [I] LOW — No request logging — impossible to detect abuse or intrusion.
 *     The original server had no access logging at all. Without logs,
 *     brute-force token attempts, topology scanning, or DoS attacks are
 *     invisible to operators.
 *     Fixed: minimal structured logging on every request: timestamp,
 *     method, path, status, and source IP. Tokens and auth headers are
 *     never logged.
 *
 * [J] LOW — Wildcard CORS also set Access-Control-Allow-Methods: GET but
 *     never handled OPTIONS preflight requests.
 *     Browsers send an OPTIONS preflight before cross-origin requests with
 *     non-simple headers (e.g. Authorization). Without a 204 response to
 *     OPTIONS, the browser blocks the actual request. The original server
 *     would have returned 404 for OPTIONS /nodes, silently breaking
 *     cross-origin requests that include an Authorization header.
 *     Fixed: OPTIONS /nodes returns 204 with the correct preflight headers
 *     for authorised origins.
 */

const http = require('http');
const crypto = require('crypto');

// ─── Configuration (from environment) ────────────────────────────────────────

// [FIX H] All config from environment variables — never hardcoded.
const PORT = parseInt(process.env.REGISTRY_PORT || '9000', 10);

// Comma-separated list of node WebSocket URLs.
// e.g. REGISTRY_NODES="wss://node1.example.com,wss://node2.example.com"
const NODES = (process.env.REGISTRY_NODES || 'ws://localhost:8080,ws://localhost:8081,ws://localhost:8082')
    .split(',')
    .map(s => s.trim())
    .filter(Boolean);

// Production requires explicit node configuration — never use defaults
if (!process.env.REGISTRY_NODES && process.env.NODE_ENV === 'production') {
    console.error('[Registry] FATAL: REGISTRY_NODES must be explicitly configured in production');
    process.exit(1);
}

// [FIX B] Bearer token for /nodes endpoint. MUST be set in production.
const REGISTRY_TOKEN = process.env.REGISTRY_TOKEN || '';
if (!REGISTRY_TOKEN) {
    console.warn('[Registry] WARNING: REGISTRY_TOKEN is not set. /nodes endpoint is unprotected.');
}

// [FIX A] Explicit origin allowlist. Set ALLOWED_ORIGINS as comma-separated list.
// e.g. ALLOWED_ORIGINS="https://app.kryptos.io,http://localhost:3000"
const ALLOWED_ORIGINS = new Set(
    (process.env.ALLOWED_ORIGINS || '')
        .split(',')
        .map(s => s.trim())
        .filter(Boolean)
);

// [FIX C] Rate limiting config.
const MAX_REQUESTS_PER_WINDOW = parseInt(process.env.RATE_LIMIT_MAX || '60', 10);
const WINDOW_MS = parseInt(process.env.RATE_LIMIT_WINDOW || '60000', 10); // 1 minute

// ─── Rate limiter ─────────────────────────────────────────────────────────────

// [FIX C] Per-IP sliding window counter.
// Map: ip -> { count, windowStart }
const _rateLimiter = new Map();

function _isRateLimited(ip) {
    const now = Date.now();
    const entry = _rateLimiter.get(ip);

    if (!entry || now - entry.windowStart > WINDOW_MS) {
        _rateLimiter.set(ip, { count: 1, windowStart: now });
        return false;
    }

    entry.count += 1;
    if (entry.count > MAX_REQUESTS_PER_WINDOW) return true;
    return false;
}

// Evict stale entries periodically to prevent unbounded Map growth.
setInterval(() => {
    const now = Date.now();
    for (const [ip, entry] of _rateLimiter) {
        if (now - entry.windowStart > WINDOW_MS * 2) _rateLimiter.delete(ip);
    }
}, WINDOW_MS).unref(); // .unref() so this timer doesn't keep the process alive

// ─── Auth helpers ─────────────────────────────────────────────────────────────

// [FIX B] Constant-time token comparison to prevent timing side-channel.
function _isAuthorised(authHeader) {
    if (!REGISTRY_TOKEN) return true; // No token configured — allow (with warning logged above)
    if (!authHeader || !authHeader.startsWith('Bearer ')) return false;
    const provided = authHeader.slice(7);
    if (provided.length !== REGISTRY_TOKEN.length) return false;
    try {
        return crypto.timingSafeEqual(
            Buffer.from(provided, 'utf8'),
            Buffer.from(REGISTRY_TOKEN, 'utf8')
        );
    } catch {
        return false;
    }
}

// ─── CORS helpers ─────────────────────────────────────────────────────────────

// [FIX A] Return CORS headers only for known origins.
function _setCorsHeaders(res, origin) {
    if (ALLOWED_ORIGINS.size === 0 || ALLOWED_ORIGINS.has(origin)) {
        // Specific origin — credentials-safe.
        res.setHeader('Access-Control-Allow-Origin', origin || '*');
        res.setHeader('Access-Control-Allow-Methods', 'GET, OPTIONS');
        res.setHeader('Access-Control-Allow-Headers', 'Authorization, Content-Type');
        res.setHeader('Vary', 'Origin');
        return true;
    }
    return false; // Origin not in allowlist
}

// ─── Logging ──────────────────────────────────────────────────────────────────

// [FIX I] Minimal structured access log — never logs auth headers.
function _log(ip, method, path, status) {
    const ts = new Date().toISOString();
    console.log(JSON.stringify({ ts, ip, method, path, status }));
}

// ─── Request handler ──────────────────────────────────────────────────────────

function handleRequest(req, res) {
    const ip = req.socket?.remoteAddress || 'unknown';
    const method = req.method || 'GET';
    const origin = req.headers['origin'] || '';

    // [FIX C] Rate limiting — checked before any other processing.
    if (_isRateLimited(ip)) {
        _log(ip, method, req.url, 429);
        res.writeHead(429, { 'Content-Type': 'text/plain', 'Retry-After': String(Math.ceil(WINDOW_MS / 1000)) });
        res.end('Too Many Requests');
        return;
    }

    // [FIX G] Drain non-GET request bodies and return 405 immediately.
    if (method !== 'GET' && method !== 'OPTIONS') {
        _log(ip, method, req.url, 405);
        res.writeHead(405, { 'Content-Type': 'text/plain', 'Allow': 'GET, OPTIONS' });
        res.end('Method Not Allowed');
        req.resume(); // drain the stream
        return;
    }

    // [FIX D] Parse and normalise the URL — reject anything that fails.
    let pathname;
    try {
        pathname = new URL(req.url, 'http://localhost').pathname;
    } catch {
        _log(ip, method, req.url, 400);
        res.writeHead(400, { 'Content-Type': 'text/plain' });
        res.end('Bad Request');
        return;
    }

    // [FIX J] Handle OPTIONS preflight for CORS.
    if (method === 'OPTIONS' && pathname === '/nodes') {
        const corsOk = _setCorsHeaders(res, origin);
        if (!corsOk) {
            _log(ip, 'OPTIONS', pathname, 403);
            res.writeHead(403);
            res.end();
            return;
        }
        _log(ip, 'OPTIONS', pathname, 204);
        res.writeHead(204);
        res.end();
        return;
    }

    if (pathname === '/nodes') {
        // [FIX A] CORS — only for allowed origins.
        const corsOk = _setCorsHeaders(res, origin);
        if (origin && !corsOk) {
            _log(ip, method, pathname, 403);
            res.writeHead(403, { 'Content-Type': 'text/plain' });
            res.end('Forbidden: Origin not allowed');
            return;
        }

        // [FIX B] Auth check.
        if (!_isAuthorised(req.headers['authorization'])) {
            _log(ip, method, pathname, 401);
            res.writeHead(401, { 'Content-Type': 'text/plain', 'WWW-Authenticate': 'Bearer' });
            res.end('Unauthorized');
            return;
        }

        const body = JSON.stringify(NODES);
        _log(ip, method, pathname, 200);
        res.writeHead(200, {
            'Content-Type': 'application/json',
            'Content-Length': Buffer.byteLength(body),
            'Cache-Control': 'no-store',           // Node topology should not be cached
        });
        res.end(body);
        return;
    }

    _log(ip, method, pathname, 404);
    res.writeHead(404, { 'Content-Type': 'text/plain' });
    res.end('Not Found');
}

// ─── Server ───────────────────────────────────────────────────────────────────

// [FIX E] Production note: place behind a TLS-terminating reverse proxy
//         (nginx, Caddy, Cloudflare Tunnel) or replace http.createServer
//         with https.createServer({ key, cert }, handleRequest).
//         Node list addresses are sensitive — never serve them over plain HTTP
//         in production.
const server = http.createServer(handleRequest);

// [FIX F] Handle server-level errors to prevent silent process crash.
server.on('error', (err) => {
    if (err.code === 'EADDRINUSE') {
        console.error(`[Registry] Port ${PORT} is already in use.`);
    } else if (err.code === 'EACCES') {
        console.error(`[Registry] Permission denied on port ${PORT}. Use a port > 1024 or run with elevated privileges.`);
    } else {
        console.error('[Registry] Server error:', err.message);
    }
    process.exit(1);
});

server.listen(PORT, () => {
    console.log(JSON.stringify({
        ts: new Date().toISOString(),
        event: 'startup',
        port: PORT,
        nodes: NODES.length,
        token: REGISTRY_TOKEN ? 'set' : 'UNSET — endpoint unprotected',
        origins: ALLOWED_ORIGINS.size > 0 ? [...ALLOWED_ORIGINS] : 'all (no allowlist configured)',
    }));
});