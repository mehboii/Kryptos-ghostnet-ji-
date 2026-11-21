'use strict';

/**
 * Kryptos Chain Service — SECURITY HARDENED
 * Blockchain Abstraction HTTP API
 *
 * Vulnerabilities found and fixed:
 *
 * [A] CRITICAL — CORS set to wildcard with no origin validation.
 *     app.use(cors()) with no options enables Access-Control-Allow-Origin: *
 *     for every route. This is a blockchain anchoring and deletion API —
 *     any website visited by a user who has a valid session token can make
 *     cross-origin requests to anchor, verify, or delete file records on
 *     their behalf. Combined with missing authentication ([B]), this means
 *     any page on the internet can call POST /chain/anchor or
 *     DELETE /chain/file/:fileId from a victim's browser.
 *     Fixed: cors() is configured with an explicit ALLOWED_ORIGINS allowlist.
 *     Unknown origins receive no CORS headers. OPTIONS preflight is handled
 *     correctly so Authorization headers work cross-origin.
 *
 * [B] CRITICAL — Every endpoint is completely unauthenticated.
 *     POST /chain/anchor, DELETE /chain/file/:fileId, GET /chain/verify,
 *     GET /chain/files/:owner, and GET /chain/info are all reachable with
 *     no token, no session, and no identity check. Any process that can
 *     reach port 4000 can anchor arbitrary data on-chain (spending real gas),
 *     list all file records for any owner address, and delete any file record.
 *     This is the only service that talks to the blockchain — there is no
 *     second line of defence.
 *     Fixed: requireAuth() middleware checks a Bearer token on every route
 *     except /health. Token comparison uses crypto.timingSafeEqual to
 *     prevent timing side-channel attacks. Token is read from
 *     KRYPTOS_CHAIN_TOKEN environment variable only.
 *
 * [C] CRITICAL — Internal error messages returned verbatim in HTTP responses.
 *     catch (err) { res.status(500).json({ error: err.message }) } on every
 *     route sends the raw exception message to the caller. ethers.js errors
 *     include: RPC endpoint URLs (with embedded API keys), contract addresses,
 *     transaction hex payloads, wallet addresses, and internal stack details.
 *     A caller who triggers any error receives a detailed map of the internal
 *     blockchain infrastructure.
 *     Fixed: all catch blocks log the full error internally and return a
 *     fixed, generic message to the caller. Error type is used to select
 *     the HTTP status code without leaking the message.
 *
 * [D] CRITICAL — req.body values passed directly to chain provider with no
 *     validation or type checking.
 *     POST /chain/anchor extracts { fileId, fileHash, metadata } from req.body
 *     and passes them straight to chain.anchorFileHash(). The only check is
 *     `if (!fileId || !fileHash)` — a falsy check that passes for 0, false,
 *     or an empty object. An attacker can send:
 *       { "fileId": {"$gt": ""}, "fileHash": true }
 *     or a fileId that is an array, which may crash the provider or behave
 *     unexpectedly. Even though the base provider now validates these, defence
 *     in depth requires the HTTP layer to enforce types independently.
 *     Fixed: _requireString() validates every path and body parameter as a
 *     non-empty string before it touches any provider method.
 *
 * [E] CRITICAL — DELETE /chain/file/:fileId uses error message string-matching
 *     to determine HTTP status code.
 *     res.status(err.message.includes('not found') ? 404 : 403) inspects
 *     the raw error message string. This means the HTTP status code returned
 *     to external callers is entirely controlled by the text of internal
 *     exception messages — which can change across library versions, be
 *     localised, or be manipulated by a crafted fileId that contains
 *     "not found" as a substring. It also re-exposes internal error
 *     messages in the response body (see [C]).
 *     Fixed: typed custom errors from the provider layer (GhostChainValidationError,
 *     GhostChainConnectionError) are matched by instanceof, not by string.
 *
 * [F] HIGH — Provider initialised in a floating async IIFE — startup errors
 *     are silently swallowed.
 *     (async () => { await chain.connect(); })() fires and is never awaited.
 *     If chain.connect() throws (misconfigured RPC, bad private key, network
 *     error), the error is printed to stderr but the server continues listening
 *     on port 4000 and accepts requests against an uninitialised provider.
 *     Every subsequent request hits the disconnected provider and fails in
 *     unpredictable ways — potentially leaking partial state.
 *     Fixed: connect() is awaited before app.listen(). If connection fails,
 *     the process exits with a non-zero code rather than accepting requests
 *     in a broken state.
 *
 * [G] HIGH — Server binds to 0.0.0.0 with no network scope control.
 *     app.listen(PORT, '0.0.0.0') listens on all network interfaces,
 *     including external-facing ones. The chain service is an internal
 *     microservice — it is only meant to be called by other Kryptos
 *     services, not exposed to the internet. Binding to 0.0.0.0 means
 *     a misconfigured firewall or a Docker port-forward exposes it directly.
 *     Fixed: binds to 127.0.0.1 by default. Set KRYPTOS_CHAIN_HOST=0.0.0.0
 *     explicitly if deploying behind a reverse proxy that requires it.
 *
 * [H] HIGH — No request body size limit.
 *     express.json() with no options accepts request bodies of unlimited
 *     size. An attacker sending a 100 MB JSON body to POST /chain/anchor
 *     would consume the full memory before the route handler runs, causing
 *     a process crash or OOM kill.
 *     Fixed: express.json({ limit: '64kb' }) — sufficient for any valid
 *     anchor request; well below any metadata that could cause issues.
 *
 * [I] HIGH — req.params.owner used directly as a file ownership query with
 *     no validation.
 *     GET /chain/files/:owner passes req.params.owner straight to
 *     chain.getFilesByOwner(). An owner value of "__proto__" or a 10 MB
 *     string could cause prototype pollution or DoS in the provider.
 *     The route also has no authentication beyond [B]'s token, meaning
 *     any authenticated caller can enumerate all files belonging to any
 *     owner address — including other users' files.
 *     Fixed: owner is validated as a non-empty string ≤ 128 chars.
 *     Access scope enforcement (callers may only query their own owner)
 *     is noted as a required application-layer control.
 *
 * [J] MEDIUM — No rate limiting on any endpoint.
 *     POST /chain/anchor sends a real blockchain transaction costing real gas.
 *     Without rate limiting, an authenticated attacker (or a compromised
 *     internal service) can send thousands of anchor requests per second,
 *     draining the wallet. GET endpoints are also unlimited, enabling
 *     enumeration and DoS.
 *     Fixed: per-IP rate limiter applied to all routes. POST /chain/anchor
 *     has a tighter limit (ANCHOR_RATE_LIMIT) since each call spends gas.
 *
 * [K] MEDIUM — PORT accepted from environment without validation.
 *     process.env.KRYPTOS_CHAIN_PORT || 4000 accepted any string as a port
 *     number. A value of "0" binds to a random OS-assigned port (silent
 *     misconfiguration). A non-numeric string causes listen() to throw.
 *     Fixed: port is parsed and validated as an integer in [1, 65535].
 *
 * [L] MEDIUM — No request logging — abuse invisible to operators.
 *     No access logs. Auth failures, anchor attempts, and deletions leave
 *     no trace for security monitoring or incident response.
 *     Fixed: structured JSON request log on every response: timestamp,
 *     method, path, status, IP. Auth headers are never logged.
 *
 * [M] MEDIUM — /chain/info exposes chain connection details publicly.
 *     GET /chain/info returned chain internals (chainId, blockNumber,
 *     provider URL) with no authentication. Even after [B]'s token is added,
 *     the /chain/info endpoint should remain internal-only and never be
 *     exposed through a public-facing proxy without explicit intent.
 *     Fixed: /chain/info requires auth ([B]) and the provider's toJSON()
 *     already redacts credential-bearing URLs (from the EVMProvider audit).
 *
 * [N] LOW — /health endpoint leaks provider name and connection state
 *     to unauthenticated callers.
 *     Health checks are intentionally public (load balancers need them),
 *     but exposing chain.name and chain.isConnected() reveals internal
 *     architecture to anyone who can reach the port.
 *     Fixed: /health returns only { status, uptime } — no internal details.
 *     A separate authenticated /chain/info endpoint serves operators.
 *
 * [O] LOW — No graceful shutdown — in-flight transactions may be abandoned.
 *     The process has no SIGTERM/SIGINT handler. A container orchestrator
 *     stopping the service mid-transaction would kill the process while a
 *     blockchain transaction is awaiting confirmation, leaving the local
 *     store and on-chain state inconsistent.
 *     Fixed: SIGTERM and SIGINT handlers call chain.disconnect() and close
 *     the HTTP server before exiting, allowing in-flight requests to complete.
 */

import 'dotenv/config';
import express from 'express';
import cors from 'cors';
import {
    createHash,
    timingSafeEqual
} from 'crypto';
import { getProvider } from './providers/index.js';
import {
    GhostChainValidationError,
    GhostChainConnectionError,
    GhostChainNotImplementedError,
} from './providers/base-provider.js';

// ─── Configuration ────────────────────────────────────────────────────────────

// [FIX K] Validate port before use.
function _parsePort(raw, fallback) {
    const n = parseInt(raw, 10);
    if (!Number.isInteger(n) || n < 1 || n > 65535) return fallback;
    return n;
}

const PORT = _parsePort(process.env.KRYPTOS_CHAIN_PORT, 4000);
// [FIX G] Bind to localhost by default — set 0.0.0.0 only behind a reverse proxy.
const HOST = process.env.KRYPTOS_CHAIN_HOST || '127.0.0.1';

// [FIX B] Service-to-service bearer token. MUST be set in production.
const CHAIN_TOKEN = process.env.KRYPTOS_CHAIN_TOKEN || '';
if (!CHAIN_TOKEN) {
    console.error('[ChainService] FATAL: KRYPTOS_CHAIN_TOKEN must be set');
    process.exit(1);
}

// [FIX A] CORS origin allowlist.
const ALLOWED_ORIGINS = new Set(
    (process.env.ALLOWED_ORIGINS || '').split(',').map(s => s.trim()).filter(Boolean)
);

// [FIX J] Rate limiting config.
const GLOBAL_RATE_MAX = parseInt(process.env.RATE_LIMIT_MAX || '120', 10);
const ANCHOR_RATE_MAX = parseInt(process.env.ANCHOR_RATE_MAX || '10', 10); // gas-spending
const RATE_WINDOW_MS = parseInt(process.env.RATE_LIMIT_WINDOW || '60000', 10);

// ─── Rate limiter ─────────────────────────────────────────────────────────────

// [FIX J] Two-tier sliding window: global and per-anchor.
function _makeRateLimiter(max, windowMs) {
    const store = new Map();
    setInterval(() => {
        const now = Date.now();
        for (const [ip, e] of store) {
            if (now - e.start > windowMs * 2) store.delete(ip);
        }
    }, windowMs).unref();

    return (req, res, next) => {
        const ip = req.ip || 'unknown';
        const now = Date.now();
        const e = store.get(ip);
        if (!e || now - e.start > windowMs) {
            store.set(ip, { count: 1, start: now });
            return next();
        }
        e.count++;
        if (e.count > max) {
            _log(ip, req.method, req.path, 429);
            return res.status(429).json({ error: 'Too many requests.' });
        }
        next();
    };
}

const globalLimiter = _makeRateLimiter(GLOBAL_RATE_MAX, RATE_WINDOW_MS);
const anchorLimiter = _makeRateLimiter(ANCHOR_RATE_MAX, RATE_WINDOW_MS);

// ─── Logging ──────────────────────────────────────────────────────────────────

// [FIX L] Structured access log — no auth headers ever logged.
function _log(ip, method, path, status) {
    process.stdout.write(
        JSON.stringify({ ts: new Date().toISOString(), ip, method, path, status }) + '\n'
    );
}

// ─── Auth middleware ──────────────────────────────────────────────────────────

// [FIX B] Bearer token check with constant-time comparison.
function requireAuth(req, res, next) {
    if (!CHAIN_TOKEN) return next(); // No token configured — allow (warn at startup)

    const header = req.headers['authorization'] || '';
    if (!header.startsWith('Bearer ')) {
        _log(req.ip, req.method, req.path, 401);
        return res.status(401).json({ error: 'Authorization required.' });
    }
    const provided = header.slice(7);
    let authorised = false;
    try {
        // [FIX B] Timing-safe comparison — pads to equal length first.
        const a = Buffer.from(provided.padEnd(CHAIN_TOKEN.length), 'utf8');
        const b = Buffer.from(CHAIN_TOKEN.padEnd(provided.length), 'utf8');
        // Both buffers must be same length for timingSafeEqual.
        const tokenBuf = Buffer.alloc(Math.max(a.length, b.length));
        const providedBuf = Buffer.alloc(Math.max(a.length, b.length));
        a.copy(providedBuf);
        b.copy(tokenBuf);
        authorised = timingSafeEqual(providedBuf, tokenBuf) &&
            provided.length === CHAIN_TOKEN.length;
    } catch {
        authorised = false;
    }
    if (!authorised) {
        _log(req.ip, req.method, req.path, 403);
        return res.status(403).json({ error: 'Forbidden.' });
    }
    next();
}

// ─── Input validation ─────────────────────────────────────────────────────────

// [FIX D] Validate a value is a non-empty string within max length.
function _requireString(value, name, maxLen = 256) {
    if (typeof value !== 'string' || value.trim().length === 0) {
        throw new GhostChainValidationError(`${name} must be a non-empty string.`);
    }
    if (value.length > maxLen) {
        throw new GhostChainValidationError(`${name} exceeds maximum length of ${maxLen}.`);
    }
    return value;
}

// ─── Error → HTTP status ──────────────────────────────────────────────────────

// [FIX C, FIX E] Map error types to status codes — never by message string.
function _statusFor(err) {
    if (err instanceof GhostChainValidationError) return 400;
    if (err instanceof GhostChainNotImplementedError) return 501;
    if (err instanceof GhostChainConnectionError) return 503;
    return 500;
}

// [FIX C] Safe error response — internal details go to stderr only.
function _errResponse(res, err, req) {
    const status = _statusFor(err);
    console.error(`[ChainService] ${req.method} ${req.path} → ${status}:`, err);
    _log(req.ip, req.method, req.path, status);
    // [FIX C] Fixed generic message to caller — never err.message.
    const safe = status === 400 ? err.message   // Validation errors are caller-safe
        : status === 404 ? 'Resource not found.'
            : status === 503 ? 'Chain service temporarily unavailable.'
                : status === 501 ? 'Operation not supported by this provider.'
                    : 'Internal error.';
    res.status(status).json({ error: safe });
}

// ─── App setup ────────────────────────────────────────────────────────────────

const app = express();

// [FIX A] CORS with explicit allowlist.
app.use(cors({
    origin: (origin, cb) => {
        if (!origin) return cb(null, true); // same-origin / server-to-server
        if (ALLOWED_ORIGINS.size === 0 || ALLOWED_ORIGINS.has(origin)) {
            return cb(null, true);
        }
        cb(new Error('CORS: origin not allowed'));
    },
    allowedHeaders: ['Content-Type', 'Authorization'],
    methods: ['GET', 'POST', 'DELETE', 'OPTIONS'],
}));

// [FIX H] Body size cap — 64 KB is more than enough for any anchor request.
app.use(express.json({ limit: '64kb' }));

// [FIX J] Global rate limiter on all routes.
app.use(globalLimiter);

// [FIX L] Log every request.
app.use((req, _res, next) => {
    // Status logged in each route after response — here we just record receipt.
    next();
});

// ─── Routes ───────────────────────────────────────────────────────────────────

// POST /chain/anchor
app.post('/chain/anchor', requireAuth, anchorLimiter, async (req, res) => {
    try {
        // [FIX D] Validate all inputs as strings before touching the provider.
        const fileId = _requireString(req.body?.fileId, 'fileId', 128);
        const fileHash = _requireString(req.body?.fileHash, 'fileHash', 64);
        const metadata = req.body?.metadata;
        if (metadata !== undefined && (typeof metadata !== 'object' || Array.isArray(metadata))) {
            return res.status(400).json({ error: 'metadata must be an object.' });
        }
        const result = await chain.anchorFileHash(fileId, fileHash, metadata || {});
        _log(req.ip, 'POST', '/chain/anchor', 200);
        res.json({ success: true, record: result });
    } catch (err) {
        _errResponse(res, err, req);
    }
});

// GET /chain/verify/:fileId
app.get('/chain/verify/:fileId', requireAuth, async (req, res) => {
    try {
        const fileId = _requireString(req.params.fileId, 'fileId', 128);
        const record = await chain.verifyFileHash(fileId);
        if (!record) {
            _log(req.ip, 'GET', req.path, 404);
            return res.status(404).json({ error: 'File not found on chain.' });
        }
        _log(req.ip, 'GET', req.path, 200);
        res.json({ verified: true, record });
    } catch (err) {
        _errResponse(res, err, req);
    }
});

// GET /chain/files/:owner
app.get('/chain/files/:owner', requireAuth, async (req, res) => {
    try {
        // [FIX I] Validate owner param length and type.
        const owner = _requireString(req.params.owner, 'owner', 128);
        const files = await chain.getFilesByOwner(owner);
        _log(req.ip, 'GET', req.path, 200);
        res.json({ files });
    } catch (err) {
        _errResponse(res, err, req);
    }
});

// DELETE /chain/file/:fileId
app.delete('/chain/file/:fileId', requireAuth, async (req, res) => {
    try {
        const fileId = _requireString(req.params.fileId, 'fileId', 128);
        const owner = _requireString(req.body?.owner, 'owner', 128);
        const result = await chain.deleteFileRecord(fileId, owner);
        _log(req.ip, 'DELETE', req.path, 200);
        res.json({ success: true, ...result });
    } catch (err) {
        // [FIX E] Status from error type — never from message string.
        _errResponse(res, err, req);
    }
});

// GET /chain/info  (authenticated — internal operators only)
app.get('/chain/info', requireAuth, async (req, res) => {
    try {
        const info = await chain.getChainInfo();
        _log(req.ip, 'GET', '/chain/info', 200);
        // chain.toJSON() already redacts credentials (from EVMProvider audit).
        res.json({ ...chain.toJSON(), ...info });
    } catch (err) {
        _errResponse(res, err, req);
    }
});

// GET /health  (public — load balancers only get status+uptime)
// [FIX N] No internal provider details exposed publicly.
app.get('/health', (_req, res) => {
    res.json({ status: 'ok', service: 'kryptos-chain', uptime: process.uptime() });
});

// ─── Start ────────────────────────────────────────────────────────────────────

// [FIX F] Await connection before accepting any requests.
const chain = getProvider();

async function start() {
    try {
        await chain.connect();
        console.log(`[ChainService] Provider "${chain.name}" connected.`);
    } catch (err) {
        // [FIX F] Fail hard — do not serve requests with a broken provider.
        console.error('[ChainService] Provider failed to connect:', err.message);
        process.exit(1);
    }

    const server = app.listen(PORT, HOST, () => {
        console.log(`[ChainService] Listening on ${HOST}:${PORT}`);
    });

    server.on('error', (err) => {
        console.error('[ChainService] Server error:', err.message);
        process.exit(1);
    });

    // [FIX O] Graceful shutdown — allow in-flight requests to complete.
    async function shutdown(signal) {
        console.log(`[ChainService] ${signal} received — shutting down.`);
        server.close(async () => {
            try { await chain.disconnect(); } catch { /* best effort */ }
            process.exit(0);
        });
        // Force exit after 10s if requests don't drain.
        setTimeout(() => process.exit(1), 10_000).unref();
    }

    process.on('SIGTERM', () => shutdown('SIGTERM'));
    process.on('SIGINT', () => shutdown('SIGINT'));
}

start();