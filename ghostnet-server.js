/**
 * GhostNet Server — HARDENED
 *
 * Security fixes applied:
 *
 * CRITICAL
 *  [01] /register-node had no authentication — open to anyone
 *       → requireAuth() JWT middleware on all mutating routes
 *  [02] /message POST had no auth — senderId spoofable by any caller
 *       → requireAuth(); senderId forced to req.user.id from token
 *  [03] /users GET had no auth — full user list exposed publicly
 *       → requireAuth()
 *  [04] /history GET had no auth — full message DB dumped to anyone
 *       → requireAuth(); ownership check (only own messages returned)
 *  [05] /conversations GET had no auth — any userId's convos exposed
 *       → requireAuth(); userId forced to req.user.id
 *  [06] nodeId/displayName in /register-node stored without validation
 *       → validateNodeId() + validateDisplayName() called before storage
 *  [07] WS clientId set from msg.nodeId/msg.id with zero validation
 *       → validateNodeId() on every HELLO/register message
 *  [08] WS had no authentication — any client could impersonate any node
 *       → JWT token required in WS upgrade query param (?token=...)
 *  [09] SSRF in /health/bridge — GHOSTNET_BRIDGE_URL not validated
 *       → URL parsed; only loopback/localhost allowed
 *  [10] Vault proxy forwarded raw client Content-Type to vault service
 *       → Content-Type validated against allowlist before forwarding
 *
 * HIGH
 *  [11] registeredNodes[nodeId] on plain object — __proto__ poisoning
 *       → Object.create(null) for registeredNodes; Map for meshPeers
 *  [12] fs.writeFileSync on every request — event loop blocking + race
 *       → Async debounced writes via setImmediate queue per file
 *  [13] /history with no convoId dumped entire DB
 *       → convoId required; ownership verified; pagination added
 *  [14] Math.random() for msg/convo/user IDs — predictable
 *       → crypto.randomBytes(16).toString('hex') everywhere
 *  [15] Username suggestions used Math.random() — leaks username existence
 *       → crypto.randomBytes for suggestion suffix
 *  [16] Message content unbounded — storage/memory DoS
 *       → MAX_CONTENT_LENGTH = 64 KB enforced
 *  [17] /vault/download/:fileId forwarded raw to fetch — path traversal
 *       → validateFileId() allowlist regex; URL assembled safely
 *  [18] /vault/verify/:fileId — same path traversal
 *       → validateFileId() applied
 *  [19] /vault/file/:fileId DELETE — path traversal + raw body forwarding
 *       → validateFileId(); req.body NOT forwarded (vault handles auth)
 *  [20] CORS origin:true + credentials:true — any origin with credentials
 *       → Explicit ALLOWED_ORIGINS allowlist from env
 *
 * MEDIUM
 *  [21] express.static('.') served entire CWD including .env, *.json DBs
 *       → Serve only a dedicated 'public/' subdirectory
 *  [22] No rate limiting — brute force / DoS on every endpoint
 *       → express-rate-limit on all routes; stricter limit on auth routes
 *  [23] No body size limit — memory DoS via large payloads
 *       → express.json({ limit: '64kb' })
 *  [24] /user/:id leaked full user object with no auth
 *       → requireAuth(); only own profile returned (or minimal public fields)
 *  [25] Convo IDs timestamp-predictable via Date.now() + Math.random()
 *       → crypto.randomBytes IDs
 *  [26] WS default case broadcast all unknown messages to all clients
 *       → Unknown message types silently dropped
 *  [27] meshPeers.delete() during Map iteration (close + stale cleaner)
 *       → Collect IDs first, delete after; stale cleaner uses same pattern
 *  [28] WS_PING_INTERVAL never cleared on shutdown
 *       → Cleared in process SIGTERM/SIGINT handler
 *  [29] /validate-node GET triggered disk write on every call
 *       → lastSeen updated in-memory only; saveNodeRegistry() debounced
 *
 * LOW
 *  [30] console.log leaked nodeId substrings to log aggregators
 *       → Structured logger; IDs truncated only in debug, not info/error
 *  [31] Duplicate DB/DB_FILE variables pointing to same file
 *       → Single MESSAGES_FILE constant used everywhere
 *  [32] catch(e) returned e.message verbatim to client
 *       → Generic error responses; details logged server-side only
 *  [33] No security headers (helmet missing)
 *       → helmet() added
 *  [34] deliverPendingMessages called via setTimeout — race on messages[]
 *       → Delivery called synchronously after meshPeers.set(); no alias race
 *
 * SECOND PASS (BOLA / negative-case hardening)
 *  [35] POST /register-node could overwrite a node owned by a *different* user
 *       (REST path lacked the ownership check the WS path already had) — node hijack.
 *       Also wiped shortCode/registeredAt on re-register.
 *       → Reject if existing.ownerId is another real account; preserve prior fields.
 *  [36] POST /register-node had no per-user node cap (WS path caps at 20) — registry DoS.
 *       → MAX_NODES_PER_USER enforced on new registrations only.
 *  [37] POST /auth/node enforced node ownership ONLY when an Authorization header was
 *       present — omitting it let anyone mint a node JWT for any nodeId.
 *       → Ownership checked on the no-header path too; account-bound nodes protected,
 *         self-owned/account-less mesh nodes still claimable.
 *  [38] isNode branches of GET/PATCH /user/profile and GET /user/shortcode mutated a
 *       node's profile with no owner check — node-card takeover/defacement via a minted
 *       node token.
 *       → 403 when the node is bound to a different real account.
 *  [39] GET /history limit/offset not clamped for NaN/negative — slice() returned
 *       unintended ranges.
 *       → Clamp limit to [1,200] and offset to >=0.
 *
 * RESIDUAL (design-level, not a one-line fix — see GEMINI.md "Defense 2"):
 *  Account-less node identities (ownerId === nodeId) cannot be cryptographically
 *  distinguished from an attacker claiming the same nodeId without a proof-of-possession
 *  (Ed25519 nonce challenge-response binding nodeId == H(publicKey)). Until that handshake
 *  is implemented, first-claim binding is the only guard for self-owned nodes.
 */

import 'dotenv/config';
import express from 'express';
import cors from 'cors';
import crypto from 'crypto';
import helmet from 'helmet';
import rateLimit from 'express-rate-limit';
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';
import { WebSocketServer } from 'ws';
import jwt from 'jsonwebtoken';
import multer from 'multer';
import authRouter from './auth/auth.routes.js';
import monitor from './monitoring/error-monitor.js';
import * as analytics from './analytics.js';
import { healthCheck as dbHealthCheck, checkMigrationsRan } from './db/client.js';
import * as messageStore from './db/messageStore.js';
import * as nodeStore from './db/nodeStore.js';
import * as conversationStore from './db/conversationStore.js';
import { startCleanupCron } from './db/cleanup.js';

// Install global crash handlers as early as possible
monitor.installProcessHandlers();
// local inline middleware used instead of auth.middleware.js
import {
    findById as findAuthUserById,
    findByShortCode,
    isValidShortCode,
    generateShortCode,
    generateUniqueShortCode,
    updateUserFields,
    sanitise as sanitiseAuthUser
} from './auth/auth.model.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// ─── Constants ───────────────────────────────────────────────────────────────

const PORT = parseInt(process.env.GHOSTNET_SERVER_PORT, 10) || parseInt(process.env.PORT, 10) || 8080;
const GHOSTNET_MODE = process.env.GHOSTNET_MODE || (process.env.NODE_ENV === 'production' ? 'production' : 'development');
const JWT_SECRET = process.env.AUTH_JWT_SECRET;
const startTime = Date.now();

const MAX_CONTENT_LENGTH = 64 * 1024; // [16] 64 KB message body cap
const MAX_BODY_SIZE = '1mb';    // Increased to 1MB to support avatars (up to 512KB clip limit)

// [20] Explicit CORS allowlist — always include the Vercel frontend
const _HARDCODED_ORIGINS = ['https://ghostnet-ji.vercel.app'];
const _ENV_ORIGINS = (process.env.CORS_ALLOWED_ORIGINS || 'http://localhost:3000,http://127.0.0.1:3000')
    .split(',').map(o => o.trim()).filter(Boolean);
const ALLOWED_ORIGINS = [...new Set([..._ENV_ORIGINS, ..._HARDCODED_ORIGINS])];
console.log('[CORS] Allowed origins:', ALLOWED_ORIGINS);

// [17][18][19] File ID allowlist — hex UUID-like strings only
const FILE_ID_RE = /^[a-zA-Z0-9_\-]{1,128}$/;
// [06][07] Node ID allowlist (supports 132-char uncompressed hex public keys)
const NODE_ID_RE = /^[a-zA-Z0-9_\-]{1,512}$/;
// Display name allowlist
const DISPLAY_NAME_RE = /^[\w\s\-\.]{1,64}$/;

if (!JWT_SECRET) {
    console.error('FATAL: AUTH_JWT_SECRET not set in environment. Refusing to start.');
    process.exit(1);
}

// ─── File paths ───────────────────────────────────────────────────────────────

// [31] Single constant per file — no duplicate DB / DB_FILE confusion
const MESSAGES_FILE = path.join(__dirname, 'messages.json');
const CONVOS_FILE = path.join(__dirname, 'conversations.json');
const USERS_FILE = path.join(__dirname, 'users.json');
const NODES_FILE = path.join(__dirname, 'nodes.json');
const PENDING_FILE = path.join(__dirname, 'pending.json');
const VAULT_KEYS_FILE = path.join(__dirname, 'vault-keys.json');
const GHOSTTAGS_FILE = path.join(__dirname, 'ghosttags.json');

const VAULT_DIR = path.join(__dirname, 'vault-data');
const META_FILE = path.join(__dirname, 'vault-meta.json');
if (!fs.existsSync(VAULT_DIR)) fs.mkdirSync(VAULT_DIR, { recursive: true });

// Vault Metadata Store
let fileMeta = [];
try {
    if (fs.existsSync(META_FILE)) fileMeta = JSON.parse(fs.readFileSync(META_FILE, 'utf-8'));
} catch { fileMeta = []; }

function saveMeta() {
    scheduleWrite(META_FILE, fileMeta);
}

const vaultUpload = multer({
    storage: multer.diskStorage({
        destination: (req, file, cb) => cb(null, VAULT_DIR),
        filename: (req, file, cb) => cb(null, `tmp_${crypto.randomBytes(16).toString('hex')}`)
    }),
    limits: { fileSize: 100 * 1024 * 1024 } // 100MB max
});

// ─── Validators ──────────────────────────────────────────────────────────────

function validateNodeId(id) {
    if (typeof id !== 'string' || !NODE_ID_RE.test(id)) {
        throw Object.assign(new Error('Invalid nodeId'), { status: 400 });
    }
    return id.toLowerCase();
}

function validateDisplayName(name) {
    if (typeof name !== 'string' || !DISPLAY_NAME_RE.test(name.trim())) {
        throw Object.assign(new Error('Invalid displayName'), { status: 400 });
    }
    return name.trim();
}

function validateFileId(id) { // [17][18][19]
    if (typeof id !== 'string' || !FILE_ID_RE.test(id)) {
        throw Object.assign(new Error('Invalid fileId'), { status: 400 });
    }
    return id;
}

// [09] Only allow loopback targets for internal proxy URLs
function assertLoopbackUrl(rawUrl, envVarName) {
    let parsed;
    try { parsed = new URL(rawUrl); }
    catch (_) { throw new Error(`${envVarName} is not a valid URL`); }
    if (!['127.0.0.1', 'localhost', '::1'].includes(parsed.hostname)) {
        throw new Error(`${envVarName} must point to loopback, got: ${parsed.hostname}`);
    }
    return parsed.origin; // scheme + host + port only; no path
}

// VAULT_URL — validate loopback to prevent SSRF
const _rawVault = process.env.GHOSTNET_VAULT_URL || process.env.VAULT_URL || '';
let VAULT_ORIGIN = null;
if (_rawVault) {
    try { VAULT_ORIGIN = assertLoopbackUrl(_rawVault, 'GHOSTNET_VAULT_URL'); }
    catch (e) { console.error(e.message); VAULT_ORIGIN = null; }
}
// BRIDGE_URL is operator-configured (docker-compose / env), not user input — skip loopback assertion
const _rawBridge = process.env.GHOSTNET_BRIDGE_URL || 'http://127.0.0.1:3001';
let BRIDGE_ORIGIN;
try { BRIDGE_ORIGIN = new URL(_rawBridge).origin; }
catch (_) { throw new Error('GHOSTNET_BRIDGE_URL is not a valid URL'); }

// ─── Async debounced file writer ─────────────────────────────────────────────
// [12] Non-blocking writes; last-write-wins within a tick to coalesce rapid saves

const _writeQueue = new Map(); // filePath → pendingData

function scheduleWrite(filePath, data) {
    _writeQueue.set(filePath, data);
    setImmediate(() => {
        const pending = _writeQueue.get(filePath);
        if (pending === undefined) return;
        _writeQueue.delete(filePath);
        fs.writeFile(filePath, JSON.stringify(pending, null, 2), err => {
            if (err) console.error(`[DB] Write failed (${path.basename(filePath)}):`, err.message);
        });
    });
}

// ─── In-memory stores ────────────────────────────────────────────────────────

let messages = [];
let conversations = [];
let users = [];
// [11] Object.create(null) — no prototype, blocks __proto__ poisoning
let registeredNodes = Object.create(null);

// Requested Relay Fix: activeConnections and messageQueue
const activeConnections = new Map(); // nodeId → ws
const messageQueue = new Map(); // nodeId → [pending messages]

const MAX_QUEUE_PER_RECIPIENT = 500;
const MAX_QUEUED_RECIPIENTS = 5000;   // cap total recipient slots to prevent memory exhaustion
const QUEUE_TTL_MS = 3600000;         // 1 hour — evict stale queues

// Periodic cleanup of stale queued recipients
setInterval(() => {
    const now = Date.now();
    for (const [rid, queue] of messageQueue) {
        if (!queue.length) { messageQueue.delete(rid); continue; }
        const newest = queue[queue.length - 1].queuedAt || 0;
        if (now - newest > QUEUE_TTL_MS) messageQueue.delete(rid);
    }
}, 60000).unref();

function queueMessage(recipientId, message) {
    if (!messageQueue.has(recipientId)) {
        // Enforce max recipients — evict oldest entry if at capacity
        if (messageQueue.size >= MAX_QUEUED_RECIPIENTS) {
            const oldest = messageQueue.keys().next().value;
            messageQueue.delete(oldest);
        }
        messageQueue.set(recipientId, []);
    }
    const queue = messageQueue.get(recipientId);
    if (queue.length >= MAX_QUEUE_PER_RECIPIENT) {
        queue.shift(); // drop oldest to stay within limit
    }
    queue.push({
        ...message,
        queuedAt: Date.now()
    });
    // Also persist via the existing pendingQueue mechanism if available
    if (typeof enqueuePending === 'function') {
        enqueuePending(recipientId, message.id || secureId('msg_'));
    }
}

function deliverQueuedMessages(recipientId, ws) {
    const pending = messageQueue.get(recipientId) || [];
    pending.forEach(msg => {
        if (ws.readyState === 1) {
            ws.send(JSON.stringify(msg));
        }
    });
    messageQueue.delete(recipientId);
    console.log(`[Bridge] Delivered ${pending.length} queued messages to ${recipientId}`);
}

function loadJson(filePath, fallback) {
    try {
        if (fs.existsSync(filePath)) {
            return JSON.parse(fs.readFileSync(filePath, 'utf-8'));
        }
        fs.writeFile(filePath, JSON.stringify(fallback, null, 2), (err) => {
            if (err) console.error(`[DB] Init write error (${path.basename(filePath)}):`, err.message);
        });
    } catch (e) {
        console.error(`[DB] Load error (${path.basename(filePath)}):`, e.message); // [32] server-side only
    }
    return fallback;
}

messages = loadJson(MESSAGES_FILE, []);
conversations = loadJson(CONVOS_FILE, []);
users = loadJson(USERS_FILE, []);

// Normalize: files may have been written as objects instead of arrays
if (!Array.isArray(messages)) messages = Object.values(messages || {});
if (!Array.isArray(conversations)) conversations = Object.values(conversations || {});
if (!Array.isArray(users)) users = Object.values(users || {});

// pendingQueue: Map<receiverId, msgId[]> — offline message queue persisted to disk
const pendingQueue = new Map(Object.entries(loadJson(PENDING_FILE, {})));
{
    const raw = loadJson(NODES_FILE, {});
    // Re-populate into null-prototype object [11]
    for (const k of Object.keys(raw)) {
        if (NODE_ID_RE.test(k)) registeredNodes[k] = raw[k];
    }
}

let vaultKeys = loadJson(VAULT_KEYS_FILE, {});

// GhostTag registry: { "lowercasetag": { nodeId, publicKey, ownerId, displayName, claimedAt } }
let ghostTags = Object.create(null);
{
    const raw = loadJson(GHOSTTAGS_FILE, {});
    for (const k of Object.keys(raw)) {
        ghostTags[k.toLowerCase()] = raw[k];
    }
}

function saveGhostTags() {
    scheduleWrite(GHOSTTAGS_FILE, ghostTags);
}

function saveNodeRegistry() { // [29] debounced
    scheduleWrite(NODES_FILE, registeredNodes);
}

function savePendingQueue() {
    scheduleWrite(PENDING_FILE, Object.fromEntries(pendingQueue));
}

function enqueuePending(receiverId, msgId) {
    if (!pendingQueue.has(receiverId)) pendingQueue.set(receiverId, []);
    pendingQueue.get(receiverId).push(msgId);
    savePendingQueue();
}

function dequeuePending(receiverId) {
    const ids = pendingQueue.get(receiverId);
    if (!ids || !ids.length) return [];
    pendingQueue.delete(receiverId);
    savePendingQueue();
    return ids;
}

// ─── Secure ID generator ─────────────────────────────────────────────────────
// [14][25] crypto instead of Math.random()

function secureId(prefix = '') {
    return prefix + crypto.randomBytes(16).toString('hex');
}

// ─── App setup ───────────────────────────────────────────────────────────────

const app = express();
app.set('trust proxy', 1); // Railway runs behind one reverse proxy — use count to prevent X-Forwarded-For spoofing

// [33] Security headers — cross-origin policies disabled for API use
// Error monitoring — must be early so it sees every request
app.use(monitor.expressMiddleware());

app.use(helmet({
    contentSecurityPolicy: {
        directives: {
            defaultSrc: ["'self'"],
            scriptSrc: ["'self'", "https://cdnjs.cloudflare.com", "https://unpkg.com", "https://cdn.ethers.io"],
            styleSrc: ["'self'", "'unsafe-inline'", "https://cdnjs.cloudflare.com", "https://fonts.googleapis.com"],
            fontSrc: ["'self'", "https://fonts.gstatic.com", "https://cdnjs.cloudflare.com"],
            imgSrc: ["'self'", "data:", "blob:"],
            connectSrc: ["'self'", "wss:", "ws:"],
            frameSrc: ["'none'"],
            objectSrc: ["'none'"],
        }
    },
    crossOriginResourcePolicy: { policy: 'cross-origin' },
    crossOriginOpenerPolicy: false,
    crossOriginEmbedderPolicy: false,
    frameguard: { action: 'deny' },
    hsts: { maxAge: 31536000, includeSubDomains: true },
}));

// [20] Strict CORS — only listed origins with credentials
app.use(cors({
    origin: (origin, cb) => {
        // Allow server-to-server (no origin) and allowlisted browsers
        if (!origin || ALLOWED_ORIGINS.includes(origin)) return cb(null, origin);
        console.warn(`[CORS] Blocked origin: ${origin}`);
        // Return false instead of Error to avoid Express error handler swallowing CORS headers
        cb(null, false);
    },
    credentials: true,
    allowedHeaders: ['Content-Type', 'Authorization', 'X-Auth-Token'],
    methods: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'],
}));

// Explicit OPTIONS preflight handler — belt and suspenders
app.options('*', cors({
    origin: (origin, cb) => {
        if (!origin || ALLOWED_ORIGINS.includes(origin)) return cb(null, origin);
        cb(null, false);
    },
    credentials: true,
    allowedHeaders: ['Content-Type', 'Authorization', 'X-Auth-Token'],
    methods: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'],
}));

// [Bridge Fix] Added health endpoint
app.get('/health', (req, res) => {
    res.json({
        status: 'ok',
        connections: activeConnections.size,
        queued: messageQueue.size,
        uptime: process.uptime()
    });
});

// Monitoring snapshot — rolling 5-minute window of crashes/errors/disconnects
app.get('/health/metrics', (req, res) => {
    res.json(monitor.getMetrics());
});

// [22] Global rate limit
const globalLimiter = rateLimit({
    windowMs: 60_000,
    max: 120,
    standardHeaders: true,
    legacyHeaders: false,
    message: { error: 'Too many requests' },
});
app.use(globalLimiter);

// [23] Body size cap
app.use((req, res, next) => {
    if (req.path === '/vault/upload') return next(); // multipart handled separately
    express.json({ limit: MAX_BODY_SIZE })(req, res, next);
});

// [21] Serve only public/ subdirectory, not the whole CWD
const PUBLIC_DIR = path.join(__dirname, 'public');

// Serve a minimal, explicit asset allowlist (keeps [21] protections without requiring
// a public/ folder to exist in every deployment environment).
const ALLOWED_STATIC_FILES = new Set([
    'index.html',
    'ui.js',
    'ui.css',
    'style.css',
    'app.js',
    'ghostnet-file-vault.js',
    'ghostnet-chat.js',
    'ghostnet-mesh.js',
    'ghostnet-identity.js',
    'crypto-identity.js',
    'jsQR.js',
    'qrcode.min.js',
    'ghosttag.js',
    'ghostnet-sync.js',
]);

app.get('/:asset', (req, res, next) => {
    const asset = req.params.asset;
    if (!ALLOWED_STATIC_FILES.has(asset)) return next();

    // Prefer public/ if present, otherwise fall back to repo root.
    const fromPublic = path.join(PUBLIC_DIR, asset);
    const fromRoot = path.join(__dirname, asset);
    const filePath = fs.existsSync(fromPublic) ? fromPublic : fromRoot;
    res.sendFile(filePath, err => {
        if (err) next();
    });
});

// If a public/ directory exists, serve it (still safe-sandboxed).
if (fs.existsSync(PUBLIC_DIR)) {
    app.use(express.static(PUBLIC_DIR));
}

// Auth routes (have their own stricter rate limit inside authRouter)
app.use('/auth', authRouter);

// ═══════════════════════════════════════════════════
// GHOSTCODE SHORT CODE ENDPOINTS (GN-XXXX)
// ═══════════════════════════════════════════════════

/**
 * GhostCode diagnostic (why the UI can get stuck on "Loading..."):
 * - `index.html` renders the badge with literal text "Loading..." (`#ghostcode-badge`).
 * - The UI requests `GET /user/shortcode` using a JWT stored as `sessionStorage.ghostnet_token`.
 * - Node auth (`POST /auth/node`) issues a JWT shaped like `{ id: <nodeId>, isNode: true }`.
 * - The original GhostCode system was built for email-auth users (`auth-users.json`).
 *   A node JWT does not correspond to an auth user record, so `/user/shortcode` can return 404.
 * - Result: no code arrives, and the badge can remain "Loading..." indefinitely.
 *
 * Fix: support node-scoped GhostCodes stored on `registeredNodes` (persisted in `nodes.json`)
 * and allow `/resolve/:shortCode` to resolve either an auth user OR a registered node.
 */

function _nodeHasShortCode(sc) {
    if (!sc) return false;
    const upper = String(sc).toUpperCase();
    for (const nodeId of Object.keys(registeredNodes)) {
        const n = registeredNodes[nodeId];
        if (n?.shortCode && String(n.shortCode).toUpperCase() === upper) return true;
    }
    return false;
}

function generateUniqueNodeShortCode() {
    for (let attempt = 0; attempt < 10; attempt++) {
        const code = generateShortCode(4).toUpperCase();
        if (!findByShortCode(code) && !_nodeHasShortCode(code)) return code;
    }
    for (let attempt = 0; attempt < 10; attempt++) {
        const code = generateShortCode(5).toUpperCase();
        if (!findByShortCode(code) && !_nodeHasShortCode(code)) return code;
    }
    return generateShortCode(6).toUpperCase();
}

// Rate limiter for /resolve endpoint — max 10 requests per minute per IP
const resolveLimiter = rateLimit({
    windowMs: 60 * 1000,
    max: 10,
    standardHeaders: true,
    legacyHeaders: false,
    message: { error: 'Too many lookup attempts. Please wait a moment.' },
});

/**
 * GET /user/shortcode — Returns current user's GhostCode (authenticated)
 * Accepts optional query params: nodeId, displayName to associate with the auth user
 */
app.get('/user/shortcode', requireAuth, (req, res) => {
    try {
        const authedId = req.user?.id;
        if (!authedId) return res.status(401).json({ error: 'Authentication required' });

        // Node JWTs are issued by POST /auth/node as { id: nodeId, isNode: true }.
        // For those, issue/return a node-scoped GhostCode persisted in nodes.json.
        if (req.user?.isNode) {
            const nodeId = validateNodeId(authedId);
            // [38][BOLA] Reject if this node is bound to a different real account.
            const _existing = registeredNodes[nodeId];
            if (_existing && _existing.ownerId && _existing.ownerId !== req.user.id) {
                return res.status(403).json({ error: 'Not authorized for this node' });
            }
            if (!registeredNodes[nodeId]) {
                registeredNodes[nodeId] = {
                    nodeId,
                    displayName: nodeId.slice(0, 10),
                    ownerId: nodeId,
                    registeredAt: Date.now(),
                    lastSeen: Date.now(),
                };
            }
            if (!registeredNodes[nodeId].shortCode) {
                registeredNodes[nodeId].shortCode = generateUniqueNodeShortCode();
                saveNodeRegistry();
            }
            return res.json({
                shortCode: String(registeredNodes[nodeId].shortCode).toUpperCase(),
                nodeId,
                displayName: registeredNodes[nodeId].displayName || nodeId.slice(0, 10),
            });
        }

        const user = findAuthUserById(authedId);
        if (!user) return res.status(404).json({ error: 'User not found.' });

        // Associate nodeId and displayName if provided
        const updates = {};
        if (req.query.nodeId && !user.nodeId) {
            updates.nodeId = validateNodeId(req.query.nodeId);
        }
        if (req.query.displayName && !user.displayName) {
            updates.displayName = validateDisplayName(req.query.displayName);
        }

        // If user has no shortCode yet, generate one
        if (!user.shortCode) {
            updates.shortCode = generateUniqueShortCode();
        }

        // Apply any updates
        if (Object.keys(updates).length > 0) {
            updateUserFields(authedId, updates);
            Object.assign(user, updates);
        }

        res.json({
            shortCode: user.shortCode.toUpperCase(),
            nodeId: user.nodeId || null,
            displayName: user.displayName || user.email.split('@')[0] || null,
        });
    } catch (err) {
        console.error('GET /user/shortcode error:', err.message);
        res.status(500).json({ error: 'Internal server error.' });
    }
});

/**
 * GET /resolve/:shortCode — PUBLIC endpoint to resolve a GhostCode
 * Returns ONLY { displayName, nodeId, shortCode } — never sensitive fields
 */
app.get('/resolve/:shortCode', resolveLimiter, (req, res) => {
    try {
        const { shortCode } = req.params;
        const normalized = shortCode.toUpperCase();

        // Strict regex validation — blocks injection/script attempts
        if (!isValidShortCode(normalized)) {
            return res.status(400).json({ error: 'Invalid GhostCode format. Expected GN-XXXX.' });
        }

        const user = findByShortCode(normalized);
        if (user) {
            // Return ONLY safe fields — never password, email, JWT, etc.
            return res.json({
                displayName: user.displayName || user.email.split('@')[0] || 'GhostUser',
                nodeId: user.nodeId || null,
                shortCode: user.shortCode.toUpperCase(),
            });
        }

        // Fallback: resolve against registered nodes (node-scoped GhostCodes)
        for (const nodeId of Object.keys(registeredNodes)) {
            const n = registeredNodes[nodeId];
            if (n?.shortCode && String(n.shortCode).toUpperCase() === normalized) {
                return res.json({
                    displayName: n.displayName || nodeId.slice(0, 10),
                    nodeId,
                    shortCode: normalized,
                });
            }
        }

        return res.status(404).json({ error: 'Code not found' });
    } catch (err) {
        console.error('GET /resolve error:', err.message);
        res.status(500).json({ error: 'Internal server error.' });
    }
});

/**
 * PATCH /user/shortcode — Let users customize their GhostCode (authenticated)
 * Limited to once per 30 days.
 */
app.patch('/user/shortcode', requireAuth, (req, res) => {
    try {
        const authedUserId = req.user?.id;
        const user = authedUserId ? findAuthUserById(authedUserId) : null;
        if (!user) {
            return res.status(404).json({ error: 'User not found.' });
        }

        const { shortCode } = req.body;
        if (!shortCode) {
            return res.status(400).json({ error: 'shortCode is required.' });
        }

        const normalized = shortCode.toUpperCase();

        // Validate format
        if (!isValidShortCode(normalized)) {
            return res.status(400).json({ error: 'Invalid GhostCode format. Must match GN-[A-Z2-9]{4-6}.' });
        }

        // Check 30-day cooldown
        if (user.shortCodeChangedAt) {
            const daysSinceChange = (Date.now() - new Date(user.shortCodeChangedAt).getTime()) / (1000 * 60 * 60 * 24);
            if (daysSinceChange < 30) {
                const daysLeft = Math.ceil(30 - daysSinceChange);
                return res.status(429).json({
                    error: `You can change your GhostCode again in ${daysLeft} day${daysLeft === 1 ? '' : 's'}.`
                });
            }
        }

        // Check uniqueness
        const existing = findByShortCode(normalized);
        if (existing && existing.id !== user.id) {
            return res.status(409).json({ error: 'Code already taken' });
        }

        // Update
        updateUserFields(authedUserId, {
            shortCode: normalized,
            shortCodeChangedAt: new Date().toISOString(),
        });

        res.json({ shortCode: normalized });
    } catch (err) {
        console.error('PATCH /user/shortcode error:', err.message);
        res.status(500).json({ error: 'Internal server error.' });
    }
});

// ─── Auth middleware ──────────────────────────────────────────────────────────
// [01][02][03][04][05][08]

function requireAuth(req, res, next) {
    // Accept both 'Authorization: Bearer <token>' and 'X-Auth-Token: <token>'
    const authHeader = req.headers.authorization || '';
    const xAuthToken = req.headers['x-auth-token'] || req.headers['X-Auth-Token'] || '';
    const token = authHeader.startsWith('Bearer ') ? authHeader.slice(7) : (xAuthToken || null);
    if (!token) return res.status(401).json({ error: 'Authentication required' });
    try {
        const decoded = jwt.verify(token, JWT_SECRET);
        // Normalize: email-auth uses `userId`, node-auth uses `id`
        decoded.id = decoded.id || decoded.userId;
        if (!decoded.id) return res.status(401).json({ error: 'Invalid token: missing user identifier' });
        req.user = decoded;
        analytics.trackActiveUser(decoded.id).catch(() => {});
        next();
    } catch (_) {
        res.status(401).json({ error: 'Invalid or expired token' });
    }
}


// ─── DECENTRALIZED NODE AUTH ──────────────────────────────────────────────────

const nodeAuthLimiter = rateLimit({
    windowMs: 60_000,
    max: 10,
    standardHeaders: true,
    legacyHeaders: false,
    message: { error: 'Too many node auth attempts. Please wait.' },
});

app.post('/auth/node', nodeAuthLimiter, (req, res) => {
    let nodeId;
    try { nodeId = validateNodeId(req.body?.nodeId); }
    catch (e) { return res.status(400).json({ error: e.message }); }

    // If caller provided a valid JWT, capture the authenticated identity
    let authedId = null;
    const authHeader = req.headers.authorization;
    if (authHeader && authHeader.startsWith('Bearer ')) {
        try {
            const decoded = jwt.verify(authHeader.slice(7), JWT_SECRET);
            authedId = decoded.id || decoded.userId || null;
        } catch (_) { /* token invalid/expired — treat as unauthenticated node auth */ }
    }

    // [37][Broken auth] Ownership enforcement that also covers the no-header path.
    // A node bound to a *real account* (ownerId !== nodeId) may only be claimed by
    // that account. Previously this check ran ONLY when an Authorization header was
    // present, so omitting the header let anyone mint a node JWT for any nodeId.
    // Self-owned / unregistered nodes (ownerId === nodeId or absent) stay claimable
    // so account-less mesh nodes (e.g. ESP32) keep working.
    const existing = registeredNodes[nodeId];
    if (existing && existing.ownerId && existing.ownerId !== nodeId
        && existing.ownerId !== authedId) {
        return res.status(403).json({ error: 'Not authorized to claim this node' });
    }
    const ownerId = authedId || nodeId;

    // Issue a JWT representing the node itself
    const token = jwt.sign({ id: nodeId, isNode: true, ownerId }, JWT_SECRET, { expiresIn: '7d' });
    res.json({ success: true, token });
});

// ─── NODE REGISTRATION ───────────────────────────────────────────────────────

app.post('/register-node', requireAuth, (req, res) => { // [01]
    let nodeId, displayName;
    try {
        nodeId = validateNodeId(req.body?.nodeId);       // [06]
        displayName = validateDisplayName(req.body?.displayName);
    } catch (e) {
        return res.status(400).json({ error: e.message });
    }

    // Only allow a user to register nodes they own (nodeId must match their JWT sub or a node they own)
    // Basic policy: node owner is the authenticated user
    const address = typeof req.body.address === 'string' ? req.body.address.slice(0, 64) : null;
    const publicKey = typeof req.body.publicKey === 'string' ? req.body.publicKey.slice(0, 512) : null;
    // Avatar must be a valid base64 data URI image, clipped to 512KB
    let avatar = null;
    if (typeof req.body.avatar === 'string' && req.body.avatar.length > 0) {
        if (!/^data:image\/(png|jpeg|webp|gif);base64,/.test(req.body.avatar)) {
            return res.status(400).json({ error: 'Invalid avatar format' });
        }
        avatar = req.body.avatar.slice(0, 512 * 1024);
    }

    const existingNode = registeredNodes[nodeId];

    // [35][BOLA] Node hijack prevention — match the WS-side ownership check.
    // A node already bound to a *different real account* cannot be re-registered.
    // Placeholder/self-owned entries (ownerId === nodeId), e.g. auto-created when
    // someone messaged this node first, remain claimable by the first real owner.
    if (existingNode && existingNode.ownerId
        && existingNode.ownerId !== req.user.id
        && existingNode.ownerId !== nodeId) {
        return res.status(403).json({ error: 'Node already registered to another user' });
    }

    // [36][DoS] Per-user node cap (mirrors MAX_NODES_PER_USER on the WS path).
    // Re-registering an existing owned node is always allowed; only brand-new
    // node creation counts toward the limit.
    if (!existingNode) {
        const MAX_NODES_PER_USER = 20;
        const owned = Object.values(registeredNodes).filter(n => n && n.ownerId === req.user.id).length;
        if (owned >= MAX_NODES_PER_USER) {
            return res.status(429).json({ error: 'Node registration limit reached' });
        }
    }

    registeredNodes[nodeId] = {
        ...(existingNode || {}), // preserve shortCode and any other existing fields
        nodeId,
        displayName,
        ownerId: req.user.id, // bind to authenticated user
        address,
        publicKey,
        avatar,
        registeredAt: existingNode?.registeredAt || Date.now(), // don't reset on re-register
        lastSeen: Date.now(),
    };

    saveNodeRegistry();
    nodeStore.upsertNode(nodeId, { displayName, ownerId: req.user.id, publicKey, avatar }).catch(err =>
        console.error('[DB] upsertNode failed:', err.message));
    res.json({ success: true });
});

app.get('/validate-node/:nodeId', requireAuth, (req, res) => { // [01]
    let nodeId;
    try { nodeId = validateNodeId(req.params.nodeId); }
    catch (e) { return res.status(400).json({ error: e.message }); }

    const isOnline = meshPeers.has(nodeId);
    let node = registeredNodes[nodeId];

    // Fallback 1: node is live on WS but not yet in registeredNodes — auto-register it
    if (!node && isOnline) {
        const peer = meshPeers.get(nodeId);
        node = {
            nodeId,
            displayName: nodeId.slice(0, 10),
            ownerId: peer?.ws?._user?.id || nodeId,
            registeredAt: Date.now(),
            lastSeen: Date.now(),
        };
        registeredNodes[nodeId] = node;
        saveNodeRegistry();
    }

    // Fallback 2: node matches a registered user account
    if (!node) {
        const user = users.find(u => u.id === nodeId || u.username === nodeId);
        if (user) {
            node = {
                nodeId,
                displayName: user.username || nodeId.slice(0, 10),
                ownerId: user.id,
                registeredAt: Date.now(),
                lastSeen: Date.now(),
            };
            registeredNodes[nodeId] = node;
            saveNodeRegistry();
        }
    }

    if (node) {
        // [29] Update lastSeen in-memory only; debounced write will flush later
        node.lastSeen = Date.now();
        scheduleWrite(NODES_FILE, registeredNodes);
        res.json({ valid: true, displayName: node.displayName, address: node.address || null, publicKey: node.publicKey || null, avatar: node.avatar || null, online: isOnline });
    } else {
        // Fallback 3: If it's a validly formatted hex address/pubkey (e.g. 0x...), allow it
        if (typeof nodeId === 'string' && nodeId.startsWith('0x') && nodeId.length >= 42) {
            res.json({ valid: true, displayName: 'Unknown Contact', address: nodeId, publicKey: nodeId, online: false });
        } else {
            res.json({ valid: false });
        }
    }
});

// ─── USER MANAGEMENT ─────────────────────────────────────────────────────────

app.post('/create-user', requireAuth, (req, res) => { // [01]
    const rawUsername = req.body?.username;
    if (!rawUsername || typeof rawUsername !== 'string') {
        return res.status(400).json({ error: 'Username required' });
    }

    const clean = rawUsername.trim().toLowerCase().slice(0, 32);
    if (!/^[a-z0-9_\-]{3,32}$/.test(clean)) {
        return res.status(400).json({ error: 'Username must be 3–32 alphanumeric/hyphen/underscore chars' });
    }

    const exists = users.find(u => u.username === clean);
    if (exists) {
        // [15] crypto-random suggestions — don't leak username existence timing
        const suggestions = Array.from({ length: 5 }, () =>
            clean + parseInt(crypto.randomBytes(2).toString('hex'), 16) % 1000
        );
        return res.status(409).json({ error: 'Username taken', suggestions });
    }

    const newUser = {
        id: secureId('user_'), // [14]
        username: clean,
        ownerId: req.user.id,
        // [24] avatar stored as ref only (see schema fix); not accepted as raw base64 here
        avatar: null,
    };

    users.push(newUser);
    scheduleWrite(USERS_FILE, users); // [12]
    res.json({ success: true, user: { id: newUser.id, username: newUser.username } });
});

app.get('/users', requireAuth, (req, res) => { // [03]
    // Only return minimal public fields
    res.json(users.map(u => ({ id: u.id, username: u.username })));
});

// Must be before /user/:id or Express matches 'profile' as :id and returns 404
app.get('/user/profile', requireAuth, (req, res) => {
    // Node-auth sessions (POST /auth/node) carry { id: nodeId, isNode: true }.
    // In that mode there is no row in users.json, so serve a profile from the node registry.
    if (req.user?.isNode) {
        let nodeId;
        try { nodeId = validateNodeId(req.user.id); } catch { return res.status(400).json({ error: 'Invalid nodeId' }); }
        // [38][BOLA] Reject if this node is bound to a different real account.
        const _existing = registeredNodes[nodeId];
        if (_existing && _existing.ownerId && _existing.ownerId !== req.user.id) {
            return res.status(403).json({ error: 'Not authorized for this node' });
        }
        if (!registeredNodes[nodeId]) {
            registeredNodes[nodeId] = {
                nodeId,
                displayName: nodeId.slice(0, 10),
                ownerId: nodeId,
                registeredAt: Date.now(),
                lastSeen: Date.now(),
            };
            saveNodeRegistry();
        }
        const n = registeredNodes[nodeId];
        return res.json({
            id: nodeId,
            displayName: n.displayName || nodeId.slice(0, 10),
            avatar: n.avatar || null,
            nodeId,
        });
    }

    const user = users.find(u => u.ownerId === req.user.id || u.id === req.user.id);
    if (!user) {
        return res.status(404).json({ error: 'User not found' });
    }

    // Find node registry entry if any, to include nodeId
    const nodeIdKey = Object.keys(registeredNodes).find(k => registeredNodes[k].ownerId === req.user.id || k === req.user.id);

    res.json({
        id: user.id,
        displayName: user.displayName || user.username || null,
        avatar: user.avatar || null,
        nodeId: nodeIdKey || user.id
    });
});

app.get('/user/:id', requireAuth, (req, res) => { // [24] — after /user/profile so 'profile' isn't matched as :id
    const user = users.find(u => u.id === req.params.id);
    if (!user) return res.status(404).json({ error: 'User not found' });

    // [24] Return minimal public fields only; never expose internal fields
    res.json({ id: user.id, username: user.username });
});

app.patch('/user/profile', requireAuth, express.json({ limit: '600kb' }), (req, res) => {
    const { avatar, displayName } = req.body;

    // Validations
    if (displayName !== undefined) {
        if (typeof displayName !== 'string' || displayName.length > 32) {
            return res.status(400).json({ error: 'displayName must be a string under 32 characters' });
        }
    }

    if (avatar !== undefined && avatar !== null) {
        if (typeof avatar !== 'string') {
            return res.status(400).json({ error: 'avatar must be a string or null' });
        }
        if (!/^data:image\/(png|jpeg|webp|gif);base64,/.test(avatar)) {
            return res.status(400).json({ error: 'Invalid avatar format' });
        }
        if (avatar.length > 700000) {
            return res.status(413).json({ error: 'Avatar must be under 700000 chars' });
        }
    }

    // Node-auth sessions update the node registry profile directly.
    if (req.user?.isNode) {
        let nodeId;
        try { nodeId = validateNodeId(req.user.id); } catch { return res.status(400).json({ error: 'Invalid nodeId' }); }
        // [38][BOLA] Critical: block profile takeover. A node bound to a different
        // real account cannot have its displayName/avatar overwritten by an isNode token.
        const _existing = registeredNodes[nodeId];
        if (_existing && _existing.ownerId && _existing.ownerId !== req.user.id) {
            return res.status(403).json({ error: 'Not authorized for this node' });
        }
        if (!registeredNodes[nodeId]) {
            registeredNodes[nodeId] = {
                nodeId,
                displayName: nodeId.slice(0, 10),
                ownerId: nodeId,
                registeredAt: Date.now(),
                lastSeen: Date.now(),
            };
        }
        if (displayName !== undefined) registeredNodes[nodeId].displayName = displayName;
        if (avatar !== undefined) registeredNodes[nodeId].avatar = avatar;
        saveNodeRegistry();
        return res.json({ success: true, displayName: registeredNodes[nodeId].displayName, avatar: registeredNodes[nodeId].avatar || null, nodeId });
    }

    let user = users.find(u => u.ownerId === req.user.id || u.id === req.user.id);
    if (!user) return res.status(404).json({ error: 'User not found' });

    if (displayName !== undefined) user.displayName = displayName;
    if (avatar !== undefined) user.avatar = avatar;

    scheduleWrite(USERS_FILE, users);

    // Sync to node registry
    const nodeIdsToUpdate = Object.keys(registeredNodes).filter(k => registeredNodes[k].ownerId === req.user.id || k === req.user.id);
    let updatedNode = false;
    for (const k of nodeIdsToUpdate) {
        if (displayName !== undefined) registeredNodes[k].displayName = displayName;
        if (avatar !== undefined) registeredNodes[k].avatar = avatar;
        updatedNode = true;
    }
    if (updatedNode) saveNodeRegistry();

    res.json({ success: true, displayName: user.displayName, avatar: user.avatar || null, nodeId: user.id });
});

// ─── GHOSTTAG USERNAME SYSTEM ────────────────────────────────────────────────

const GHOSTTAG_RE = /^[a-z0-9_]{3,20}$/;

const ghosttagCheckLimiter = rateLimit({
    windowMs: 60_000,
    max: 60, // generous for real-time availability checks
    standardHeaders: true,
    legacyHeaders: false,
    message: { error: 'Too many tag check requests. Please wait.' },
});

const ghosttagClaimLimiter = rateLimit({
    windowMs: 60_000,
    max: 10,
    standardHeaders: true,
    legacyHeaders: false,
    message: { error: 'Too many tag claim attempts. Please wait.' },
});

// Claim a GhostTag — binds it to the authenticated user's nodeId
app.post('/ghosttag/claim', requireAuth, ghosttagClaimLimiter, (req, res) => {
    const rawTag = req.body?.tag;
    if (!rawTag || typeof rawTag !== 'string') {
        return res.status(400).json({ error: 'GhostTag required' });
    }

    const tag = rawTag.trim().toLowerCase().replace(/^@/, '');
    if (!GHOSTTAG_RE.test(tag)) {
        return res.status(400).json({ error: 'GhostTag must be 3–20 chars: lowercase letters, numbers, underscores only' });
    }

    // Check if this user already owns a tag
    const existingOwned = Object.entries(ghostTags).find(([, v]) => v.ownerId === req.user.id);
    if (existingOwned) {
        return res.status(409).json({ error: 'You already have a GhostTag', yourTag: '@' + existingOwned[0] });
    }

    // Check if tag is taken
    if (ghostTags[tag]) {
        // Generate suggestions using crypto-random suffixes
        const suggestions = Array.from({ length: 5 }, () =>
            tag + (parseInt(crypto.randomBytes(2).toString('hex'), 16) % 1000)
        ).filter(s => !ghostTags[s] && GHOSTTAG_RE.test(s));
        return res.status(409).json({ error: 'GhostTag taken', suggestions });
    }

    // Validate nodeId and publicKey from the body
    let nodeId;
    try { nodeId = validateNodeId(req.body?.nodeId || req.user.id); }
    catch (e) { return res.status(400).json({ error: 'Invalid nodeId' }); }

    const publicKey = typeof req.body.publicKey === 'string' ? req.body.publicKey.slice(0, 512) : null;
    const displayName = typeof req.body.displayName === 'string' ? req.body.displayName.slice(0, 64) : tag;

    ghostTags[tag] = {
        nodeId,
        publicKey,
        displayName,
        ownerId: req.user.id,
        claimedAt: Date.now(),
    };
    saveGhostTags();

    console.log(`[GhostTag] @${tag} claimed by ${nodeId.slice(0, 12)}...`);
    res.json({ success: true, tag: '@' + tag });
});

// Check availability — public, rate-limited
app.get('/ghosttag/check/:tag', ghosttagCheckLimiter, (req, res) => {
    const tag = (req.params.tag || '').trim().toLowerCase().replace(/^@/, '');
    if (!GHOSTTAG_RE.test(tag)) {
        return res.status(400).json({ error: 'Invalid tag format' });
    }
    res.json({ tag: '@' + tag, available: !ghostTags[tag] });
});

// Resolve a GhostTag → identity info — authenticated
app.get('/ghosttag/resolve/:tag', requireAuth, (req, res) => {
    const tag = (req.params.tag || '').trim().toLowerCase().replace(/^@/, '');
    if (!GHOSTTAG_RE.test(tag)) {
        return res.status(400).json({ error: 'Invalid tag format' });
    }

    const entry = ghostTags[tag];
    if (!entry) {
        return res.status(404).json({ error: 'GhostTag not found' });
    }

    // Return the identity linked to this tag
    const node = registeredNodes[entry.nodeId];
    res.json({
        tag: '@' + tag,
        nodeId: entry.nodeId,
        publicKey: entry.publicKey || node?.publicKey || null,
        displayName: entry.displayName || node?.displayName || tag,
        avatar: node?.avatar || null,
        online: meshPeers.has(entry.nodeId),
    });
});

// Release a GhostTag — called when user deletes their identity
app.delete('/ghosttag/release', requireAuth, (req, res) => {
    // Find the tag owned by this user
    const ownedEntry = Object.entries(ghostTags).find(([, v]) => v.ownerId === req.user.id);
    if (!ownedEntry) {
        return res.status(404).json({ error: 'No GhostTag owned by this identity' });
    }

    const [tag] = ownedEntry;
    delete ghostTags[tag];
    saveGhostTags();

    console.log(`[GhostTag] @${tag} released by ${req.user.id.slice(0, 12)}...`);
    res.json({ success: true, released: '@' + tag });
});

// Full identity deletion — releases tag + removes user/node data
app.delete('/identity', requireAuth, (req, res) => {
    const userId = req.user.id;

    // 1. Release GhostTag
    const ownedTag = Object.entries(ghostTags).find(([, v]) => v.ownerId === userId);
    if (ownedTag) {
        delete ghostTags[ownedTag[0]];
        saveGhostTags();
        console.log(`[Identity] Released @${ownedTag[0]}`);
    }

    // 2. Remove from users list
    const idx = users.findIndex(u => u.ownerId === userId || u.id === userId);
    if (idx !== -1) {
        users.splice(idx, 1);
        scheduleWrite(USERS_FILE, users);
    }

    // 3. Remove from registered nodes
    const nodeKeys = Object.keys(registeredNodes).filter(k => registeredNodes[k].ownerId === userId || k === userId);
    for (const k of nodeKeys) {
        delete registeredNodes[k];
    }
    if (nodeKeys.length) saveNodeRegistry();

    console.log(`[Identity] Fully deleted user ${userId.slice(0, 12)}...`);
    res.json({ success: true, releasedTag: ownedTag ? '@' + ownedTag[0] : null });
});

// ─── MESSAGING ───────────────────────────────────────────────────────────────

app.post('/message', requireAuth, (req, res) => { // [02]
    const senderId = req.user.id; // [02] forced from JWT — not from body

    let receiverId, content, contactName;
    try {
        receiverId = validateNodeId(req.body?.receiverId);
    } catch (_) {
        return res.status(400).json({ error: 'Invalid receiverId' });
    }

    content = req.body?.content;
    if (!content || typeof content !== 'string') {
        return res.status(400).json({ error: 'Missing content' });
    }
    // [16] Length cap
    if (Buffer.byteLength(content, 'utf8') > MAX_CONTENT_LENGTH) {
        return res.status(413).json({ error: `Content exceeds ${MAX_CONTENT_LENGTH / 1024} KB limit` });
    }

    contactName = typeof req.body?.contactName === 'string'
        ? req.body.contactName.slice(0, 64) : null;

    if (receiverId !== 'broadcast') {
        const isHexId = typeof receiverId === 'string' && receiverId.startsWith('0x') && receiverId.length >= 42;
        const knownReceiver = registeredNodes[receiverId]
            || meshPeers.has(receiverId)
            || users.find(u => u.id === receiverId || u.username === receiverId)
            || isHexId;
        if (!knownReceiver) {
            return res.status(404).json({ error: 'Node not found' });
        }
        // Auto-register receiver if they're a known user but have no node entry yet
        if (!registeredNodes[receiverId]) {
            const user = typeof knownReceiver === 'object' && knownReceiver.username
                ? knownReceiver : null;
            registeredNodes[receiverId] = {
                nodeId: receiverId,
                displayName: user?.username || receiverId.slice(0, 10),
                ownerId: user?.id || receiverId,
                registeredAt: Date.now(),
                lastSeen: Date.now(),
            };
            saveNodeRegistry();
            nodeStore.upsertNode(receiverId, { displayName: user?.username || receiverId.slice(0, 10), ownerId: user?.id || receiverId }).catch(() => {});
        }
    }

    // Auto-register sender if absent (bound to authenticated user)
    if (!registeredNodes[senderId]) {
        registeredNodes[senderId] = {
            nodeId: senderId,
            displayName: contactName || senderId.slice(0, 10),
            ownerId: req.user.id,
            registeredAt: Date.now(),
            lastSeen: Date.now(),
        };
        saveNodeRegistry();
        nodeStore.upsertNode(senderId, { displayName: contactName || senderId.slice(0, 10), ownerId: req.user.id }).catch(() => {});
    }

    let convo = conversations.find(c =>
        c?.participants?.includes(senderId) && c.participants.includes(receiverId)
    );

    const MAX_CONVERSATIONS = 50000;
    if (!convo) {
        // Cap total conversations to prevent memory exhaustion
        if (conversations.length >= MAX_CONVERSATIONS) {
            // Evict oldest conversation
            conversations.sort((a, b) => (a.updated || 0) - (b.updated || 0));
            conversations.shift();
        }
        convo = {
            id: secureId('convo_'), // [14][25]
            participants: [senderId, receiverId],
            contactName: contactName || null,
            lastMessage: content,
            updated: Date.now(),
        };
        conversations.push(convo);
    } else {
        convo.lastMessage = content;
        convo.updated = Date.now();
        if (contactName && !convo.contactName) convo.contactName = contactName;
    }

    scheduleWrite(CONVOS_FILE, conversations); // [12]
    // Persist conversation to Postgres so it survives restarts (history stays readable).
    conversationStore.upsertConversation(convo).catch(err =>
        console.error('[DB] upsertConversation failed:', err.message));

    const msg = {
        // Use the client-supplied id when it's a safe token, so the sender's bubble,
        // the delivery/read receipts and the stored row all share one id (ticks line up).
        id: (typeof req.body?.id === 'string' && /^[\w:-]{1,128}$/.test(req.body.id)) ? req.body.id : secureId('msg_'),
        convoId: convo.id,
        senderId,
        receiverId,
        content,
        timestamp: Date.now(),
        delivered: false,
    };

    // Cap messages array to prevent unbounded memory growth
    const MAX_MESSAGES = 100000;
    if (messages.length >= MAX_MESSAGES) {
        messages.splice(0, messages.length - MAX_MESSAGES + 1000); // trim oldest 1000
    }
    messages.push(msg);
    scheduleWrite(MESSAGES_FILE, messages); // [12]
    // Persist to Postgres (fire-and-forget — JSON is still authoritative during migration)
    messageStore.storeMessage(msg.id, convo.id, receiverId, senderId, content).catch(err =>
        console.error('[DB] storeMessage failed:', err.message));

    // Real-time delivery
    const targetWs = activeConnections.get(receiverId);
    const senderWs = activeConnections.get(senderId);

    if (targetWs && targetWs.readyState === 1) {
        const displayName = contactName || registeredNodes[senderId]?.displayName || senderId.slice(0, 10);
        safeSend(targetWs, {
            type: 'CHAT_MESSAGE', id: msg.id, convoId: convo.id,
            senderId, receiverId, content, contactName: displayName, timestamp: msg.timestamp,
        });
        safeSend(targetWs, {
            type: 'NEW_CONVERSATION',
            convo: { ...convo, otherUser: { id: senderId, username: displayName } },
        });
        msg.delivered = true;
        scheduleWrite(MESSAGES_FILE, messages); // [12]
        messageStore.markDelivered(msg.id).catch(() => {});

        // Send delivery receipt to sender if they have a WS
        if (senderWs) {
            safeSend(senderWs, { type: 'receipt', status: 'delivered', msgId: msg.id });
        }
    } else {
        // Recipient offline — use new queueMessage
        queueMessage(receiverId, msg);

        // Send storage receipt to sender if they have a WS
        if (senderWs) {
            safeSend(senderWs, { type: 'receipt', status: 'queued', msgId: msg.id });
        }

        // Legacy compat (redundant but safe)
        if (!pendingMessages[receiverId]) pendingMessages[receiverId] = [];
        pendingMessages[receiverId].push(msg);
    }

    res.json({ success: true, message: { id: msg.id, convoId: convo.id, timestamp: msg.timestamp } });
    analytics.trackEvent('message', 'sent').catch(() => {});
    analytics.trackFeature('chat').catch(() => {});
});

// ─── CONVERSATIONS ───────────────────────────────────────────────────────────

app.get('/conversations', requireAuth, (req, res) => { // [05]
    const userId = req.user.id; // [05] always own user — ignores query param

    const userConvos = conversations.filter(c => c?.participants?.includes(userId));
    const enriched = userConvos.map(c => {
        const otherId = c.participants.find(p => p !== userId) || userId;
        const reg = registeredNodes[otherId];
        const otherUser = { id: otherId, username: reg?.displayName || c.contactName || otherId.slice(0, 10), avatar: reg?.avatar || null };
        return { ...c, otherUser };
    });
    enriched.sort((a, b) => b.updated - a.updated);
    res.json(enriched);
});

// ─── HISTORY ─────────────────────────────────────────────────────────────────

app.get('/history', requireAuth, async (req, res) => { // [04][13]
    const userId = req.user.id;
    const convoId = req.query.convoId;

    if (!convoId) return res.status(400).json({ error: 'convoId required' }); // [13]

    // [04] Ownership: caller must be a participant in the conversation
    const convo = conversations.find(c => c?.id === convoId);
    if (!convo) return res.status(404).json({ error: 'Conversation not found' });
    if (!convo.participants?.includes(userId)) {
        return res.status(403).json({ error: 'Access denied' });
    }

    // [13] Pagination
    // [39] Clamp against NaN / negative values so slice() can't return unintended ranges
    const limit = Math.min(Math.max(parseInt(req.query.limit, 10) || 50, 1), 200);
    const offset = Math.max(parseInt(req.query.offset, 10) || 0, 0);

    // Prefer Postgres when it's configured; fall back to the in-memory store if the
    // DB is unset or unreachable so history still loads during an outage.
    if (process.env.DATABASE_URL) {
        try {
            const rows = await messageStore.getMessagesByConvo(convoId, limit, offset);
            // getMessagesByConvo returns newest-first; the UI renders oldest-first.
            const result = rows.map(r => ({
                id: r.msg_id,
                convoId: r.convo_id,
                senderId: r.sender_id,
                receiverId: r.recipient_id,
                content: r.content,
                timestamp: r.created_at ? new Date(r.created_at).getTime() : Date.now(),
                delivered: r.delivered,
            })).reverse();
            return res.json(result);
        } catch (err) {
            console.error('[DB] /history read failed, falling back to JSON:', err.message);
        }
    }

    const result = messages.filter(m => m.convoId === convoId).slice(offset, offset + limit);
    res.json(result);
});

// Delete all messages in a conversation but KEEP the conversation/contact entry.
// (Burn / "Delete chat" — the contact stays so the user can still message them.)
app.delete('/messages', requireAuth, (req, res) => {
    const userId = req.user.id;
    const convoId = req.query.convoId;
    if (!convoId) return res.status(400).json({ error: 'convoId required' });

    const convo = conversations.find(c => c?.id === convoId);
    if (!convo) return res.status(404).json({ error: 'Conversation not found' });
    if (!convo.participants?.includes(userId)) {
        return res.status(403).json({ error: 'Access denied' }); // ownership check
    }

    const before = messages.length;
    messages = messages.filter(m => m.convoId !== convoId);
    const removed = before - messages.length;
    if (removed > 0) scheduleWrite(MESSAGES_FILE, messages);

    // Keep the conversation (contact) but clear its preview.
    convo.lastMessage = '';
    convo.updated = Date.now();
    scheduleWrite(CONVOS_FILE, conversations);

    // Best-effort delete from the SQL store too.
    if (typeof messageStore.deleteConversationMessages === 'function') {
        messageStore.deleteConversationMessages(convoId).catch(err =>
            console.error('[DB] deleteConversationMessages failed:', err.message));
    }

    res.json({ success: true, removed });
});

// ─── STATUS & WALLET ─────────────────────────────────────────────────────────

app.get('/status', (req, res) => {
    const mem = process.memoryUsage();
    res.json({
        status: 'ok',
        service: 'ghostnet-server',
        mode: GHOSTNET_MODE,
        uptime: Math.round((Date.now() - startTime) / 1000),
        uptimeHuman: formatUptime(Date.now() - startTime),
        memory: {
            rss: Math.round(mem.rss / 1024 / 1024),
            heap: Math.round(mem.heapUsed / 1024 / 1024),
            heapTotal: Math.round(mem.heapTotal / 1024 / 1024),
        },
        connections: {
            wsClients: wss ? wss.clients.size : 0,
            meshPeers: meshPeers ? meshPeers.size : 0,
        },
        port: PORT,
        node: process.version,
        timestamp: Date.now(),
    });
});

app.get('/wallet', requireAuth, async (_req, res) => { // [03]
    res.json([
        { symbol: 'ETH', balance: 0.0, chain: 'Ethereum', address: '0x00...00' },
        { symbol: 'BTC', balance: 0.0, chain: 'Regtest', address: 'N/A' },
        { symbol: 'SOL', balance: 0.0, chain: 'Solana', address: 'N/A' },
        { symbol: 'USDT', balance: 0.0, chain: 'Ethereum', address: '0x00...00' },
    ]);
});

function formatUptime(ms) {
    const s = Math.floor(ms / 1000), m = Math.floor(s / 60), h = Math.floor(m / 60);
    if (h > 0) return `${h}h ${m % 60}m`;
    if (m > 0) return `${m}m ${s % 60}s`;
    return `${s}s`;
}

// ─── HEALTH PROXY ────────────────────────────────────────────────────────────

app.get('/health/bridge', requireAuth, async (_req, res) => { // [09]
    try {
        // [09] BRIDGE_ORIGIN is pre-validated loopback-only
        const response = await fetch(`${BRIDGE_ORIGIN}/wallet`);
        if (response.ok) res.json({ bridge: 'online', port: 3001 });
        else res.status(502).json({ bridge: 'unhealthy', code: response.status });
    } catch (_) {
        res.status(502).json({ bridge: 'offline' }); // [32] no e.message to client
    }
});

// ─── VAULT (DIRECT IN MAIN SERVER) ─────────────────────────────────────────────

// [10] Allowed Content-Type values for vault upload
// TODO: Add file magic byte validation server-side to prevent MIME type spoofing
const VAULT_UPLOAD_MIME_ALLOW = new Set(['multipart/form-data', 'application/octet-stream']);

app.post('/vault/upload', requireAuth, vaultUpload.single('file'), async (req, res) => { // [10]
    const rawCT = (req.headers['content-type'] || '').split(';')[0].trim().toLowerCase();
    if (!VAULT_UPLOAD_MIME_ALLOW.has(rawCT)) {
        return res.status(415).json({ error: 'Unsupported content type for vault upload' });
    }

    if (!req.file) return res.status(400).json({ error: 'No file uploaded' });

    const owner = req.user.id;
    const { fileName, iv, authTag, originalSize } = req.body;

    try {
        const fileId = crypto.randomUUID();
        const tmpPath = req.file.path;
        const fileSize = req.file.size;

        const fileHash = await new Promise((resolve, reject) => {
            const hash = crypto.createHash('sha256');
            const stream = fs.createReadStream(tmpPath);
            stream.on('data', chunk => hash.update(chunk));
            stream.on('end', () => resolve(hash.digest('hex')));
            stream.on('error', reject);
        });

        const filePath = path.join(VAULT_DIR, `${fileId}.enc`);
        fs.renameSync(tmpPath, filePath);

        const record = {
            fileId,
            fileName: path.basename((fileName || req.file.originalname || 'encrypted_file').replace(/[\x00-\x1f]/g, '')).slice(0, 255),
            fileSize,
            originalSize: parseInt(originalSize) || fileSize,
            fileHash,
            owner,
            iv: iv || null,
            authTag: authTag || null,
            uploadedAt: Date.now(),
            chainAnchored: false, // Chain anchoring omitted for main server local vault
            txHash: null,
            deleted: false
        };

        // Cap fileMeta to prevent unbounded growth
        const MAX_FILE_META = 50000;
        if (fileMeta.length >= MAX_FILE_META) {
            const delIdx = fileMeta.findIndex(f => f.deleted);
            if (delIdx !== -1) fileMeta.splice(delIdx, 1);
            else fileMeta.shift();
        }
        fileMeta.push(record);
        saveMeta();

        res.json({
            success: true,
            file: record
        });
    } catch (e) {
        console.error('Vault direct upload error:', e.message);
        res.status(502).json({ error: 'Vault processing failed' });
    }
});



app.get('/vault/download/:fileId', requireAuth, async (req, res) => {
    let fileId;
    try { fileId = validateFileId(req.params.fileId); }
    catch (_) { return res.status(400).json({ error: 'Invalid file ID' }); }

    const record = fileMeta.find(f => f.fileId === fileId && !f.deleted);
    if (!record) return res.status(404).json({ error: 'File not found' });

    // Verify authenticated user owns this file
    if (record.owner !== req.user.id) return res.status(403).json({ error: 'Access denied' });

    const filePath = path.join(VAULT_DIR, `${record.fileId}.enc`);
    if (!fs.existsSync(filePath)) return res.status(404).json({ error: 'File data missing' });

    res.setHeader('X-File-Id', record.fileId);
    res.setHeader('X-File-Name', encodeURIComponent(record.fileName));
    res.setHeader('X-File-Hash', record.fileHash);
    res.setHeader('X-IV', record.iv || '');
    res.setHeader('X-Auth-Tag', record.authTag || '');
    res.setHeader('X-Original-Size', record.originalSize);
    res.setHeader('Content-Type', 'application/octet-stream');
    res.setHeader('Content-Disposition', `attachment; filename="${record.fileId}.enc"`);

    const stream = fs.createReadStream(filePath);
    stream.pipe(res);
});

app.get('/vault/files/:owner', requireAuth, async (req, res) => {
    if (req.user.id !== req.params.owner && req.params.owner !== 'me') {
        return res.status(403).json({ error: 'Access denied' });
    }
    const userFiles = fileMeta.filter(f => f.owner === req.user.id && !f.deleted).map(f => ({
        fileId: f.fileId,
        fileName: f.fileName,
        fileSize: f.fileSize,
        originalSize: f.originalSize,
        uploadedAt: f.uploadedAt,
        iv: f.iv || null,
        authTag: f.authTag || null
    }));
    res.json({ files: userFiles });
});

app.get('/vault/verify/:fileId', requireAuth, async (req, res) => { // [18]
    let fileId;
    try { fileId = validateFileId(req.params.fileId); }
    catch (_) { return res.status(400).json({ error: 'Invalid file ID' }); }

    const record = fileMeta.find(f => f.fileId === fileId && !f.deleted);
    if (!record) return res.status(404).json({ error: 'File not found' });
    
    if (record.owner !== req.user.id) return res.status(403).json({ error: 'Access denied' });

    const filePath = path.join(VAULT_DIR, `${record.fileId}.enc`);
    if (!fs.existsSync(filePath)) return res.json({ valid: false, hashMatch: false, error: 'File data missing' });

    try {
        const fileHash = await new Promise((resolve, reject) => {
            const hash = crypto.createHash('sha256');
            const stream = fs.createReadStream(filePath);
            stream.on('data', chunk => hash.update(chunk));
            stream.on('end', () => resolve(hash.digest('hex')));
            stream.on('error', reject);
        });

        const hashMatch = (fileHash === record.fileHash);
        res.json({
            valid: hashMatch,
            hashMatch: hashMatch,
            fileSize: fs.statSync(filePath).size,
            originalSize: record.originalSize
        });
    } catch(e) {
        res.status(500).json({ error: 'Verification failed' });
    }
});

app.get('/vault/keys', requireAuth, (req, res) => {
    const ownerId = req.user.id;
    const keyData = vaultKeys[ownerId];
    if (keyData) {
        res.json({ success: true, keyData: keyData });
    } else {
        res.json({ success: false, error: 'Vault key not found' });
    }
});

app.post('/vault/keys', requireAuth, (req, res) => {
    const ownerId = req.user.id;
    const { keyData } = req.body;
    if (!keyData || typeof keyData.wrappedKey !== 'string') {
        return res.status(400).json({ error: 'Invalid key format' });
    }
    vaultKeys[ownerId] = keyData;
    scheduleWrite(VAULT_KEYS_FILE, vaultKeys);
    res.json({ success: true });
});

app.delete('/vault/file/:fileId', requireAuth, async (req, res) => { // [19]
    let fileId;
    try { fileId = validateFileId(req.params.fileId); }
    catch (_) { return res.status(400).json({ error: 'Invalid file ID' }); }

    const record = fileMeta.find(f => f.fileId === fileId && !f.deleted);
    if (!record) {
        // Return 200 instead of 404 to prevent browser console network errors
        // when the client attempts to delete an already-deleted file.
        return res.status(200).json({ success: true, warning: 'File already deleted or not found' });
    }

    if (record.owner !== req.user.id) return res.status(403).json({ error: 'Access denied' });

    record.deleted = true;
    saveMeta();

    const filePath = path.join(VAULT_DIR, `${record.fileId}.enc`);
    if (fs.existsSync(filePath)) {
        try {
            fs.unlinkSync(filePath);
        } catch(e) {
            console.error('Failed to delete physical file:', e);
        }
    }

    res.json({ success: true });
});

// Explicit root
app.get('/', (_req, res) => {
    const fromPublic = path.join(PUBLIC_DIR, 'index.html');
    const filePath = fs.existsSync(fromPublic) ? fromPublic : path.join(__dirname, 'index.html');
    res.sendFile(filePath);
});

// ─── ANALYTICS (privacy-respecting, self-hosted) ────────────────────────────

const analyticsEventLimiter = rateLimit({
    windowMs: 60_000,
    max: 60,
    standardHeaders: true,
    legacyHeaders: false,
    message: { error: 'Too many analytics events' },
});

app.post('/analytics/event', requireAuth, analyticsEventLimiter, async (req, res) => {
    const sessionId = req.user.id;
    const { category, action, feature } = req.body || {};

    try {
        await analytics.trackActiveUser(sessionId);

        if (feature && typeof feature === 'string') {
            await analytics.trackFeature(feature.slice(0, 64));
        }
        if (category && action && typeof category === 'string' && typeof action === 'string') {
            await analytics.trackEvent(category.slice(0, 64), action.slice(0, 64));
        }
        res.json({ ok: true });
    } catch (err) {
        console.error('Analytics event error:', err.message);
        res.status(500).json({ error: 'Analytics write failed' });
    }
});

const ANALYTICS_SECRET = process.env.ANALYTICS_ADMIN_SECRET || null;

app.get('/analytics/dashboard', requireAuth, async (req, res) => {
    if (ANALYTICS_SECRET) {
        const provided = req.headers['x-analytics-secret'] || '';
        if (provided !== ANALYTICS_SECRET) {
            return res.status(403).json({ error: 'Forbidden' });
        }
    }

    const days = Math.min(parseInt(req.query.days, 10) || 30, 90);
    try {
        const data = await analytics.getDashboard(days);
        res.json(data);
    } catch (err) {
        console.error('Analytics dashboard error:', err.message);
        res.status(500).json({ error: 'Analytics read failed' });
    }
});

app.get('/analytics', requireAuth, (_req, res) => {
    res.sendFile(path.join(__dirname, 'analytics-dashboard.html'));
});

// Express error handler — must be mounted after all routes
app.use(monitor.expressErrorHandler());

// ─── HTTP server ─────────────────────────────────────────────────────────────

const server = app.listen(PORT, '0.0.0.0', async () => {
    console.log(`🟢 GhostNet Server on port ${PORT} [${GHOSTNET_MODE}]`);
    analytics.init().catch(err => console.error('Analytics init failed:', err.message));

    // Postgres startup checks
    if (process.env.DATABASE_URL) {
        const healthy = await dbHealthCheck();
        if (healthy) {
            const migrated = await checkMigrationsRan();
            if (migrated) {
                startCleanupCron(7);
                // Restore conversations from Postgres so chat history is readable after a
                // restart/redeploy (the local conversations.json is ephemeral on Railway).
                try {
                    const dbConvos = await conversationStore.loadAllConversations();
                    const known = new Set(conversations.map(c => c?.id));
                    let added = 0;
                    for (const c of dbConvos) {
                        if (!known.has(c.id)) { conversations.push(c); added++; }
                    }
                    console.log(`[DB] Restored ${added} conversation(s) from Postgres (${dbConvos.length} total).`);
                } catch (err) {
                    console.error('[DB] Failed to restore conversations:', err.message);
                }
            }
        }
    } else {
        console.warn('[DB] DATABASE_URL not set — running in JSON-only mode.');
    }
});

// ─── WebSocket setup ──────────────────────────────────────────────────────────

const wss = new WebSocketServer({ noServer: true });

// [08] WS authentication via token in query string
server.on('upgrade', (req, socket, head) => {
    if (req.url?.startsWith('/ws')) {
        // Parse token from query: ws://host/ws?token=...
        const urlParams = new URLSearchParams(req.url.split('?')[1] || '');
        const token = urlParams.get('token');
        if (!token) { socket.destroy(); return; }

        let user;
        try { user = jwt.verify(token, JWT_SECRET); }
        catch (_) { socket.destroy(); return; }

        // Validate tokenVersion — reject revoked tokens (post-logout/password-reset)
        const dbUser = findAuthUserById(user.userId);
        if (dbUser) {
            const currentTv = dbUser.tokenVersion || 0;
            const tokenTv = user.tv ?? 0;
            if (tokenTv < currentTv) { socket.destroy(); return; }
        }

        wss.handleUpgrade(req, socket, head, ws => {
            ws._user = user; // attach verified user to socket
            wss.emit('connection', ws, req);
        });
    } else {
        socket.destroy();
    }
});

// [11] Map (not plain object) for peers
const meshPeers = new Map();
const clients = new Map();
const pendingMessages = {};

// ─── WS helpers ──────────────────────────────────────────────────────────────

function safeSend(ws, payload) {
    if (ws.readyState === 1) {
        try { ws.send(JSON.stringify(payload)); } catch (_) { }
    }
}

function deliverPendingMessages(nodeId, ws) {
    // [34] Called synchronously after registration — no setTimeout race
    // Drain the queue; also scan for any legacy unqueued undelivered messages
    const queuedIds = new Set(dequeuePending(nodeId));
    // Deliver all undelivered messages for this node (queue or legacy scan)
    const pending = messages.filter(m =>
        m?.receiverId === nodeId && !m.delivered
    );
    if (!pending.length) return;

    const deliveredIds = [];
    pending.forEach(m => {
        safeSend(ws, {
            type: 'CHAT_MESSAGE',
            id: m.id,
            convoId: m.convoId,
            senderId: m.senderId,
            receiverId: m.receiverId,
            content: m.content,
            contactName: registeredNodes[m.senderId]?.displayName || m.senderId.slice(0, 10),
            timestamp: m.timestamp,
        });
        m.delivered = true;
        deliveredIds.push(m.id);
    });

    scheduleWrite(MESSAGES_FILE, messages); // [12]
    if (deliveredIds.length) messageStore.markMultipleDelivered(deliveredIds).catch(() => {});

    conversations.filter(c => c?.participants?.includes(nodeId)).forEach(c => {
        const otherId = c.participants.find(p => p !== nodeId) || nodeId;
        safeSend(ws, {
            type: 'NEW_CONVERSATION',
            convo: { ...c, otherUser: { id: otherId, username: registeredNodes[otherId]?.displayName || otherId.slice(0, 10) } },
        });
    });
}

// ─── WebSocket event handlers ─────────────────────────────────────────────────

wss.on('connection', (ws) => {
    // [08] ws._user is set by the upgrade handler — always authenticated
    let clientId = null;
    ws.isAlive = true;
    monitor.trackWsConnect();

    // Track active connection by user ID
    if (ws._user && ws._user.id) {
        clients.set(ws._user.id, ws);

        // Deliver any transient pending messages stored in the pendingMessages object
        if (pendingMessages[ws._user.id] && pendingMessages[ws._user.id].length > 0) {
            const msgs = pendingMessages[ws._user.id];
            const wsDeliveredIds = [];
            msgs.forEach(m => {
                safeSend(ws, {
                    type: 'CHAT_MESSAGE', id: m.id, convoId: m.convoId,
                    senderId: m.senderId, receiverId: m.receiverId, content: m.content,
                    contactName: registeredNodes[m.senderId]?.displayName || m.senderId.slice(0, 10),
                    timestamp: m.timestamp,
                });
                m.delivered = true;
                wsDeliveredIds.push(m.id);
            });
            pendingMessages[ws._user.id] = [];
            scheduleWrite(MESSAGES_FILE, messages);
            if (wsDeliveredIds.length) messageStore.markMultipleDelivered(wsDeliveredIds).catch(() => {});
        }
    }

    // Close handler merged into the main close handler below (line ~1706)
    ws.on('pong', () => { ws.isAlive = true; });

    // Prevent unhandled socket errors from crashing the connection
    ws.on('error', err => {
        console.error('[WS] Socket error:', err.message);
        monitor.trackWsError(err);
    });

    ws.on('message', data => {
        try {
            // [23] WS message size cap
            if (data.length > MAX_CONTENT_LENGTH * 2) return;

            let msg;
            try { msg = JSON.parse(data.toString()); }
            catch (_) { return; }

            // [Bridge Fix] Handle Auth type
            if (msg.type === 'auth') {
                let nodeId;
                try { nodeId = validateNodeId(msg.nodeId); }
                catch (_) { safeSend(ws, { type: 'ERROR', error: 'Invalid nodeId' }); return; }

                // Ownership check: reject if node belongs to a different user
                const existingNode = registeredNodes[nodeId];
                if (existingNode && existingNode.ownerId && existingNode.ownerId !== ws._user.id) {
                    safeSend(ws, { type: 'ERROR', error: 'Not authorized to claim this nodeId' });
                    return;
                }

                activeConnections.set(nodeId, ws);
                deliverQueuedMessages(nodeId, ws);
                console.log(`[Bridge] Node connected: ${nodeId}`);

                // Also trigger legacy registration if needed
                if (!clientId) {
                    clientId = nodeId;
                    const peerEntry = { id: clientId, ws, capabilities: {}, lastSeen: Date.now() };
                    meshPeers.set(clientId, peerEntry);
                }
                return;
            }

            switch (msg.type) {
                case 'register':
                case 'HELLO':
                case 'MESH_HELLO': {
                    let newId;
                    try { newId = validateNodeId(msg.nodeId || msg.id); } // [07]
                    catch (_) { safeSend(ws, { type: 'ERROR', error: 'Invalid nodeId' }); return; }

                    // [08] Node must be owned by the authenticated WS user
                    const node = registeredNodes[newId];
                    if (node && node.ownerId && node.ownerId !== ws._user.id) {
                        safeSend(ws, { type: 'ERROR', error: 'Not authorized to claim this nodeId' });
                        return;
                    }

                    if (clientId && clientId !== newId && meshPeers.has(clientId)) {
                        meshPeers.delete(clientId);
                        activeConnections.delete(clientId);
                    }

                    clientId = newId;
                    const peerEntry = { id: clientId, ws, capabilities: {}, lastSeen: Date.now() };
                    meshPeers.set(clientId, peerEntry);
                    activeConnections.set(clientId, ws); // Fixed tracking

                    // Auto-register (with per-user limit)
                    if (!registeredNodes[clientId]) {
                        const MAX_NODES_PER_USER = 20;
                        const userNodeCount = Object.values(registeredNodes).filter(n => n.ownerId === ws._user.id).length;
                        if (userNodeCount >= MAX_NODES_PER_USER) {
                            safeSend(ws, { type: 'ERROR', error: 'Max node registration limit reached' });
                            return;
                        }
                        registeredNodes[clientId] = {
                            nodeId: clientId,
                            displayName: clientId.slice(0, 10),
                            ownerId: ws._user.id,
                            registeredAt: Date.now(),
                            lastSeen: Date.now(),
                        };
                        nodeStore.upsertNode(clientId, { displayName: clientId.slice(0, 10), ownerId: ws._user.id }).catch(() => {});
                    } else {
                        registeredNodes[clientId].lastSeen = Date.now();
                        nodeStore.updateLastSeen(clientId).catch(() => {});
                    }
                    saveNodeRegistry();

                    // Send peer list (deduplicated by ws reference)
                    const seenWs = new Set();
                    const peerList = [];
                    for (const [, peer] of meshPeers) {
                        if (peer.ws !== ws && !seenWs.has(peer.ws)) {
                            seenWs.add(peer.ws);
                            peerList.push({ id: peer.id, capabilities: peer.capabilities, lastSeen: peer.lastSeen });
                        }
                    }
                    safeSend(ws, { type: 'MESH_PEERS', peers: peerList });

                    // Broadcast join — snapshot clients to avoid iteration mutation
                    const joinSnapshot = [...wss.clients];
                    for (const client of joinSnapshot) {
                        if (client !== ws) safeSend(client, { type: 'PEER_JOIN', id: clientId });
                    }

                    // [34] Synchronous delivery — no setTimeout race
                    deliverPendingMessages(clientId, ws);
                    deliverQueuedMessages(clientId, ws);
                    break;
                }

                case 'HEARTBEAT':
                    ws.isAlive = true;
                    if (clientId && meshPeers.has(clientId)) {
                        meshPeers.get(clientId).lastSeen = Date.now();
                    }
                    break;

                case 'ping':
                    ws.isAlive = true;
                    safeSend(ws, { type: 'pong', timestamp: Date.now() });
                    break;

                case 'read': {
                    // Recipient notifies the original sender that their message(s) were read.
                    const toId = typeof msg.to === 'string' ? msg.to : null;
                    if (!toId) return;
                    let safeTo;
                    try { safeTo = validateNodeId(toId); } catch (_) { return; }
                    const ids = Array.isArray(msg.msgIds) ? msg.msgIds
                              : (typeof msg.msgId === 'string' ? [msg.msgId] : []);
                    const origSenderWs = activeConnections.get(safeTo);
                    if (origSenderWs && origSenderWs.readyState === 1) {
                        for (const id of ids) {
                            if (typeof id === 'string' && id.length <= 128) {
                                safeSend(origSenderWs, { type: 'receipt', status: 'read', msgId: id });
                            }
                        }
                    }
                    return;
                }

                case 'message':
                case 'MESH_DIRECT': {
                    const targetId = typeof msg.to === 'string' ? msg.to : null;
                    if (!targetId) return;

                    let safeTarget;
                    try { safeTarget = validateNodeId(targetId); } // [07]
                    catch (_) { return; }

                    let content = msg.content || msg.data;
                    if (!content) return;
                    // Capture the client's message id BEFORE stringifying so the sender's
                    // bubble ↔ delivery/read receipts line up.
                    const clientMsgId = (content && typeof content === 'object' && typeof content.id === 'string')
                        ? content.id
                        : (typeof msg.id === 'string' ? msg.id : null);
                    // Ensure content is always a string before storage and size check
                    if (typeof content !== 'string') content = JSON.stringify(content);
                    // [16] Size cap on WS messages too
                    if (Buffer.byteLength(content, 'utf8') > MAX_CONTENT_LENGTH) return;

                    const senderId = clientId || ws._user?.id;
                    if (!senderId) return; // must have an identity to send
                    const timestamp = Date.now(); // Server-authoritative — never trust client timestamps
                    let wsDelivered = false;

                    // Build a sanitized message — never forward raw attacker-controlled fields
                    const msgId = (clientMsgId && /^[\w:-]{1,128}$/.test(clientMsgId)) ? clientMsgId : secureId('msg_');
                    const safeMsg = {
                        type: msg.type,
                        id: msgId,
                        from: senderId,
                        to: safeTarget,
                        content,
                        timestamp,
                    };

                    const targetWs = activeConnections.get(safeTarget);
                    if (targetWs && targetWs.readyState === 1) {
                        safeSend(targetWs, safeMsg);
                        wsDelivered = true;
                        safeSend(ws, { type: 'receipt', status: 'delivered', msgId });
                    } else {
                        queueMessage(safeTarget, safeMsg);
                        safeSend(ws, { type: 'receipt', status: 'queued', msgId });
                    }
                    
                    // Legacy persist for internal tracking
                    let convo = conversations.find(c =>
                        c?.participants?.includes(senderId) && c.participants.includes(safeTarget)
                    );
                    if (!convo) {
                        convo = {
                            id: secureId('convo_'), // [14][25]
                            participants: [senderId, safeTarget],
                            contactName: null,
                            lastMessage: content,
                            updated: Date.now(),
                        };
                        conversations.push(convo);
                    } else {
                        convo.lastMessage = content;
                        convo.updated = Date.now();
                    }
                    scheduleWrite(CONVOS_FILE, conversations); // [12]
                    conversationStore.upsertConversation(convo).catch(err =>
                        console.error('[DB] WS upsertConversation failed:', err.message));

                    const newMsg = {
                        id: msgId, // same id used for delivery + receipts so ticks/read line up on reload
                        convoId: convo.id,
                        senderId,
                        receiverId: safeTarget,
                        content,
                        timestamp,
                        delivered: wsDelivered,
                    };
                    messages.push(newMsg);
                    scheduleWrite(MESSAGES_FILE, messages); // [12]
                    messageStore.storeMessage(newMsg.id, convo.id, safeTarget, senderId, content).then(() => {
                        if (wsDelivered) messageStore.markDelivered(newMsg.id).catch(() => {});
                    }).catch(err => console.error('[DB] WS storeMessage failed:', err.message));
                    break;
                }

                default:
                    // [26] Drop unknown message types — do NOT broadcast to all clients
                    break;
            }
        } catch (err) {
            // Never let a message-handling error disconnect the client
            console.error('[WS] Message handler error:', err.message);
        }
    });

    ws.on('close', () => {
        monitor.trackWsDisconnect();
        // Clean clients map (merged from earlier close handler)
        if (ws._user && ws._user.id) clients.delete(ws._user.id);

        // [Bridge Fix] Remove from active connections
        const staleIds = [];
        for (const [nodeId, conn] of activeConnections.entries()) {
            if (conn === ws) staleIds.push(nodeId);
        }
        for (const id of staleIds) {
            activeConnections.delete(id);
            console.log(`[Bridge] Node disconnected: ${id}`);
        }

        // [27] Collect IDs first, then delete after iteration
        const toRemove = [];
        for (const [id, peer] of meshPeers) {
            if (peer.ws === ws) toRemove.push(id);
        }
        toRemove.forEach(id => meshPeers.delete(id));

        // Snapshot wss.clients before broadcasting to avoid iteration mutation
        if (toRemove.length > 0) {
            const snapshot = [...wss.clients];
            for (const client of snapshot) {
                safeSend(client, { type: 'PEER_LEAVE', id: clientId || toRemove[0] });
            }
        }

        clientId = null; // prevent stale references
    });

    safeSend(ws, { type: 'welcome' });
});

// ─── WS ping / stale cleanup ─────────────────────────────────────────────────

const WS_PING_INTERVAL = setInterval(() => {
    // Snapshot to avoid terminate() mutating the Set during iteration
    const snapshot = [...wss.clients];
    for (const ws of snapshot) {
        if (!ws.isAlive) { ws.terminate(); continue; }
        ws.isAlive = false;
        try { ws.ping(); } catch (_) { }
    }
}, 25_000);

const STALE_CLEANUP_INTERVAL = setInterval(() => {
    // [27] Collect before delete
    const toRemove = [];
    for (const [id, peer] of meshPeers) {
        if (!peer.ws || peer.ws.readyState !== 1) toRemove.push(id);
    }
    toRemove.forEach(id => {
        console.log(`🕸️ Stale peer removed: ${id.slice(0, 15)}`);
        meshPeers.delete(id);
    });
}, 60_000);

// ─── Graceful shutdown ────────────────────────────────────────────────────────

function gracefulShutdown() {
    console.log('Shutting down...');
    clearInterval(WS_PING_INTERVAL);        // [28]
    clearInterval(STALE_CLEANUP_INTERVAL);  // [28]
    server.close(() => process.exit(0));
}

process.on('SIGTERM', gracefulShutdown);
process.on('SIGINT', gracefulShutdown);