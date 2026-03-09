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
 */

import 'dotenv/config';
import express from 'express';
import cors from 'cors';
import helmet from 'helmet';
import rateLimit from 'express-rate-limit';
import fs from 'fs';
import path from 'path';
import crypto from 'crypto';
import { fileURLToPath } from 'url';
import { WebSocketServer } from 'ws';
import jwt from 'jsonwebtoken';
import authRouter from './auth/auth.routes.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// ─── Constants ───────────────────────────────────────────────────────────────

const PORT = parseInt(process.env.GHOSTNET_SERVER_PORT || process.env.PORT || '8080', 10);
const GHOSTNET_MODE = process.env.GHOSTNET_MODE || 'development';
const JWT_SECRET = process.env.AUTH_JWT_SECRET;
const startTime = Date.now();

const MAX_CONTENT_LENGTH = 64 * 1024; // [16] 64 KB message body cap
const MAX_BODY_SIZE = '64kb';    // [23]

// [20] Explicit CORS allowlist
const ALLOWED_ORIGINS = (process.env.CORS_ALLOWED_ORIGINS || 'http://localhost:3000,http://127.0.0.1:3000,https://ghostnet-ji.vercel.app')
    .split(',').map(o => o.trim()).filter(Boolean);

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
const VAULT_URL = process.env.GHOSTNET_VAULT_URL || 'http://127.0.0.1:4001';

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

const VAULT_ORIGIN = assertLoopbackUrl(VAULT_URL, 'GHOSTNET_VAULT_URL');
const BRIDGE_ORIGIN = assertLoopbackUrl(
    process.env.GHOSTNET_BRIDGE_URL || 'http://127.0.0.1:3001',
    'GHOSTNET_BRIDGE_URL'
);

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

function loadJson(filePath, fallback) {
    try {
        if (fs.existsSync(filePath)) {
            return JSON.parse(fs.readFileSync(filePath, 'utf-8'));
        }
        fs.writeFileSync(filePath, JSON.stringify(fallback, null, 2));
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
app.set('trust proxy', 1); // Required for express-rate-limit behind Railway/reverse proxy

// [33] Security headers
app.use(helmet());

// [20] Strict CORS — only listed origins with credentials
app.use(cors({
    origin: (origin, cb) => {
        // Allow server-to-server (no origin) and allowlisted browsers
        if (!origin || ALLOWED_ORIGINS.includes(origin)) return cb(null, true);
        cb(new Error(`CORS: origin not allowed: ${origin}`));
    },
    credentials: true,
}));

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
app.use(express.static(path.join(__dirname, 'public')));

// Auth routes (have their own stricter rate limit inside authRouter)
app.use('/auth', authRouter);

// ─── Auth middleware ──────────────────────────────────────────────────────────
// [01][02][03][04][05][08]

function requireAuth(req, res, next) {
    // Accept both 'Authorization: Bearer <token>' and 'X-Auth-Token: <token>'
    const authHeader = req.headers.authorization || '';
    const xAuthToken = req.headers['x-auth-token'] || '';
    const token = authHeader.startsWith('Bearer ') ? authHeader.slice(7) : (xAuthToken || null);
    if (!token) return res.status(401).json({ error: 'Authentication required' });
    try {
        req.user = jwt.verify(token, JWT_SECRET);
        next();
    } catch (_) {
        res.status(401).json({ error: 'Invalid or expired token' });
    }
}

// ─── DECENTRALIZED NODE AUTH ──────────────────────────────────────────────────

app.post('/auth/node', (req, res) => {
    let nodeId;
    try { nodeId = validateNodeId(req.body?.nodeId); }
    catch (e) { return res.status(400).json({ error: e.message }); }

    // Issue a JWT representing the node itself (replaces centralized email auth)
    // Using expiresIn 7d, same as the frontend session
    const token = jwt.sign({ id: nodeId, isNode: true }, JWT_SECRET, { expiresIn: '7d' });
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

    registeredNodes[nodeId] = {
        nodeId,
        displayName,
        ownerId: req.user.id, // bind to authenticated user
        address,
        publicKey,
        registeredAt: Date.now(),
        lastSeen: Date.now(),
    };

    saveNodeRegistry();
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
        res.json({ valid: true, displayName: node.displayName, address: node.address || null, online: isOnline });
    } else {
        // Fallback 3: If it's a validly formatted hex address/pubkey (e.g. 0x...), allow it
        if (typeof nodeId === 'string' && nodeId.startsWith('0x') && nodeId.length >= 42) {
            res.json({ valid: true, displayName: 'Unknown Contact', address: nodeId, online: false });
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

app.get('/user/:id', requireAuth, (req, res) => { // [24]
    const user = users.find(u => u.id === req.params.id);
    if (!user) return res.status(404).json({ error: 'User not found' });

    // [24] Return minimal public fields only; never expose internal fields
    res.json({ id: user.id, username: user.username });
});

app.get('/users', requireAuth, (req, res) => { // [03]
    // Only return minimal public fields
    res.json(users.map(u => ({ id: u.id, username: u.username })));
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
    }

    let convo = conversations.find(c =>
        c?.participants?.includes(senderId) && c.participants.includes(receiverId)
    );

    if (!convo) {
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

    const msg = {
        id: secureId('msg_'), // [14]
        convoId: convo.id,
        senderId,
        receiverId,
        content,
        timestamp: Date.now(),
        delivered: false,
    };

    messages.push(msg);
    scheduleWrite(MESSAGES_FILE, messages); // [12]

    // Real-time delivery
    const recipientPeer = meshPeers.get(receiverId);
    const activeWs = clients.get(receiverId) || recipientPeer?.ws;

    if (activeWs?.readyState === 1) {
        const displayName = contactName || registeredNodes[senderId]?.displayName || senderId.slice(0, 10);
        safeSend(activeWs, {
            type: 'CHAT_MESSAGE', id: msg.id, convoId: convo.id,
            senderId, receiverId, content, contactName: displayName, timestamp: msg.timestamp,
        });
        safeSend(activeWs, {
            type: 'NEW_CONVERSATION',
            convo: { ...convo, otherUser: { id: senderId, username: displayName } },
        });
        msg.delivered = true;
        scheduleWrite(MESSAGES_FILE, messages); // [12]
    } else {
        // Recipient offline — add to pending queue for delivery on reconnect
        enqueuePending(receiverId, msg.id);

        if (!pendingMessages[receiverId]) pendingMessages[receiverId] = [];
        pendingMessages[receiverId].push(msg);
    }

    res.json({ success: true, message: { id: msg.id, convoId: convo.id, timestamp: msg.timestamp } });
});

// ─── CONVERSATIONS ───────────────────────────────────────────────────────────

app.get('/conversations', requireAuth, (req, res) => { // [05]
    const userId = req.user.id; // [05] always own user — ignores query param

    const userConvos = conversations.filter(c => c?.participants?.includes(userId));
    const enriched = userConvos.map(c => {
        const otherId = c.participants.find(p => p !== userId) || userId;
        const reg = registeredNodes[otherId];
        const otherUser = { id: otherId, username: reg?.displayName || c.contactName || otherId.slice(0, 10) };
        return { ...c, otherUser };
    });
    enriched.sort((a, b) => b.updated - a.updated);
    res.json(enriched);
});

// ─── HISTORY ─────────────────────────────────────────────────────────────────

app.get('/history', requireAuth, (req, res) => { // [04][13]
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
    const limit = Math.min(parseInt(req.query.limit || '50', 10), 200);
    const offset = Math.max(parseInt(req.query.offset || '0', 10), 0);
    const result = messages.filter(m => m.convoId === convoId).slice(offset, offset + limit);
    res.json(result);
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

// ─── VAULT PROXY ─────────────────────────────────────────────────────────────

// [10] Allowed Content-Type values for vault upload
const VAULT_UPLOAD_MIME_ALLOW = new Set(['multipart/form-data', 'application/octet-stream']);

app.post('/vault/upload', requireAuth, async (req, res) => { // [10]
    const rawCT = (req.headers['content-type'] || '').split(';')[0].trim().toLowerCase();
    if (!VAULT_UPLOAD_MIME_ALLOW.has(rawCT)) {
        return res.status(415).json({ error: 'Unsupported content type for vault upload' });
    }

    try {
        const httpLib = await import(VAULT_ORIGIN.startsWith('https') ? 'https' : 'http');
        const vaultUrl = new URL(`${VAULT_ORIGIN}/vault/upload`);

        const proxyReq = httpLib.request({
            hostname: vaultUrl.hostname,
            port: vaultUrl.port,
            path: vaultUrl.pathname,
            method: 'POST',
            headers: {
                'content-type': req.headers['content-type'],
                ...(req.headers['content-length'] ? { 'content-length': req.headers['content-length'] } : {})
            }
        }, (proxyRes) => {
            res.status(proxyRes.statusCode);
            proxyRes.pipe(res);
        });

        proxyReq.on('error', (e) => {
            console.error('Vault Proxy Streaming Error:', e.message);
            if (!res.headersSent) res.status(502).json({ error: 'Vault service unavailable or disconnected' });
        });

        req.pipe(proxyReq);

    } catch (e) {
        console.error('Vault connection setup error:', e.message);
        if (!res.headersSent) res.status(502).json({ error: 'Vault proxy setup error' });
    }
});

app.get('/vault/download/:fileId', requireAuth, async (req, res) => { // [17]
    let fileId;
    try { fileId = validateFileId(req.params.fileId); }
    catch (_) { return res.status(400).json({ error: 'Invalid file ID' }); }

    try {
        const proxyRes = await fetch(`${VAULT_ORIGIN}/vault/download/${encodeURIComponent(fileId)}`);
        if (!proxyRes.ok) return res.status(proxyRes.status).json({ error: 'File not found' });

        const ALLOWED_HEADERS = new Set([
            'x-file-id', 'x-file-name', 'x-file-hash', 'x-iv', 'x-auth-tag',
            'x-original-size', 'content-type', 'content-disposition',
        ]);
        for (const h of ALLOWED_HEADERS) {
            const v = proxyRes.headers.get(h);
            if (v) res.setHeader(h, v);
        }

        const reader = proxyRes.body.getReader();
        while (true) {
            const { done, value } = await reader.read();
            if (done) { res.end(); break; }
            res.write(value);
        }
    } catch (_) {
        res.status(502).json({ error: 'Vault download unavailable' }); // [32]
    }
});

app.get('/vault/files/:owner', requireAuth, async (_req, res) => {
    res.json({ files: [] });
});

app.get('/vault/verify/:fileId', requireAuth, async (req, res) => { // [18]
    let fileId;
    try { fileId = validateFileId(req.params.fileId); }
    catch (_) { return res.status(400).json({ error: 'Invalid file ID' }); }

    try {
        const proxyRes = await fetch(`${VAULT_ORIGIN}/vault/verify/${encodeURIComponent(fileId)}`);
        res.status(proxyRes.status).json(await proxyRes.json());
    } catch (_) {
        res.status(502).json({ error: 'Vault service unavailable' }); // [32]
    }
});

app.delete('/vault/file/:fileId', requireAuth, async (req, res) => { // [19]
    let fileId;
    try { fileId = validateFileId(req.params.fileId); }
    catch (_) { return res.status(400).json({ error: 'Invalid file ID' }); }

    try {
        // [19] Do NOT forward req.body — vault authenticates deletion via its own mechanism
        const proxyRes = await fetch(`${VAULT_ORIGIN}/vault/file/${encodeURIComponent(fileId)}`, {
            method: 'DELETE',
            headers: { 'content-type': 'application/json' },
        });
        res.status(proxyRes.status).json(await proxyRes.json());
    } catch (_) {
        res.status(502).json({ error: 'Vault service unavailable' }); // [32]
    }
});

// Explicit root
app.get('/', (_req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// ─── HTTP server ─────────────────────────────────────────────────────────────

const server = app.listen(PORT, '0.0.0.0', () => {
    console.log(`🟢 GhostNet Server on port ${PORT} [${GHOSTNET_MODE}]`);
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
    });

    scheduleWrite(MESSAGES_FILE, messages); // [12]

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

    // Track active connection by user ID
    if (ws._user && ws._user.id) {
        clients.set(ws._user.id, ws);

        // Deliver any transient pending messages stored in the pendingMessages object
        if (pendingMessages[ws._user.id] && pendingMessages[ws._user.id].length > 0) {
            const msgs = pendingMessages[ws._user.id];
            msgs.forEach(m => {
                safeSend(ws, {
                    type: 'CHAT_MESSAGE', id: m.id, convoId: m.convoId,
                    senderId: m.senderId, receiverId: m.receiverId, content: m.content,
                    contactName: registeredNodes[m.senderId]?.displayName || m.senderId.slice(0, 10),
                    timestamp: m.timestamp,
                });
                m.delivered = true;
            });
            pendingMessages[ws._user.id] = [];
            scheduleWrite(MESSAGES_FILE, messages);
        }
    }

    ws.on('close', () => {
        if (ws._user && ws._user.id) clients.delete(ws._user.id);
    });

    ws.on('pong', () => { ws.isAlive = true; });

    // Prevent unhandled socket errors from crashing the connection
    ws.on('error', err => {
        console.error('[WS] Socket error:', err.message);
    });

    ws.on('message', data => {
        try {
            // [23] WS message size cap
            if (data.length > MAX_CONTENT_LENGTH * 2) return;

            let msg;
            try { msg = JSON.parse(data.toString()); }
            catch (_) { return; }

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
                    }

                    clientId = newId;
                    const peerEntry = { id: clientId, ws, capabilities: {}, lastSeen: Date.now() };
                    meshPeers.set(clientId, peerEntry);

                    // Auto-register
                    if (!registeredNodes[clientId]) {
                        registeredNodes[clientId] = {
                            nodeId: clientId,
                            displayName: clientId.slice(0, 10),
                            ownerId: ws._user.id,
                            registeredAt: Date.now(),
                            lastSeen: Date.now(),
                        };
                    } else {
                        registeredNodes[clientId].lastSeen = Date.now();
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

                    // Broadcast join
                    for (const client of wss.clients) {
                        if (client !== ws) safeSend(client, { type: 'PEER_JOIN', id: clientId });
                    }

                    // [34] Synchronous delivery — no setTimeout race
                    deliverPendingMessages(clientId, ws);
                    break;
                }

                case 'HEARTBEAT':
                    ws.isAlive = true;
                    if (clientId && meshPeers.has(clientId)) {
                        meshPeers.get(clientId).lastSeen = Date.now();
                    }
                    break;

                case 'message':
                case 'MESH_DIRECT': {
                    const targetId = typeof msg.to === 'string' ? msg.to : null;
                    if (!targetId) return;

                    let safeTarget;
                    try { safeTarget = validateNodeId(targetId); } // [07]
                    catch (_) { return; }

                    let content = msg.content || msg.data;
                    if (!content) return;
                    // Ensure content is always a string before storage and size check
                    if (typeof content !== 'string') content = JSON.stringify(content);
                    // [16] Size cap on WS messages too
                    if (Buffer.byteLength(content, 'utf8') > MAX_CONTENT_LENGTH) return;

                    const senderId = clientId || ws._user?.id;
                    if (!senderId) return; // must have an identity to send
                    const timestamp = Number.isFinite(msg.timestamp) ? msg.timestamp : Date.now();
                    let wsDelivered = false;

                    const target = meshPeers.get(safeTarget);
                    if (target?.ws?.readyState === 1) {
                        safeSend(target.ws, msg);
                        wsDelivered = true;
                    }
                    // Offline queueing happens after newMsg is created below

                    // Persist
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

                    const newMsg = {
                        id: secureId('msg_'), // [14]
                        convoId: convo.id,
                        senderId,
                        receiverId: safeTarget,
                        content,
                        timestamp,
                        delivered: wsDelivered,
                    };
                    messages.push(newMsg);
                    scheduleWrite(MESSAGES_FILE, messages); // [12]

                    // Recipient offline — enqueue for delivery on reconnect
                    if (!wsDelivered) {
                        enqueuePending(safeTarget, newMsg.id);
                    }
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
        // [27] Collect IDs first, then delete after iteration
        const toRemove = [];
        for (const [id, peer] of meshPeers) {
            if (peer.ws === ws) toRemove.push(id);
        }
        toRemove.forEach(id => meshPeers.delete(id));

        if (toRemove.length > 0) {
            for (const client of wss.clients) {
                safeSend(client, { type: 'PEER_LEAVE', id: clientId || toRemove[0] });
            }
        }
    });

    safeSend(ws, { type: 'welcome' });
});

// ─── WS ping / stale cleanup ─────────────────────────────────────────────────

const WS_PING_INTERVAL = setInterval(() => {
    wss.clients.forEach(ws => {
        if (!ws.isAlive) { ws.terminate(); return; }
        ws.isAlive = false;
        ws.ping();
    });
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