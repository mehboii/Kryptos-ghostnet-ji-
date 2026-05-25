import express from 'express';
import fs from 'fs';
import path from 'path';
import crypto from 'crypto';
import { fileURLToPath } from 'url';
import { WebSocketServer } from 'ws';
import jwt from 'jsonwebtoken';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
const PORT = process.env.GHOSTNET_SERVER_PORT || 8080;
// [DAST-F20] Configurable bind address — default to localhost
const BIND_ADDR = process.env.GHOSTNET_BIND_ADDR || '127.0.0.1';

// [DAST-F21] Remove Express fingerprint header
app.disable('x-powered-by');

const JWT_SECRET = process.env.AUTH_JWT_SECRET;
if (!JWT_SECRET) {
    console.error('FATAL: AUTH_JWT_SECRET environment variable is required. Refusing to start.');
    process.exit(1);
}

// [DAST-F12] Enforce algorithm, issuer, audience on every jwt.verify call
const JWT_VERIFY_OPTS = { maxAge: '24h', algorithms: ['HS256'], issuer: 'ghostnet', audience: 'ghostnet-api' };

// [DAST-F22] Revoked tokens stored with timestamp for TTL-based eviction
const _revokedTokens = new Map();
const _activeWsSessions = new Map();

// [DAST-F22] Purge expired revoked tokens every hour (tokens older than 24h auto-expire via maxAge)
setInterval(() => {
    const cutoff = Date.now() - 86400000;
    for (const [jti, revokedAt] of _revokedTokens) {
        if (revokedAt < cutoff) _revokedTokens.delete(jti);
    }
}, 3600000);

// [DAST-F13] Cookie parser helper — no dependency needed
function _parseCookies(cookieStr) {
    const cookies = {};
    if (!cookieStr) return cookies;
    cookieStr.split(';').forEach(pair => {
        const [name, ...rest] = pair.trim().split('=');
        if (name) cookies[name.trim()] = decodeURIComponent(rest.join('=').trim());
    });
    return cookies;
}

// [DAST-F16] Encrypted file storage — key derived from JWT_SECRET
const STORAGE_KEY = crypto.createHash('sha256').update('ghostnet-storage:' + JWT_SECRET).digest();

function _encryptForDisk(data) {
    const iv = crypto.randomBytes(12);
    const cipher = crypto.createCipheriv('aes-256-gcm', STORAGE_KEY, iv);
    let encrypted = cipher.update(JSON.stringify(data), 'utf8', 'hex');
    encrypted += cipher.final('hex');
    const tag = cipher.getAuthTag();
    return JSON.stringify({ iv: iv.toString('hex'), ct: encrypted, tag: tag.toString('hex') });
}

function _decryptFromDisk(raw) {
    const parsed = JSON.parse(raw);
    if (parsed.iv && parsed.ct && parsed.tag) {
        const decipher = crypto.createDecipheriv('aes-256-gcm', STORAGE_KEY, Buffer.from(parsed.iv, 'hex'));
        decipher.setAuthTag(Buffer.from(parsed.tag, 'hex'));
        let decrypted = decipher.update(parsed.ct, 'hex', 'utf8');
        decrypted += decipher.final('utf8');
        return JSON.parse(decrypted);
    }
    return parsed;
}

function _readDbFile(filepath) {
    try {
        if (!fs.existsSync(filepath)) return [];
        const raw = fs.readFileSync(filepath, 'utf-8');
        return _decryptFromDisk(raw);
    } catch {
        return [];
    }
}

// [DAST-F13] Read JWT from HttpOnly cookie instead of Authorization header
function authenticateToken(req, res, next) {
    const cookies = _parseCookies(req.headers.cookie || '');
    const token = cookies.ghostnet_jwt;
    if (!token) return res.status(401).json({ error: 'Authentication required' });
    try {
        const decoded = jwt.verify(token, JWT_SECRET, JWT_VERIFY_OPTS);
        if (decoded.jti && _revokedTokens.has(decoded.jti)) {
            return res.status(401).json({ error: 'Token revoked' });
        }
        req.userId = decoded.userId;
        next();
    } catch {
        return res.status(401).json({ error: 'Invalid or expired token' });
    }
}

const MAX_MESSAGES = 10_000;
const MAX_MESSAGE_LENGTH = 4096;
// [DAST-F23] Size limits for conversations and users
const MAX_CONVERSATIONS = 50_000;
const MAX_USERS = 10_000;
const MESSAGE_TTL_MS = 30 * 24 * 60 * 60 * 1000;

// [DAST-F06] Allowed WebSocket/CORS origins
const ALLOWED_ORIGINS = new Set(
    (process.env.GHOSTNET_ALLOWED_ORIGINS || `http://localhost:${PORT},http://127.0.0.1:${PORT},https://localhost:${PORT}`)
        .split(',').map(s => s.trim()).filter(Boolean)
);

const _createUserBuckets = new Map();
setInterval(() => {
    const now = Date.now();
    for (const [ip, bucket] of _createUserBuckets) {
        if (now > bucket.resetAt) _createUserBuckets.delete(ip);
    }
}, 120000);
function createUserRateLimit(req, res, next) {
    const ip = req.ip || req.connection.remoteAddress;
    const now = Date.now();
    const bucket = _createUserBuckets.get(ip) || { count: 0, resetAt: now + 600000 };
    if (now > bucket.resetAt) {
        bucket.count = 0;
        bucket.resetAt = now + 600000;
    }
    bucket.count++;
    _createUserBuckets.set(ip, bucket);
    if (bucket.count > 5) {
        return res.status(429).json({ error: 'Too many requests. Try again later.' });
    }
    next();
}

// [DAST-F04] Per-user message rate limiter — 30 messages/minute
const _messageBuckets = new Map();
setInterval(() => {
    const now = Date.now();
    for (const [uid, bucket] of _messageBuckets) {
        if (now > bucket.resetAt) _messageBuckets.delete(uid);
    }
}, 120000);
function messageRateLimit(req, res, next) {
    const userId = req.userId;
    const now = Date.now();
    const bucket = _messageBuckets.get(userId) || { count: 0, resetAt: now + 60000 };
    if (now > bucket.resetAt) {
        bucket.count = 0;
        bucket.resetAt = now + 60000;
    }
    bucket.count++;
    _messageBuckets.set(userId, bucket);
    if (bucket.count > 30) {
        return res.status(429).json({ error: 'Message rate limit exceeded. Try again later.' });
    }
    next();
}

let _dbWriteTimer = null;
let _convosWriteTimer = null;
let _usersWriteTimer = null;

const DB_FILE = path.join(__dirname, 'messages.json');
const CONVOS_FILE = path.join(__dirname, 'conversations.json');
const USERS_FILE = path.join(__dirname, 'users.json');

function debouncedWriteDb() {
    if (_dbWriteTimer) return;
    _dbWriteTimer = setTimeout(() => {
        _dbWriteTimer = null;
        fs.writeFile(DB_FILE, _encryptForDisk(messages.slice(-MAX_MESSAGES)), () => {});
    }, 1000);
}
function debouncedWriteConvos() {
    if (_convosWriteTimer) return;
    _convosWriteTimer = setTimeout(() => {
        _convosWriteTimer = null;
        fs.writeFile(CONVOS_FILE, _encryptForDisk(conversations), () => {});
    }, 1000);
}
function debouncedWriteUsers() {
    if (_usersWriteTimer) return;
    _usersWriteTimer = setTimeout(() => {
        _usersWriteTimer = null;
        fs.writeFile(USERS_FILE, _encryptForDisk(users), () => {});
    }, 1000);
}

// [DAST-F16] Read with auto-decrypt (handles both encrypted and plaintext migration)
let messages = _readDbFile(DB_FILE);
let conversations = _readDbFile(CONVOS_FILE);
let users = _readDbFile(USERS_FILE);

// [DAST-F01] Security headers — CSP, HSTS, X-Frame-Options, X-Content-Type-Options
app.use((req, res, next) => {
    res.setHeader('Content-Security-Policy', "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data: https://assets.coingecko.com https://api.qrserver.com; connect-src 'self' wss: ws:; font-src 'self'");
    res.setHeader('X-Frame-Options', 'DENY');
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains');
    res.setHeader('Referrer-Policy', 'no-referrer');
    res.setHeader('Permissions-Policy', 'camera=(), microphone=(), geolocation=()');
    // [DAST-F02] CORS — restrict to configured origins
    const origin = req.headers.origin;
    if (origin && ALLOWED_ORIGINS.has(origin)) {
        res.setHeader('Access-Control-Allow-Origin', origin);
        res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
        res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
        res.setHeader('Access-Control-Allow-Credentials', 'true');
    }
    if (req.method === 'OPTIONS') return res.status(204).end();
    next();
});

// [IAST-01] Serve only from dedicated public/ directory
const PUBLIC_DIR = path.join(__dirname, 'public');
if (!fs.existsSync(PUBLIC_DIR)) fs.mkdirSync(PUBLIC_DIR, { recursive: true });
const ALLOWED_STATIC_EXTENSIONS = new Set(['.html', '.css', '.png', '.jpg', '.jpeg', '.gif', '.svg', '.ico', '.woff', '.woff2', '.ttf', '.eot', '.js']);
app.use((req, res, next) => {
    const reqPath = path.normalize(req.path).replace(/\\/g, '/');
    if (reqPath.includes('..')) return res.status(400).end();
    const ext = path.extname(reqPath).toLowerCase();
    if (reqPath !== '/' && !ALLOWED_STATIC_EXTENSIONS.has(ext)) {
        return res.status(404).end();
    }
    next();
});
app.use(express.static(PUBLIC_DIR));
app.use(express.json({ limit: '16kb' }));

// --- API: AUTHENTICATION ---

// [DAST-F11] Public registration — rate-limited, no auth required
app.post("/register", createUserRateLimit, (req, res) => {
    const { username, password } = req.body;
    if (!username || !password || typeof username !== 'string' || typeof password !== 'string') {
        return res.status(400).json({ error: 'Username and password required' });
    }
    if (password.length < 8) {
        return res.status(400).json({ error: 'Password must be at least 8 characters' });
    }

    const clean = username.trim().toLowerCase();
    // [DAST-F05] Validate username length and character set
    if (clean.length < 1 || clean.length > 32 || !/^[a-z0-9_.\-]+$/.test(clean)) {
        return res.status(400).json({ error: 'Username must be 1-32 characters: letters, numbers, underscore, dot, hyphen' });
    }

    if (users.length >= MAX_USERS) {
        return res.status(503).json({ error: 'Registration temporarily unavailable' });
    }

    const exists = users.find(u => u.username === clean);
    if (exists) {
        return res.status(200).json({ success: true, message: 'If this username is available, the account has been created.' });
    }

    const passwordSalt = crypto.randomBytes(16).toString('hex');
    const passwordHash = crypto.scryptSync(password, passwordSalt, 64).toString('hex');

    const newUser = {
        id: 'user_' + crypto.randomUUID(),
        username: clean,
        avatar: null,
        passwordHash,
        passwordSalt,
    };

    users.push(newUser);
    debouncedWriteUsers();
    res.json({ success: true, message: 'If this username is available, the account has been created.' });
});

// [DAST-F11] Login — issues JWT as HttpOnly cookie
app.post("/login", createUserRateLimit, (req, res) => {
    const { username, password } = req.body;
    if (!username || !password || typeof username !== 'string' || typeof password !== 'string') {
        return res.status(400).json({ error: 'Username and password required' });
    }

    const clean = username.trim().toLowerCase();
    const user = users.find(u => u.username === clean);
    if (!user || !user.passwordHash || !user.passwordSalt) {
        return res.status(401).json({ error: 'Invalid credentials' });
    }

    const hash = crypto.scryptSync(password, user.passwordSalt, 64).toString('hex');
    if (!crypto.timingSafeEqual(Buffer.from(hash, 'hex'), Buffer.from(user.passwordHash, 'hex'))) {
        return res.status(401).json({ error: 'Invalid credentials' });
    }

    const jti = crypto.randomUUID();
    const token = jwt.sign(
        { userId: user.id, jti },
        JWT_SECRET,
        { algorithm: 'HS256', issuer: 'ghostnet', audience: 'ghostnet-api', expiresIn: '24h' }
    );

    // [DAST-F13] Set as HttpOnly cookie — not accessible to JavaScript
    res.cookie('ghostnet_jwt', token, {
        httpOnly: true,
        secure: process.env.NODE_ENV === 'production',
        sameSite: 'lax',
        maxAge: 86400000,
        path: '/'
    });

    res.json({ success: true, userId: user.id, username: user.username });
});

// [DAST-F11] Logout — clear cookie and revoke token
app.post("/logout", (req, res) => {
    const cookies = _parseCookies(req.headers.cookie || '');
    const token = cookies.ghostnet_jwt;
    if (token) {
        try {
            const decoded = jwt.verify(token, JWT_SECRET, JWT_VERIFY_OPTS);
            if (decoded.jti) _revokedTokens.set(decoded.jti, Date.now());
        } catch {}
    }
    res.clearCookie('ghostnet_jwt', { httpOnly: true, secure: process.env.NODE_ENV === 'production', sameSite: 'lax', path: '/' });
    res.json({ success: true });
});

// --- API: USER MANAGEMENT ---

// [IAST-02] Require authentication for account management
app.post("/create-user", authenticateToken, createUserRateLimit, (req, res) => {
    const { username, avatar, password } = req.body;

    if (!username) {
        return res.status(400).json({ error: "Username required" });
    }

    // [DAST-F05] Validate username length and character set
    const clean = username.trim().toLowerCase();
    if (clean.length < 1 || clean.length > 32 || !/^[a-z0-9_.\-]+$/.test(clean)) {
        return res.status(400).json({ error: 'Username must be 1-32 characters: letters, numbers, underscore, dot, hyphen' });
    }

    let sanitizedAvatar = null;
    if (avatar) {
        if (typeof avatar !== 'string' || avatar.length > 2048) {
            return res.status(400).json({ error: "Invalid avatar" });
        }
        if (/^data:image\/(png|jpeg|gif|webp);base64,/.test(avatar)) {
            if (avatar.length > 65536) return res.status(400).json({ error: "Avatar data too large" });
            sanitizedAvatar = avatar;
        }
    }

    if (users.length >= MAX_USERS) {
        return res.status(503).json({ error: 'User registration temporarily unavailable' });
    }

    const exists = users.find(u => u.username === clean);
    if (exists) {
        return res.status(200).json({
            success: true,
            message: "If this username is available, the account has been created."
        });
    }

    let passwordHash = null;
    let passwordSalt = null;
    if (password && typeof password === 'string' && password.length >= 8) {
        passwordSalt = crypto.randomBytes(16).toString('hex');
        passwordHash = crypto.scryptSync(password, passwordSalt, 64).toString('hex');
    }

    const newUser = {
        id: "user_" + crypto.randomUUID(),
        username: clean,
        avatar: sanitizedAvatar,
        passwordHash,
        passwordSalt,
    };

    users.push(newUser);
    debouncedWriteUsers();

    res.json({ success: true, message: "If this username is available, the account has been created." });
});

app.get("/user/:id", authenticateToken, (req, res) => {
    try {
        const user = users.find(u => u.id === req.params.id);
        if (user) {
            const { passwordHash, passwordSalt, ...safeUser } = user;
            res.json(safeUser);
        }
        else res.status(404).json({ error: "User not found" });
    } catch (e) {
        res.status(500).json({ error: "Internal error" });
    }
});

// [IAST-03] Scoped to conversation participants
app.get("/users", authenticateToken, (req, res) => {
    const userId = req.userId;
    const contactIds = new Set();
    for (const c of conversations) {
        if (c.participants.includes(userId)) {
            c.participants.forEach(p => { if (p !== userId) contactIds.add(p); });
        }
    }
    const contacts = users
        .filter(u => contactIds.has(u.id))
        .map(u => ({ id: u.id, username: u.username, avatar: u.avatar }));
    res.json(contacts);
});

// [DAST-F03] Minimal health check — no information disclosure
app.get('/status', (req, res) => {
    res.status(200).end();
});

app.get('/conversations', authenticateToken, (req, res) => {
    const userId = req.userId;
    if (!userId) return res.status(400).json({ error: "userId required" });

    const userConvos = conversations.filter(c => c.participants.includes(userId));

    const enriched = userConvos.map(c => {
        const otherId = c.participants.find(p => p !== userId) || userId;
        const registeredUser = users.find(u => u.id === otherId);
        const otherUser = registeredUser
            ? { id: registeredUser.id, username: registeredUser.username, avatar: registeredUser.avatar }
            : { id: otherId, username: c.contactName || otherId };
        return { ...c, otherUser };
    });

    enriched.sort((a, b) => b.updated - a.updated);
    res.json(enriched);
});

// [DAST-F04] Rate-limited per user
app.post('/message', authenticateToken, messageRateLimit, (req, res) => {
    const senderId = req.userId;
    const { receiverId, content, contactName } = req.body;

    if (!receiverId || !content) {
        return res.status(400).json({ error: "Missing fields" });
    }

    if (typeof content !== 'string' || content.length > MAX_MESSAGE_LENGTH) {
        return res.status(400).json({ error: "Invalid or oversized content" });
    }

    try {
        const parsed = JSON.parse(content);
        if (!parsed.enc || !parsed.iv || !parsed.data) {
            return res.status(400).json({ error: "Content must be encrypted" });
        }
    } catch {
        return res.status(400).json({ error: "Content must be encrypted JSON envelope" });
    }

    if (typeof receiverId !== 'string' || receiverId.length > 128) {
        return res.status(400).json({ error: "Invalid receiverId" });
    }

    const receiverExists = users.find(u => u.id === receiverId);
    if (!receiverExists) {
        return res.status(404).json({ error: "Recipient not found" });
    }

    if (senderId === receiverId) {
        return res.status(400).json({ error: "Cannot message yourself" });
    }

    let convo = conversations.find(c =>
        c.participants.includes(senderId) && c.participants.includes(receiverId)
    );

    if (!convo) {
        // [DAST-F23] Enforce conversation count limit
        if (conversations.length >= MAX_CONVERSATIONS) {
            return res.status(503).json({ error: "Conversation limit reached" });
        }

        // [DAST-F14] Sanitize contactName server-side
        let safeContactName = null;
        if (typeof contactName === 'string' && contactName.length <= 64) {
            safeContactName = contactName.replace(/[<>&"']/g, '');
        }

        convo = {
            id: "convo_" + crypto.randomUUID(),
            participants: [senderId, receiverId],
            contactName: safeContactName,
            lastMessage: '[encrypted]',
            updated: Date.now()
        };
        conversations.push(convo);
    } else {
        convo.lastMessage = '[encrypted]';
        convo.updated = Date.now();
        if (contactName && typeof contactName === 'string' && contactName.length <= 64 && !convo.contactName) {
            convo.contactName = contactName.replace(/[<>&"']/g, '');
        }
    }

    debouncedWriteConvos();

    const msg = {
        id: "msg_" + crypto.randomUUID(),
        convoId: convo.id,
        senderId,
        content,
        timestamp: Date.now()
    };

    messages.push(msg);
    if (messages.length > MAX_MESSAGES) {
        messages = messages.slice(-MAX_MESSAGES);
    }
    debouncedWriteDb();

    for (const [peerId, peer] of meshPeers) {
        if (peer.ws.readyState === 1 && (peerId === senderId || peerId === receiverId)) {
            peer.ws.send(JSON.stringify({ type: 'MSG', id: msg.id, convoId: msg.convoId, senderId: msg.senderId, timestamp: msg.timestamp }));
        }
    }

    res.json({ success: true, message: msg, convo });
});

app.get('/', (req, res) => {
    res.sendFile(path.join(PUBLIC_DIR, 'index.html'));
});

app.get("/history", authenticateToken, (req, res) => {
    try {
        const { convoId } = req.query;
        if (!convoId || typeof convoId !== 'string') {
            return res.status(400).json({ error: "convoId required" });
        }
        // [DAST-F15] Validate convoId format
        if (!/^convo_[a-f0-9\-]+$/.test(convoId)) {
            return res.status(400).json({ error: "Invalid convoId format" });
        }
        const convo = conversations.find(c => c.id === convoId);
        if (!convo || !convo.participants.includes(req.userId)) {
            return res.status(403).json({ error: "Access denied" });
        }
        res.json(messages.filter(m => m.convoId === convoId));
    } catch (e) {
        res.json([]);
    }
});

// [DAST-F20] Bind to configurable address
const server = app.listen(PORT, BIND_ADDR, () => {
    console.log(`GhostNet Local Server running on ${BIND_ADDR}:${PORT}`);
});

const wss = new WebSocketServer({ noServer: true });
const meshPeers = new Map();

server.on("upgrade", (req, socket, head) => {
    const url = new URL(req.url, `http://${req.headers.host}`);
    const pathname = url.pathname;
    if (pathname !== "/ws" && pathname !== "/") {
        socket.destroy();
        return;
    }

    // [DAST-F06] Validate Origin header
    const origin = req.headers.origin;
    if (origin && !ALLOWED_ORIGINS.has(origin)) {
        socket.destroy();
        return;
    }

    // [DAST-F13] Authenticate from HttpOnly cookie during upgrade — no first-message AUTH needed
    const cookies = _parseCookies(req.headers.cookie || '');
    const token = cookies.ghostnet_jwt;
    if (!token) {
        socket.destroy();
        return;
    }

    try {
        const decoded = jwt.verify(token, JWT_SECRET, JWT_VERIFY_OPTS);
        if (decoded.jti && _revokedTokens.has(decoded.jti)) {
            socket.destroy();
            return;
        }

        wss.handleUpgrade(req, socket, head, ws => {
            ws.authenticatedUserId = decoded.userId;
            const existing = _activeWsSessions.get(decoded.userId);
            if (existing && existing.readyState === 1) {
                existing.send(JSON.stringify({ type: 'SESSION_CONFLICT', message: 'Another session connected' }));
            }
            _activeWsSessions.set(decoded.userId, ws);
            wss.emit("connection", ws, req);
        });
    } catch {
        socket.destroy();
    }
});

const MAX_WS_MESSAGE_SIZE = 8192;

wss.on("connection", (ws, req) => {
    let clientId = null;

    // [DAST-F13] Already authenticated via cookie during upgrade
    ws.send(JSON.stringify({ type: 'welcome', userId: ws.authenticatedUserId }));

    const _rateLimit = { tokens: 30, lastRefill: Date.now(), maxTokens: 30, refillRate: 10 };
    function _checkRate() {
        const now = Date.now();
        const elapsed = (now - _rateLimit.lastRefill) / 1000;
        _rateLimit.tokens = Math.min(_rateLimit.maxTokens, _rateLimit.tokens + elapsed * _rateLimit.refillRate);
        _rateLimit.lastRefill = now;
        if (_rateLimit.tokens < 1) return false;
        _rateLimit.tokens--;
        return true;
    }

    const _broadcastRate = { tokens: 5, lastRefill: Date.now(), maxTokens: 5, refillRate: 2 };
    function _checkBroadcastRate() {
        const now = Date.now();
        const elapsed = (now - _broadcastRate.lastRefill) / 1000;
        _broadcastRate.tokens = Math.min(_broadcastRate.maxTokens, _broadcastRate.tokens + elapsed * _broadcastRate.refillRate);
        _broadcastRate.lastRefill = now;
        if (_broadcastRate.tokens < 1) return false;
        _broadcastRate.tokens--;
        return true;
    }

    ws.on("message", data => {
        try {
            const raw = data.toString();
            if (raw.length > MAX_WS_MESSAGE_SIZE) return;
            if (!_checkRate()) return;

            const msg = JSON.parse(raw);
            if (!msg || typeof msg !== 'object' || typeof msg.type !== 'string') return;

            switch (msg.type) {
                case 'HELLO':
                case 'MESH_HELLO': {
                    clientId = ws.authenticatedUserId;
                    meshPeers.set(clientId, {
                        id: clientId,
                        ws: ws,
                        capabilities: msg.capabilities || {},
                        lastSeen: Date.now()
                    });

                    const peerList = [];
                    for (const [id, peer] of meshPeers) {
                        if (id !== clientId) {
                            peerList.push({ id: peer.id, capabilities: peer.capabilities, lastSeen: peer.lastSeen });
                        }
                    }
                    ws.send(JSON.stringify({ type: 'MESH_PEERS', peers: peerList }));

                    for (const [id, peer] of meshPeers) {
                        if (id !== clientId && peer.ws.readyState === 1) {
                            peer.ws.send(JSON.stringify({ type: 'PEER_JOIN', id: clientId, capabilities: msg.capabilities }));
                        }
                    }
                    break;
                }

                case 'HEARTBEAT':
                    if (clientId && meshPeers.has(clientId)) {
                        meshPeers.get(clientId).lastSeen = Date.now();
                    }
                    break;

                default: {
                    const ALLOWED_RELAY_TYPES = new Set(['MESH_MSG', 'MESH_DIRECT', 'MSG', 'HEARTBEAT_ACK']);
                    if (!ALLOWED_RELAY_TYPES.has(msg.type)) break;
                    delete msg._serverVerified;
                    delete msg.__proto__;
                    msg.from = ws.authenticatedUserId;
                    msg._serverStamped = Date.now();
                    const outbound = JSON.stringify(msg);
                    if (msg.to && typeof msg.to === 'string') {
                        // [DAST-F07/F08] Only relay to connected peers
                        const targetPeer = meshPeers.get(msg.to);
                        if (targetPeer && targetPeer.ws.readyState === 1) {
                            targetPeer.ws.send(outbound);
                        }
                    } else {
                        if (!_checkBroadcastRate()) break;
                        for (const [id, peer] of meshPeers) {
                            if (id !== clientId && peer.ws.readyState === 1) {
                                peer.ws.send(outbound);
                            }
                        }
                    }
                    break;
                }
            }
        } catch {}
    });

    ws.on("close", () => {
        if (ws.authenticatedUserId && _activeWsSessions.get(ws.authenticatedUserId) === ws) {
            _activeWsSessions.delete(ws.authenticatedUserId);
        }
        if (clientId) {
            meshPeers.delete(clientId);
            for (const [, peer] of meshPeers) {
                if (peer.ws.readyState === 1) {
                    peer.ws.send(JSON.stringify({ type: 'PEER_LEAVE', id: clientId }));
                }
            }
        }
    });
});

setInterval(() => {
    const now = Date.now();
    for (const [id, peer] of meshPeers) {
        if (now - peer.lastSeen > 90000) {
            console.log(`Stale peer removed`);
            meshPeers.delete(id);
            if (peer.ws.readyState === 1) {
                peer.ws.close();
            }
        }
    }
}, 30000);

setInterval(() => {
    const cutoff = Date.now() - MESSAGE_TTL_MS;
    const before = messages.length;
    messages = messages.filter(m => m.timestamp > cutoff);
    if (messages.length < before) {
        debouncedWriteDb();
    }
}, 3600000);
