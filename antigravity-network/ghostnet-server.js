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

const JWT_SECRET = process.env.AUTH_JWT_SECRET;
if (!JWT_SECRET) {
    console.error('FATAL: AUTH_JWT_SECRET environment variable is required. Refusing to start.');
    process.exit(1);
}

// [IAST-06] Token revocation set — stores revoked jti values
const _revokedTokens = new Set();
const _activeWsSessions = new Map();

function authenticateToken(req, res, next) {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.startsWith('Bearer ') ? authHeader.slice(7) : null;
    if (!token) return res.status(401).json({ error: 'Authentication required' });
    try {
        // [RT-BREAK-03] Enforce max token age — reject tokens older than 24h even without exp
        const decoded = jwt.verify(token, JWT_SECRET, { maxAge: '24h' });
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
// [DAST-14] Message TTL — auto-purge messages older than 30 days
const MESSAGE_TTL_MS = 30 * 24 * 60 * 60 * 1000;

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

let _dbWriteTimer = null;
let _convosWriteTimer = null;
let _usersWriteTimer = null;

function debouncedWriteDb() {
    if (_dbWriteTimer) return;
    _dbWriteTimer = setTimeout(() => {
        _dbWriteTimer = null;
        fs.writeFile(DB_FILE, JSON.stringify(messages.slice(-MAX_MESSAGES), null, 2), () => {});
    }, 1000);
}
function debouncedWriteConvos() {
    if (_convosWriteTimer) return;
    _convosWriteTimer = setTimeout(() => {
        _convosWriteTimer = null;
        fs.writeFile(CONVOS_FILE, JSON.stringify(conversations, null, 2), () => {});
    }, 1000);
}
function debouncedWriteUsers() {
    if (_usersWriteTimer) return;
    _usersWriteTimer = setTimeout(() => {
        _usersWriteTimer = null;
        fs.writeFile(USERS_FILE, JSON.stringify(users, null, 2), () => {});
    }, 1000);
}

// 🟢 HARD STORAGE (MINIMAL)
// STEP 1 — message DB
const DB = path.join(__dirname, "messages.json");

if (!fs.existsSync(DB)) {
    fs.writeFileSync(DB, "[]");
}

// [IAST-01] Serve only from dedicated public/ directory — never expose source code
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

// Initialize messages store
const DB_FILE = path.join(__dirname, 'messages.json');
let messages = [];

try {
    if (fs.existsSync(DB_FILE)) {
        messages = JSON.parse(fs.readFileSync(DB_FILE, 'utf-8'));
    } else {
        fs.writeFileSync(DB_FILE, '[]');
    }
} catch (e) {
    console.error("DB Load Error:", e);
    messages = [];
}

// Initialize conversations store
const CONVOS_FILE = path.join(__dirname, 'conversations.json');
let conversations = [];

try {
    if (fs.existsSync(CONVOS_FILE)) {
        conversations = JSON.parse(fs.readFileSync(CONVOS_FILE, 'utf-8'));
    } else {
        fs.writeFileSync(CONVOS_FILE, '[]');
    }
} catch (e) {
    console.error("Convos DB Load Error:", e);
    conversations = [];
}

// User Management Setup
const USERS_FILE = path.join(__dirname, "users.json");

let users = [];

try {
    if (fs.existsSync(USERS_FILE)) {
        users = JSON.parse(fs.readFileSync(USERS_FILE));
    } else {
        fs.writeFileSync(USERS_FILE, "[]");
    }
} catch (e) {
    console.error("User DB load error", e);
    users = [];
}

// --- API: USER MANAGEMENT ---

// [IAST-02] Require authentication for account creation
app.post("/create-user", authenticateToken, createUserRateLimit, (req, res) => {
    const { username, avatar } = req.body;

    if (!username) {
        return res.status(400).json({ error: "Username required" });
    }

    // [DAST-12] Validate avatar if provided
    let sanitizedAvatar = null;
    if (avatar) {
        if (typeof avatar !== 'string' || avatar.length > 2048) {
            return res.status(400).json({ error: "Invalid avatar" });
        }
        // [RT-BREAK-06] External URLs rejected — prevent IP tracking via avatar fetches
        if (/^data:image\/(png|jpeg|gif|webp);base64,/.test(avatar)) {
            if (avatar.length > 65536) return res.status(400).json({ error: "Avatar data too large" });
            sanitizedAvatar = avatar;
        }
        // Anything else (javascript:, http://, arbitrary strings) is silently rejected
    }

    const clean = username.trim().toLowerCase();

    // [DAST-13][RT-08] Anti-enumeration: identical response shape regardless of outcome
    const exists = users.find(u => u.username === clean);
    if (exists) {
        return res.status(200).json({
            success: true,
            message: "If this username is available, the account has been created."
        });
    }

    const newUser = {
        id: "user_" + crypto.randomUUID(),
        username: clean,
        avatar: sanitizedAvatar
    };

    users.push(newUser);
    debouncedWriteUsers();

    // [RT-08] Same shape as "exists" response — no user object leaked
    res.json({ success: true, message: "If this username is available, the account has been created." });
});

app.get("/user/:id", authenticateToken, (req, res) => {
    try {
        const user = users.find(u => u.id === req.params.id);
        if (user) res.json(user);
        else res.status(404).json({ error: "User not found" });
    } catch (e) {
        res.status(500).json({ error: "Internal error" });
    }
});

// [IAST-03] Scoped to conversation participants — no full user enumeration
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

// Routes
app.get('/status', (req, res) => {
    res.json({ status: "ok" });
});

app.get('/conversations', authenticateToken, (req, res) => {
    const userId = req.userId;
    if (!userId) return res.status(400).json({ error: "userId required" });

    const userConvos = conversations.filter(c => c.participants.includes(userId));

    // Enrich with other user details
    const enriched = userConvos.map(c => {
        const otherId = c.participants.find(p => p !== userId) || userId;
        // Use registered user info, OR conversation-stored contactName, OR the raw ID
        const registeredUser = users.find(u => u.id === otherId);
        const otherUser = registeredUser || { id: otherId, username: c.contactName || otherId };
        return { ...c, otherUser };
    });

    enriched.sort((a, b) => b.updated - a.updated);
    res.json(enriched);
});

// Save Message (Local JSON)
app.post('/message', authenticateToken, (req, res) => {
    const senderId = req.userId;
    const { receiverId, content, contactName } = req.body;

    if (!receiverId || !content) {
        return res.status(400).json({ error: "Missing fields" });
    }

    if (typeof content !== 'string' || content.length > MAX_MESSAGE_LENGTH) {
        return res.status(400).json({ error: "Invalid or oversized content" });
    }

    // [RT-BREAK-07] Reject plaintext content — require encrypted envelope format
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

    // [RT-BREAK-01] Verify receiver exists before allowing conversation creation
    const receiverExists = users.find(u => u.id === receiverId);
    if (!receiverExists) {
        return res.status(404).json({ error: "Recipient not found" });
    }

    // [RT-BREAK-01] Sender cannot message themselves
    if (senderId === receiverId) {
        return res.status(400).json({ error: "Cannot message yourself" });
    }

    let convo = conversations.find(c =>
        c.participants.includes(senderId) && c.participants.includes(receiverId)
    );

    if (!convo) {
        convo = {
            id: "convo_" + crypto.randomUUID(),
            participants: [senderId, receiverId],
            contactName: (typeof contactName === 'string' && contactName.length <= 64) ? contactName : null,
            lastMessage: '[encrypted]',
            updated: Date.now()
        };
        conversations.push(convo);
    } else {
        convo.lastMessage = '[encrypted]';
        convo.updated = Date.now();
        if (contactName && typeof contactName === 'string' && contactName.length <= 64 && !convo.contactName) {
            convo.contactName = contactName;
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

// [IAST-01] Serve index.html from public/ directory
app.get('/', (req, res) => {
    res.sendFile(path.join(PUBLIC_DIR, 'index.html'));
});

// STEP 3 — HISTORY API
app.get("/history", authenticateToken, (req, res) => {
    try {
        const { convoId } = req.query;
        if (!convoId || typeof convoId !== 'string') {
            return res.status(400).json({ error: "convoId required" });
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

// Start
const server = app.listen(PORT, "0.0.0.0", () => {
    console.log(`GhostNet Local Server running on port ${PORT}`);
});

// WebSocket Upgrade Handling (Proper Separation)
const wss = new WebSocketServer({ noServer: true });

// [IAST-05] Track unauthenticated connections to prevent resource exhaustion
let _unauthConnCount = 0;
const MAX_UNAUTH_CONNECTIONS = 50;

server.on("upgrade", (req, socket, head) => {
    const url = new URL(req.url, `http://${req.headers.host}`);
    const pathname = url.pathname;
    if (pathname !== "/ws" && pathname !== "/") {
        socket.destroy();
        return;
    }
    // [IAST-05] Reject if too many unauthenticated connections pending
    if (_unauthConnCount >= MAX_UNAUTH_CONNECTIONS) {
        socket.destroy();
        return;
    }
    wss.handleUpgrade(req, socket, head, ws => {
        ws.authenticatedUserId = null;
        _unauthConnCount++;
        // [IAST-05] Reduced auth timeout from 10s to 3s
        ws._authTimeout = setTimeout(() => {
            if (!ws.authenticatedUserId) {
                _unauthConnCount--;
                ws.close(4001, 'Auth timeout');
            }
        }, 3000);
        wss.emit("connection", ws, req);
    });
});
// Track connected mesh peers
const meshPeers = new Map(); // peerId -> { id, ws, capabilities, lastSeen }

const MAX_WS_MESSAGE_SIZE = 8192;

wss.on("connection", (ws, req) => {
    let clientId = null;

    // [IAST-11] Per-connection rate limiting — token bucket
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

    // [IAST-12] Broadcast rate limiting — stricter bucket
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

            // [IAST-11] Enforce per-connection rate limit
            if (!_checkRate()) return;

            const msg = JSON.parse(raw);
            if (!msg || typeof msg !== 'object' || typeof msg.type !== 'string') return;

            if (msg.type === 'AUTH' && !ws.authenticatedUserId) {
                if (typeof msg.token !== 'string') return;
                try {
                    // [RT-BREAK-03] Enforce max token age on WS auth too
                    const decoded = jwt.verify(msg.token, JWT_SECRET, { maxAge: '24h' });
                    if (decoded.jti && _revokedTokens.has(decoded.jti)) {
                        _unauthConnCount = Math.max(0, _unauthConnCount - 1);
                        ws.close(4001, 'Token revoked');
                        return;
                    }
                    ws.authenticatedUserId = decoded.userId;
                    clearTimeout(ws._authTimeout);
                    _unauthConnCount = Math.max(0, _unauthConnCount - 1);
                    // [IAST-06] Track concurrent sessions — warn on multiple
                    const existingSession = _activeWsSessions.get(decoded.userId);
                    if (existingSession && existingSession.readyState === 1) {
                        existingSession.send(JSON.stringify({ type: 'SESSION_CONFLICT', message: 'Another session connected' }));
                    }
                    _activeWsSessions.set(decoded.userId, ws);
                    ws.send(JSON.stringify({ type: 'welcome', userId: ws.authenticatedUserId }));
                } catch {
                    _unauthConnCount = Math.max(0, _unauthConnCount - 1);
                    ws.close(4001, 'Invalid token');
                }
                return;
            }

            // All messages after this require auth
            if (!ws.authenticatedUserId) return;

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
                    // [RT-BREAK-08] Strip any client-injected trust flags before stamping
                    delete msg._serverVerified;
                    delete msg.__proto__;
                    msg.from = ws.authenticatedUserId;
                    msg._serverStamped = Date.now();
                    const outbound = JSON.stringify(msg);
                    if (msg.to && typeof msg.to === 'string') {
                        const targetPeer = meshPeers.get(msg.to);
                        if (targetPeer && targetPeer.ws.readyState === 1) {
                            targetPeer.ws.send(outbound);
                        }
                    } else {
                        // [IAST-12] Broadcast rate limiting
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
        } catch { /* malformed message — silently drop */ }
    });

    ws.on("close", () => {
        // [IAST-06] Clean up session tracker
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

    // [RT-11] No pre-auth — welcome sent only after first-message AUTH succeeds
});

// Clean stale peers every 30 seconds
setInterval(() => {
    const now = Date.now();
    for (const [id, peer] of meshPeers) {
        if (now - peer.lastSeen > 90000) { // 90 seconds no heartbeat
            console.log(`🕸️ Stale peer removed`);
            meshPeers.delete(id);
            if (peer.ws.readyState === 1) {
                peer.ws.close();
            }
        }
    }
}, 30000);

// [DAST-14] Purge expired messages every hour
setInterval(() => {
    const cutoff = Date.now() - MESSAGE_TTL_MS;
    const before = messages.length;
    messages = messages.filter(m => m.timestamp > cutoff);
    if (messages.length < before) {
        debouncedWriteDb();
    }
}, 3600000);
