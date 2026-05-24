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

function authenticateToken(req, res, next) {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.startsWith('Bearer ') ? authHeader.slice(7) : null;
    if (!token) return res.status(401).json({ error: 'Authentication required' });
    try {
        const decoded = jwt.verify(token, JWT_SECRET);
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

const ALLOWED_STATIC_EXTENSIONS = new Set(['.html', '.css', '.png', '.jpg', '.jpeg', '.gif', '.svg', '.ico', '.woff', '.woff2', '.ttf', '.eot']);
app.use((req, res, next) => {
    const reqPath = path.normalize(req.path).replace(/\\/g, '/');
    const ext = path.extname(reqPath).toLowerCase();
    if (reqPath !== '/' && !ALLOWED_STATIC_EXTENSIONS.has(ext)) {
        return res.status(404).end();
    }
    next();
});
app.use(express.static(__dirname));
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

app.post("/create-user", createUserRateLimit, (req, res) => {
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
        if (/^https:\/\//.test(avatar)) {
            sanitizedAvatar = avatar.slice(0, 2048);
        // [RT-09] SVG removed — can contain embedded JavaScript (stored XSS)
        } else if (/^data:image\/(png|jpeg|gif|webp);base64,/.test(avatar)) {
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

app.get("/users", authenticateToken, (req, res) => {
    res.json(users.map(u => ({ id: u.id, username: u.username, avatar: u.avatar })));
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

    if (typeof receiverId !== 'string' || receiverId.length > 128) {
        return res.status(400).json({ error: "Invalid receiverId" });
    }

    // Auto-create or update conversation
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

// Explicit root for index.html
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'index.html'));
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

// [DAST-17] Accept WS upgrade without token in URL — auth via first message
server.on("upgrade", (req, socket, head) => {
    const url = new URL(req.url, `http://${req.headers.host}`);
    const pathname = url.pathname;
    if (pathname !== "/ws" && pathname !== "/") {
        socket.destroy();
        return;
    }
    // [RT-11] No URL token — auth exclusively via first message (no backward compat)
    wss.handleUpgrade(req, socket, head, ws => {
        ws.authenticatedUserId = null;
        ws._authTimeout = setTimeout(() => {
            if (!ws.authenticatedUserId) ws.close(4001, 'Auth timeout');
        }, 10000);
        wss.emit("connection", ws, req);
    });
});
// Track connected mesh peers
const meshPeers = new Map(); // peerId -> { id, ws, capabilities, lastSeen }

const MAX_WS_MESSAGE_SIZE = 8192;

wss.on("connection", (ws, req) => {
    let clientId = null;

    ws.on("message", data => {
        try {
            const raw = data.toString();
            if (raw.length > MAX_WS_MESSAGE_SIZE) return;

            const msg = JSON.parse(raw);
            if (!msg || typeof msg !== 'object' || typeof msg.type !== 'string') return;

            // [DAST-17] First-message JWT auth (if not already authenticated via URL)
            if (msg.type === 'AUTH' && !ws.authenticatedUserId) {
                if (typeof msg.token !== 'string') return;
                try {
                    const decoded = jwt.verify(msg.token, JWT_SECRET);
                    ws.authenticatedUserId = decoded.userId;
                    clearTimeout(ws._authTimeout);
                    ws.send(JSON.stringify({ type: 'welcome', userId: ws.authenticatedUserId }));
                } catch { ws.close(4001, 'Invalid token'); }
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
                    msg.from = ws.authenticatedUserId;
                    const outbound = JSON.stringify(msg);
                    if (msg.to && typeof msg.to === 'string') {
                        const targetPeer = meshPeers.get(msg.to);
                        if (targetPeer && targetPeer.ws.readyState === 1) {
                            targetPeer.ws.send(outbound);
                        }
                    } else {
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
