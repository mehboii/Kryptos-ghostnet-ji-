import express from 'express';
import fs from 'fs';
import path from 'path';
import crypto from 'crypto';
import { fileURLToPath } from 'url';
import { WebSocketServer } from 'ws';
import jwt from 'jsonwebtoken';
import cors from 'cors';
import rateLimit from 'express-rate-limit';
import helmet from 'helmet';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
const PORT = process.env.PORT || 8080;

// [FIX 14] CORS — explicit origin allowlist instead of open
const ALLOWED_ORIGINS = (process.env.CORS_ORIGINS || 'http://localhost:8080,http://127.0.0.1:8080')
    .split(',').map(o => o.trim()).filter(Boolean);

app.use(cors({
    origin: (origin, callback) => {
        if (!origin || ALLOWED_ORIGINS.includes(origin)) {
            callback(null, true);
        } else {
            callback(new Error('CORS: origin not allowed'));
        }
    },
    credentials: true,
}));

// [FIX 15] Security headers (includes CSRF-adjacent protections)
app.use(helmet());

// [FIX 12] Global rate limiter — 100 requests per minute per IP
const globalLimiter = rateLimit({
    windowMs: 60 * 1000,
    max: 100,
    standardHeaders: true,
    legacyHeaders: false,
    message: { error: 'Too many requests. Try again later.' },
});
app.use(globalLimiter);

// [FIX 06] Serve ONLY a dedicated public directory, not the project root
app.use(express.static(path.join(__dirname, 'public')));
app.use(express.json({ limit: '16kb' }));

// ─── JWT Secret ─────────────────────────────────────────────────────────────
const JWT_SECRET = process.env.AUTH_JWT_SECRET
    || crypto.randomBytes(64).toString('hex');

// ─── Auth Middleware ────────────────────────────────────────────────────────
// [FIX 01] Authentication required on sensitive routes

function requireAuth(req, res, next) {
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
        return res.status(401).json({ error: 'Authentication required.' });
    }
    const token = authHeader.split(' ')[1];
    try {
        const decoded = jwt.verify(token, JWT_SECRET);
        req.userId = decoded.userId;
        next();
    } catch (err) {
        if (err.name === 'TokenExpiredError') {
            return res.status(401).json({ error: 'Token expired.' });
        }
        return res.status(401).json({ error: 'Invalid token.' });
    }
}

// ─── CSRF Protection for state-changing requests ────────────────────────────
// [FIX 15] Require a custom header on POST/PUT/DELETE — browsers won't send
// this from a cross-origin form submission without a preflight OPTIONS check
// which CORS will block. This is a lightweight CSRF defense.

function requireCsrfHeader(req, res, next) {
    if (['POST', 'PUT', 'DELETE', 'PATCH'].includes(req.method)) {
        const csrfHeader = req.headers['x-ghostnet-client'];
        if (!csrfHeader) {
            return res.status(403).json({ error: 'Missing X-GhostNet-Client header.' });
        }
    }
    next();
}

app.use(requireCsrfHeader);

// ─── Data Storage ───────────────────────────────────────────────────────────
const DB_FILE = path.join(__dirname, 'messages.json');
let messages = [];

try {
    if (fs.existsSync(DB_FILE)) {
        messages = JSON.parse(fs.readFileSync(DB_FILE, 'utf-8'));
    } else {
        fs.writeFileSync(DB_FILE, '[]');
    }
} catch (e) {
    // [FIX 17] No stack trace in logs — just the category
    console.error("DB load failed — starting with empty messages");
    messages = [];
}

const CONVOS_FILE = path.join(__dirname, 'conversations.json');
let conversations = [];

try {
    if (fs.existsSync(CONVOS_FILE)) {
        conversations = JSON.parse(fs.readFileSync(CONVOS_FILE, 'utf-8'));
    } else {
        fs.writeFileSync(CONVOS_FILE, '[]');
    }
} catch (e) {
    console.error("Conversations DB load failed — starting empty");
    conversations = [];
}

const USERS_FILE = path.join(__dirname, "users.json");
let users = [];

try {
    if (fs.existsSync(USERS_FILE)) {
        users = JSON.parse(fs.readFileSync(USERS_FILE));
    } else {
        fs.writeFileSync(USERS_FILE, "[]");
    }
} catch (e) {
    console.error("User DB load failed — starting empty");
    users = [];
}

// ─── Stricter rate limiters for auth-sensitive routes ────────────────────────
const createUserLimiter = rateLimit({
    windowMs: 10 * 60 * 1000,
    max: 10,
    message: { error: 'Too many signup attempts.' },
});

const messageLimiter = rateLimit({
    windowMs: 60 * 1000,
    max: 60,
    message: { error: 'Too many messages. Slow down.' },
});

// ─── API: USER MANAGEMENT ───────────────────────────────────────────────────
// [FIX 01] All routes require auth

app.post("/create-user", requireAuth, createUserLimiter, (req, res) => {
    const { username, avatar } = req.body;

    if (!username || typeof username !== 'string') {
        return res.status(400).json({ error: "Username required" });
    }

    const clean = username.trim().toLowerCase().slice(0, 32);

    if (!/^[a-z0-9_.-]+$/.test(clean)) {
        return res.status(400).json({ error: "Username may only contain a-z, 0-9, _, ., -" });
    }

    const exists = users.find(u => u.username === clean);

    if (exists) {
        // [FIX 08] Use crypto.randomInt instead of Math.random
        const suggestions = [];
        for (let i = 0; i < 5; i++) {
            suggestions.push(clean + crypto.randomInt(100, 999));
        }
        return res.status(409).json({ error: "Username taken", suggestions });
    }

    // [FIX 08] Cryptographically random ID
    const newUser = {
        id: "user_" + crypto.randomUUID(),
        username: clean,
        avatar: avatar || null
    };

    users.push(newUser);
    fs.writeFileSync(USERS_FILE, JSON.stringify(users, null, 2));

    res.json({ success: true, user: newUser });
});

// [FIX 07] /user/:id — only return the requesting user's own data
app.get("/user/:id", requireAuth, (req, res) => {
    if (req.params.id !== req.userId) {
        return res.status(403).json({ error: "Access denied" });
    }
    const user = users.find(u => u.id === req.params.id);
    if (user) res.json(user);
    else res.status(404).json({ error: "User not found" });
});

// [FIX 07] /users — removed. Exposing the entire user list is unnecessary.
// If peer discovery is needed, it should go through the mesh protocol.

app.get('/status', (req, res) => {
    res.json({ status: "ok" });
});

// [FIX 07] /conversations — userId derived from JWT, not query param
app.get('/conversations', requireAuth, (req, res) => {
    const userId = req.userId;

    const userConvos = conversations.filter(c => c.participants.includes(userId));

    const enriched = userConvos.map(c => {
        const otherId = c.participants.find(p => p !== userId) || userId;
        const registeredUser = users.find(u => u.id === otherId);
        const otherUser = registeredUser || { id: otherId, username: c.contactName || otherId };
        return { ...c, otherUser };
    });

    enriched.sort((a, b) => b.updated - a.updated);
    res.json(enriched);
});

// [FIX 01, 08, 17] Save Message — authenticated, crypto IDs, no content logging
app.post('/message', requireAuth, messageLimiter, (req, res) => {
    const { receiverId, content, contactName } = req.body;
    const senderId = req.userId;

    // [FIX 17] Do NOT log message content or contact names
    console.log(`[msg] from=${senderId.slice(0, 8)}… to=${(receiverId || '').slice(0, 8)}…`);

    if (!senderId || !receiverId || !content) {
        return res.status(400).json({ error: "Missing fields" });
    }

    let convo = conversations.find(c =>
        c.participants.includes(senderId) && c.participants.includes(receiverId)
    );

    if (!convo) {
        // [FIX 08] Crypto-random conversation ID
        convo = {
            id: "convo_" + crypto.randomUUID(),
            participants: [senderId, receiverId],
            contactName: contactName || null,
            lastMessage: content,
            updated: Date.now()
        };
        conversations.push(convo);
    } else {
        convo.lastMessage = content;
        convo.updated = Date.now();
        if (contactName && !convo.contactName) convo.contactName = contactName;
    }

    fs.writeFileSync(CONVOS_FILE, JSON.stringify(conversations, null, 2));

    const msg = {
        id: "msg_" + crypto.randomUUID(),
        convoId: convo.id,
        senderId,
        content,
        timestamp: Date.now()
    };

    messages.push(msg);
    try {
        fs.writeFileSync(DB_FILE, JSON.stringify(messages, null, 2));
    } catch (e) { console.error("Message save failed"); }

    // [FIX 03] Route to intended recipient only, not broadcast
    if (typeof wss !== 'undefined') {
        const targetPeer = meshPeers.get(receiverId);
        if (targetPeer && targetPeer.ws.readyState === 1) {
            targetPeer.ws.send(JSON.stringify({ type: 'MSG', ...msg }));
        }
        // Also send back to sender for multi-device sync
        const senderPeer = meshPeers.get(senderId);
        if (senderPeer && senderPeer.ws.readyState === 1 && senderPeer.ws !== targetPeer?.ws) {
            senderPeer.ws.send(JSON.stringify({ type: 'MSG', ...msg }));
        }
    }

    res.json({ success: true, message: msg, convo });
});

app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// [FIX 07] /history — verify the user is a participant in the conversation
app.get("/history", requireAuth, (req, res) => {
    try {
        const { convoId } = req.query;
        if (!convoId) {
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

// ─── Server Start ───────────────────────────────────────────────────────────
const server = app.listen(PORT, "0.0.0.0", () => {
    console.log(`GhostNet server running on port ${PORT}`);
});

// ─── WebSocket ──────────────────────────────────────────────────────────────
const wss = new WebSocketServer({ noServer: true });

// [FIX 02] WebSocket upgrade — validate origin + require auth token
server.on("upgrade", (req, socket, head) => {
    // [FIX 17] Validate origin
    const origin = req.headers.origin || '';
    if (origin && !ALLOWED_ORIGINS.includes(origin)) {
        socket.write('HTTP/1.1 403 Forbidden\r\n\r\n');
        socket.destroy();
        return;
    }

    // [FIX 02] Require JWT in query string for WS auth
    const url = new URL(req.url, `http://${req.headers.host}`);
    const token = url.searchParams.get('token');
    if (!token) {
        socket.write('HTTP/1.1 401 Unauthorized\r\n\r\n');
        socket.destroy();
        return;
    }

    let decoded;
    try {
        decoded = jwt.verify(token, JWT_SECRET);
    } catch (e) {
        socket.write('HTTP/1.1 401 Unauthorized\r\n\r\n');
        socket.destroy();
        return;
    }

    const pathname = url.pathname;
    if (pathname === "/ws" || pathname === "/") {
        wss.handleUpgrade(req, socket, head, ws => {
            ws.authenticatedUserId = decoded.userId;
            wss.emit("connection", ws, req);
        });
    } else {
        socket.destroy();
    }
});

// Track connected mesh peers
const meshPeers = new Map();

// [FIX 12] Per-client WS rate limiter
const wsRateLimits = new Map();
const WS_MAX_MESSAGES_PER_MINUTE = 120;

function checkWsRateLimit(clientId) {
    const now = Date.now();
    let entry = wsRateLimits.get(clientId);
    if (!entry || now > entry.reset) {
        entry = { count: 0, reset: now + 60000 };
        wsRateLimits.set(clientId, entry);
    }
    entry.count++;
    return entry.count <= WS_MAX_MESSAGES_PER_MINUTE;
}

// [FIX 10] Seen message IDs for replay protection
const seenMessageIds = new Set();
const MAX_SEEN = 10000;

function isReplay(msgId) {
    if (!msgId) return false;
    if (seenMessageIds.has(msgId)) return true;
    seenMessageIds.add(msgId);
    if (seenMessageIds.size > MAX_SEEN) {
        const first = seenMessageIds.values().next().value;
        seenMessageIds.delete(first);
    }
    return false;
}

wss.on("connection", (ws) => {
    // [FIX 11] Client ID comes from the authenticated JWT, not self-declared
    const clientId = ws.authenticatedUserId;
    if (!clientId) {
        ws.close(4001, 'Unauthenticated');
        return;
    }

    console.log(`[ws] peer connected: ${clientId.slice(0, 8)}…`);

    meshPeers.set(clientId, {
        id: clientId,
        ws: ws,
        capabilities: {},
        lastSeen: Date.now()
    });

    // Send peer list to newly connected client
    const peerList = [];
    for (const [id, peer] of meshPeers) {
        if (id !== clientId) {
            peerList.push({ id: peer.id, capabilities: peer.capabilities, lastSeen: peer.lastSeen });
        }
    }
    ws.send(JSON.stringify({ type: 'MESH_PEERS', peers: peerList }));

    // Broadcast PEER_JOIN to others
    wss.clients.forEach(c => {
        if (c.readyState === 1 && c !== ws) {
            c.send(JSON.stringify({ type: 'PEER_JOIN', id: clientId }));
        }
    });

    ws.on("message", data => {
        // [FIX 12] Rate limit per client
        if (!checkWsRateLimit(clientId)) {
            ws.send(JSON.stringify({ type: 'ERROR', error: 'Rate limit exceeded' }));
            return;
        }

        try {
            const raw = data.toString();
            if (raw.length > 65536) return; // drop oversized messages

            const msg = JSON.parse(raw);

            // Validate message has a type field
            if (!msg || typeof msg.type !== 'string') return;

            // [FIX 10] Replay protection
            if (msg.id && isReplay(msg.id)) return;

            switch (msg.type) {
                case 'MESH_HELLO':
                    // [FIX 11] Update capabilities only — ID is already set from JWT
                    if (meshPeers.has(clientId)) {
                        meshPeers.get(clientId).capabilities = msg.capabilities || {};
                        meshPeers.get(clientId).lastSeen = Date.now();
                    }
                    break;

                case 'HEARTBEAT':
                    if (meshPeers.has(clientId)) {
                        meshPeers.get(clientId).lastSeen = Date.now();
                    }
                    break;

                default:
                    // [FIX 03] Route to intended recipient only — no blind broadcast
                    // Stamp the verified sender ID so clients can trust the `from` field
                    msg.from = clientId;

                    if (msg.to && msg.to !== 'broadcast') {
                        // Unicast — send only to the intended recipient
                        const targetPeer = meshPeers.get(msg.to);
                        if (targetPeer && targetPeer.ws.readyState === 1) {
                            targetPeer.ws.send(JSON.stringify(msg));
                        }
                    } else if (msg.to === 'broadcast') {
                        // Explicit broadcast — still don't send to self
                        wss.clients.forEach(c => {
                            if (c.readyState === 1 && c !== ws) {
                                c.send(JSON.stringify(msg));
                            }
                        });
                    }
                    // Messages with no `to` field are dropped (invalid)
                    break;
            }
        } catch (e) {
            // [FIX 17] Don't log message contents on parse errors
            console.error("[ws] malformed message from", clientId.slice(0, 8));
        }
    });

    ws.on("close", () => {
        console.log(`[ws] peer left: ${clientId.slice(0, 8)}…`);
        meshPeers.delete(clientId);
        wsRateLimits.delete(clientId);

        wss.clients.forEach(c => {
            if (c.readyState === 1) {
                c.send(JSON.stringify({ type: 'PEER_LEAVE', id: clientId }));
            }
        });
    });

    ws.send(JSON.stringify({ type: "welcome", assignedId: clientId }));
});

// Clean stale peers every 30 seconds
setInterval(() => {
    const now = Date.now();
    for (const [id, peer] of meshPeers) {
        if (now - peer.lastSeen > 90000) {
            meshPeers.delete(id);
            if (peer.ws.readyState === 1) {
                peer.ws.close();
            }
        }
    }
}, 30000);

// Clean stale WS rate limit entries every 5 minutes
setInterval(() => {
    const now = Date.now();
    for (const [key, entry] of wsRateLimits) {
        if (now > entry.reset) wsRateLimits.delete(key);
    }
}, 300000);
