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

const JWT_SECRET = process.env.AUTH_JWT_SECRET || '';

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

const BLOCKED_FILES = new Set([
    '/messages.json', '/users.json', '/conversations.json',
    '/package.json', '/package-lock.json',
    '/.env', '/.gitignore',
    '/ghostnet-server.js',
]);
app.use((req, res, next) => {
    if (BLOCKED_FILES.has(req.path.toLowerCase())) {
        return res.status(404).end();
    }
    if (req.path.endsWith('.env') || req.path.endsWith('.key') || req.path.endsWith('.pem')) {
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

app.post("/create-user", (req, res) => {
    const { username, avatar } = req.body;

    if (!username) {
        return res.status(400).json({ error: "Username required" });
    }

    const clean = username.trim().toLowerCase();

    const exists = users.find(u => u.username === clean);

    if (exists) {
        // Suggest alternatives
        const suggestions = [];
        for (let i = 1; i <= 5; i++) {
            suggestions.push(clean + Math.floor(Math.random() * 999));
        }

        return res.status(409).json({
            error: "Username taken",
            suggestions
        });
    }

    const newUser = {
        id: "user_" + crypto.randomUUID(),
        username: clean,
        avatar: avatar || null
    };

    users.push(newUser);
    debouncedWriteUsers();

    res.json({ success: true, user: newUser });
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
            lastMessage: content.slice(0, 200),
            updated: Date.now()
        };
        conversations.push(convo);
    } else {
        convo.lastMessage = content.slice(0, 200);
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

    // Broadcast to authenticated WS clients only
    for (const [, peer] of meshPeers) {
        if (peer.ws.readyState === 1) {
            peer.ws.send(JSON.stringify({ type: 'MSG', ...msg }));
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

server.on("upgrade", (req, socket, head) => {
    const url = new URL(req.url, `http://${req.headers.host}`);
    const pathname = url.pathname;
    if (pathname !== "/ws" && pathname !== "/") {
        socket.destroy();
        return;
    }
    const token = url.searchParams.get('token');
    if (!token) {
        socket.write('HTTP/1.1 401 Unauthorized\r\n\r\n');
        socket.destroy();
        return;
    }
    try {
        const decoded = jwt.verify(token, JWT_SECRET);
        req.authenticatedUserId = decoded.userId;
    } catch {
        socket.write('HTTP/1.1 401 Unauthorized\r\n\r\n');
        socket.destroy();
        return;
    }
    wss.handleUpgrade(req, socket, head, ws => {
        ws.authenticatedUserId = req.authenticatedUserId;
        wss.emit("connection", ws, req);
    });
});
// Track connected mesh peers
const meshPeers = new Map(); // peerId -> { id, ws, capabilities, lastSeen }

const MAX_WS_MESSAGE_SIZE = 8192;

wss.on("connection", (ws, req) => {
    const authenticatedUserId = ws.authenticatedUserId;
    let clientId = null;

    ws.on("message", data => {
        try {
            const raw = data.toString();
            if (raw.length > MAX_WS_MESSAGE_SIZE) return;

            const msg = JSON.parse(raw);
            if (!msg || typeof msg !== 'object' || typeof msg.type !== 'string') return;

            switch (msg.type) {
                case 'HELLO':
                case 'MESH_HELLO': {
                    clientId = authenticatedUserId;
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

                default:
                    msg.from = authenticatedUserId;
                    const outbound = JSON.stringify(msg);
                    for (const [id, peer] of meshPeers) {
                        if (id !== clientId && peer.ws.readyState === 1) {
                            peer.ws.send(outbound);
                        }
                    }
                    break;
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

    ws.send(JSON.stringify({ type: "welcome", userId: authenticatedUserId }));
});

// Clean stale peers every 30 seconds
setInterval(() => {
    const now = Date.now();
    for (const [id, peer] of meshPeers) {
        if (now - peer.lastSeen > 90000) { // 90 seconds no heartbeat
            console.log(`🕸️ Stale peer removed: ${id}`);
            meshPeers.delete(id);
            if (peer.ws.readyState === 1) {
                peer.ws.close();
            }
        }
    }
}, 30000);
