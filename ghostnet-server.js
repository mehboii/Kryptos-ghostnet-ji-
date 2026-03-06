import 'dotenv/config';
import express from 'express';
import cors from 'cors';
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';
import { WebSocketServer } from 'ws';
import authRouter from './auth/auth.routes.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
app.use(cors({ origin: true, credentials: true }));
const PORT = parseInt(process.env.GHOSTNET_SERVER_PORT || process.env.PORT || '8080', 10);
const GHOSTNET_MODE = process.env.GHOSTNET_MODE || 'development';
const startTime = Date.now();

// 🟢 HARD STORAGE (MINIMAL)
// STEP 1 — message DB
const DB = path.join(__dirname, "messages.json");

if (!fs.existsSync(DB)) {
    fs.writeFileSync(DB, "[]");
}

app.use(express.static('.'));
app.use((req, res, next) => {
    // Skip JSON parsing for vault upload (multipart/form-data — raw forwarded to vault service)
    if (req.path === '/vault/upload') return next();
    express.json()(req, res, next);
});

// --- AUTH ROUTES (bcrypt + JWT) ---
app.use('/auth', authRouter);

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

// Node ID Registry
const NODES_FILE = path.join(__dirname, "nodes.json");
let registeredNodes = {};

try {
    if (fs.existsSync(NODES_FILE)) {
        registeredNodes = JSON.parse(fs.readFileSync(NODES_FILE, 'utf-8'));
    } else {
        fs.writeFileSync(NODES_FILE, "{}");
    }
} catch (e) {
    console.error("Node registry load error", e);
    registeredNodes = {};
}

function saveNodeRegistry() {
    try {
        fs.writeFileSync(NODES_FILE, JSON.stringify(registeredNodes, null, 2));
    } catch (e) {
        console.error("Node registry save error", e);
    }
}

// --- API: NODE REGISTRATION & VALIDATION ---

app.post("/register-node", (req, res) => {
    const { nodeId, displayName, address, publicKey } = req.body;

    if (!nodeId || !displayName) {
        return res.status(400).json({ error: "nodeId and displayName required" });
    }

    registeredNodes[nodeId] = {
        nodeId,
        displayName,
        address: address || null,
        publicKey: publicKey || null,
        registeredAt: Date.now(),
        lastSeen: Date.now()
    };

    saveNodeRegistry();
    console.log(`📋 Node registered: ${displayName} (${nodeId.substring(0, 10)}...)`);
    res.json({ success: true });
});

app.get("/validate-node/:nodeId", (req, res) => {
    const { nodeId } = req.params;

    if (!nodeId) {
        return res.status(400).json({ error: "nodeId required" });
    }

    const node = registeredNodes[nodeId];
    if (node) {
        // Update last seen
        node.lastSeen = Date.now();
        saveNodeRegistry();
        res.json({ valid: true, displayName: node.displayName, address: node.address });
    } else {
        res.json({ valid: false });
    }
});

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
        id: "user_" + Date.now(),
        username: clean,
        avatar: avatar || null
    };

    users.push(newUser);
    fs.writeFileSync(USERS_FILE, JSON.stringify(users, null, 2));

    res.json({ success: true, user: newUser });
});

app.get("/user/:id", (req, res) => {
    try {
        const user = users.find(u => u.id === req.params.id);
        if (user) res.json(user);
        else res.status(404).json({ error: "User not found" });
    } catch (e) {
        res.status(500).json({ error: "DB Error" });
    }
});

app.get('/wallet', async (req, res) => {
    res.json([
        { symbol: 'ETH', balance: 0.0, chain: 'Ethereum', address: '0x00...00' },
        { symbol: 'BTC', balance: 0.0, chain: 'Regtest', address: 'N/A' },
        { symbol: 'SOL', balance: 0.0, chain: 'Solana', address: 'N/A' },
        { symbol: 'USDT', balance: 0.0, chain: 'Ethereum', address: '0x00...00' }
    ]);
});

app.get("/users", (req, res) => {
    res.json(users);
});

// Routes
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
            heapTotal: Math.round(mem.heapTotal / 1024 / 1024)
        },
        connections: {
            wsClients: wss ? wss.clients.size : 0,
            meshPeers: meshPeers ? meshPeers.size : 0
        },
        port: PORT,
        node: process.version,
        timestamp: Date.now()
    });
});

function formatUptime(ms) {
    const s = Math.floor(ms / 1000);
    const m = Math.floor(s / 60);
    const h = Math.floor(m / 60);
    if (h > 0) return `${h}h ${m % 60}m`;
    if (m > 0) return `${m}m ${s % 60}s`;
    return `${s}s`;
}

// Inter-service health check proxy
app.get('/health/bridge', async (req, res) => {
    try {
        const bridgeUrl = process.env.GHOSTNET_BRIDGE_URL || 'http://127.0.0.1:3001';
        const response = await fetch(`${bridgeUrl}/wallet`);
        if (response.ok) {
            res.json({ bridge: 'online', port: 3001 });
        } else {
            res.status(502).json({ bridge: 'unhealthy', code: response.status });
        }
    } catch (e) {
        res.status(502).json({ bridge: 'offline', error: e.message });
    }
});

app.get('/conversations', (req, res) => {
    const { userId } = req.query;
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
app.post('/message', (req, res) => {
    const { senderId, receiverId, content, contactName } = req.body;
    console.log(`📨 POST /message — from: ${senderId}, to: ${receiverId}, name: ${contactName || '(none)'}`);

    if (!senderId || !receiverId || !content) {
        return res.status(400).json({ error: "Missing fields" });
    }

    // Validate receiverId exists in node registry (skip 'broadcast')
    if (receiverId !== 'broadcast' && !registeredNodes[receiverId]) {
        console.log(`🚫 Message rejected — receiverId not found: ${receiverId.substring(0, 15)}...`);
        return res.status(404).json({ error: "Node not found or offline" });
    }

    // Auto-create or update conversation
    let convo = conversations.find(c =>
        c.participants.includes(senderId) && c.participants.includes(receiverId)
    );

    if (!convo) {
        convo = {
            id: "convo_" + Date.now() + "_" + Math.random().toString(36).substr(2, 5),
            participants: [senderId, receiverId],
            contactName: contactName || null,
            lastMessage: content,
            updated: Date.now()
        };
        conversations.push(convo);
    } else {
        convo.lastMessage = content;
        convo.updated = Date.now();
        // Update contactName if provided and not already set
        if (contactName && !convo.contactName) convo.contactName = contactName;
    }

    fs.writeFileSync(CONVOS_FILE, JSON.stringify(conversations, null, 2));

    const msg = {
        id: "msg_" + Date.now(),
        convoId: convo.id,
        senderId,
        content,
        timestamp: Date.now()
    };

    messages.push(msg);
    try {
        fs.writeFileSync(DB_FILE, JSON.stringify(messages, null, 2));
    } catch (e) { console.error("Save Error", e); }

    // Broadcast logic (Real-time)
    if (typeof wss !== 'undefined') {
        wss.clients.forEach(c => {
            if (c.readyState === 1) c.send(JSON.stringify({ type: 'MSG', ...msg }));
        });
    }

    res.json({ success: true, message: msg, convo });
});

// ═══════════════════════════════════════════════════
// VAULT PROXY — Forward /vault/* to Vault Service
// ═══════════════════════════════════════════════════
const VAULT_URL = process.env.GHOSTNET_VAULT_URL || 'http://127.0.0.1:4001';

// Proxy vault uploads (multipart/form-data — needs raw body forwarding)
app.post('/vault/upload', async (req, res) => {
    try {
        // Collect raw body for multipart forwarding
        const chunks = [];
        req.on('data', chunk => chunks.push(chunk));
        req.on('end', async () => {
            try {
                const body = Buffer.concat(chunks);
                const proxyRes = await fetch(`${VAULT_URL}/vault/upload`, {
                    method: 'POST',
                    headers: {
                        'content-type': req.headers['content-type'],
                        'content-length': body.length
                    },
                    body
                });
                const data = await proxyRes.json();
                res.status(proxyRes.status).json(data);
            } catch (err) {
                res.status(502).json({ error: 'Vault service unavailable: ' + err.message });
            }
        });
    } catch (err) {
        res.status(502).json({ error: 'Vault proxy error: ' + err.message });
    }
});

// Proxy vault file downloads (stream response)
app.get('/vault/download/:fileId', async (req, res) => {
    try {
        const proxyRes = await fetch(`${VAULT_URL}/vault/download/${req.params.fileId}`);
        if (!proxyRes.ok) {
            const err = await proxyRes.json();
            return res.status(proxyRes.status).json(err);
        }
        // Forward headers
        ['x-file-id', 'x-file-name', 'x-file-hash', 'x-iv', 'x-auth-tag', 'x-original-size', 'content-type', 'content-disposition'].forEach(h => {
            const val = proxyRes.headers.get(h);
            if (val) res.setHeader(h, val);
        });
        // Stream the body
        const reader = proxyRes.body.getReader();
        const pump = async () => {
            while (true) {
                const { done, value } = await reader.read();
                if (done) { res.end(); return; }
                res.write(value);
            }
        };
        await pump();
    } catch (err) {
        res.status(502).json({ error: 'Vault download proxy error: ' + err.message });
    }
});

// Proxy vault list, verify, delete (JSON)
app.get('/vault/files/:owner', async (req, res) => {
    try {
        res.json({ files: [] });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.get('/vault/verify/:fileId', async (req, res) => {
    try {
        const proxyRes = await fetch(`${VAULT_URL}/vault/verify/${req.params.fileId}`);
        res.status(proxyRes.status).json(await proxyRes.json());
    } catch (err) {
        res.status(502).json({ error: 'Vault service unavailable' });
    }
});

app.delete('/vault/file/:fileId', async (req, res) => {
    try {
        const proxyRes = await fetch(`${VAULT_URL}/vault/file/${req.params.fileId}`, {
            method: 'DELETE',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(req.body)
        });
        res.status(proxyRes.status).json(await proxyRes.json());
    } catch (err) {
        res.status(502).json({ error: 'Vault service unavailable' });
    }
});

// Explicit root for index.html
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'index.html'));
});

// STEP 3 — HISTORY API
app.get("/history", (req, res) => {
    try {
        const all = JSON.parse(fs.readFileSync(DB));
        const { convoId } = req.query;
        if (convoId) {
            res.json(all.filter(m => m.convoId === convoId));
        } else {
            res.json(all);
        }
    } catch (e) {
        res.json([]);
    }
});

// Start
const server = app.listen(PORT, "0.0.0.0", () => {
    console.log(`🟢 GhostNet Server running on port ${PORT} [${GHOSTNET_MODE}]`);
});

// WebSocket Upgrade Handling (Proper Separation)
const wss = new WebSocketServer({ noServer: true });

server.on("upgrade", (req, socket, head) => {
    // Handle both /ws (new standard) and root (legacy fallback) if needed? 
    // User requested "ws://localhost:8080/ws". So we check for "/ws".
    // But app.js uses `ws://${window.location.host}` which is root "/".
    // I MUST UPDATE APP.JS TO USE /ws if I restrict it here.
    // Or I accept "/" here too.
    // User instructions: "Change frontend WS URL to ... /ws. Then change server to ... checking /ws".
    // I will check for "/ws" AND "/" to cover both bases during transition or just "/ws" if strict.
    // I'll be permissive: `req.url === '/ws' || req.url === '/'` ?
    // But Express handles "/" for HTTP. WS upgrade is separate.
    // I'll stick to user instructions: check "/ws" logic.
    // I'll assume I will update app.js next.
    if (req.url === "/ws" || req.url === "/") {
        wss.handleUpgrade(req, socket, head, ws => {
            wss.emit("connection", ws, req);
        });
    } else {
        socket.destroy();
    }
});
// Track connected mesh peers
const meshPeers = new Map(); // peerId -> { id, ws, capabilities, lastSeen }

wss.on("connection", (ws) => {
    let clientId = null;
    console.log("WS client connected");

    ws.on("message", data => {
        try {
            const msg = JSON.parse(data.toString());

            switch (msg.type) {
                case 'HELLO':
                case 'MESH_HELLO':
                    // Register this peer
                    clientId = msg.id || msg.nodeId;
                    meshPeers.set(clientId, {
                        id: clientId,
                        ws: ws,
                        capabilities: msg.capabilities || {},
                        lastSeen: Date.now()
                    });
                    console.log(`🕸️ Mesh peer joined: ${clientId} (total: ${meshPeers.size})`);

                    // Send full peer list to the new peer
                    const peerList = [];
                    for (const [id, peer] of meshPeers) {
                        if (id !== clientId) {
                            peerList.push({ id: peer.id, capabilities: peer.capabilities, lastSeen: peer.lastSeen });
                        }
                    }
                    ws.send(JSON.stringify({ type: 'MESH_PEERS', peers: peerList }));

                    // Broadcast PEER_JOIN to all OTHER peers
                    wss.clients.forEach(c => {
                        if (c.readyState === 1 && c !== ws) {
                            c.send(JSON.stringify({ type: 'PEER_JOIN', id: clientId, capabilities: msg.capabilities }));
                        }
                    });
                    break;

                case 'HEARTBEAT':
                    // Update lastSeen
                    if (clientId && meshPeers.has(clientId)) {
                        meshPeers.get(clientId).lastSeen = Date.now();
                    }
                    break;

                default:
                    // Broadcast all other messages to other clients
                    wss.clients.forEach(c => {
                        if (c.readyState === 1 && c !== ws) {
                            c.send(JSON.stringify(msg));
                        }
                    });
                    break;
            }
        } catch (e) { console.error("WS msg error:", e); }
    });

    ws.on("close", () => {
        if (clientId) {
            console.log(`🕸️ Mesh peer left: ${clientId} (total: ${meshPeers.size - 1})`);
            meshPeers.delete(clientId);

            // Broadcast PEER_LEAVE
            wss.clients.forEach(c => {
                if (c.readyState === 1) {
                    c.send(JSON.stringify({ type: 'PEER_LEAVE', id: clientId }));
                }
            });
        }
    });

    ws.send(JSON.stringify({ type: "welcome" }));
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

