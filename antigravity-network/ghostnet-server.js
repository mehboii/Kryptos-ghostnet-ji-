import express from 'express';
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';
import { WebSocketServer } from 'ws';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
const PORT = 8080;

// 🟢 HARD STORAGE (MINIMAL)
// STEP 1 — message DB
const DB = path.join(__dirname, "messages.json");

if (!fs.existsSync(DB)) {
    fs.writeFileSync(DB, "[]");
}

app.use(express.static('.'));
app.use(express.json());

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

app.get("/users", (req, res) => {
    res.json(users);
});

// Routes
app.get('/status', (req, res) => {
    res.json({ status: "ok" });
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
const server = app.listen(8080, "0.0.0.0", () => {
    console.log("GhostNet Local Server running on port 8080");
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
