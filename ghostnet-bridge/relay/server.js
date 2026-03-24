const WebSocket = require('ws');
const crypto = require('crypto');

// Generate static keypair for this relay instance (Feature from Level 9)
const relayKeyPair = crypto.generateKeyPairSync("x25519");
const relayPublicKey = relayKeyPair.publicKey.export({ type: "spki", format: "der" }).toString("hex");

const FRAME_SIZE = 1024;
const port = Number(process.env.PORT) || Number(process.argv[2]) || 8080;
const wss = new WebSocket.Server({ port });

// Session key must be derived via ECDH — no static fallback
let sessionKey = null; // Must be derived via ECDH, no fallback

// Authentication token for WebSocket connections
const RELAY_TOKEN = process.env.RELAY_TOKEN || '';

// --- LEVEL 10: REPLAY PROTECTION ---
const seen = new Map(); // id -> timestamp
const MAX_AGE = 30; // seconds

// Cleanup interval (Every 5s)
setInterval(() => {
    const t = Math.floor(Date.now() / 1000);
    for (const [id, ts] of seen.entries()) {
        if (t - ts > MAX_AGE) seen.delete(id);
    }
}, 5000);

// console.log(`[Relay:${port}] Public Key: ${relayPublicKey.slice(0, 16)}...`);

// --- LEVEL 11: UNAUTHORIZED ACCESS DECOY MODE ---
function sendDecoy(ws) {
    // Simulate a generic public node response to confuse attackers
    ws.send(JSON.stringify({
        payload: "Welcome to GhostNet Public Node. Access Restricted."
    }));
}

wss.on('connection', (ws, req) => {
    // Basic token authentication
    if (RELAY_TOKEN) {
        const url = new URL(req.url, `http://localhost:${port}`);
        const token = url.searchParams.get('token') || '';
        if (token !== RELAY_TOKEN) {
            console.log(`[Relay:${port}] Unauthorized connection rejected`);
            ws.close(4001, 'Unauthorized');
            return;
        }
    }

    let connSessionKey = null; // Must be derived via ECDH, no fallback

    // Send Handshake for clients that support Level 9
    ws.send(JSON.stringify({
        type: "handshake",
        pub: relayPublicKey
    }));

    ws.on("message", (data) => {
        try {
            let msg;
            try {
                msg = JSON.parse(data);
            } catch (e) {
                // Malformed JSON -> Decoy
                console.log(`[Relay:${port}] Malformed JSON -> Decoy`);
                sendDecoy(ws);
                return;
            }

            // Handle Client Public Key -> Derive Session Key (Level 9)
            if (msg.type === "client_pub") {
                const clientPub = Buffer.from(msg.pub, "hex");
                const shared = crypto.diffieHellman({
                    privateKey: relayKeyPair.privateKey,
                    publicKey: crypto.createPublicKey({
                        key: clientPub,
                        format: "der",
                        type: "spki"
                    })
                });
                connSessionKey = crypto.createHash("sha256").update(shared).digest();
                console.log(`[Relay:${port}] Session Key Established`);
                return;
            }

            // Handle Encrypted Onion Layer
            if (msg.payload) {
                // Reject if ECDH key exchange has not been completed
                if (!connSessionKey) {
                    console.log(`[Relay:${port}] No session key established — rejecting`);
                    ws.close(4002, 'ECDH key exchange required');
                    return;
                }

                // 1. Decrypt
                let peeled;
                try {
                    peeled = decrypt(msg.payload, connSessionKey).toString();
                } catch (e) {
                    console.log(`[Relay:${port}] Decrypt Failed -> Decoy`);
                    sendDecoy(ws);
                    return;
                }

                // 2. Parse JSON Layer
                let layer;
                try {
                    layer = JSON.parse(peeled);
                } catch (jsonErr) {
                    console.log(`[Relay:${port}] Malformed Layer -> Decoy`);
                    sendDecoy(ws);
                    return;
                }

                // 3. Enforce Replay Protection & Freshness (Level 10)
                const now = Math.floor(Date.now() / 1000);

                // Validation: Check for required fields
                if (!layer.id || !layer.ts || layer.next === undefined) {
                    console.log(`[Relay:${port}] Invalid Protocol Fields -> Decoy`);
                    sendDecoy(ws);
                    return;
                }

                // Check Freshness (30s window)
                if (Math.abs(now - layer.ts) > MAX_AGE) {
                    console.log(`[Relay:${port}] Stale Packet -> Decoy`);
                    sendDecoy(ws);
                    return;
                }

                // Check Replay (Seen ID)
                if (seen.has(layer.id)) {
                    console.log(`[Relay:${port}] Replay Detected -> Decoy`);
                    sendDecoy(ws);
                    return;
                }
                seen.set(layer.id, layer.ts);

                // 4. Routing Logic
                if (layer.next !== null) {
                    // Forwarding — validate target to prevent SSRF
                    const parsedNext = new URL(layer.next);
                    const blockedHosts = ['127.0.0.1', 'localhost', '::1', '0.0.0.0'];
                    if (blockedHosts.includes(parsedNext.hostname) || parsedNext.hostname.startsWith('10.') || parsedNext.hostname.startsWith('192.168.') || parsedNext.hostname.startsWith('172.')) {
                        ws.close(4003, 'Invalid relay target');
                        return;
                    }
                    console.log(`[Relay:${port}] Forwarding to ${layer.next}`);
                    const forward = new WebSocket(layer.next);

                    forward.on("open", () => {
                        forward.send(JSON.stringify({ payload: layer.payload }));
                        forward.close(); // Ephemeral forward
                    });
                    forward.on('error', (e) => { }); // Silent

                } else {
                    // Exit Node Logic
                    if (layer.payload.startsWith && layer.payload.startsWith("__DUMMY__")) {
                        console.log(`[Relay:${port}] Dummy packet dropped`);
                    } else {
                        console.log(`[Relay:${port}] Final Payload:`, layer.payload);
                    }
                }
            }
        } catch (e) {
            console.error(`[Relay:${port}] Unexpected Error -> Decoy`, e.message);
            sendDecoy(ws);
        }
    });
});

function decrypt(hex, key) {
    const buf = Buffer.from(hex, "hex");
    const iv = buf.subarray(0, 12);
    const tag = buf.subarray(buf.length - 16);
    const text = buf.subarray(12, buf.length - 16);

    const decipher = crypto.createDecipheriv("aes-256-gcm", key, iv);
    decipher.setAuthTag(tag);

    return Buffer.concat([decipher.update(text), decipher.final()]);
}

console.log(`GhostNet Relay Server listening on port ${port}`);
