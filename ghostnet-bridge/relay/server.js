const WebSocket = require('ws');
const crypto = require('crypto');

// Generate static keypair for this relay instance (Feature from Level 9)
const relayKeyPair = crypto.generateKeyPairSync("x25519");
const relayPublicKey = relayKeyPair.publicKey.export({ type: "spki", format: "der" }).toString("hex");

const FRAME_SIZE = 1024;
const port = Number(process.env.PORT) || Number(process.argv[2]) || 8080;
const wss = new WebSocket.Server({ port });

// Keys for fallback (Feature from Level 6-7)
const keys = {
    8080: Buffer.from("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "utf8"),
    8081: Buffer.from("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", "utf8"),
    8082: Buffer.from("cccccccccccccccccccccccccccccccc", "utf8")
};
const defaultKey = keys[port];

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

wss.on('connection', (ws) => {
    let sessionKey = defaultKey; // Default to hardcoded for multi-hop dummy demo

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
                sessionKey = crypto.createHash("sha256").update(shared).digest();
                console.log(`[Relay:${port}] Session Key Established`);
                return;
            }

            // Handle Encrypted Onion Layer
            if (msg.payload) {
                // 1. Decrypt
                let peeled;
                try {
                    peeled = decrypt(msg.payload, sessionKey).toString();
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
                    // Forwarding
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
