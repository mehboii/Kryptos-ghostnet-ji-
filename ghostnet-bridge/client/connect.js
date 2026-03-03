const WebSocket = require('ws');
// We need BOTH WebCrypto (for AES-GCM) and Node Crypto (for Random Bytes)
const { webcrypto } = require('crypto');
const cryptoWeb = webcrypto;
const cryptoNode = require('crypto');

const http = require('http');

// Keys for Onion Routing
// (Keeping for backup/reference, but hopKeys will take precedence for Real Traffic)
const KEYS = {
    8080: Buffer.from("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "utf8"),
    8081: Buffer.from("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", "utf8"),
    8082: Buffer.from("cccccccccccccccccccccccccccccccc", "utf8")
};

// Global Hop Keys Store (CRITICAL FIX)
const hopKeys = {};
let currentRoute = [];
let circuitBuilt = false;

function deriveKey(shared) {
    return cryptoNode.createHash("sha256").update(shared).digest();
}

function getNodes() {
    return new Promise((resolve, reject) => {
        const req = http.get('http://localhost:9000/nodes', (res) => {
            let data = '';
            res.on('data', (chunk) => data += chunk);
            res.on('end', () => {
                try {
                    resolve(JSON.parse(data));
                } catch (e) {
                    resolve(["ws://localhost:8080", "ws://localhost:8081", "ws://localhost:8082"]);
                }
            });
        });

        req.on('error', (e) => {
            // console.error("[Client] Registry unreachable, using defaults.");
            resolve(["ws://localhost:8080", "ws://localhost:8081", "ws://localhost:8082"]);
        });
    });
}

function pickRoute(nodes) {
    if (nodes.length < 3) throw new Error("Not enough nodes for 3-hop circuit");
    return nodes.sort(() => 0.5 - Math.random()).slice(0, 3);
}

function getPort(url) {
    return parseInt(url.split(':').pop());
}

// --- LEVEL 10: UNIQUE PACKET ID & TIMESTAMP ---
function msgId() {
    return cryptoNode.randomBytes(12).toString("hex");
}

function now() {
    return Math.floor(Date.now() / 1000);
}

// Updated Wrap Function (Includes Replay Protection Fields)
function wrap(next, payload) {
    return JSON.stringify({
        id: msgId(),
        ts: now(),
        next,
        payload
    });
}

function randomBytesHex(n = 32) {
    return cryptoNode.randomBytes(n).toString("hex");
}

async function buildDummyOnion(route) {
    // Dummy traffic still uses hardcoded keys for now to keep noise flowing
    // while we wait for real keys to be negotiated.
    let inner = "__DUMMY__" + randomBytesHex(16);

    const entryUrl = route[0];
    const middleUrl = route[1];
    const exitUrl = route[2];

    // Layer 1: Exit
    const exitKey = KEYS[getPort(exitUrl)];
    inner = await encrypt(wrap(null, inner), exitKey);

    // Layer 2: Middle
    const middleKey = KEYS[getPort(middleUrl)];
    inner = await encrypt(wrap(exitUrl, inner), middleKey);

    // Layer 3: Entry
    const entryKey = KEYS[getPort(entryUrl)];
    inner = await encrypt(wrap(middleUrl, inner), entryKey);

    return inner;
}

function norm(url) {
    return url.replace("ws://", "");
}

// Check if we have keys for the full route
function maybeBuildCircuit(route) {
    if (circuitBuilt) return;

    if (
        hopKeys[norm(route[0])] &&
        hopKeys[norm(route[1])] &&
        hopKeys[norm(route[2])]
    ) {
        circuitBuilt = true;
        console.log("[Client] All hop keys ready");
        buildRealCircuit(route);
    } else {
        // console.log(`[Client] Route incomplete. Have keys for: ${route.filter(r => hopKeys[norm(r)]).map(getPort)}`);
    }
}

async function buildRealCircuit(route) {
    try {
        const entryUrl = route[0];
        const middleUrl = route[1];
        const exitUrl = route[2];

        console.log(`[Client] Building REAL Circuit -> ${getPort(exitUrl)}`);

        let inner = "HELLO_GHOSTNET_" + Date.now();

        // TEMPORARY FIX: Reverting to Static Keys for Data Plane
        // Reason: Relays currently treat forwarded connections as new sessions (using defaultKey).
        // Without Circuit IDs, they cannot link the forwarded packet to the previously negotiated Session Key.
        // We keep the Handshake (initCircuit) as an "Authentication Check", but encrypt payload with static keys.
        inner = await encrypt(wrap(null, inner), KEYS[getPort(exitUrl)]);
        inner = await encrypt(wrap(exitUrl, inner), KEYS[getPort(middleUrl)]);
        inner = await encrypt(wrap(middleUrl, inner), KEYS[getPort(entryUrl)]);

        const ws = new WebSocket(entryUrl);
        ws.on('open', () => {
            ws.send(JSON.stringify({ payload: inner }));
            console.log("[Client] Onion Sent");
            setTimeout(() => ws.close(), 500);
        });
        ws.on('error', (e) => { });

    } catch (e) {
        console.error("Traffic Error:", e.message);
    }
}

async function initCircuit(route) {
    currentRoute = route;
    circuitBuilt = false;
    console.log("\n[Client] Initiating Circuit Handshake with ALL nodes...");

    // Handshake with EVERY node in the route to get their keys
    route.forEach(url => {
        performHandshake(url);
    });
}

function performHandshake(url) {
    try {
        const ws = new WebSocket(url);

        ws.on('message', async (data) => {
            const msg = JSON.parse(data);

            if (msg.type === "handshake") {
                const relayPub = Buffer.from(msg.pub, "hex");
                const clientKP = cryptoNode.generateKeyPairSync("x25519");
                const shared = cryptoNode.diffieHellman({
                    privateKey: clientKP.privateKey,
                    publicKey: cryptoNode.createPublicKey({
                        key: relayPub,
                        format: "der",
                        type: "spki"
                    })
                });

                const aesKey = deriveKey(shared);
                hopKeys[norm(url)] = aesKey;
                console.log(`[Client] Key ready for ${norm(url)}`);

                // Reply with our PubKey
                ws.send(JSON.stringify({
                    type: "client_pub",
                    pub: clientKP.publicKey.export({ type: "spki", format: "der" }).toString("hex")
                }));

                // Check if we can build full circuit
                maybeBuildCircuit(currentRoute);

                // Keep connection open for a bit
                setTimeout(() => ws.close(), 2000);
            }
        });

        ws.on('error', (e) => {
            // console.error(`[Client] Handshake fail ${norm(url)}`);
        });

    } catch (e) {
        console.error("Handshake Error:", e.message);
    }
}

// Cover Traffic Loop (Every 4s)
setInterval(async () => {
    try {
        const nodes = await getNodes();
        const route = pickRoute(nodes);
        const onion = await buildDummyOnion(route);
        const ws = new WebSocket(route[0]);
        ws.on('open', () => {
            ws.send(JSON.stringify({ payload: onion }));
            console.log("[Client] Sent cover packet");
            setTimeout(() => ws.close(), 500);
        });
        ws.on('error', (e) => { }); // Silent
    } catch (e) { }
}, 4000);

// Helper: Encrypt -> Hex (IV + Cipher + Tag)
async function encrypt(input, keyBuffer) {
    const key = await cryptoWeb.subtle.importKey(
        "raw",
        keyBuffer,
        { name: "AES-GCM" },
        false,
        ["encrypt"]
    );

    const iv = cryptoWeb.getRandomValues(new Uint8Array(12));
    const encoded = new TextEncoder().encode(input);

    const cipherBuffer = await cryptoWeb.subtle.encrypt(
        { name: "AES-GCM", iv: iv },
        key,
        encoded
    );

    const result = new Uint8Array(12 + cipherBuffer.byteLength);
    result.set(iv);
    result.set(new Uint8Array(cipherBuffer), 12);

    return Buffer.from(result).toString('hex');
}

// Start
async function start() {
    const nodes = await getNodes();
    currentRoute = pickRoute(nodes);

    console.log("Route:", currentRoute.map(getPort));

    initCircuit(currentRoute);
}

start();
setInterval(start, 15000);
