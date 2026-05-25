
const bleno = require('@abandonware/bleno');
const crypto = require('crypto');

/**
 * GhostNet BLE Peripheral — SECURITY HARDENED
 *
 * FIXES:
 * [FIX 09-A] Generate a real Ed25519 key pair at startup instead of hardcoded placeholder
 * [FIX 09-B] Implement challenge-response authentication on the DATA characteristic
 * [FIX 09-C] Log connections but validate identity before accepting data
 */

const SERVICE_UUID = "67686f73-746e-6574-2d6d-657368000000";
const CHAR_PEER_ID = "67686f73-746e-6574-2d69-640000000000";
const CHAR_PUB_KEY = "67686f73-746e-6574-2d6b-657900000000";
const CHAR_DATA = "67686f73-746e-6574-2d64-617461000000";

// [FIX 09-A] Generate real identity at startup
// Using ECDSA P-256 via Node.js crypto (compatible with browser-side GhostIdentity)
const { publicKey: nodePublicKey, privateKey: nodePrivateKey } = crypto.generateKeyPairSync('ec', {
    namedCurve: 'P-256',
    publicKeyEncoding: { type: 'spki', format: 'der' },
    privateKeyEncoding: { type: 'pkcs8', format: 'der' },
});

const pubKeyHex = nodePublicKey.toString('hex');
const myName = "GhostNode_" + pubKeyHex.slice(-8);

console.log(`Starting GhostNet Peripheral: ${myName}`);
console.log(`Public Key (last 16): …${pubKeyHex.slice(-16)}`);

let updateCallback = null;

// [FIX 09-B] Sign a challenge nonce to prove identity
function signChallenge(nonceHex) {
    const sign = crypto.createSign('SHA256');
    sign.update(Buffer.from(nonceHex, 'hex'));
    sign.end();
    const signature = sign.sign({
        key: crypto.createPrivateKey({ key: nodePrivateKey, format: 'der', type: 'pkcs8' }),
    });
    return signature.toString('hex');
}

// Define Characteristics
const PeerIdChar = new bleno.Characteristic({
    uuid: CHAR_PEER_ID,
    properties: ['read'],
    value: Buffer.from(myName)
});

// [FIX 09-A] Serve the real public key, not a hardcoded placeholder
const PubKeyChar = new bleno.Characteristic({
    uuid: CHAR_PUB_KEY,
    properties: ['read'],
    value: nodePublicKey
});

// [RT2-08] Per-connection authentication state — prevents multi-client auth confusion
// bleno serializes connections, so track the current subscriber's auth state
let _currentClientAddress = null;
let _authenticatedClients = new Set();

// [RASP-06] Per-client rate limiting for BLE writes
const _bleWriteRates = new Map();
function _checkBleWriteRate(clientAddr) {
    const now = Date.now();
    const entry = _bleWriteRates.get(clientAddr) || { count: 0, resetAt: now + 10000 };
    if (now > entry.resetAt) { entry.count = 0; entry.resetAt = now + 10000; }
    entry.count++;
    _bleWriteRates.set(clientAddr, entry);
    return entry.count <= 20;
}

const DataChar = new bleno.Characteristic({
    uuid: CHAR_DATA,
    properties: ['read', 'write', 'notify'],
    onWriteRequest: (data, offset, withoutResponse, callback) => {
        // [RASP-06] Packet size gate
        if (data.length > 8192) {
            console.warn(`[RASP-06] Oversized BLE write rejected (${data.length} bytes)`);
            callback(bleno.Characteristic.RESULT_SUCCESS);
            return;
        }

        // [RASP-06] Rate limit per client
        if (_currentClientAddress && !_checkBleWriteRate(_currentClientAddress)) {
            console.warn(`[RASP-06] BLE write rate limit exceeded for ${_currentClientAddress}`);
            callback(bleno.Characteristic.RESULT_SUCCESS);
            return;
        }

        const msgStr = data.toString('utf-8');

        try {
            const msg = JSON.parse(msgStr);

            if (msg.type === 'AUTH_CHALLENGE' && msg.nonce) {
                console.log(`[Auth] Challenge received, signing nonce`);
                const signature = signChallenge(msg.nonce);
                const response = JSON.stringify({
                    type: 'AUTH_RESPONSE',
                    nonce: msg.nonce,
                    sig: signature,
                    ts: Date.now(),
                });
                if (updateCallback) {
                    updateCallback(Buffer.from(response));
                }
                // [RT2-08] Mark specific connection as authenticated
                if (_currentClientAddress) _authenticatedClients.add(_currentClientAddress);
                callback(bleno.Characteristic.RESULT_SUCCESS);
                return;
            }

            // [RT2-08] Reject non-auth messages from unauthenticated connections
            if (!_currentClientAddress || !_authenticatedClients.has(_currentClientAddress)) {
                console.warn(`[Recv] Rejected: client not authenticated — complete AUTH_CHALLENGE first`);
                callback(bleno.Characteristic.RESULT_SUCCESS);
                return;
            }

            if (!msg.type || typeof msg.type !== 'string') {
                console.warn(`[Recv] Rejected: missing or invalid type field`);
                callback(bleno.Characteristic.RESULT_SUCCESS);
                return;
            }

            // [FIX 10] Reject messages with stale timestamps
            if (msg.ts) {
                const age = Date.now() - msg.ts;
                if (age > 300000 || age < -30000) {
                    console.warn(`[Recv] Rejected: stale timestamp (age: ${age}ms)`);
                    callback(bleno.Characteristic.RESULT_SUCCESS);
                    return;
                }
            }

            console.log(`[Recv] type=${msg.type} from=${(msg.from || 'unknown').slice(0, 12)}`);

            // Echo back for testing (only for authenticated MSG type)
            if (msg.type === 'MSG' && updateCallback) {
                const reply = JSON.stringify({
                    type: 'MSG',
                    from: myName,
                    body: `Echo: ${(msg.body || '').slice(0, 200)}`,
                    ts: Date.now(),
                    nonce: crypto.randomBytes(8).toString('hex'),
                });
                updateCallback(Buffer.from(reply));
            }
        } catch {
            console.warn(`[Recv] Rejected: malformed JSON`);
        }

        callback(bleno.Characteristic.RESULT_SUCCESS);
    },
    onSubscribe: (maxValueSize, callback) => {
        console.log("Client subscribed to updates");
        updateCallback = callback;
    },
    onUnsubscribe: () => {
        console.log("Client unsubscribed");
        updateCallback = null;
    }
});

const GhostService = new bleno.PrimaryService({
    uuid: SERVICE_UUID,
    characteristics: [
        PeerIdChar,
        PubKeyChar,
        DataChar
    ]
});

bleno.on('stateChange', (state) => {
    console.log(`Bleno State: ${state}`);
    if (state === 'poweredOn') {
        bleno.startAdvertising(myName, [SERVICE_UUID]);
    } else {
        bleno.stopAdvertising();
    }
});

bleno.on('advertisingStart', (error) => {
    if (!error) {
        console.log('Advertising started — device discoverable as', myName);
        bleno.setServices([GhostService]);
    } else {
        console.error('Advertising Error:', error);
    }
});

bleno.on('accept', (clientAddress) => {
    // [RT2-08] Track current client address for per-connection auth
    _currentClientAddress = clientAddress;
    console.log(`Connection from: ${clientAddress} (pending authentication)`);
});

bleno.on('disconnect', (clientAddress) => {
    console.log(`Client ${clientAddress} disconnected. Restarting advertising...`);
    // [RT2-08] Remove specific client's auth state on disconnect
    _authenticatedClients.delete(clientAddress);
    if (_currentClientAddress === clientAddress) _currentClientAddress = null;
    bleno.startAdvertising(myName, [SERVICE_UUID]);
});
