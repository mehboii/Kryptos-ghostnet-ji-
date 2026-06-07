/**
 * GhostNet Mesh Transport Layer
 * ghostnet-mesh.js
 * 
 * Hybrid automatic mesh networking:
 * - WebSocket: Auto-connects to all nearby devices on the same network (always-on)
 * - BLE: One-tap scan + auto-reconnect to previously paired devices
 * - Message bridging: All transports relay messages to each other
 * 
 * BROWSER LIMITATION NOTE:
 * Web Bluetooth API REQUIRES a user gesture (click/tap) for initial scan.
 * This cannot be bypassed — it's a browser security requirement.
 * However, once paired, devices can auto-reconnect.
 */

// GHOSTNET SECURITY — WS message sanitizer (mesh layer)
const _ALLOWED_MESH_TYPES = new Set([
    'chat', 'mesh', 'ping', 'pong', 'signal',
    'node-announce', 'node-discover', 'route',
    'ack', 'relay', 'onion', 'cover',
    // server/control types used by demo mesh
    'HELLO', 'MESH_HELLO', 'welcome',
    'PEER_JOIN', 'PEER_LEAVE', 'MESH_MSG',
    'MSG', 'MESH_DIRECT', 'MESH_PEERS', 'HEARTBEAT', 'HEARTBEAT_ACK'
]);

function _sanitizeMeshMessage(raw) {
    let msg;
    try {
        if (typeof raw !== 'string') return null;
        if (raw.length > 65536) return null; // 64KB hard cap before parsing
        msg = JSON.parse(raw);
    } catch {
        return null;
    }

    if (!msg || typeof msg !== 'object' || Array.isArray(msg)) return null;
    if (!_ALLOWED_MESH_TYPES.has(msg.type)) return null;

    if (msg.body !== undefined) {
        if (typeof msg.body !== 'string') return null;
        if (msg.body.length > 4096) return null;
    }

    if (msg.senderId !== undefined && msg.senderId !== null) {
        if (typeof msg.senderId !== 'string') return null;
        if (!/^0x[a-fA-F0-9]{8,64}$/.test(msg.senderId)) return null;
    }

    const now = Date.now();
    if (msg.timestamp !== undefined) {
        if (typeof msg.timestamp !== 'number') return null;
        if (msg.timestamp < now - 300000) return null; // older than 5 minutes
        if (msg.timestamp > now + 30000) return null;  // more than 30s in future
    }

    const sanitized = {
        type: String(msg.type),
        body: msg.body ? String(msg.body).slice(0, 4096) : undefined,
        senderId: msg.senderId || null,
        timestamp: msg.timestamp || now,
        hopCount: typeof msg.hopCount === 'number'
            ? Math.min(Math.max(0, msg.hopCount), 10)
            : 0
    };

    if (msg.id) sanitized.id = String(msg.id);
    if (msg.from) sanitized.from = String(msg.from);
    if (msg.to) sanitized.to = String(msg.to);
    if (msg.ts) sanitized.ts = msg.ts;
    if (msg.hops !== undefined) sanitized.hops = typeof msg.hops === 'number' ? Math.min(msg.hops, 10) : 0;
    if (msg.maxHops !== undefined) sanitized.maxHops = typeof msg.maxHops === 'number' ? Math.min(msg.maxHops, 10) : 5;
    // [RT-BREAK-04] Validate enc structure — prevent prototype pollution and deep nesting
    if (msg.enc && typeof msg.enc === 'object' && !Array.isArray(msg.enc)) {
        const encStr = JSON.stringify(msg.enc);
        if (encStr.length <= 131072) {
            sanitized.enc = JSON.parse(encStr);
        }
    }
    // [RT2-06] Validate data field — must be string or plain object, size-limited
    if (msg.data !== undefined) {
        if (typeof msg.data === 'string') {
            if (msg.data.length <= 8192) sanitized.data = msg.data;
        } else if (typeof msg.data === 'object' && msg.data !== null && !Array.isArray(msg.data)) {
            const dataStr = JSON.stringify(msg.data);
            if (dataStr.length <= 8192) sanitized.data = JSON.parse(dataStr);
        }
    }
    if (msg.content !== undefined && typeof msg.content === 'string') {
        sanitized.content = msg.content.slice(0, 8192);
    }
    if (msg.peers && Array.isArray(msg.peers)) sanitized.peers = msg.peers;
    if (msg.capabilities && typeof msg.capabilities === 'object' && !Array.isArray(msg.capabilities)) {
        sanitized.capabilities = JSON.parse(JSON.stringify(msg.capabilities));
    }
    if (msg.name) sanitized.name = String(msg.name).slice(0, 64);
    // [RT-BREAK-04] Preserve meshSig through sanitizer — required for signature verification
    if (msg.meshSig && typeof msg.meshSig === 'string' && /^[0-9a-f]+$/i.test(msg.meshSig) && msg.meshSig.length <= 256) {
        sanitized.meshSig = msg.meshSig;
    }

    return sanitized;
}

class GhostMesh {
    constructor(identity) {
        this.identity = identity; // { id, nodeId, pub }
        this.peers = new Map();  // peerId -> { id, transport, connected, lastSeen, device? }
        this.ws = null;
        this.wsReady = false;
        this.bleAvailable = false;
        this.bleScanning = false;
        this.reconnectTimer = null;
        this.heartbeatTimer = null;
        this.knownBLEDevices = []; // Stored encrypted in localStorage

        // [DAST-02] Message deduplication at mesh layer
        this._seenMsgIds = new Set();
        this._seenMsgIdsMax = 2000;

        // [DAST-16] Transport downgrade tracking
        this._transportConsent = { bleOnly: false, downgradeAcked: false };

        // [RASP-07] Peer trust scoring — auto-quarantine misbehaving peers
        this._peerTrust = new Map();
        this._quarantinedPeers = new Set();
        this._TRUST_INITIAL = 50;
        this._TRUST_MIN = 0;
        this._TRUST_MAX = 100;
        this._TRUST_QUARANTINE_THRESHOLD = 15;

        // [RASP-08] Routing anomaly detection
        this._routeHistory = new Map();
        this._ROUTE_CHANGE_WINDOW = 30000;
        this._ROUTE_CHANGE_MAX = 5;

        // [RASP-09] Mesh surveillance/mapping detection
        this._connectionLog = [];
        this._SURVEILLANCE_WINDOW = 60000;
        this._SURVEILLANCE_SPIKE_THRESHOLD = 10;
        this._SURVEILLANCE_UNIQUE_THRESHOLD = 8;

        this.SERVICE_UUID = '67686f73-746e-6574-2d6d-657368000000';
        this.CHAR_DATA = '67686f73-746e-6574-2d64-617461000000';
        this.CHAR_PEER_ID = '67686f73-746e-6574-2d69-640000000000';
        this.CHAR_PUB_KEY = '67686f73-746e-6574-2d6b-657900000000';

        // Event handlers (set by app.js)
        this.onPeerJoin = (peer) => { };
        this.onPeerLeave = (peer) => { };
        this.onMessage = (msg, from, transport) => { };
        this.onMeshUpdate = (peers) => { };
        this.onStatusChange = (status) => { };

        // [DAST-11] BLE device list loaded via encrypted storage (see _loadEncryptedBleDevices)
        this._bleDeviceKey = null;
        this._initBleDeviceKey().then(() => this._loadEncryptedBleDevices()).catch(() => {});

        // Check BLE availability
        this.bleAvailable = typeof navigator !== 'undefined' && !!navigator.bluetooth;

        console.log(` GhostMesh initialized. BLE: ${this.bleAvailable ? 'available' : 'unavailable'}`);
    }

    // ============================================
    // PUBLIC API
    // ============================================

    /** Start the mesh — connects WebSocket automatically */
    async start() {
        this.onStatusChange({ state: 'connecting', transport: 'ws' });

        // 1. Auto-connect WebSocket (always)
        this.connectWebSocket();

        // 2. Start heartbeat
        this.startHeartbeat();

        // 3. Try auto-reconnect to known BLE devices
        if (this.bleAvailable && this.knownBLEDevices.length > 0) {
            console.log(` Attempting BLE auto-reconnect to ${this.knownBLEDevices.length} known devices...`);
            // Note: Auto-reconnect to previously paired devices doesn't require gesture
            // But watchAdvertisements() has limited support
            this.attemptBLEAutoReconnect();
        }

        return true;
    }

    /** Scan for new BLE devices (REQUIRES user gesture - call from button click) */
    async scanBLE() {
        if (!this.bleAvailable) {
            console.warn('BLE not available in this browser');
            this.onStatusChange({ state: 'error', message: 'Bluetooth not available. Use Chrome on a secure connection (HTTPS or localhost).' });
            return [];
        }

        if (this.bleScanning) {
            console.log('Already scanning...');
            return;
        }

        this.bleScanning = true;
        this.onStatusChange({ state: 'scanning', transport: 'ble' });

        try {
            console.log(' BLE: Requesting device scan...');

            // Request device with our service UUID, or accept all devices
            const device = await navigator.bluetooth.requestDevice({
                acceptAllDevices: true,
                optionalServices: [this.SERVICE_UUID]
            });

            if (device) {
                console.log(` BLE: User selected: ${device.name || device.id}`);
                await this.connectBLEDevice(device);

                // Remember this device for auto-reconnect
                this.rememberBLEDevice(device);
            }
        } catch (e) {
            if (e.name === 'NotFoundError') {
                console.log('BLE: User cancelled scan');
            } else if (e.name === 'SecurityError') {
                console.error('BLE: Security error — need user gesture (click)');
                this.onStatusChange({ state: 'error', message: 'Bluetooth requires a button tap to scan. Tap "Scan" to find devices.' });
            } else {
                console.error('BLE Scan Error:', e);
                this.onStatusChange({ state: 'error', message: `BLE Error: ${e.message}` });
            }
        } finally {
            this.bleScanning = false;
        }
    }

    /** Send a message to all connected peers via all transports */
    async broadcast(message) {
        // [DAST-F19] Broadcast as signed plaintext — local-only keys can't be decrypted by peers.
        // E2E encryption is handled by GhostChat/GhostTransport at the application layer.
        let payload = {
            type: 'MESH_MSG',
            id: crypto.randomUUID(),
            from: this.identity.id,
            data: message,
            ts: Date.now(),
            hops: 0,
            maxHops: 5
        };

        // [IAST-09] Sign mesh message — abort send on failure
        try {
            payload = await this._signMeshPayload(payload);
        } catch (e) {
            console.error('[IAST-09] Mesh signing failed — message not sent:', e.message);
            return;
        }

        if (this.ws && this.wsReady) {
            try {
                this.ws.send(JSON.stringify(payload));
            } catch (e) { }
        }

        for (const [peerId, peer] of this.peers) {
            if (peer.transport === 'ble' && peer.connected && peer.writeChar) {
                try {
                    const data = new TextEncoder().encode(JSON.stringify(payload));
                    await peer.writeChar.writeValue(data);
                } catch (e) { }
            }
        }
    }

    /** Decrypt an encrypted mesh message envelope using session broadcast key */
    async _decryptMeshPayload(enc) {
        if (!enc || !enc.data || !enc.iv) return null;
        if (!this._broadcastKey) return null;
        try {
            const ivBytes = new Uint8Array(enc.iv.match(/.{1,2}/g).map(b => parseInt(b, 16)));
            const decrypted = await crypto.subtle.decrypt(
                { name: 'AES-GCM', iv: ivBytes }, this._broadcastKey, new Uint8Array(enc.data)
            );
            return JSON.parse(new TextDecoder().decode(decrypted));
        } catch {
            return null;
        }
    }

    /** Send a message to a specific peer */
    async sendToPeer(peerId, message) {
        const peer = this.peers.get(peerId);

        // [DAST-F19] Send as signed plaintext — per-peer keys were local-only and undecryptable.
        // E2E encryption is handled by GhostChat/GhostTransport at the application layer.
        let payload = {
            type: 'MESH_DIRECT',
            id: crypto.randomUUID(),
            from: this.identity.id,
            to: peerId,
            data: message,
            ts: Date.now()
        };

        // [RT-BREAK-05] Sign direct messages — all mesh messages must be signed
        try {
            payload = await this._signMeshPayload(payload);
        } catch (e) {
            console.error('[RT-BREAK-05] Direct message signing failed:', e.message);
            return;
        }

        if (peer && peer.transport === 'ble' && peer.connected && peer.writeChar) {
            const data = new TextEncoder().encode(JSON.stringify(payload));
            await peer.writeChar.writeValue(data);
        } else if (this.ws && this.wsReady) {
            this.ws.send(JSON.stringify(payload));
        }
    }

    /** Get all connected peers */
    getPeers() {
        const result = [];
        for (const [id, peer] of this.peers) {
            result.push({
                id: peer.id,
                transport: peer.transport,
                connected: peer.connected,
                lastSeen: peer.lastSeen,
                name: peer.name || peer.id.substr(-6)
            });
        }
        return result;
    }

    /** Get mesh status */
    getStatus() {
        const blePeers = [...this.peers.values()].filter(p => p.transport === 'ble' && p.connected).length;
        const wsPeers = [...this.peers.values()].filter(p => p.transport === 'ws').length;

        return {
            wsConnected: this.wsReady,
            bleAvailable: this.bleAvailable,
            bleScanning: this.bleScanning,
            totalPeers: this.peers.size,
            blePeers,
            wsPeers,
            knownBLEDevices: this.knownBLEDevices.length
        };
    }

    // ============================================
    // WEBSOCKET TRANSPORT (Auto-connects)
    // ============================================

    connectWebSocket() {
        try {
            // [DAST-F13] Cookie-based auth — no token in JS, cookie sent automatically with upgrade
            const baseUrl = (typeof GHOSTNET_WS_URL !== 'undefined' && GHOSTNET_WS_URL)
                || (typeof window !== 'undefined' && window.GHOSTNET_CONFIG && window.GHOSTNET_CONFIG.wsUrl)
                || `wss://${location.host}/ws`;
            console.log('Mesh: Connecting WebSocket');

            this.ws = new WebSocket(baseUrl);

            this.ws.onopen = async () => {
                console.log('Mesh: WebSocket connected');
                this.wsReady = true;

                // [RT2-04] Include public key in MESH_HELLO for signature verification by peers
                let pubKeyHex = null;
                if (this.identity.publicKey) {
                    try {
                        const exported = await crypto.subtle.exportKey('spki', this.identity.publicKey);
                        pubKeyHex = Array.from(new Uint8Array(exported)).map(b => b.toString(16).padStart(2, '0')).join('');
                    } catch {}
                }
                this.ws.send(JSON.stringify({
                    type: 'MESH_HELLO',
                    id: this.identity.id,
                    pubKey: pubKeyHex,
                    capabilities: {
                        ble: this.bleAvailable,
                        ws: true
                    }
                }));

                this.onStatusChange({ state: 'connected', transport: 'ws' });
            };

            this.ws.onmessage = (event) => {
                const msg = _sanitizeMeshMessage(event.data);
                if (!msg) return;
                this.handleWSMessage(msg);
            };

            this.ws.onclose = () => {
                console.warn('Mesh: WebSocket disconnected');
                this.wsReady = false;

                // [DAST-16] Track transport downgrade — if BLE peers remain, this is a downgrade
                const blePeersActive = [...this.peers.values()].some(p => p.transport === 'ble' && p.connected);
                if (blePeersActive && !this._transportConsent.downgradeAcked) {
                    this.onStatusChange({
                        state: 'downgraded',
                        transport: 'ble-only',
                        message: 'WebSocket lost — operating over BLE only. Messages may not reach all peers.'
                    });
                    this._transportConsent.downgradeAcked = true;
                } else {
                    this.onStatusChange({ state: 'disconnected', transport: 'ws' });
                }

                for (const [id, peer] of this.peers) {
                    if (peer.transport === 'ws') {
                        this.peers.delete(id);
                        this.onPeerLeave(peer);
                    }
                }
                this.onMeshUpdate(this.getPeers());

                clearTimeout(this.reconnectTimer);
                this.reconnectTimer = setTimeout(() => {
                    this._transportConsent.downgradeAcked = false;
                    this.connectWebSocket();
                }, 3000);
            };

            this.ws.onerror = (e) => {
                console.warn('WebSocket error:', e);
            };

        } catch (e) {
            console.error('WebSocket connection failed:', e);
            // Retry in 5 seconds
            clearTimeout(this.reconnectTimer);
            this.reconnectTimer = setTimeout(() => this.connectWebSocket(), 5000);
        }
    }

    async handleWSMessage(msg) {
        switch (msg.type) {
            case 'HELLO':
            case 'MESH_HELLO':
                // Server echo or legacy hello — ignore our own
                break;

            case 'PEER_JOIN':
                if (msg.id !== this.identity.id) {
                    // [DAST-03] Reject if peer ID already connected via different transport
                    const existing = this.peers.get(msg.id);
                    if (existing && existing.connected && existing.transport !== 'ws') {
                        console.warn('[DAST-03] Peer ID conflict — already connected via', existing.transport);
                        break;
                    }
                    const peer = {
                        id: msg.id,
                        transport: 'ws',
                        connected: true,
                        lastSeen: Date.now(),
                        name: msg.name || msg.id.substr(-8),
                        // [RT2-04] Store peer's public key for mesh signature verification
                        pubKey: (msg.pubKey && typeof msg.pubKey === 'string' && /^[0-9a-f]+$/i.test(msg.pubKey)) ? msg.pubKey : null
                    };
                    this.peers.set(msg.id, peer);
                    this.onPeerJoin(peer);
                    this.onMeshUpdate(this.getPeers());
                }
                break;

            case 'PEER_LEAVE':
                if (this.peers.has(msg.id)) {
                    const peer = this.peers.get(msg.id);
                    this.peers.delete(msg.id);
                    this.onPeerLeave(peer);
                    this.onMeshUpdate(this.getPeers());
                }
                break;

            case 'MESH_MSG':
            case 'MSG':
                if (msg.from !== this.identity.id) {
                    // [RASP-07] Reject messages from quarantined peers
                    if (this._isPeerQuarantined(msg.from)) break;
                    if (this._isDuplicate(msg.id)) break;
                    if (!this._isTimestampValid(msg.ts)) {
                        this._adjustTrust(msg.from, -5, 'invalid_timestamp');
                        break;
                    }

                    // [IAST-04] Mesh signature is MANDATORY — reject unsigned messages
                    if (!msg.meshSig || !await this._verifyMeshSignature(msg)) {
                        this._adjustTrust(msg.from, -10, 'invalid_signature');
                        break;
                    }

                    // [RASP-07] Reward valid signed messages
                    this._adjustTrust(msg.from, 1, 'valid_message');

                    // [RASP-08] Track routing changes
                    if (msg.hops > 0) this._trackRouteChange(msg.from);

                    if (this.peers.has(msg.from)) {
                        this.peers.get(msg.from).lastSeen = Date.now();
                    }

                    // [DAST-F19] Broadcasts are signed plaintext; enc field is for future E2E use
                    let msgContent = msg.data || msg.content || msg;
                    if (msg.enc) {
                        const decrypted = await this._decryptMeshPayload(msg.enc);
                        if (decrypted) msgContent = decrypted;
                    }
                    this.onMessage(msgContent, msg.from, 'ws');

                    if (msg.hops !== undefined && msg.hops < (msg.maxHops || 5)) {
                        this.relayToBLE({ ...msg, hops: (msg.hops || 0) + 1 });
                    }
                }
                break;

            case 'MESH_PEERS':
                // Server sent us the full peer list
                if (msg.peers) {
                    msg.peers.forEach(p => {
                        if (p.id !== this.identity.id && !this.peers.has(p.id)) {
                            const peer = {
                                id: p.id,
                                transport: 'ws',
                                connected: true,
                                lastSeen: p.lastSeen || Date.now(),
                                name: p.name || p.id.substr(-8),
                                // [RT2-04] Store peer's public key for mesh signature verification
                                pubKey: (p.pubKey && typeof p.pubKey === 'string' && /^[0-9a-f]+$/i.test(p.pubKey)) ? p.pubKey : null
                            };
                            this.peers.set(p.id, peer);
                            this.onPeerJoin(peer);
                        }
                    });
                    this.onMeshUpdate(this.getPeers());
                }
                break;

            case 'HEARTBEAT':
                // Respond to keep connection alive
                if (this.ws && this.wsReady) {
                    this.ws.send(JSON.stringify({ type: 'HEARTBEAT_ACK', id: this.identity.id }));
                }
                break;

            default:
                // Forward unknown messages to app handler
                this.onMessage(msg, msg.from || 'server', 'ws');
                break;
        }
    }

    // ============================================
    // BLE TRANSPORT
    // ============================================

    async connectBLEDevice(device) {
        try {
            // Listen for disconnection
            device.addEventListener('gattserverdisconnected', () => {
                console.log(` BLE: ${device.name || device.id} disconnected`);
                const peerId = device.id;
                if (this.peers.has(peerId)) {
                    const peer = this.peers.get(peerId);
                    peer.connected = false;
                    this.onPeerLeave(peer);
                    this.onMeshUpdate(this.getPeers());
                }

                // Auto-reconnect attempt after 2 seconds
                setTimeout(() => this.tryReconnectBLEDevice(device), 2000);
            });

            // [RASP-07] Reject quarantined peers
            if (this._isPeerQuarantined(device.id)) {
                console.warn(`[RASP-07] Rejecting quarantined device ${device.id}`);
                return;
            }

            // [RASP-09] Log connection for surveillance detection
            if (this._logConnection(device.id)) {
                console.warn('[RASP-09] Entering stealth mode — suppressing further connections');
                return;
            }

            console.log(` BLE: Connecting GATT to ${device.name || device.id}...`);
            const server = await device.gatt.connect();

            let service, charData, charId, charKey;
            try {
                service = await server.getPrimaryService(this.SERVICE_UUID);
                charData = await service.getCharacteristic(this.CHAR_DATA);
                charId = await service.getCharacteristic(this.CHAR_PEER_ID);
                try { charKey = await service.getCharacteristic(this.CHAR_PUB_KEY); } catch (e) { charKey = null; }
            } catch (e) {
                // [RT-01] Reject devices without GhostNet service — no unauthenticated peers
                console.warn(`BLE: GhostNet service not found on ${device.name || device.id} — rejecting`);
                device.gatt.disconnect();
                return;
            }

            let peerId = device.id;
            let peerKeyHex = null;
            try {
                const idVal = await charId.readValue();
                peerId = new TextDecoder().decode(idVal);
            } catch (e) {
                console.warn('Could not read peer ID, using device ID');
            }

            if (charKey) {
                try {
                    const keyVal = await charKey.readValue();
                    peerKeyHex = Array.from(new Uint8Array(keyVal.buffer || keyVal))
                        .map(b => b.toString(16).padStart(2, '0')).join('');
                    if (!peerKeyHex || !/^[0-9a-f]+$/i.test(peerKeyHex) || peerKeyHex.length < 16) {
                        console.warn('BLE: Invalid peer public key — rejecting connection');
                        device.gatt.disconnect();
                        return;
                    }
                    const keyHash = await crypto.subtle.digest('SHA-256',
                        new Uint8Array(peerKeyHex.match(/.{1,2}/g).map(b => parseInt(b, 16))));
                    const expectedId = '0x' + Array.from(new Uint8Array(keyHash))
                        .map(b => b.toString(16).padStart(2, '0')).join('').substring(0, 40);
                    if (peerId.startsWith('0x') && peerId !== expectedId) {
                        console.warn('BLE: Peer identity mismatch — nodeId does not match public key hash');
                        device.gatt.disconnect();
                        return;
                    }
                } catch (e) {
                    console.warn('BLE: Could not verify peer key:', e);
                }
            }

            // [DAST-01][RT-01] Challenge-response is MANDATORY — no pubkey = no connection
            if (!peerKeyHex) {
                console.warn('[RT-01] BLE: No public key — rejecting unauthenticated peer');
                device.gatt.disconnect();
                return;
            }
            try {
                await charData.startNotifications();
                const authResult = await this._bleChallengeResponse(charData, peerKeyHex, peerId);
                if (!authResult) {
                    console.warn('[DAST-01] BLE challenge-response failed — disconnecting');
                    device.gatt.disconnect();
                    return;
                }
            } catch (e) {
                // [RT-01] Challenge failure is FATAL — do not continue
                console.warn('[RT-01] BLE challenge-response error — disconnecting');
                device.gatt.disconnect();
                return;
            }

            try {
                if (!charData._notificationsStarted) await charData.startNotifications();
                charData.addEventListener('characteristicvaluechanged', async (event) => {
                    const val = new TextDecoder().decode(event.target.value);
                    // [RASP-06] BLE packet inspection gate
                    if (!this._inspectBlePacket(val, peerId)) return;
                    const msg = _sanitizeMeshMessage(val);
                    if (!msg) return;
                    if (msg.from === this.identity.id) return;

                    if (this._isDuplicate(msg.id)) return;
                    if (!this._isTimestampValid(msg.ts)) return;
                    // [IAST-04] Mesh signature is MANDATORY — reject unsigned messages
                    if (!msg.meshSig || !await this._verifyMeshSignature(msg)) return;

                    let msgContent = msg.data || msg;
                    if (msg.enc) {
                        const decrypted = await this._decryptMeshPayload(msg.enc);
                        if (decrypted) msgContent = decrypted;
                    }
                    this.onMessage(msgContent, msg.from || peerId, 'ble');

                    if (msg.hops !== undefined && msg.hops < (msg.maxHops || 5)) {
                        this.relayToWS({ ...msg, hops: (msg.hops || 0) + 1 });
                    }
                });
            } catch (e) {
                console.warn('BLE notifications not supported:', e);
            }

            // [RT-07] Check for peer ID conflict before adding BLE peer
            const existingPeer = this.peers.get(peerId);
            if (existingPeer && existingPeer.connected && existingPeer.transport !== 'ble') {
                // [DAST-03] Peer ID already connected via different transport — reject
                console.warn('[RT-07] BLE peer ID conflict — already connected via', existingPeer.transport);
                device.gatt.disconnect();
                return;
            }

            // [DAST-15] Preserve crypto session when migrating between transports
            const peer = {
                id: peerId,
                transport: 'ble',
                connected: true,
                lastSeen: Date.now(),
                name: device.name || 'BLE-' + peerId.substr(-4),
                device: device,
                server: server,
                writeChar: charData,
                pubKey: peerKeyHex || (existingPeer && existingPeer.pubKey) || null,
                sessionMigrated: !!existingPeer
            };

            this.peers.set(peerId, peer);
            this.onPeerJoin(peer);
            this.onMeshUpdate(this.getPeers());
            this.onStatusChange({ state: 'connected', transport: 'ble', peerId });

            console.log(` BLE: Connected to ${peer.name} (${peerId})`);

        } catch (e) {
            console.error('BLE connection failed:', e);
            this.onStatusChange({ state: 'error', message: `BLE connection failed: ${e.message}` });
        }
    }

    async tryReconnectBLEDevice(device) {
        if (!device || !device.gatt) return;

        try {
            console.log(` BLE: Attempting reconnect to ${device.name || device.id}...`);
            await this.connectBLEDevice(device);
        } catch (e) {
            console.warn(`BLE reconnect failed for ${device.name || device.id}:`, e);
        }
    }

    async attemptBLEAutoReconnect() {
        // Web Bluetooth remembers paired devices, but we need the device object
        // We can try getDevices() (Chrome 85+) to get previously paired devices
        if (navigator.bluetooth && navigator.bluetooth.getDevices) {
            try {
                const devices = await navigator.bluetooth.getDevices();
                console.log(` BLE: Found ${devices.length} previously paired devices`);

                for (const device of devices) {
                    // Check if this device is in our known list
                    const known = this.knownBLEDevices.find(d => d.id === device.id);
                    if (known) {
                        try {
                            // watchAdvertisements() lets us detect when the device comes in range
                            if (device.watchAdvertisements) {
                                await device.watchAdvertisements();
                                device.addEventListener('advertisementreceived', async (event) => {
                                    console.log(` BLE: ${device.name || device.id} detected nearby!`);
                                    if (!this.peers.has(device.id) || !this.peers.get(device.id).connected) {
                                        await this.connectBLEDevice(device);
                                    }
                                });
                                console.log(` BLE: Watching for ${device.name || device.id}...`);
                            } else {
                                // Fallback: try direct connect (device must be in range)
                                await this.connectBLEDevice(device);
                            }
                        } catch (e) {
                            console.warn(`BLE auto-reconnect to ${device.name || device.id} failed:`, e);
                        }
                    }
                }
            } catch (e) {
                console.warn('BLE getDevices() not supported or failed:', e);
            }
        }
    }

    rememberBLEDevice(device) {
        const entry = {
            id: device.id,
            name: device.name || 'Unknown',
            lastConnected: Date.now()
        };

        // De-duplicate
        this.knownBLEDevices = this.knownBLEDevices.filter(d => d.id !== device.id);
        this.knownBLEDevices.push(entry);

        // Keep only last 20 devices
        if (this.knownBLEDevices.length > 20) {
            this.knownBLEDevices = this.knownBLEDevices.slice(-20);
        }

        // [DAST-11] Encrypt before storing
        this._saveEncryptedBleDevices();
    }

    // ============================================
    // MESH RELAY (Bridge between transports)
    // ============================================

    relayToBLE(msg) {
        // [RT2-02] Include data field in relay — required for signed plaintext messages
        const relayMsg = { type: msg.type, id: msg.id, from: msg.from, data: msg.data, enc: msg.enc, meshSig: msg.meshSig, hops: msg.hops, maxHops: msg.maxHops, ts: msg.ts };
        const serialized = JSON.stringify(relayMsg);
        const validated = _sanitizeMeshMessage(serialized);
        if (!validated) return;

        for (const [peerId, peer] of this.peers) {
            if (peer.transport === 'ble' && peer.connected && peer.writeChar) {
                try {
                    const data = new TextEncoder().encode(serialized);
                    peer.writeChar.writeValue(data);
                } catch (e) { }
            }
        }
    }

    relayToWS(msg) {
        // [RT2-02] Include data field in relay — required for signed plaintext messages
        const relayMsg = { type: msg.type, id: msg.id, from: msg.from, data: msg.data, enc: msg.enc, meshSig: msg.meshSig, hops: msg.hops, maxHops: msg.maxHops, ts: msg.ts };
        const serialized = JSON.stringify(relayMsg);
        const validated = _sanitizeMeshMessage(serialized);
        if (!validated) return;

        if (this.ws && this.wsReady) {
            try {
                this.ws.send(serialized);
            } catch (e) { }
        }
    }

    // ============================================
    // HEARTBEAT & MAINTENANCE
    // ============================================

    startHeartbeat() {
        clearInterval(this.heartbeatTimer);
        this.heartbeatTimer = setInterval(() => {
            // Clean stale peers (no activity for 60s)
            const now = Date.now();
            for (const [id, peer] of this.peers) {
                if (peer.transport === 'ws' && now - peer.lastSeen > 60000) {
                    this.peers.delete(id);
                    this.onPeerLeave(peer);
                }
            }

            // Send heartbeat via WS
            if (this.ws && this.wsReady) {
                this.ws.send(JSON.stringify({
                    type: 'HEARTBEAT',
                    id: this.identity.id,
                    ts: now,
                    peers: this.peers.size
                }));
            }

            this.onMeshUpdate(this.getPeers());
        }, 15000); // Every 15 seconds
    }

    // ============================================
    // CLEANUP
    // ============================================

    destroy() {
        clearInterval(this.heartbeatTimer);
        clearTimeout(this.reconnectTimer);

        if (this.ws) {
            this.ws.close();
            this.ws = null;
        }

        // Disconnect BLE devices
        for (const [id, peer] of this.peers) {
            if (peer.transport === 'ble' && peer.device && peer.device.gatt.connected) {
                try { peer.device.gatt.disconnect(); } catch (e) { }
            }
        }

        this.peers.clear();
    }

    // ============================================
    // [DAST-11] ENCRYPTED BLE DEVICE STORAGE
    // ============================================

    // [RT2-10] Store BLE base key in IndexedDB as non-extractable CryptoKey — XSS cannot read it
    async _initBleDeviceKey() {
        let salt;
        const storedSalt = localStorage.getItem('ghostnet_ble_key_salt');
        if (storedSalt) {
            salt = new Uint8Array(JSON.parse(storedSalt));
        } else {
            salt = crypto.getRandomValues(new Uint8Array(16));
            localStorage.setItem('ghostnet_ble_key_salt', JSON.stringify(Array.from(salt)));
        }
        // [RT2-10] Base key in IndexedDB — non-extractable, not accessible via XSS
        let baseKey;
        try {
            baseKey = await new Promise((resolve, reject) => {
                const req = indexedDB.open('ghostnet_ble_keys', 1);
                req.onupgradeneeded = (e) => e.target.result.createObjectStore('keys');
                req.onerror = () => reject(req.error);
                req.onsuccess = async () => {
                    const db = req.result;
                    const tx = db.transaction('keys', 'readonly');
                    const store = tx.objectStore('keys');
                    const getReq = store.get('ble_base_key');
                    getReq.onsuccess = async () => {
                        if (getReq.result) {
                            resolve(getReq.result);
                        } else {
                            const newKey = await crypto.subtle.generateKey(
                                { name: 'HKDF' }, false, ['deriveKey']
                            ).catch(() => null);
                            if (!newKey) {
                                const rawKey = crypto.getRandomValues(new Uint8Array(32));
                                const imported = await crypto.subtle.importKey('raw', rawKey, 'HKDF', false, ['deriveKey']);
                                const wtx = db.transaction('keys', 'readwrite');
                                wtx.objectStore('keys').put(imported, 'ble_base_key');
                                wtx.oncomplete = () => resolve(imported);
                                wtx.onerror = () => reject(wtx.error);
                            } else {
                                const wtx = db.transaction('keys', 'readwrite');
                                wtx.objectStore('keys').put(newKey, 'ble_base_key');
                                wtx.oncomplete = () => resolve(newKey);
                                wtx.onerror = () => reject(wtx.error);
                            }
                        }
                    };
                    getReq.onerror = () => reject(getReq.error);
                };
            });
        } catch {
            const rawKey = crypto.getRandomValues(new Uint8Array(32));
            baseKey = await crypto.subtle.importKey('raw', rawKey, 'HKDF', false, ['deriveKey']);
        }
        // Migrate: remove old localStorage key if present
        localStorage.removeItem('ghostnet_ble_base_key');
        this._bleDeviceKey = await crypto.subtle.deriveKey(
            { name: 'HKDF', hash: 'SHA-256', salt, info: new TextEncoder().encode('ble-device-enc') },
            baseKey,
            { name: 'AES-GCM', length: 256 },
            false, ['encrypt', 'decrypt']
        );
    }

    async _loadEncryptedBleDevices() {
        try {
            const stored = localStorage.getItem('ghostnet_ble_devices_enc');
            if (!stored || !this._bleDeviceKey) return;
            const { iv, data } = JSON.parse(stored);
            const decrypted = await crypto.subtle.decrypt(
                { name: 'AES-GCM', iv: new Uint8Array(iv) },
                this._bleDeviceKey,
                new Uint8Array(data)
            );
            this.knownBLEDevices = JSON.parse(new TextDecoder().decode(decrypted));
        } catch { this.knownBLEDevices = []; }
    }

    async _saveEncryptedBleDevices() {
        if (!this._bleDeviceKey) return;
        try {
            const iv = crypto.getRandomValues(new Uint8Array(12));
            const plaintext = new TextEncoder().encode(JSON.stringify(this.knownBLEDevices));
            const ciphertext = await crypto.subtle.encrypt(
                { name: 'AES-GCM', iv }, this._bleDeviceKey, plaintext
            );
            localStorage.setItem('ghostnet_ble_devices_enc', JSON.stringify({
                iv: Array.from(iv),
                data: Array.from(new Uint8Array(ciphertext))
            }));
            localStorage.removeItem('ghostnet_ble_devices');
        } catch { }
    }

    // ============================================
    // [DAST-02] MESSAGE DEDUPLICATION
    // ============================================

    _isDuplicate(msgId) {
        // [RT-02] Reject messages with missing/falsy ID — no ID means no dedup possible
        if (!msgId || typeof msgId !== 'string') return true;
        if (this._seenMsgIds.has(msgId)) return true;
        this._seenMsgIds.add(msgId);
        if (this._seenMsgIds.size > this._seenMsgIdsMax) {
            const it = this._seenMsgIds.values();
            this._seenMsgIds.delete(it.next().value);
        }
        return false;
    }

    _isTimestampValid(ts) {
        // [RT-03] Reject non-numeric or falsy timestamps — no timestamp = no time validation
        if (typeof ts !== 'number' || ts <= 0) return false;
        const now = Date.now();
        return ts > now - 300000 && ts < now + 30000;
    }

    // ============================================
    // [DAST-01] BLE CHALLENGE-RESPONSE AUTH
    // ============================================

    async _bleChallengeResponse(writeChar, peerKeyHex, peerId) {
        const nonce = crypto.getRandomValues(new Uint8Array(32));
        const nonceHex = Array.from(nonce).map(b => b.toString(16).padStart(2, '0')).join('');
        const challenge = JSON.stringify({ type: 'AUTH_CHALLENGE', nonce: nonceHex });
        // [DAST-F09] Record challenge send time for replay protection
        const challengeSentAt = Date.now();
        await writeChar.writeValue(new TextEncoder().encode(challenge));

        return new Promise((resolve) => {
            const timeout = setTimeout(() => resolve(false), 5000);
            const handler = async (event) => {
                try {
                    const val = new TextDecoder().decode(event.target.value);
                    const resp = JSON.parse(val);
                    if (resp.type !== 'AUTH_RESPONSE' || !resp.sig) return;
                    writeChar.removeEventListener('characteristicvaluechanged', handler);
                    clearTimeout(timeout);

                    // [DAST-F09] Reject responses with stale timestamps (>2s from challenge)
                    if (resp.ts && Math.abs(resp.ts - challengeSentAt) > 2000) {
                        console.warn('[DAST-F09] BLE auth response timestamp too far from challenge — possible replay');
                        resolve(false);
                        return;
                    }

                    const keyBytes = new Uint8Array(peerKeyHex.match(/.{1,2}/g).map(b => parseInt(b, 16)));
                    const pubKey = await crypto.subtle.importKey(
                        'spki', keyBytes, { name: 'ECDSA', namedCurve: 'P-256' }, false, ['verify']
                    );
                    const sigBytes = new Uint8Array(resp.sig.match(/.{1,2}/g).map(b => parseInt(b, 16)));
                    const valid = await crypto.subtle.verify(
                        { name: 'ECDSA', hash: 'SHA-256' }, pubKey, sigBytes, nonce
                    );
                    resolve(valid);
                } catch { resolve(false); }
            };
            writeChar.addEventListener('characteristicvaluechanged', handler);
        });
    }

    // ============================================
    // [DAST-04] SIGN MESH MESSAGES
    // ============================================

    // [IAST-09] Signing failure is fatal — never send unsigned mesh messages
    async _signMeshPayload(payload) {
        if (!this.identity.privateKey) {
            throw new Error('Cannot send mesh message: no signing key available');
        }
        const encHash = payload.enc ? JSON.stringify(payload.enc) : '';
        // [RT2-03] Include data hash in canonical — prevents undetected content tampering
        const dataHash = payload.data ? JSON.stringify(payload.data) : '';
        const canonical = `${payload.id}|${payload.from}|${payload.ts}|${payload.type}|${encHash}|${dataHash}`;
        const sig = await crypto.subtle.sign(
            { name: 'ECDSA', hash: 'SHA-256' },
            this.identity.privateKey,
            new TextEncoder().encode(canonical)
        );
        payload.meshSig = Array.from(new Uint8Array(sig))
            .map(b => b.toString(16).padStart(2, '0')).join('');
        return payload;
    }

    // ============================================
    // [RASP-06] BLE PACKET INSPECTION GATE
    // ============================================

    _inspectBlePacket(data, peerId) {
        if (!data || data.length === 0) {
            this._adjustTrust(peerId, -5, 'empty_packet');
            return false;
        }
        if (data.length > 8192) {
            this._adjustTrust(peerId, -10, 'oversized_packet');
            return false;
        }
        let msg;
        try {
            msg = JSON.parse(typeof data === 'string' ? data : new TextDecoder().decode(data));
        } catch {
            this._adjustTrust(peerId, -5, 'malformed_json');
            return false;
        }
        if (!msg || typeof msg !== 'object' || !msg.type) {
            this._adjustTrust(peerId, -5, 'missing_type');
            return false;
        }
        if (!_ALLOWED_MESH_TYPES.has(msg.type)) {
            this._adjustTrust(peerId, -10, 'disallowed_type');
            return false;
        }
        return true;
    }

    // ============================================
    // [RASP-07] PEER TRUST SCORING
    // ============================================

    _getPeerTrust(peerId) {
        if (!this._peerTrust.has(peerId)) {
            this._peerTrust.set(peerId, this._TRUST_INITIAL);
        }
        return this._peerTrust.get(peerId);
    }

    _adjustTrust(peerId, delta, reason) {
        const current = this._getPeerTrust(peerId);
        const newScore = Math.max(this._TRUST_MIN, Math.min(this._TRUST_MAX, current + delta));
        this._peerTrust.set(peerId, newScore);
        if (newScore <= this._TRUST_QUARANTINE_THRESHOLD && !this._quarantinedPeers.has(peerId)) {
            this._quarantinedPeers.add(peerId);
            console.warn(`[RASP-07] Peer ${peerId.slice(0, 12)} quarantined (trust=${newScore}, reason=${reason})`);
            const peer = this.peers.get(peerId);
            if (peer && peer.device && peer.device.gatt && peer.device.gatt.connected) {
                try { peer.device.gatt.disconnect(); } catch {}
            }
            this.peers.delete(peerId);
            this.onPeerLeave({ id: peerId });
            this.onMeshUpdate(this.getPeers());
        }
    }

    _isPeerQuarantined(peerId) {
        return this._quarantinedPeers.has(peerId);
    }

    // ============================================
    // [RASP-08] ROUTING ANOMALY DETECTION
    // ============================================

    _trackRouteChange(peerId) {
        const now = Date.now();
        if (!this._routeHistory.has(peerId)) {
            this._routeHistory.set(peerId, []);
        }
        const history = this._routeHistory.get(peerId);
        history.push(now);
        // Prune old entries
        while (history.length > 0 && history[0] < now - this._ROUTE_CHANGE_WINDOW) {
            history.shift();
        }
        if (history.length > this._ROUTE_CHANGE_MAX) {
            console.warn(`[RASP-08] Routing anomaly: peer ${peerId.slice(0, 12)} changed routes ${history.length} times in ${this._ROUTE_CHANGE_WINDOW / 1000}s`);
            this._adjustTrust(peerId, -15, 'routing_anomaly');
            return true;
        }
        return false;
    }

    // ============================================
    // [RASP-09] MESH SURVEILLANCE DETECTION
    // ============================================

    _logConnection(peerId) {
        const now = Date.now();
        this._connectionLog.push({ peerId, ts: now });
        // Prune old entries
        this._connectionLog = this._connectionLog.filter(e => e.ts > now - this._SURVEILLANCE_WINDOW);
        // Check for connection spikes
        if (this._connectionLog.length > this._SURVEILLANCE_SPIKE_THRESHOLD) {
            const uniquePeers = new Set(this._connectionLog.map(e => e.peerId));
            if (uniquePeers.size >= this._SURVEILLANCE_UNIQUE_THRESHOLD) {
                console.warn(`[RASP-09] Surveillance pattern detected: ${uniquePeers.size} unique peers in ${this._SURVEILLANCE_WINDOW / 1000}s`);
                return true;
            }
        }
        return false;
    }

    async _verifyMeshSignature(msg) {
        if (!msg.meshSig || !msg.from) return false;
        const peer = this.peers.get(msg.from);
        // [RT-04] If message has meshSig but we have no pubKey to verify, reject — no auto-pass
        if (!peer || !peer.pubKey) return false;
        try {
            // [RT2-03] Must match sign canonical — includes enc hash and data hash
            const encHash = msg.enc ? JSON.stringify(msg.enc) : '';
            const dataHash = msg.data ? JSON.stringify(msg.data) : '';
            const canonical = `${msg.id}|${msg.from}|${msg.ts}|${msg.type}|${encHash}|${dataHash}`;
            const keyBytes = new Uint8Array(peer.pubKey.match(/.{1,2}/g).map(b => parseInt(b, 16)));
            const pubKey = await crypto.subtle.importKey(
                'spki', keyBytes, { name: 'ECDSA', namedCurve: 'P-256' }, false, ['verify']
            );
            const sigBytes = new Uint8Array(msg.meshSig.match(/.{1,2}/g).map(b => parseInt(b, 16)));
            return await crypto.subtle.verify(
                { name: 'ECDSA', hash: 'SHA-256' }, pubKey, sigBytes,
                new TextEncoder().encode(canonical)
            );
        } catch { return false; }
    }
}

// Expose globally
if (typeof window !== 'undefined') {
    window.GhostMesh = GhostMesh;
}
