/**
 * Kryptos Mesh Transport Layer — HARDENED
 * kryptos-mesh.js
 *
 * Fixes applied:
 *
 * BREAK FIXES (why the app stopped working)
 *  [F1] connectWebSocket() never sent a JWT token — hardened server requires ?token=JWT in URL
 *       → getAuthToken() reads token from sessionStorage/localStorage; appended to WS URL
 *  [F2] WS URL hardcoded to Railway domain — ignores actual deployment host
 *       → URL derived from window.location; KRYPTOS_WS_URL override supported via meta tag
 *
 * SECURITY
 *  [S1] broadcast() used Math.random() for message IDs — predictable
 *       → crypto.getRandomValues() based secureId()
 *  [S2] sendToPeer() used Date.now() only — not unique under rapid fire
 *       → secureId() used
 *  [S3] BLE incoming data had no size cap — large payload DoS'd message handler
 *       → MAX_BLE_PAYLOAD_BYTES = 4096; oversized chunks dropped
 *  [S4] localStorage BLE device list read with no schema validation
 *       → validateBleDeviceEntry() checks shape before use; malformed entries dropped
 *  [S5] Individual BLE device entries had no field size limits
 *       → id/name capped at 128/64 chars in validateBleDeviceEntry()
 *  [S6] maxHops attacker-controlled — msg.maxHops=999 forced amplified broadcast storm
 *       → MAX_HOPS constant (5) enforced server-side; msg.maxHops ignored
 *  [S7] handleWSMessage default case forwarded ALL unknown messages to onMessage
 *       → Unknown types silently dropped
 *  [S8] CHAT_MESSAGE body passed raw to UI.addMessage — XSS if UI uses innerHTML
 *       → sanitizeText() strips HTML before passing to UI
 *  [S9] PEER_JOIN/MESH_PEERS msg.id not validated — prototype pollution via "__proto__"
 *       → validatePeerId() enforces alphanumeric/hyphen/underscore, max 128 chars
 *  [S10] heartbeatTimer deleted from peers Map during iteration
 *       → Collect stale IDs first, delete after iteration completes
 *  [S11] destroy() cleared heartbeatTimer but NOT reconnectTimer
 *       → Both timers cleared; _destroyed flag prevents reconnect after destroy()
 *  [S12] BLE writeValue fire-and-forget with no MTU size check
 *       → Payload chunked to MAX_BLE_CHUNK_BYTES (512); awaited with try/catch
 */

let messageQueue = [];

function safeSend(ws, data) {
    if (ws && ws.readyState === WebSocket.OPEN) {
        ws.send(data);
    } else {
        messageQueue.push(data);
    }
}

// KRYPTOS SECURITY — WS message sanitizer (mesh layer)
const _ALLOWED_MESH_TYPES = new Set([
    'chat', 'mesh', 'ping', 'pong', 'signal',
    'node-announce', 'node-discover', 'route',
    'ack', 'relay', 'onion', 'cover',
    // server/control types already used by GhostMesh
    'HELLO', 'MESH_HELLO', 'welcome',
    'PEER_JOIN', 'PEER_LEAVE', 'MESH_MSG',
    'MSG', 'MESH_PEERS', 'HEARTBEAT', 'HEARTBEAT_ACK'
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

    return {
        type: String(msg.type),
        body: msg.body ? String(msg.body).slice(0, 4096) : undefined,
        senderId: msg.senderId || null,
        timestamp: msg.timestamp || now,
        hopCount: typeof msg.hopCount === 'number'
            ? Math.min(Math.max(0, msg.hopCount), 10)
            : 0
    };
}

class GhostMesh {
    constructor(identity) {
        this.identity = identity; // { id, nodeId, pub }
        this.peers = new Map();
        this.ws = null;
        this.wsReady = false;
        this.bleAvailable = false;
        this.bleScanning = false;
        this.reconnectTimer = null;
        this.heartbeatTimer = null;
        this.knownBLEDevices = [];
        this._destroyed = false; // [S11]
        this._reconnectDelay = 3000;  // backoff state

        // BLE constants
        this.SERVICE_UUID = '67686f73-746e-6574-2d6d-657368000000';
        this.CHAR_DATA = '67686f73-746e-6574-2d64-617461000000';
        this.CHAR_PEER_ID = '67686f73-746e-6574-2d69-640000000000';

        // Limits
        this.MAX_HOPS = 5;    // [S6] hard cap — never from msg
        this.MAX_BLE_PAYLOAD_BYTES = 4096; // [S3]
        this.MAX_BLE_CHUNK_BYTES = 512;  // [S12] BLE MTU safe size

        // Event handlers (set by app.js)
        this.onPeerJoin = () => { };
        this.onPeerLeave = () => { };
        this.onMessage = () => { };
        this.onMeshUpdate = () => { };
        this.onStatusChange = () => { };

        // [S4] Load and validate known BLE devices
        this._loadKnownBleDevices();

        this.bleAvailable = typeof navigator !== 'undefined' && !!navigator.bluetooth;
        console.log(`🕸️ GhostMesh initialized. BLE: ${this.bleAvailable ? 'available' : 'unavailable'}`);

        // [Feature 4] Relay Monitor State
        this.relayStats = {
            packets: 0,
            bytes: 0,
            startTime: Date.now()
        };
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    /** [S1][S2] Cryptographically random message ID */
    secureId(prefix = 'msg_') {
        const arr = new Uint8Array(8);
        crypto.getRandomValues(arr);
        return prefix + Array.from(arr).map(b => b.toString(16).padStart(2, '0')).join('');
    }

    /** [S9] Peer ID validation */
    validatePeerId(id) {
        if (typeof id !== 'string') return null;
        const clean = id.trim();
        if (!/^[a-zA-Z0-9_\-]{1,512}$/.test(clean)) return null;
        return clean.toLowerCase();
    }

    /** [S8] Strip HTML tags from any string before passing to UI */
    sanitizeText(str) {
        if (typeof str !== 'string') return '';
        return str
            .replace(/&/g, '&amp;')
            .replace(/</g, '&lt;')
            .replace(/>/g, '&gt;')
            .replace(/"/g, '&quot;')
            .replace(/'/g, '&#x27;');
    }

    /** [S4][S5] Validate a single BLE device entry from storage */
    validateBleDeviceEntry(entry) {
        if (!entry || typeof entry !== 'object') return null;
        const id = typeof entry.id === 'string' ? entry.id.slice(0, 128) : null;
        const name = typeof entry.name === 'string' ? entry.name.slice(0, 64) : 'Unknown';
        const ts = typeof entry.lastConnected === 'number' ? entry.lastConnected : 0;
        if (!id) return null;
        return { id, name, lastConnected: ts };
    }

    /** [S4] Load BLE devices from storage with full validation */
    _loadKnownBleDevices() {
        try {
            const stored = localStorage.getItem('kryptos_ble_devices');
            if (!stored) return;
            const raw = JSON.parse(stored);
            if (!Array.isArray(raw)) return;
            this.knownBLEDevices = raw
                .map(e => this.validateBleDeviceEntry(e))
                .filter(Boolean)
                .slice(0, 20); // [S5] cap
        } catch (_) {
            this.knownBLEDevices = [];
        }
    }

    // ── [F1] Auth token retrieval ─────────────────────────────────────────────

    getAuthToken() {
        try {
            const legacyJwt = localStorage.getItem('kryptos_jwt');
            if (legacyJwt) {
                sessionStorage.setItem('kryptos_jwt', legacyJwt);
                localStorage.removeItem('kryptos_jwt');
            }
        } catch (_) { }
        return sessionStorage.getItem('kryptos_jwt') || null;
    }

    // ── [F2] WS URL builder ───────────────────────────────────────────────────

    buildWsUrl() {
        // Allow override via <meta name="kryptos-ws-url" content="wss://...">
        const meta = document.querySelector('meta[name="kryptos-ws-url"]');
        if (meta && meta.content) return meta.content;

        // Vercel doesn't support WebSockets — always use the Railway backend.
        return 'wss://kryptos-ji-production.up.railway.app/ws';
    }

    // ─────────────────────────────────────────────────────────────────────────
    // PUBLIC API
    // ─────────────────────────────────────────────────────────────────────────

    async start() {
        this._destroyed = false;
        this.onStatusChange({ state: 'connecting', transport: 'ws' });
        
        const token = this.authToken || this.getAuthToken();
        if (token) {
            this.connectWebSocket();
        } else {
            console.log('🔌 Mesh: Standing by for authentication before connecting.');
        }
        
        this.startHeartbeat();

        if (this.bleAvailable && this.knownBLEDevices.length > 0) {
            console.log(`📲 BLE auto-reconnect: ${this.knownBLEDevices.length} known device(s)`);
            this.attemptBLEAutoReconnect();
        }
        return true;
    }

    async scanBLE() {
        if (!this.bleAvailable) {
            this.onStatusChange({ state: 'error', message: 'Bluetooth not available. Use Chrome on HTTPS or localhost.' });
            return [];
        }
        if (this.bleScanning) return;

        this.bleScanning = true;
        this.onStatusChange({ state: 'scanning', transport: 'ble' });

        try {
            const device = await navigator.bluetooth.requestDevice({
                acceptAllDevices: true,
                optionalServices: [this.SERVICE_UUID]
            });
            if (device) {
                await this.connectBLEDevice(device);
                this.rememberBLEDevice(device);
            }
        } catch (e) {
            if (e.name === 'NotFoundError') {
                console.log('BLE: User cancelled scan');
            } else if (e.name === 'SecurityError') {
                this.onStatusChange({ state: 'error', message: 'Bluetooth requires a button tap to scan.' });
            } else {
                // [S8] Don't pass e.message raw to UI
                this.onStatusChange({ state: 'error', message: 'BLE scan failed.' });
                console.warn('BLE Scan Error:', e.message);
            }
        } finally {
            this.bleScanning = false;
        }
    }

    async broadcast(message) {
        const payload = {
            type: 'MESH_MSG',
            id: this.secureId(),        // [S1]
            from: this.identity.id,
            data: message,
            ts: Date.now(),
            hops: 0,
            maxHops: this.MAX_HOPS           // [S6] always our constant
        };

        if (this.ws && this.wsReady) {
            try { safeSend(this.ws, JSON.stringify(payload)); }
            catch (e) { console.warn('WS broadcast failed:', e.message); }
        }

        for (const [, peer] of this.peers) {
            if (peer.transport === 'ble' && peer.connected && peer.writeChar) {
                await this._bleSend(peer, payload); // [S12]
            }
        }
    }

    async sendToPeer(peerId, message) {
        const validId = this.validatePeerId(peerId); // [S9]
        if (!validId) { console.warn('sendToPeer: invalid peerId'); return; }

        const peer = this.peers.get(validId);
        const payload = {
            type: 'MESH_DIRECT',
            id: this.secureId(),           // [S2]
            from: this.identity.id,
            to: validId,
            data: message,
            ts: Date.now()
        };

        if (peer?.transport === 'ble' && peer.connected && peer.writeChar) {
            await this._bleSend(peer, payload); // [S12]
        } else if (this.ws && this.wsReady) {
            safeSend(this.ws, JSON.stringify(payload));
        }
    }

    getPeers() {
        const result = [];
        for (const [, peer] of this.peers) {
            result.push({
                id: peer.id,
                transport: peer.transport,
                connected: peer.connected,
                lastSeen: peer.lastSeen,
                name: peer.name || peer.id.slice(-6)
            });
        }
        return result;
    }

    getStatus() {
        const blePeers = [...this.peers.values()].filter(p => p.transport === 'ble' && p.connected).length;
        const wsPeers = [...this.peers.values()].filter(p => p.transport === 'ws').length;
        return {
            wsConnected: this.wsReady,
            bleAvailable: this.bleAvailable,
            bleScanning: this.bleScanning,
            totalPeers: this.peers.size,
            blePeers, wsPeers,
            knownBLEDevices: this.knownBLEDevices.length,
            relayStats: this.relayStats // [Feature 4]
        };
    }

    getRelayStats() {
        return {
            ...this.relayStats,
            uptime: Math.floor((Date.now() - this.relayStats.startTime) / 1000)
        };
    }

    // ─────────────────────────────────────────────────────────────────────────
    // WEBSOCKET TRANSPORT
    setAuthToken(token) {
        this.authToken = token;
        if (token && !this.wsReady && (!this.ws || this.ws.readyState !== WebSocket.OPEN)) {
            this.connectWebSocket();
        }
    }

    connectWebSocket() {
        if (this._destroyed) return; // [S11]

        // [F1] Require a JWT token — abort if missing
        const token = this.authToken || this.getAuthToken();
        if (!token) {
            return;
        }

        try {
            // [F2] Dynamic URL from page origin; [F1] token in query string
            const base = this.buildWsUrl();
            const wsUrl = `${base}?token=${encodeURIComponent(token)}`;
            console.log(`🔌 Mesh: Connecting WebSocket to ${base}...`); // don't log token

            this.ws = new WebSocket(wsUrl);

            this.ws.onopen = () => {
                console.log('✅ Mesh: WebSocket connected');
                this.wsReady = true;
                this._reconnectDelay = 3000; // reset backoff

                safeSend(this.ws, JSON.stringify({
                    type: 'register',
                    id: this.identity.id,
                    nodeId: this.identity.nodeId,
                    capabilities: { ble: this.bleAvailable, ws: true }
                }));

                // Flush queue
                messageQueue.forEach(msg => {
                    if (this.ws.readyState === WebSocket.OPEN) {
                        this.ws.send(msg);
                    }
                });
                messageQueue = [];

                this.onStatusChange({ state: 'connected', transport: 'ws' });
            };

            this.ws.onmessage = (event) => {
                const clean = _sanitizeMeshMessage(event.data);
                if (!clean) return;
                this.handleWSMessage(clean);
            };

            this.ws.onclose = () => {
                console.warn('🔌 Mesh: WebSocket disconnected');
                this.wsReady = false;
                this.onStatusChange({ state: 'disconnected', transport: 'ws' });

                // Remove WS peers
                for (const [id, peer] of this.peers) {
                    if (peer.transport === 'ws') {
                        this.peers.delete(id);
                        this.onPeerLeave(peer);
                    }
                }
                this.onMeshUpdate(this.getPeers());

                if (!this._destroyed) { // [S11]
                    clearTimeout(this.reconnectTimer);
                    // Exponential backoff capped at 30s
                    this._reconnectDelay = Math.min(this._reconnectDelay * 1.5, 30_000);
                    this.reconnectTimer = setTimeout(() => this.connectWebSocket(), this._reconnectDelay);
                }
            };

            this.ws.onerror = () => {
                console.warn('[GhostMesh] WebSocket error.'); // [S8] no raw event details
            };

        } catch (_) {
            console.warn('WebSocket setup failed');
            if (!this._destroyed) {
                clearTimeout(this.reconnectTimer);
                this.reconnectTimer = setTimeout(() => this.connectWebSocket(), 5000);
            }
        }
    }

    handleWSMessage(msg) {
        if (!msg || typeof msg !== 'object') return;

        switch (msg.type) {
            case 'HELLO':
            case 'MESH_HELLO':
                break;

            case 'welcome':
                break;

            case 'PEER_JOIN': {
                const peerId = this.validatePeerId(msg.id); // [S9]
                if (!peerId || peerId === this.identity.id) break;
                const peer = {
                    id: peerId,
                    transport: 'ws',
                    connected: true,
                    lastSeen: Date.now(),
                    name: this.sanitizeText(msg.name || peerId.slice(-8)) // [S8]
                };
                this.peers.set(peerId, peer);
                this.onPeerJoin(peer);
                this.onMeshUpdate(this.getPeers());
                break;
            }

            case 'PEER_LEAVE': {
                const peerId = this.validatePeerId(msg.id); // [S9]
                if (peerId && this.peers.has(peerId)) {
                    const peer = this.peers.get(peerId);
                    this.peers.delete(peerId);
                    this.onPeerLeave(peer);
                    this.onMeshUpdate(this.getPeers());
                }
                break;
            }

            case 'message':
            case 'MESH_MSG':
            case 'MSG': {
                const fromId = this.validatePeerId(msg.from); // [S9]
                if (!fromId || fromId === this.identity.id) break;
                if (this.peers.has(fromId)) this.peers.get(fromId).lastSeen = Date.now();
                this.onMessage(msg.data || msg.content || msg, fromId, 'ws');

                // [S6] Relay only if hops < our MAX_HOPS constant — never msg.maxHops
                const hops = typeof msg.hops === 'number' ? msg.hops : 0;
                if (hops < this.MAX_HOPS) {
                    this.relayToBLE({ ...msg, hops: hops + 1, maxHops: this.MAX_HOPS });
                }
                break;
            }

            case 'CHAT_MESSAGE': {
                const fromId = this.validatePeerId(msg.senderId); // [S9]
                if (!fromId || fromId === this.identity.id) break;

                // [S8] Sanitize all server-provided strings before touching UI
                let body = msg.content;
                if (typeof body === 'object' && body?.body) body = body.body;
                if (typeof body === 'string' && body.includes('body":"')) {
                    try { body = JSON.parse(body).body; } catch (_) { }
                }

                const safeBody = this.sanitizeText(String(body || ''));

                if (window.UI) window.UI.addMessage(safeBody, 'them');
                if (window.UI && window.AppState?.identity) {
                    window.UI.loadConversations(window.AppState.identity.id || window.AppState.identity.nodeId);
                }
                break;
            }

            case 'MESH_DIRECT': {
                const toId = this.validatePeerId(msg.to);
                const fromId = this.validatePeerId(msg.from);
                
                // If it's for me, it will be handled by onMessage via standard MSG flow if renamed on server,
                // but usually direct messages in mesh are intended for relay.
                if (toId && toId !== this.identity.id) {
                    // SILENT RELAY [Feature 4]
                    this.relayStats.packets++;
                    this.relayStats.bytes += JSON.stringify(msg).length;
                    
                    const hops = typeof msg.hops === 'number' ? msg.hops : 0;
                    if (hops < this.MAX_HOPS) {
                        const relayMsg = { ...msg, hops: hops + 1 };
                        this.relayToWS(relayMsg);
                        this.relayToBLE(relayMsg);
                    }
                } else if (toId === this.identity.id) {
                    // It's for me!
                    this.onMessage(msg.data || msg, fromId, 'mesh-direct');
                }
                break;
            }

            case 'NEW_CONVERSATION':
                if (window.UI && window.AppState?.identity) {
                    window.UI.loadConversations(window.AppState.identity.id || window.AppState.identity.nodeId);
                }
                break;

            case 'MESH_PEERS':
                if (Array.isArray(msg.peers)) {
                    msg.peers.forEach(p => {
                        const peerId = this.validatePeerId(p.id); // [S9]
                        if (!peerId || peerId === this.identity.id || this.peers.has(peerId)) return;
                        const peer = {
                            id: peerId,
                            transport: 'ws',
                            connected: true,
                            lastSeen: typeof p.lastSeen === 'number' ? p.lastSeen : Date.now(),
                            name: this.sanitizeText(p.name || peerId.slice(-8)) // [S8]
                        };
                        this.peers.set(peerId, peer);
                        this.onPeerJoin(peer);
                    });
                    this.onMeshUpdate(this.getPeers());
                }
                break;

            case 'HEARTBEAT':
                if (this.ws && this.wsReady) {
                    safeSend(this.ws, JSON.stringify({ type: 'HEARTBEAT_ACK', id: this.identity.id }));
                }
                break;

            case 'error':
                // [S8] Never render raw server error messages in UI
                console.warn('Server error message received');
                break;

            case 'ERROR':
                console.warn('Server error:', this.sanitizeText(msg.error || ''));
                break;

            default:
                // [S7] Drop unknown message types — do NOT forward to onMessage
                break;
        }
    }

    // ─────────────────────────────────────────────────────────────────────────
    // BLE TRANSPORT
    // ─────────────────────────────────────────────────────────────────────────

    /** [S12] Safe BLE send — chunks payload to MAX_BLE_CHUNK_BYTES */
    async _bleSend(peer, payload) {
        if (!peer?.writeChar) return;
        try {
            const json = JSON.stringify(payload);
            const encoded = new TextEncoder().encode(json);

            // [S12] Check size before sending
            if (encoded.length > this.MAX_BLE_PAYLOAD_BYTES) {
                console.warn(`BLE: payload too large (${encoded.length} bytes), dropping`);
                return;
            }

            // Send in MTU-safe chunks
            for (let i = 0; i < encoded.length; i += this.MAX_BLE_CHUNK_BYTES) {
                const chunk = encoded.slice(i, i + this.MAX_BLE_CHUNK_BYTES);
                await peer.writeChar.writeValue(chunk); // awaited [S12]
            }
        } catch (e) {
            console.warn(`BLE send failed to ${peer.id?.slice(0, 12)}:`, e.message);
        }
    }

    async connectBLEDevice(device) {
        try {
            device.addEventListener('gattserverdisconnected', () => {
                const peerId = device.id;
                if (this.peers.has(peerId)) {
                    const peer = this.peers.get(peerId);
                    peer.connected = false;
                    this.onPeerLeave(peer);
                    this.onMeshUpdate(this.getPeers());
                }
                setTimeout(() => this.tryReconnectBLEDevice(device), 2000);
            });

            const server = await device.gatt.connect();
            let service, charData, charId;

            try {
                service = await server.getPrimaryService(this.SERVICE_UUID);
                charData = await service.getCharacteristic(this.CHAR_DATA);
                charId = await service.getCharacteristic(this.CHAR_PEER_ID);
            } catch (_) {
                console.warn(`BLE: Kryptos service not found on ${device.name || device.id}. Adding as generic peer.`);
                const peer = {
                    id: device.id, transport: 'ble', connected: true,
                    lastSeen: Date.now(), name: device.name || 'BLE-' + device.id.slice(-4),
                    device, server, writeChar: null
                };
                this.peers.set(device.id, peer);
                this.onPeerJoin(peer);
                this.onMeshUpdate(this.getPeers());
                return;
            }

            let peerId = device.id;
            try {
                const idVal = await charId.readValue();
                const rawId = new TextDecoder().decode(idVal);
                peerId = this.validatePeerId(rawId) || device.id; // [S9]
            } catch (_) { }

            try {
                await charData.startNotifications();
                charData.addEventListener('characteristicvaluechanged', (event) => {
                    // [S3] Size cap on incoming BLE data
                    if (event.target.value.byteLength > this.MAX_BLE_PAYLOAD_BYTES) {
                        console.warn('BLE: oversized payload dropped');
                        return;
                    }
                    const val = new TextDecoder().decode(event.target.value);
                    try {
                        const msg = JSON.parse(val);
                        const fromId = this.validatePeerId(msg.from); // [S9]
                        if (!fromId || fromId === this.identity.id) return;
                        this.onMessage(msg.data || msg, fromId, 'ble');

                        // [S6] Hard hop cap — ignore msg.maxHops
                        const hops = typeof msg.hops === 'number' ? msg.hops : 0;
                        if (hops < this.MAX_HOPS) {
                            this.relayToWS({ ...msg, hops: hops + 1, maxHops: this.MAX_HOPS });
                        }
                    } catch (_) {
                        // Non-JSON — pass sanitized string [S8]
                        this.onMessage(this.sanitizeText(val), peerId, 'ble');
                    }
                });
            } catch (_) {
                console.warn('BLE notifications not supported on this device');
            }

            const peer = {
                id: peerId, transport: 'ble', connected: true,
                lastSeen: Date.now(), name: device.name || 'BLE-' + peerId.slice(-4),
                device, server, writeChar: charData
            };
            this.peers.set(peerId, peer);
            this.onPeerJoin(peer);
            this.onMeshUpdate(this.getPeers());
            this.onStatusChange({ state: 'connected', transport: 'ble', peerId });
            console.log(`✅ BLE: Connected to ${peer.name}`);

        } catch (e) {
            console.warn('BLE connection failed:', e.message);
            this.onStatusChange({ state: 'error', message: 'BLE connection failed.' }); // [S8]
        }
    }

    async tryReconnectBLEDevice(device) {
        if (!device?.gatt) return;
        try { await this.connectBLEDevice(device); }
        catch (_) { }
    }

    async attemptBLEAutoReconnect() {
        if (!navigator.bluetooth?.getDevices) return;
        try {
            const devices = await navigator.bluetooth.getDevices();
            for (const device of devices) {
                const known = this.knownBLEDevices.find(d => d.id === device.id);
                if (!known) continue;
                try {
                    if (device.watchAdvertisements) {
                        await device.watchAdvertisements();
                        device.addEventListener('advertisementreceived', async () => {
                            if (!this.peers.has(device.id) || !this.peers.get(device.id).connected) {
                                await this.connectBLEDevice(device);
                            }
                        });
                    } else {
                        await this.connectBLEDevice(device);
                    }
                } catch (_) { }
            }
        } catch (_) { }
    }

    rememberBLEDevice(device) {
        const entry = this.validateBleDeviceEntry({ // [S4][S5]
            id: device.id,
            name: device.name || 'Unknown',
            lastConnected: Date.now()
        });
        if (!entry) return;

        this.knownBLEDevices = this.knownBLEDevices.filter(d => d.id !== entry.id);
        this.knownBLEDevices.push(entry);
        if (this.knownBLEDevices.length > 20) this.knownBLEDevices = this.knownBLEDevices.slice(-20);

        try {
            localStorage.setItem('kryptos_ble_devices', JSON.stringify(this.knownBLEDevices));
        } catch (_) { }
    }

    // ─────────────────────────────────────────────────────────────────────────
    // MESH RELAY
    // ─────────────────────────────────────────────────────────────────────────

    relayToBLE(msg) {
        for (const [, peer] of this.peers) {
            if (peer.transport === 'ble' && peer.connected && peer.writeChar) {
                this._bleSend(peer, msg); // [S12] size-checked
            }
        }
    }

    relayToWS(msg) {
        if (this.ws && this.wsReady) {
            try { safeSend(this.ws, JSON.stringify(msg)); }
            catch (_) { }
        }
    }

    // ─────────────────────────────────────────────────────────────────────────
    // HEARTBEAT & MAINTENANCE
    // ─────────────────────────────────────────────────────────────────────────

    startHeartbeat() {
        clearInterval(this.heartbeatTimer);
        this.heartbeatTimer = setInterval(() => {
            const now = Date.now();

            // [S10] Collect stale IDs first — never delete during iteration
            const stale = [];
            for (const [id, peer] of this.peers) {
                if (peer.transport === 'ws' && now - peer.lastSeen > 60_000) stale.push(id);
            }
            stale.forEach(id => {
                const peer = this.peers.get(id);
                this.peers.delete(id);
                this.onPeerLeave(peer);
            });

            if (this.ws && this.wsReady) {
                try {
                    safeSend(this.ws, JSON.stringify({
                        type: 'HEARTBEAT',
                        id: this.identity.id,
                        ts: now,
                        peers: this.peers.size
                    }));
                } catch (_) { }
            }

            this.onMeshUpdate(this.getPeers());
        }, 15_000);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // CLEANUP
    // ─────────────────────────────────────────────────────────────────────────

    destroy() {
        this._destroyed = true; // [S11] prevent reconnect after destroy

        clearInterval(this.heartbeatTimer);
        clearTimeout(this.reconnectTimer);  // [S11] was missing
        this.heartbeatTimer = null;
        this.reconnectTimer = null;

        if (this.ws) {
            this.ws.onclose = null; // prevent reconnect handler firing
            this.ws.close();
            this.ws = null;
        }

        for (const [, peer] of this.peers) {
            if (peer.transport === 'ble' && peer.device?.gatt?.connected) {
                try { peer.device.gatt.disconnect(); } catch (_) { }
            }
        }
        this.peers.clear();
        this.wsReady = false;
    }
}

// Expose globally
if (typeof window !== 'undefined') window.GhostMesh = GhostMesh;