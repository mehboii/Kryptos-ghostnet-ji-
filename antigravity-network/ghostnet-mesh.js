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
    if (msg.enc && typeof msg.enc === 'object') sanitized.enc = msg.enc;
    if (msg.data !== undefined) sanitized.data = msg.data;
    if (msg.content !== undefined) sanitized.content = msg.content;
    if (msg.peers && Array.isArray(msg.peers)) sanitized.peers = msg.peers;
    if (msg.capabilities && typeof msg.capabilities === 'object') sanitized.capabilities = msg.capabilities;
    if (msg.name) sanitized.name = String(msg.name).slice(0, 64);

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
        this.knownBLEDevices = []; // Stored in localStorage for auto-reconnect

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

        // Load known BLE devices from storage
        try {
            const stored = localStorage.getItem('ghostnet_ble_devices');
            if (stored) this.knownBLEDevices = JSON.parse(stored);
        } catch (e) { }

        // Check BLE availability
        this.bleAvailable = typeof navigator !== 'undefined' && !!navigator.bluetooth;

        console.log(`🕸️ GhostMesh initialized. BLE: ${this.bleAvailable ? 'available' : 'unavailable'}`);
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
            console.log(`📲 Attempting BLE auto-reconnect to ${this.knownBLEDevices.length} known devices...`);
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
            console.log('📲 BLE: Requesting device scan...');

            // Request device with our service UUID, or accept all devices
            const device = await navigator.bluetooth.requestDevice({
                acceptAllDevices: true,
                optionalServices: [this.SERVICE_UUID]
            });

            if (device) {
                console.log(`📲 BLE: User selected: ${device.name || device.id}`);
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
        let encryptedData;
        let ivHex;
        try {
            if (!this._broadcastKey) {
                this._broadcastKey = await crypto.subtle.generateKey(
                    { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']
                );
            }
            const iv = crypto.getRandomValues(new Uint8Array(12));
            const plainBytes = new TextEncoder().encode(JSON.stringify(message));
            const cipherBuf = await crypto.subtle.encrypt(
                { name: 'AES-GCM', iv }, this._broadcastKey, plainBytes
            );
            encryptedData = Array.from(new Uint8Array(cipherBuf));
            ivHex = Array.from(iv).map(b => b.toString(16).padStart(2, '0')).join('');
        } catch (e) {
            console.error('Broadcast encryption failed:', e);
            return;
        }

        const payload = {
            type: 'MESH_MSG',
            id: crypto.randomUUID(),
            from: this.identity.id,
            enc: { data: encryptedData, iv: ivHex },
            ts: Date.now(),
            hops: 0,
            maxHops: 5
        };

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

        let encryptedData;
        try {
            if (!this._peerKeys) this._peerKeys = new Map();
            if (!this._peerKeys.has(peerId)) {
                this._peerKeys.set(peerId, await crypto.subtle.generateKey(
                    { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']
                ));
            }
            const peerKey = this._peerKeys.get(peerId);
            const iv = crypto.getRandomValues(new Uint8Array(12));
            const plainBytes = new TextEncoder().encode(JSON.stringify(message));
            const cipherBuf = await crypto.subtle.encrypt(
                { name: 'AES-GCM', iv }, peerKey, plainBytes
            );
            encryptedData = {
                data: Array.from(new Uint8Array(cipherBuf)),
                iv: Array.from(iv).map(b => b.toString(16).padStart(2, '0')).join('')
            };
        } catch (e) {
            return;
        }

        const payload = {
            type: 'MESH_DIRECT',
            id: crypto.randomUUID(),
            from: this.identity.id,
            to: peerId,
            enc: encryptedData,
            ts: Date.now()
        };

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
            const token = sessionStorage.getItem('ghostnet_jwt');
            if (!token) {
                console.warn('[Mesh] No auth token — cannot connect');
                return;
            }
            const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
            const baseUrl = `wss://ghostnet-ji-production.up.railway.app/ws`;
            const wsUrl = `${baseUrl}?token=${encodeURIComponent(token)}`;
            console.log(`🔌 Mesh: Connecting WebSocket: ${baseUrl}`);

            this.ws = new WebSocket(wsUrl);

            this.ws.onopen = () => {
                console.log('✅ Mesh: WebSocket connected');
                this.wsReady = true;

                // Register ourselves
                this.ws.send(JSON.stringify({
                    type: 'MESH_HELLO',
                    id: this.identity.id,
                    nodeId: this.identity.nodeId,
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

                // Auto-reconnect after 3 seconds
                clearTimeout(this.reconnectTimer);
                this.reconnectTimer = setTimeout(() => this.connectWebSocket(), 3000);
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
                    const peer = {
                        id: msg.id,
                        transport: 'ws',
                        connected: true,
                        lastSeen: Date.now(),
                        name: msg.name || msg.id.substr(-8)
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
                    if (this.peers.has(msg.from)) {
                        this.peers.get(msg.from).lastSeen = Date.now();
                    }

                    let msgContent = msg.data || msg.content || msg;
                    if (msg.enc) {
                        const decrypted = await this._decryptMeshPayload(msg.enc);
                        if (!decrypted) break;
                        msgContent = decrypted;
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
                                name: p.name || p.id.substr(-8)
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
                console.log(`📲 BLE: ${device.name || device.id} disconnected`);
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

            console.log(`📲 BLE: Connecting GATT to ${device.name || device.id}...`);
            const server = await device.gatt.connect();

            let service, charData, charId, charKey;
            try {
                service = await server.getPrimaryService(this.SERVICE_UUID);
                charData = await service.getCharacteristic(this.CHAR_DATA);
                charId = await service.getCharacteristic(this.CHAR_PEER_ID);
                try { charKey = await service.getCharacteristic(this.CHAR_PUB_KEY); } catch (e) { charKey = null; }
            } catch (e) {
                console.warn(`📲 BLE: GhostNet service not found on ${device.name || device.id}. Adding as generic BLE peer.`);
                // Still add as a peer even without our service (device is reachable)
                const peer = {
                    id: device.id,
                    transport: 'ble',
                    connected: true,
                    lastSeen: Date.now(),
                    name: device.name || 'BLE-' + device.id.substr(-4),
                    device: device,
                    server: server,
                    writeChar: null
                };
                this.peers.set(device.id, peer);
                this.onPeerJoin(peer);
                this.onMeshUpdate(this.getPeers());
                this.onStatusChange({ state: 'connected', transport: 'ble', peerId: device.id });
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

            try {
                await charData.startNotifications();
                charData.addEventListener('characteristicvaluechanged', async (event) => {
                    const val = new TextDecoder().decode(event.target.value);
                    const msg = _sanitizeMeshMessage(val);
                    if (!msg) return;
                    if (msg.from === this.identity.id) return;

                    let msgContent = msg.data || msg;
                    if (msg.enc) {
                        const decrypted = await this._decryptMeshPayload(msg.enc);
                        if (!decrypted) return;
                        msgContent = decrypted;
                    }
                    this.onMessage(msgContent, msg.from || peerId, 'ble');

                    if (msg.hops !== undefined && msg.hops < (msg.maxHops || 5)) {
                        this.relayToWS({ ...msg, hops: (msg.hops || 0) + 1 });
                    }
                });
            } catch (e) {
                console.warn('BLE notifications not supported:', e);
            }

            // Create peer entry
            const peer = {
                id: peerId,
                transport: 'ble',
                connected: true,
                lastSeen: Date.now(),
                name: device.name || 'BLE-' + peerId.substr(-4),
                device: device,
                server: server,
                writeChar: charData
            };

            this.peers.set(peerId, peer);
            this.onPeerJoin(peer);
            this.onMeshUpdate(this.getPeers());
            this.onStatusChange({ state: 'connected', transport: 'ble', peerId });

            console.log(`✅ BLE: Connected to ${peer.name} (${peerId})`);

        } catch (e) {
            console.error('BLE connection failed:', e);
            this.onStatusChange({ state: 'error', message: `BLE connection failed: ${e.message}` });
        }
    }

    async tryReconnectBLEDevice(device) {
        if (!device || !device.gatt) return;

        try {
            console.log(`📲 BLE: Attempting reconnect to ${device.name || device.id}...`);
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
                console.log(`📲 BLE: Found ${devices.length} previously paired devices`);

                for (const device of devices) {
                    // Check if this device is in our known list
                    const known = this.knownBLEDevices.find(d => d.id === device.id);
                    if (known) {
                        try {
                            // watchAdvertisements() lets us detect when the device comes in range
                            if (device.watchAdvertisements) {
                                await device.watchAdvertisements();
                                device.addEventListener('advertisementreceived', async (event) => {
                                    console.log(`📲 BLE: ${device.name || device.id} detected nearby!`);
                                    if (!this.peers.has(device.id) || !this.peers.get(device.id).connected) {
                                        await this.connectBLEDevice(device);
                                    }
                                });
                                console.log(`📲 BLE: Watching for ${device.name || device.id}...`);
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

        try {
            localStorage.setItem('ghostnet_ble_devices', JSON.stringify(this.knownBLEDevices));
        } catch (e) { }
    }

    // ============================================
    // MESH RELAY (Bridge between transports)
    // ============================================

    relayToBLE(msg) {
        const serialized = JSON.stringify(msg);
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
        const serialized = JSON.stringify(msg);
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
}

// Expose globally
if (typeof window !== 'undefined') {
    window.GhostMesh = GhostMesh;
}
