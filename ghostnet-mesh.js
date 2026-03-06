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

        // BLE Constants
        this.SERVICE_UUID = '67686f73-746e-6574-2d6d-657368000000';
        this.CHAR_DATA = '67686f73-746e-6574-2d64-617461000000';
        this.CHAR_PEER_ID = '67686f73-746e-6574-2d69-640000000000';

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
        const payload = {
            type: 'MESH_MSG',
            id: 'msg_' + Date.now() + '_' + Math.random().toString(36).substr(2, 5),
            from: this.identity.id,
            data: message,
            ts: Date.now(),
            hops: 0,
            maxHops: 5
        };

        // Send via WebSocket
        if (this.ws && this.wsReady) {
            try {
                this.ws.send(JSON.stringify(payload));
            } catch (e) {
                console.error('WS send failed:', e);
            }
        }

        // Send via BLE to all connected peers
        for (const [peerId, peer] of this.peers) {
            if (peer.transport === 'ble' && peer.connected && peer.writeChar) {
                try {
                    const data = new TextEncoder().encode(JSON.stringify(payload));
                    await peer.writeChar.writeValue(data);
                } catch (e) {
                    console.error(`BLE send to ${peerId} failed:`, e);
                }
            }
        }
    }

    /** Send a message to a specific peer */
    async sendToPeer(peerId, message) {
        const peer = this.peers.get(peerId);

        const payload = {
            type: 'MESH_DIRECT',
            id: 'msg_' + Date.now(),
            from: this.identity.id,
            to: peerId,
            data: message,
            ts: Date.now()
        };

        // Try BLE first (direct), then WebSocket relay
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
            const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
            const wsUrl = `wss://ghostnet-ji-production.up.railway.app/ws`;
            console.log(`🔌 Mesh: Connecting WebSocket: ${wsUrl}`);

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
                try {
                    const msg = JSON.parse(event.data);
                    this.handleWSMessage(msg);
                } catch (e) {
                    console.error('WS parse error:', e);
                }
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

    handleWSMessage(msg) {
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
                    // Update peer lastSeen
                    if (this.peers.has(msg.from)) {
                        this.peers.get(msg.from).lastSeen = Date.now();
                    }
                    this.onMessage(msg.data || msg.content || msg, msg.from, 'ws');

                    // Bridge to BLE peers (mesh relay)
                    if (msg.hops !== undefined && msg.hops < (msg.maxHops || 5)) {
                        this.relayToBLE({ ...msg, hops: (msg.hops || 0) + 1 });
                    }
                }
                break;

            case 'CHAT_MESSAGE':
                // Targeted message from the server (HTTP-persisted, delivered via WS)
                if (msg.senderId !== this.identity.id) {
                    console.log(`📩 Chat message from ${msg.senderId?.substring(0, 12)}...`);
                    // Extract message body
                    let body = msg.content;
                    if (typeof body === 'object' && body.body) body = body.body;
                    if (typeof body === 'string' && body.includes('body":"')) {
                        try { body = JSON.parse(body).body; } catch (e) { }
                    }
                    // Display in chat UI
                    if (window.UI) {
                        window.UI.addMessage(body || msg.content, 'them');
                    }
                    // Refresh conversation list (auto-creates contact on recipient side)
                    if (window.UI && window.AppState && window.AppState.identity) {
                        window.UI.loadConversations(window.AppState.identity.id || window.AppState.identity.nodeId);
                    }
                }
                break;

            case 'NEW_CONVERSATION':
                // Server notifies us about a new/updated conversation
                console.log('📋 New conversation notification received');
                if (window.UI && window.AppState && window.AppState.identity) {
                    window.UI.loadConversations(window.AppState.identity.id || window.AppState.identity.nodeId);
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

            // Try to get our custom service
            let service, charData, charId;
            try {
                service = await server.getPrimaryService(this.SERVICE_UUID);
                charData = await service.getCharacteristic(this.CHAR_DATA);
                charId = await service.getCharacteristic(this.CHAR_PEER_ID);
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

            // Read peer ID
            let peerId = device.id;
            try {
                const idVal = await charId.readValue();
                peerId = new TextDecoder().decode(idVal);
            } catch (e) {
                console.warn('Could not read peer ID, using device ID');
            }

            // Setup notifications for incoming data
            try {
                await charData.startNotifications();
                charData.addEventListener('characteristicvaluechanged', (event) => {
                    const val = new TextDecoder().decode(event.target.value);
                    try {
                        const msg = JSON.parse(val);
                        if (msg.from !== this.identity.id) {
                            this.onMessage(msg.data || msg, msg.from || peerId, 'ble');

                            // Bridge to WebSocket (mesh relay)
                            if (msg.hops !== undefined && msg.hops < (msg.maxHops || 5)) {
                                this.relayToWS({ ...msg, hops: (msg.hops || 0) + 1 });
                            }
                        }
                    } catch (e) {
                        // Non-JSON data, pass as string
                        this.onMessage(val, peerId, 'ble');
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
        for (const [peerId, peer] of this.peers) {
            if (peer.transport === 'ble' && peer.connected && peer.writeChar) {
                try {
                    const data = new TextEncoder().encode(JSON.stringify(msg));
                    peer.writeChar.writeValue(data);
                } catch (e) { }
            }
        }
    }

    relayToWS(msg) {
        if (this.ws && this.wsReady) {
            try {
                this.ws.send(JSON.stringify(msg));
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
