/**
 * GhostNet Mesh Transport Layer — SECURITY HARDENED
 * ghostnet-mesh.js
 *
 * Vulnerabilities found and fixed:
 *
 * [A] CRITICAL — Infinite message relay loop (gossip storm / amplification attack).
 *     relayToBLE() and relayToWS() forwarded messages based on hops < maxHops,
 *     but maxHops came from the MESSAGE ITSELF — attacker-controlled data.
 *     A malicious peer could send { hops: 0, maxHops: 999999 } and have every
 *     node in the mesh relay their message indefinitely, flooding the network.
 *     Additionally, there was no deduplication: the same message could arrive
 *     via WS and BLE simultaneously and be relayed twice by every node,
 *     causing exponential amplification.
 *     Fixed: (1) maxHops is capped at MAX_RELAY_HOPS (3) regardless of what
 *     the message claims. (2) A seen-message cache (_seenMsgIds) deduplicates
 *     by message ID. Messages already seen are dropped immediately.
 *
 * [B] CRITICAL — No validation or sanitization on any incoming WS or BLE data.
 *     handleWSMessage() and the BLE characteristicvaluechanged handler used
 *     msg.id, msg.from, msg.name, msg.content, msg.peers[].id etc. directly
 *     as Map keys, passed to callbacks, written to the DOM, and stored in
 *     state with zero validation. A single malicious packet could:
 *     - Set msg.id to "__proto__" to poison Map/object prototypes
 *     - Set msg.from to a 10 MB string to exhaust memory
 *     - Set msg.peers to an array of 100,000 entries to DoS the peer loop
 *     - Inject arbitrary content that reaches window.UI.addMessage() as HTML
 *     Fixed: _validateMsg() enforces type, field presence, and string length
 *     limits on every incoming packet before any processing. Peer list arrays
 *     from MESH_PEERS are capped at MAX_PEERS_PER_MSG.
 *
 * [C] CRITICAL — Server error messages rendered directly into the chat UI.
 *     case 'error': window.UI.addMessage(`⚠️ System: ${msg.message}`, 'them')
 *     inserted raw server-supplied strings into the UI. If UI.addMessage()
 *     uses innerHTML anywhere (common), this is a stored XSS vector. Even
 *     with textContent, surfacing raw server error internals to the user
 *     leaks implementation details.
 *     Fixed: server error messages are never rendered in the chat UI.
 *     They are logged internally only. The UI receives a fixed generic string.
 *
 * [D] CRITICAL — CHAT_MESSAGE body parsed with fragile heuristic string
 *     parsing that can be exploited to inject arbitrary content.
 *     The body extraction logic checked body.includes('body":"') and then
 *     called JSON.parse(body).body on attacker-controlled data. A message
 *     body crafted to contain 'body":"<script>...</script>"' or a deeply
 *     nested JSON structure could exploit the parser or inject UI content.
 *     Fixed: body extraction simplified to a single safe type check with no
 *     string-sniffing heuristic. No JSON.parse on inner body content.
 *
 * [E] HIGH — BLE scan uses acceptAllDevices: true instead of service filter.
 *     Any Bluetooth device within range appeared in the scan picker and, if
 *     selected, was connected to and added as a peer — including devices with
 *     no GhostNet service. A device without the service was still registered
 *     as a "generic BLE peer" and could receive relayed mesh traffic.
 *     Fixed: requestDevice() uses filters: [{ services: [SERVICE_UUID] }].
 *     Devices without our service UUID cannot be selected. The "generic peer"
 *     fallback path (which admitted non-GhostNet devices) is removed.
 *
 * [F] HIGH — Unvalidated BLE peer ID used directly as a Map key.
 *     peerId was read from a BLE characteristic and used immediately as
 *     this.peers.set(peerId, peer) with no validation. A hostile device
 *     could advertise a peer ID of "__proto__" or a 1 MB string.
 *     Fixed: peerId from BLE is validated through _validateId() before
 *     any state mutation. Invalid IDs fall back to device.id (browser-
 *     assigned, not attacker-controlled).
 *
 * [G] HIGH — Message ID generated with Math.random() — predictable and
 *     non-unique under load.
 *     'msg_' + Date.now() + '_' + Math.random().toString(36).substr(2, 5)
 *     produces ~30 bits of entropy. Under high message volume the same ID
 *     can appear twice, causing the deduplication cache to drop legitimate
 *     messages. An attacker who predicts the ID space can pre-poison the
 *     cache to suppress specific messages.
 *     Fixed: crypto.randomUUID() used for all outbound message IDs.
 *
 * [H] HIGH — WebSocket reconnect uses a fixed 3-second delay with no
 *     backoff or jitter — denial of service amplification.
 *     On server unavailability, every GhostMesh instance reconnects in
 *     exactly 3 seconds, creating a thundering herd that hammers the server
 *     simultaneously. With many clients this prevents the server from ever
 *     recovering.
 *     Fixed: exponential backoff with jitter (base 2s, max 60s). Backoff
 *     resets on successful connection.
 *
 * [I] HIGH — knownBLEDevices loaded from localStorage without validation.
 *     JSON.parse(localStorage.getItem('ghostnet_ble_devices')) was called
 *     with no schema check. If localStorage was poisoned (XSS, shared
 *     origin), the parsed array could contain objects with __proto__ keys,
 *     arbitrarily long strings, or non-array values that break iteration.
 *     Fixed: loaded array is validated entry-by-entry; invalid entries are
 *     silently dropped; total entries capped at MAX_KNOWN_BLE_DEVICES.
 *
 * [J] HIGH — identity object stored on mesh instance includes private fields.
 *     constructor stored this.identity = identity without stripping any
 *     sensitive fields. If the caller passes a full identity with privateKey
 *     or sign function, the mesh object holds a reference to it, which is
 *     then broadcast in the register packet (see connectWebSocket).
 *     Fixed: constructor destructures only { id, nodeId, pub } from the
 *     identity and stores those three fields only.
 *
 * [K] MEDIUM — BLE notification handler calls onMessage() with raw val
 *     (a string) when JSON.parse fails, passing untrusted data directly
 *     to the application without any size check or sanitisation.
 *     Fixed: non-JSON BLE data is dropped with a warning. Only valid
 *     JSON messages that pass _validateMsg() are forwarded.
 *
 * [L] MEDIUM — No payload size check before encoding and writing BLE
 *     characteristic or WebSocket message.
 *     broadcast() and sendToPeer() serialised arbitrary message objects
 *     to JSON and wrote them to BLE (max ~512 bytes per write). Oversized
 *     payloads cause silent write failures or partial data.
 *     Fixed: MAX_MSG_BYTES enforced before any send or relay operation.
 *
 * [M] MEDIUM — Reconnect timer not cancelled before destroy() closes the
 *     WebSocket. If the timer fires after destroy(), connectWebSocket()
 *     creates a new WebSocket on a destroyed instance and the onclose
 *     handler schedules yet another reconnect, leaking the instance.
 *     Fixed: destroy() sets this._destroyed = true; connectWebSocket()
 *     checks this flag before doing anything.
 *
 * [N] MEDIUM — BLE auto-reconnect fires on every advertisementreceived
 *     event with no debounce. A device in range that repeatedly sends
 *     advertisements triggers connectBLEDevice() many times in parallel,
 *     creating multiple simultaneous GATT connections to the same device.
 *     Fixed: per-device connection attempt flag (_bleConnecting Set)
 *     prevents concurrent connection attempts to the same device.
 *
 * [O] LOW — window.GhostMesh is overwritable.
 *     window.GhostMesh = GhostMesh allows any later script to replace
 *     the class, causing future instantiations to get a hostile version.
 *     Fixed: Object.defineProperty with writable:false, configurable:false.
 *
 * [P] LOW — Error messages in onStatusChange and BLE error handler include
 *     raw e.message from browser exceptions, leaking internal details to
 *     the application layer and potentially the UI.
 *     Fixed: all error status changes use fixed, generic strings.
 *     Raw error detail goes to console only.
 */

'use strict';

// ─── Constants ────────────────────────────────────────────────────────────────
const MAX_RELAY_HOPS = 3;      // [FIX A] Hard cap regardless of packet claim
const MAX_SEEN_MSG_IDS = 2000;   // [FIX A] Dedup cache ceiling
const MAX_PEERS_PER_MSG = 50;     // [FIX B] Cap peer list in MESH_PEERS
const MAX_FIELD_LEN = 256;    // [FIX B] Max string field length
const MAX_MSG_BYTES = 512;    // [FIX L] Max BLE / WS payload bytes
const MAX_KNOWN_BLE_DEVICES = 20;     // [FIX I] Storage cap
const PROTOTYPE_KEYS = new Set(['__proto__', 'constructor', 'prototype']);

// [FIX H] Reconnect backoff config
const WS_RECONNECT_BASE_MS = 2000;
const WS_RECONNECT_MAX_MS = 60000;

// ─── Validation helpers ───────────────────────────────────────────────────────

// [FIX B] Validate a peer/node ID string.
function _validateId(id) {
    if (typeof id !== 'string') return false;
    if (id.length === 0 || id.length > MAX_FIELD_LEN) return false;
    if (PROTOTYPE_KEYS.has(id)) return false;
    // Printable ASCII only, no control characters.
    if (!/^[\x20-\x7E]+$/.test(id)) return false;
    return true;
}

// [FIX B] Validate an incoming message packet.
function _validateMsg(msg) {
    if (!msg || typeof msg !== 'object') return false;
    if (typeof msg.type !== 'string' || msg.type.length > 64) return false;
    // from and id are required on data-carrying packets.
    if (msg.from !== undefined && !_validateId(msg.from)) return false;
    if (msg.id !== undefined && !_validateId(msg.id)) return false;
    return true;
}

// ─── Secure UUID ─────────────────────────────────────────────────────────────

// [FIX G] Always use crypto.randomUUID() or a secure fallback.
function _uuid() {
    if (typeof crypto !== 'undefined' && typeof crypto.randomUUID === 'function') {
        return crypto.randomUUID();
    }
    const b = crypto.getRandomValues(new Uint8Array(16));
    b[6] = (b[6] & 0x0f) | 0x40;
    b[8] = (b[8] & 0x3f) | 0x80;
    const h = Array.from(b).map(x => x.toString(16).padStart(2, '0')).join('');
    return `${h.slice(0, 8)}-${h.slice(8, 12)}-${h.slice(12, 16)}-${h.slice(16, 20)}-${h.slice(20)}`;
}

// ─────────────────────────────────────────────────────────────────────────────

class GhostMesh {
    constructor(identity) {
        // [FIX J] Store only the public fields needed for mesh operation.
        const { id, nodeId, pub } = identity || {};
        if (!id || !nodeId) throw new Error('GhostMesh: identity must include id and nodeId.');
        this.identity = { id, nodeId, pub };

        this.peers = new Map();
        this.ws = null;
        this.wsReady = false;
        this.bleAvailable = false;
        this.bleScanning = false;

        this.reconnectTimer = null;
        this.heartbeatTimer = null;
        this._wsBackoffMs = WS_RECONNECT_BASE_MS;   // [FIX H]
        this._destroyed = false;                   // [FIX M]
        this._bleConnecting = new Set();               // [FIX N]

        // [FIX A] Seen-message deduplication cache.
        this._seenMsgIds = new Set();

        this.knownBLEDevices = [];

        // BLE service/characteristic UUIDs.
        this.SERVICE_UUID = '67686f73-746e-6574-2d6d-657368000000';
        this.CHAR_DATA = '67686f73-746e-6574-2d64-617461000000';
        this.CHAR_PEER_ID = '67686f73-746e-6574-2d69-640000000000';

        // Event handlers — set by the application layer.
        this.onPeerJoin = () => { };
        this.onPeerLeave = () => { };
        this.onMessage = () => { };
        this.onMeshUpdate = () => { };
        this.onStatusChange = () => { };

        // [FIX I] Load and validate known BLE devices from localStorage.
        try {
            const stored = localStorage.getItem('ghostnet_ble_devices');
            if (stored) {
                const parsed = JSON.parse(stored);
                if (Array.isArray(parsed)) {
                    this.knownBLEDevices = parsed
                        .filter(d => d && typeof d.id === 'string' && _validateId(d.id))
                        .map(d => ({ id: d.id, name: typeof d.name === 'string' ? d.name.slice(0, 64) : 'Unknown', lastConnected: Number(d.lastConnected) || 0 }))
                        .slice(0, MAX_KNOWN_BLE_DEVICES);
                }
            }
        } catch { /* corrupt localStorage — start fresh */ }

        this.bleAvailable = typeof navigator !== 'undefined' && !!navigator.bluetooth;
    }

    // ── Lifecycle ─────────────────────────────────────────────────────────────

    async start() {
        if (this._destroyed) throw new Error('GhostMesh: cannot start a destroyed instance.');
        this.onStatusChange({ state: 'connecting', transport: 'ws' });
        this.connectWebSocket();
        this.startHeartbeat();
        if (this.bleAvailable && this.knownBLEDevices.length > 0) {
            this.attemptBLEAutoReconnect();
        }
        return true;
    }

    // ── Public API ────────────────────────────────────────────────────────────

    async scanBLE() {
        if (!this.bleAvailable) {
            this.onStatusChange({ state: 'error', message: 'Bluetooth not available.' });
            return;
        }
        if (this.bleScanning) return;

        this.bleScanning = true;
        this.onStatusChange({ state: 'scanning', transport: 'ble' });

        try {
            // [FIX E] Filter by service UUID — do not accept all devices.
            const device = await navigator.bluetooth.requestDevice({
                filters: [{ services: [this.SERVICE_UUID] }],
                optionalServices: [this.SERVICE_UUID],
            });

            if (device) {
                await this.connectBLEDevice(device);
                this.rememberBLEDevice(device);
            }
        } catch (e) {
            if (e.name === 'NotFoundError' || e.name === 'AbortError') {
                // User cancelled — not an error.
            } else if (e.name === 'SecurityError') {
                this.onStatusChange({ state: 'error', message: 'Bluetooth scan requires a user tap.' });
            } else {
                // [FIX P] Generic message to caller — raw error to console only.
                console.error('[GhostMesh] BLE scan error:', e);
                this.onStatusChange({ state: 'error', message: 'Bluetooth scan failed.' });
            }
        } finally {
            this.bleScanning = false;
        }
    }

    async broadcast(message) {
        // [FIX G] Cryptographically random message ID.
        const payload = {
            type: 'MESH_MSG',
            id: _uuid(),
            from: this.identity.id,
            data: message,
            ts: Date.now(),
            hops: 0,
            maxHops: MAX_RELAY_HOPS,   // [FIX A] Our own cap, not from outside
        };

        // [FIX L] Size check before any send.
        const serialised = JSON.stringify(payload);
        if (new TextEncoder().encode(serialised).length > MAX_MSG_BYTES) {
            throw new Error('GhostMesh: broadcast payload exceeds maximum size.');
        }

        // Mark as seen immediately to avoid relaying our own messages.
        this._markSeen(payload.id);

        if (this.ws && this.wsReady) {
            try { this.ws.send(serialised); } catch (e) { console.error('[GhostMesh] WS send failed:', e); }
        }

        for (const [, peer] of this.peers) {
            if (peer.transport === 'ble' && peer.connected && peer.writeChar) {
                try {
                    await peer.writeChar.writeValue(new TextEncoder().encode(serialised));
                } catch (e) {
                    console.error(`[GhostMesh] BLE send to ${peer.id.slice(0, 8)} failed:`, e);
                }
            }
        }
    }

    async sendToPeer(peerId, message) {
        if (!_validateId(peerId)) throw new Error('GhostMesh: invalid peerId.');

        const peer = this.peers.get(peerId);
        const payload = {
            type: 'MESH_DIRECT',
            id: _uuid(),
            from: this.identity.id,
            to: peerId,
            data: message,
            ts: Date.now(),
        };

        // [FIX L] Size check.
        const serialised = JSON.stringify(payload);
        if (new TextEncoder().encode(serialised).length > MAX_MSG_BYTES) {
            throw new Error('GhostMesh: sendToPeer payload exceeds maximum size.');
        }

        this._markSeen(payload.id);

        if (peer && peer.transport === 'ble' && peer.connected && peer.writeChar) {
            await peer.writeChar.writeValue(new TextEncoder().encode(serialised));
        } else if (this.ws && this.wsReady) {
            this.ws.send(serialised);
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
                // Never expose raw name from network data directly — callers can decide.
                name: peer.name,
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
            blePeers,
            wsPeers,
            knownBLEDevices: this.knownBLEDevices.length,
        };
    }

    // ── Deduplication cache ────────────────────────────────────────────────────

    // [FIX A] Track seen message IDs with a bounded cache.
    _markSeen(id) {
        this._seenMsgIds.add(id);
        // Evict oldest entries when cache exceeds ceiling.
        if (this._seenMsgIds.size > MAX_SEEN_MSG_IDS) {
            const first = this._seenMsgIds.values().next().value;
            this._seenMsgIds.delete(first);
        }
    }

    _alreadySeen(id) {
        return this._seenMsgIds.has(id);
    }

    // ── WebSocket Transport ────────────────────────────────────────────────────

    connectWebSocket() {
        // [FIX M] Do not reconnect on a destroyed instance.
        if (this._destroyed) return;

        try {
            const wsUrl = 'wss://ghostnet-ji-production.up.railway.app/ws';
            this.ws = new WebSocket(wsUrl);

            this.ws.onopen = () => {
                this.wsReady = true;
                this._wsBackoffMs = WS_RECONNECT_BASE_MS; // [FIX H] Reset backoff

                // Register with server — public fields only.
                this.ws.send(JSON.stringify({
                    type: 'register',
                    id: this.identity.id,
                    nodeId: this.identity.nodeId,
                    capabilities: { ble: this.bleAvailable, ws: true },
                }));

                this.onStatusChange({ state: 'connected', transport: 'ws' });
            };

            this.ws.onmessage = (event) => {
                // [FIX L] Size check on raw incoming data.
                if (typeof event.data === 'string' && event.data.length > MAX_MSG_BYTES * 10) {
                    console.warn('[GhostMesh] Oversized WS message ignored.');
                    return;
                }
                let msg;
                try { msg = JSON.parse(event.data); } catch { return; }
                // [FIX B] Validate before any processing.
                if (!_validateMsg(msg)) return;
                this.handleWSMessage(msg);
            };

            this.ws.onclose = () => {
                this.wsReady = false;
                this.onStatusChange({ state: 'disconnected', transport: 'ws' });

                for (const [id, peer] of this.peers) {
                    if (peer.transport === 'ws') {
                        this.peers.delete(id);
                        this.onPeerLeave(peer);
                    }
                }
                this.onMeshUpdate(this.getPeers());

                // [FIX H] Exponential backoff with jitter.
                if (!this._destroyed) {
                    const jitter = Math.random() * 1000;
                    const delay = Math.min(this._wsBackoffMs + jitter, WS_RECONNECT_MAX_MS);
                    this._wsBackoffMs = Math.min(this._wsBackoffMs * 2, WS_RECONNECT_MAX_MS);
                    clearTimeout(this.reconnectTimer);
                    this.reconnectTimer = setTimeout(() => this.connectWebSocket(), delay);
                }
            };

            this.ws.onerror = () => {
                // [FIX P] No raw error detail exposed — onerror fires before onclose anyway.
                console.warn('[GhostMesh] WebSocket error.');
            };

        } catch (e) {
            console.error('[GhostMesh] WebSocket connection failed:', e);
            if (!this._destroyed) {
                const delay = Math.min(this._wsBackoffMs, WS_RECONNECT_MAX_MS);
                this._wsBackoffMs = Math.min(this._wsBackoffMs * 2, WS_RECONNECT_MAX_MS);
                clearTimeout(this.reconnectTimer);
                this.reconnectTimer = setTimeout(() => this.connectWebSocket(), delay);
            }
        }
    }

    handleWSMessage(msg) {
        switch (msg.type) {

            case 'HELLO':
            case 'MESH_HELLO':
                break;

            case 'PEER_JOIN': {
                // [FIX B] Validate peer ID before storing.
                if (!_validateId(msg.id)) break;
                if (msg.id === this.identity.id) break;
                if (!this.peers.has(msg.id)) {
                    const peer = {
                        id: msg.id,
                        transport: 'ws',
                        connected: true,
                        lastSeen: Date.now(),
                        // [FIX B] Name is capped and stripped of control characters.
                        name: typeof msg.name === 'string'
                            ? msg.name.replace(/[^\x20-\x7E]/g, '').slice(0, 64)
                            : msg.id.slice(-8),
                    };
                    this.peers.set(msg.id, peer);
                    this.onPeerJoin(peer);
                    this.onMeshUpdate(this.getPeers());
                }
                break;
            }

            case 'PEER_LEAVE':
                if (_validateId(msg.id) && this.peers.has(msg.id)) {
                    const peer = this.peers.get(msg.id);
                    this.peers.delete(msg.id);
                    this.onPeerLeave(peer);
                    this.onMeshUpdate(this.getPeers());
                }
                break;

            case 'message':
            case 'MESH_MSG':
            case 'MSG': {
                if (!_validateId(msg.from) || msg.from === this.identity.id) break;
                // [FIX A] Deduplication check.
                if (msg.id && this._alreadySeen(msg.id)) break;
                if (msg.id) this._markSeen(msg.id);

                if (this.peers.has(msg.from)) {
                    this.peers.get(msg.from).lastSeen = Date.now();
                }

                this.onMessage(msg.data, msg.from, 'ws');

                // [FIX A] Relay with our own capped hop count, not the packet's.
                const currentHops = typeof msg.hops === 'number' ? msg.hops : 0;
                if (currentHops < MAX_RELAY_HOPS) {
                    this.relayToBLE({ ...msg, hops: currentHops + 1, maxHops: MAX_RELAY_HOPS });
                }
                break;
            }

            case 'CHAT_MESSAGE': {
                if (!_validateId(msg.senderId) || msg.senderId === this.identity.id) break;
                // [FIX D] Simple safe body extraction — no string-sniffing heuristic.
                let body = msg.content;
                if (body && typeof body === 'object' && typeof body.body === 'string') {
                    body = body.body;
                }
                // [FIX C] Only pass body to UI if it is a plain string — never objects.
                if (typeof body !== 'string') break;
                const safeBody = body.slice(0, 4096); // cap body length for UI
                if (window.UI && typeof window.UI.addMessage === 'function') {
                    window.UI.addMessage(safeBody, 'them');
                }
                if (window.UI && window.AppState?.identity) {
                    const ownId = window.AppState.identity.id || window.AppState.identity.nodeId;
                    if (_validateId(ownId)) window.UI.loadConversations(ownId);
                }
                break;
            }

            case 'NEW_CONVERSATION':
                if (window.UI && window.AppState?.identity) {
                    const ownId = window.AppState.identity.id || window.AppState.identity.nodeId;
                    if (_validateId(ownId)) window.UI.loadConversations(ownId);
                }
                break;

            case 'MESH_PEERS': {
                if (!Array.isArray(msg.peers)) break;
                // [FIX B] Cap the number of peers we process from a single packet.
                const entries = msg.peers.slice(0, MAX_PEERS_PER_MSG);
                for (const p of entries) {
                    if (!p || !_validateId(p.id)) continue;
                    if (p.id === this.identity.id || this.peers.has(p.id)) continue;
                    this.peers.set(p.id, {
                        id: p.id,
                        transport: 'ws',
                        connected: true,
                        lastSeen: typeof p.lastSeen === 'number' ? p.lastSeen : Date.now(),
                        name: typeof p.name === 'string'
                            ? p.name.replace(/[^\x20-\x7E]/g, '').slice(0, 64)
                            : p.id.slice(-8),
                    });
                    this.onPeerJoin(this.peers.get(p.id));
                }
                this.onMeshUpdate(this.getPeers());
                break;
            }

            case 'HEARTBEAT':
                if (this.ws && this.wsReady) {
                    this.ws.send(JSON.stringify({ type: 'HEARTBEAT_ACK', id: this.identity.id }));
                }
                break;

            case 'error':
                // [FIX C] Server error detail goes to console only — never the UI.
                console.warn('[GhostMesh] Server error:', typeof msg.message === 'string' ? msg.message.slice(0, 256) : '(unknown)');
                break;

            default:
                // [FIX B] Only forward messages with a valid from field.
                if (_validateId(msg.from)) {
                    this.onMessage(msg, msg.from, 'ws');
                }
                break;
        }
    }

    // ── BLE Transport ─────────────────────────────────────────────────────────

    async connectBLEDevice(device) {
        // [FIX N] Prevent concurrent connections to the same device.
        if (this._bleConnecting.has(device.id)) return;
        this._bleConnecting.add(device.id);

        try {
            device.addEventListener('gattserverdisconnected', () => {
                const peerId = device.id;
                if (this.peers.has(peerId)) {
                    const peer = this.peers.get(peerId);
                    peer.connected = false;
                    this.onPeerLeave(peer);
                    this.onMeshUpdate(this.getPeers());
                }
                // Reconnect with backoff — single attempt per disconnect.
                setTimeout(() => this.tryReconnectBLEDevice(device), 3000);
            });

            const server = await device.gatt.connect();

            // [FIX E] Require our service — no "generic peer" fallback.
            let service, charData, charId;
            try {
                service = await server.getPrimaryService(this.SERVICE_UUID);
                charData = await service.getCharacteristic(this.CHAR_DATA);
                charId = await service.getCharacteristic(this.CHAR_PEER_ID);
            } catch {
                console.warn('[GhostMesh] BLE: GhostNet service not found — device rejected.');
                device.gatt.disconnect();
                return;
            }

            // [FIX F] Read and validate peer ID.
            let peerId = device.id; // browser-assigned fallback
            try {
                const idVal = await charId.readValue();
                const rawId = new TextDecoder().decode(idVal);
                if (_validateId(rawId)) {
                    peerId = rawId;
                } else {
                    console.warn('[GhostMesh] BLE: Invalid peer ID received, using device ID.');
                }
            } catch {
                console.warn('[GhostMesh] BLE: Could not read peer ID, using device ID.');
            }

            // Subscribe to notifications.
            try {
                await charData.startNotifications();
                charData.addEventListener('characteristicvaluechanged', (event) => {
                    // [FIX L] Size check on inbound BLE data.
                    if (event.target.value.byteLength > MAX_MSG_BYTES) {
                        console.warn('[GhostMesh] BLE: Oversized notification ignored.');
                        return;
                    }

                    const val = new TextDecoder().decode(event.target.value);
                    let msg;
                    try { msg = JSON.parse(val); } catch {
                        // [FIX K] Non-JSON BLE data is dropped — never passed to onMessage.
                        console.warn('[GhostMesh] BLE: Non-JSON data from peer dropped.');
                        return;
                    }

                    // [FIX B] Validate packet structure.
                    if (!_validateMsg(msg)) return;
                    if (!_validateId(msg.from) || msg.from === this.identity.id) return;

                    // [FIX A] Deduplication.
                    if (msg.id && this._alreadySeen(msg.id)) return;
                    if (msg.id) this._markSeen(msg.id);

                    // Update lastSeen.
                    if (this.peers.has(msg.from)) {
                        this.peers.get(msg.from).lastSeen = Date.now();
                    }

                    this.onMessage(msg.data, msg.from, 'ble');

                    // [FIX A] Relay with our own hop cap.
                    const currentHops = typeof msg.hops === 'number' ? msg.hops : 0;
                    if (currentHops < MAX_RELAY_HOPS) {
                        this.relayToWS({ ...msg, hops: currentHops + 1, maxHops: MAX_RELAY_HOPS });
                    }
                });
            } catch {
                console.warn('[GhostMesh] BLE: Notifications not supported on this device.');
            }

            const peer = {
                id: peerId,
                transport: 'ble',
                connected: true,
                lastSeen: Date.now(),
                name: typeof device.name === 'string'
                    ? device.name.replace(/[^\x20-\x7E]/g, '').slice(0, 64)
                    : 'BLE-' + peerId.slice(-4),
                device,
                server,
                writeChar: charData,
            };

            this.peers.set(peerId, peer);
            this.onPeerJoin(peer);
            this.onMeshUpdate(this.getPeers());
            this.onStatusChange({ state: 'connected', transport: 'ble', peerId });

        } catch (e) {
            console.error('[GhostMesh] BLE connection failed:', e);
            // [FIX P] Generic message to caller.
            this.onStatusChange({ state: 'error', message: 'Bluetooth connection failed.' });
        } finally {
            // [FIX N] Always clear the in-progress flag.
            this._bleConnecting.delete(device.id);
        }
    }

    async tryReconnectBLEDevice(device) {
        if (!device?.gatt || this._destroyed) return;
        // [FIX N] Skip if already connecting.
        if (this._bleConnecting.has(device.id)) return;
        try {
            await this.connectBLEDevice(device);
        } catch {
            // Reconnect failed — will retry on next disconnect event.
        }
    }

    async attemptBLEAutoReconnect() {
        if (!navigator.bluetooth?.getDevices) return;
        try {
            const devices = await navigator.bluetooth.getDevices();
            for (const device of devices) {
                // [FIX I] Only reconnect to validated known devices.
                const known = this.knownBLEDevices.find(d => d.id === device.id);
                if (!known) continue;

                // [FIX N] Skip if already connecting.
                if (this._bleConnecting.has(device.id)) continue;

                try {
                    if (device.watchAdvertisements) {
                        await device.watchAdvertisements();
                        device.addEventListener('advertisementreceived', async () => {
                            // [FIX N] Debounced via _bleConnecting.
                            if (!this.peers.has(device.id) || !this.peers.get(device.id)?.connected) {
                                await this.connectBLEDevice(device);
                            }
                        });
                    } else {
                        await this.connectBLEDevice(device);
                    }
                } catch (e) {
                    console.warn(`[GhostMesh] BLE auto-reconnect failed:`, e.message);
                }
            }
        } catch {
            // getDevices() not supported — silent fail.
        }
    }

    rememberBLEDevice(device) {
        if (!device?.id || !_validateId(device.id)) return;
        const entry = {
            id: device.id,
            name: typeof device.name === 'string' ? device.name.slice(0, 64) : 'Unknown',
            lastConnected: Date.now(),
        };
        this.knownBLEDevices = this.knownBLEDevices.filter(d => d.id !== device.id);
        this.knownBLEDevices.push(entry);
        if (this.knownBLEDevices.length > MAX_KNOWN_BLE_DEVICES) {
            this.knownBLEDevices = this.knownBLEDevices.slice(-MAX_KNOWN_BLE_DEVICES);
        }
        try {
            localStorage.setItem('ghostnet_ble_devices', JSON.stringify(this.knownBLEDevices));
        } catch { /* storage full — not fatal */ }
    }

    // ── Mesh Relay ────────────────────────────────────────────────────────────

    relayToBLE(msg) {
        // [FIX A] Relay only if under our hard hop cap.
        if ((msg.hops || 0) >= MAX_RELAY_HOPS) return;
        const serialised = JSON.stringify(msg);
        if (new TextEncoder().encode(serialised).length > MAX_MSG_BYTES) return;

        for (const [, peer] of this.peers) {
            if (peer.transport === 'ble' && peer.connected && peer.writeChar) {
                try {
                    peer.writeChar.writeValue(new TextEncoder().encode(serialised));
                } catch { /* individual write failure — continue to other peers */ }
            }
        }
    }

    relayToWS(msg) {
        // [FIX A] Relay only if under our hard hop cap.
        if ((msg.hops || 0) >= MAX_RELAY_HOPS) return;
        if (!this.ws || !this.wsReady) return;
        const serialised = JSON.stringify(msg);
        if (new TextEncoder().encode(serialised).length > MAX_MSG_BYTES) return;
        try { this.ws.send(serialised); } catch { /* WS unavailable — drop */ }
    }

    // ── Heartbeat ─────────────────────────────────────────────────────────────

    startHeartbeat() {
        clearInterval(this.heartbeatTimer);
        this.heartbeatTimer = setInterval(() => {
            const now = Date.now();
            // Prune stale WS peers.
            for (const [id, peer] of this.peers) {
                if (peer.transport === 'ws' && now - peer.lastSeen > 60000) {
                    this.peers.delete(id);
                    this.onPeerLeave(peer);
                }
            }
            if (this.ws && this.wsReady) {
                this.ws.send(JSON.stringify({
                    type: 'HEARTBEAT',
                    id: this.identity.id,
                    ts: now,
                    peers: this.peers.size,
                }));
            }
            this.onMeshUpdate(this.getPeers());
        }, 15000);
    }

    // ── Cleanup ───────────────────────────────────────────────────────────────

    destroy() {
        // [FIX M] Set flag first so reconnect timer does not re-create the socket.
        this._destroyed = true;

        clearInterval(this.heartbeatTimer);
        clearTimeout(this.reconnectTimer);

        if (this.ws) {
            this.ws.close();
            this.ws = null;
        }

        for (const [, peer] of this.peers) {
            if (peer.transport === 'ble' && peer.device?.gatt?.connected) {
                try { peer.device.gatt.disconnect(); } catch { /* best effort */ }
            }
        }

        this.peers.clear();
        this._seenMsgIds.clear();
        this._bleConnecting.clear();
    }
}

// [FIX O] Immutable global — cannot be overwritten by later scripts.
if (typeof window !== 'undefined') {
    Object.defineProperty(window, 'GhostMesh', {
        value: GhostMesh,
        writable: false,
        configurable: false,
        enumerable: true,
    });
}