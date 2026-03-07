/**
 * GhostNet BLE Transport Layer — SECURITY HARDENED
 * Browser (WebBluetooth) + Node.js (@abandonware/noble)
 *
 * Vulnerabilities found and fixed:
 *
 * [A] CRITICAL — identity.privateKey stored on transport layer object.
 *     The constructor accepted { nodeId, publicKey, privateKey } and stored
 *     the entire object as this.identity. The private key has no business in
 *     a transport layer — it is only needed for signing/decryption at the
 *     crypto layer. Any code with a reference to the GhostBLE instance could
 *     read the private key directly.
 *     Fixed: constructor accepts only { nodeId, publicKey }. If a full
 *     identity object is passed, privateKey is explicitly stripped before
 *     storage.
 *
 * [B] HIGH — No input validation or sanitization on received BLE data.
 *     peerId and peerKey are read directly from BLE characteristics and
 *     used as Map keys, passed to callbacks, and stored in state without
 *     any validation. A malicious peer could set peerId to "__proto__",
 *     "constructor", or an arbitrarily long string.
 *     Fixed: _sanitizePeerId() validates length, character set (printable
 *     ASCII, no control chars), and rejects prototype-pollution keys.
 *     Received message bodies are also length-capped before parsing.
 *
 * [C] HIGH — JSON.parse() called without try/catch in browser notification
 *     handler. A malformed or malicious BLE notification causes an unhandled
 *     exception that terminates the notification listener silently, dropping
 *     all subsequent messages from that peer.
 *     Fixed: wrapped in try/catch; parse errors are logged and discarded.
 *
 * [D] HIGH — localName.includes("GhostNode") used as peer authenticity check.
 *     Any Bluetooth device can advertise the name "GhostNode" and will be
 *     treated as a legitimate peer, connected to, and have data read from
 *     and written to it. This is trivially spoofed.
 *     Fixed: primary filter is SERVICE_UUID match. Name-based fallback is
 *     removed. Peers that advertise the service UUID but fail subsequent
 *     characteristic validation are disconnected immediately.
 *
 * [E] HIGH — Node.js send() is silently unimplemented.
 *     The Node branch of send() contained only a comment. Callers received
 *     no error and had no way to know the message was never sent.
 *     Fixed: implemented using noble's characteristic.write(). Throws a
 *     clear error if called before the write characteristic is ready.
 *
 * [F] MEDIUM — No message or payload size validation.
 *     Received BLE notifications and outbound payloads had no size checks.
 *     BLE ATT MTU is 20–512 bytes; writing oversized payloads causes silent
 *     failure or errors. Oversized inbound data could cause excessive memory
 *     allocation during JSON.parse().
 *     Fixed: MAX_BLE_PAYLOAD (512 bytes) enforced on both send and receive.
 *
 * [G] MEDIUM — alert() used for error reporting, exposing internal details.
 *     alert("BLE Error: " + e.message) surfaces raw JS exception messages
 *     to the user. Error messages can contain internal paths, object
 *     structures, or other details useful to an attacker.
 *     Fixed: alert() replaced with _showError() which emits a fixed,
 *     user-friendly string. Internal error detail goes to console only,
 *     and only in non-production contexts.
 *
 * [H] MEDIUM — Default onMessage handler logs raw message content.
 *     The default console.log('BLE Recv:', msg, from) prints the full
 *     decrypted message payload to the console. In production this would
 *     expose message content in DevTools, system logs, and crash reports.
 *     Fixed: default handler logs only metadata (sender ID, payload type).
 *     The host application must register its own onMessage to process content.
 *
 * [I] MEDIUM — Empty catch block silently swallows JSON parse errors (Node).
 *     } catch (e) { } in the Node data handler meant parse failures were
 *     completely invisible, making it impossible to detect malformed or
 *     malicious payloads.
 *     Fixed: catch block logs a warning with the sender ID and byte length.
 *
 * [J] MEDIUM — No disconnect handler in Node mode; stale peers accumulate.
 *     The browser path had onDisconnected() wired to the GATT event, but
 *     noble peripheral disconnects were never handled. Peers remained in
 *     the Map indefinitely after disconnection, causing send() calls to
 *     attempt writes to closed connections.
 *     Fixed: peripheral.once('disconnect') registered for every Node peer,
 *     removing the peer from the Map on disconnect.
 *
 * [K] LOW — window.GhostBLE global assignment is overridable.
 *     Setting window.GhostBLE = GhostBLE allows any script loaded after
 *     this module to overwrite the reference. Code that does
 *     new window.GhostBLE() after a hostile script runs gets the hostile
 *     version.
 *     Fixed: use Object.defineProperty with writable:false and
 *     configurable:false so the global cannot be overwritten.
 */

'use strict';

let noble = null;

if (typeof process !== 'undefined' && process.versions?.node) {
    try {
        const _imported = await import('@abandonware/noble');
        noble = _imported.default || _imported;
    } catch {
        console.warn('GhostBLE: @abandonware/noble not available. BLE backend disabled.');
    }
}

const SERVICE_UUID = '67686f73-746e-6574-2d6d-657368000000';
const CHAR_PEER_ID = '67686f73-746e-6574-2d69-640000000000';
const CHAR_PUB_KEY = '67686f73-746e-6574-2d6b-657900000000';
const CHAR_DATA = '67686f73-746e-6574-2d64-617461000000';

// [FIX F] Hard ceiling on BLE payload size (bytes).
const MAX_BLE_PAYLOAD = 512;
// [FIX B] Peer ID constraints.
const MAX_PEER_ID_LENGTH = 64;
// Printable ASCII only, no control characters, no JS prototype keys.
const PEER_ID_PATTERN = /^[\x20-\x7E]{1,64}$/;
const PROTOTYPE_KEYS = new Set(['__proto__', 'constructor', 'prototype']);

// ─── Internal helpers ─────────────────────────────────────────────────────

const _isDev = typeof process !== 'undefined'
    ? process.env.NODE_ENV !== 'production'
    : (typeof window !== 'undefined' && (window.location.hostname === 'localhost' || window.location.hostname === '127.0.0.1'));

// [FIX G] Never expose raw JS error messages to the user.
function _showError(userMessage, internalError) {
    // Safe, fixed string shown in UI.
    if (typeof window !== 'undefined') {
        const banner = document.createElement('div');
        banner.style.cssText = 'position:fixed;bottom:20px;left:50%;transform:translateX(-50%);' +
            'background:#7c2d12;color:#fef2f2;padding:12px 20px;border-radius:8px;' +
            'font-size:0.85rem;z-index:9999;max-width:90vw;text-align:center;';
        banner.textContent = userMessage;
        const close = document.createElement('button');
        close.textContent = '×';
        close.style.cssText = 'margin-left:12px;background:none;border:none;color:inherit;cursor:pointer;';
        close.onclick = () => banner.remove();
        banner.appendChild(close);
        document.body?.appendChild(banner);
        setTimeout(() => banner.isConnected && banner.remove(), 6000);
    }
    // Internal detail only in dev.
    if (_isDev && internalError) console.error('[GhostBLE internal]', internalError);
}

// [FIX B] Validate and sanitize an incoming peer ID string.
function _sanitizePeerId(raw) {
    if (typeof raw !== 'string') return null;
    const trimmed = raw.trim().slice(0, MAX_PEER_ID_LENGTH);
    if (!PEER_ID_PATTERN.test(trimmed)) return null;
    if (PROTOTYPE_KEYS.has(trimmed)) return null;
    return trimmed;
}

// ─────────────────────────────────────────────────────────────────────────────

export default class GhostBLE {
    constructor(identity) {
        // [FIX A] Store only non-secret identity fields. Strip privateKey
        //         even if a full identity object is accidentally passed in.
        const { nodeId, publicKey } = identity || {};
        this.identity = { nodeId, publicKey };

        this.peers = new Map();
        this.isScanning = false;

        this.mode = (typeof navigator !== 'undefined' && navigator.bluetooth)
            ? 'browser'
            : (noble ? 'node' : 'none');

        // [FIX H] Default handler logs only metadata, never message content.
        this.onMessage = (msg, fromId) => {
            if (_isDev) console.log(`[GhostBLE] Message from ${fromId}, type=${msg?.type}`);
        };
        this.onPeer = (peer) => {
            if (_isDev) console.log(`[GhostBLE] Peer connected: ${peer.id}`);
        };
        this.onPeerLeave = (peerId) => {
            if (_isDev) console.log(`[GhostBLE] Peer disconnected: ${peerId}`);
        };

        if (this.mode === 'node') this.noble = noble;
    }

    async init() {
        if (this.mode === 'browser') {
            if (!navigator.bluetooth) {
                if (!window.isSecureContext) {
                    // [FIX G] Fixed user message — no internal detail exposed.
                    _showError('⚠ Bluetooth requires a secure connection (HTTPS or localhost).');
                } else {
                    _showError('⚠ WebBluetooth is not supported or is disabled in this browser.');
                }
                return false;
            }
            if (_isDev) console.log('GhostBLE: Browser mode initialised.');
            return true;
        }

        if (this.mode === 'node') {
            if (!this.noble) return false;
            this._setupNodeBLE();
            if (_isDev) console.log('GhostBLE: Node mode initialised.');
            return true;
        }

        return false;
    }

    // ── BROWSER ──────────────────────────────────────────────────────────────

    async scanBrowser() {
        if (this.mode !== 'browser') return;
        try {
            const device = await navigator.bluetooth.requestDevice({
                // [FIX D] Filter by service UUID — do not accept all devices.
                filters: [{ services: [SERVICE_UUID] }],
                optionalServices: [SERVICE_UUID],
            });
            await this._connectDeviceBrowser(device);
        } catch (e) {
            if (e.name === 'NotFoundError' || e.name === 'AbortError') {
                // User cancelled — not an error.
                if (_isDev) console.log('GhostBLE: Scan cancelled by user.');
            } else if (e.name === 'SecurityError') {
                // [FIX G] Generic message, no raw e.message.
                _showError('⚠ Bluetooth scan must be triggered by a user interaction.');
            } else {
                _showError('⚠ Bluetooth scan failed. Please try again.', e);
            }
        }
    }

    async _connectDeviceBrowser(device) {
        device.addEventListener('gattserverdisconnected', this._onBrowserDisconnected.bind(this));

        let server;
        try {
            server = await device.gatt.connect();
        } catch (e) {
            _showError('⚠ Could not connect to the Bluetooth device.', e);
            return;
        }

        let service;
        try {
            service = await server.getPrimaryService(SERVICE_UUID);
        } catch (e) {
            _showError('⚠ Connected device is not running GhostNet.', e);
            device.gatt.disconnect();
            return;
        }

        let charId, charKey, charData;
        try {
            charId = await service.getCharacteristic(CHAR_PEER_ID);
            charKey = await service.getCharacteristic(CHAR_PUB_KEY);
            charData = await service.getCharacteristic(CHAR_DATA);
        } catch (e) {
            _showError('⚠ GhostNet service on device is incomplete.', e);
            device.gatt.disconnect();
            return;
        }

        // Read and validate peer identity.
        const peerIdRaw = new TextDecoder().decode(await charId.readValue());
        // [FIX B] Sanitize before use.
        const peerId = _sanitizePeerId(peerIdRaw);
        if (!peerId) {
            console.warn('GhostBLE: Rejected peer — invalid ID format.');
            device.gatt.disconnect();
            return;
        }

        const peerKeyVal = await charKey.readValue();
        const peerKey = this._bufToHex(peerKeyVal);

        const peer = {
            id: peerId,
            key: peerKey,
            device,
            server,
            transport: 'ble',
            writeChar: charData,
        };

        this.peers.set(peerId, peer);
        this.onPeer(peer);

        await charData.startNotifications();
        charData.addEventListener('characteristicvaluechanged', (event) => {
            // [FIX F] Size check before processing.
            const buf = event.target.value;
            if (buf.byteLength > MAX_BLE_PAYLOAD) {
                console.warn(`GhostBLE: Oversized notification from ${peerId} (${buf.byteLength} bytes), ignored.`);
                return;
            }

            const raw = new TextDecoder().decode(buf);

            // [FIX C] try/catch around JSON.parse — never throws into the event listener.
            let parsed;
            try {
                parsed = JSON.parse(raw);
            } catch {
                console.warn(`GhostBLE: Malformed JSON from ${peerId}, discarded.`);
                return;
            }

            this.onMessage(parsed, peerId);
        });

        if (_isDev) console.log(`GhostBLE: Browser peer connected: ${peerId}`);
    }

    _onBrowserDisconnected(event) {
        const device = event.target;
        // [FIX J] Remove peer from map on disconnect.
        for (const [id, peer] of this.peers) {
            if (peer.device === device) {
                this.peers.delete(id);
                this.onPeerLeave(id);
                break;
            }
        }
    }

    // ── NODE ──────────────────────────────────────────────────────────────────

    _setupNodeBLE() {
        this.noble.on('stateChange', (state) => {
            if (state === 'poweredOn') {
                // [FIX D] Scan for our specific service UUID only, not all devices.
                this.noble.startScanning([SERVICE_UUID], true);
            } else {
                this.noble.stopScanning();
            }
        });

        this.noble.on('discover', async (peripheral) => {
            const adv = peripheral.advertisement;
            const serviceUuids = adv.serviceUuids || [];

            // [FIX D] UUID match only — no name-based fallback.
            if (!serviceUuids.includes(SERVICE_UUID)) return;

            // De-duplicate.
            const peripheralId = peripheral.id;
            if (this.peers.has(peripheralId)) return;

            // Placeholder entry to prevent concurrent connections to same peripheral.
            this.peers.set(peripheralId, null);

            peripheral.connect((err) => {
                if (err) {
                    console.error(`GhostBLE: Connection error (${peripheralId}):`, err.message);
                    this.peers.delete(peripheralId);
                    return;
                }

                peripheral.discoverServices([SERVICE_UUID], (err, services) => {
                    if (err || !services?.length) {
                        console.warn(`GhostBLE: Service discovery failed (${peripheralId}).`);
                        peripheral.disconnect();
                        this.peers.delete(peripheralId);
                        return;
                    }

                    const svc = services[0];
                    svc.discoverCharacteristics([], (err, chars) => {
                        if (err) {
                            peripheral.disconnect();
                            this.peers.delete(peripheralId);
                            return;
                        }

                        const strip = uuid => uuid.replace(/-/g, '');
                        let charData, charId, charKey;
                        for (const c of chars) {
                            if (c.uuid === strip(CHAR_DATA)) charData = c;
                            if (c.uuid === strip(CHAR_PEER_ID)) charId = c;
                            if (c.uuid === strip(CHAR_PUB_KEY)) charKey = c;
                        }

                        if (!charData || !charId || !charKey) {
                            console.warn(`GhostBLE: Incomplete characteristics (${peripheralId}).`);
                            peripheral.disconnect();
                            this.peers.delete(peripheralId);
                            return;
                        }

                        charId.read((err, data) => {
                            if (err || !data) {
                                peripheral.disconnect();
                                this.peers.delete(peripheralId);
                                return;
                            }

                            const rawId = data.toString('utf-8');
                            // [FIX B] Validate peer ID before storing.
                            const peerId = _sanitizePeerId(rawId);
                            if (!peerId) {
                                console.warn(`GhostBLE: Invalid peer ID format from ${peripheralId}, rejected.`);
                                peripheral.disconnect();
                                this.peers.delete(peripheralId);
                                return;
                            }

                            const peer = {
                                id: peerId,
                                peripheral,
                                writeChar: charData,
                                transport: 'ble',
                            };

                            // Replace placeholder with real entry.
                            this.peers.delete(peripheralId);
                            this.peers.set(peerId, peer);

                            // [FIX J] Handle disconnect in Node mode.
                            peripheral.once('disconnect', () => {
                                this.peers.delete(peerId);
                                this.onPeerLeave(peerId);
                            });

                            this.onPeer(peer);

                            charData.subscribe((err) => {
                                if (err) {
                                    console.error(`GhostBLE: Subscribe failed for ${peerId}:`, err.message);
                                    // Peer is connected but notifications unavailable — keep in map
                                    // but log clearly so the operator can see.
                                }
                            });

                            charData.on('data', (data) => {
                                // [FIX F] Size check.
                                if (!data || data.length > MAX_BLE_PAYLOAD) {
                                    console.warn(`GhostBLE: Oversized data from ${peerId} (${data?.length} bytes), ignored.`);
                                    return;
                                }

                                const raw = data.toString('utf-8');
                                // [FIX I] Named catch — no silent swallow.
                                let parsed;
                                try {
                                    parsed = JSON.parse(raw);
                                } catch {
                                    console.warn(`GhostBLE: Malformed JSON from ${peerId} (${data.length} bytes), discarded.`);
                                    return;
                                }

                                this.onMessage(parsed, peerId);
                            });

                            if (_isDev) console.log(`GhostBLE: Node peer connected: ${peerId}`);
                        });
                    });
                });
            });
        });
    }

    // ── SHARED ────────────────────────────────────────────────────────────────

    async send(peerId, payload) {
        const peer = this.peers.get(peerId);
        if (!peer) throw new Error(`GhostBLE: Peer not connected: ${peerId}`);
        if (!peer.writeChar) throw new Error(`GhostBLE: Write characteristic not ready for: ${peerId}`);

        const dataStr = JSON.stringify(payload);
        const dataBytes = new TextEncoder().encode(dataStr);

        // [FIX F] Enforce outbound size limit.
        if (dataBytes.length > MAX_BLE_PAYLOAD) {
            throw new Error(`GhostBLE: Payload too large (${dataBytes.length} bytes, max ${MAX_BLE_PAYLOAD}).`);
        }

        if (this.mode === 'browser') {
            await peer.writeChar.writeValue(dataBytes);
        } else {
            // [FIX E] Implemented — was silently empty before.
            await new Promise((resolve, reject) => {
                // withoutResponse=false: use Write With Response for reliability.
                peer.writeChar.write(Buffer.from(dataBytes), false, (err) => {
                    if (err) reject(new Error(`GhostBLE: Write failed for ${peerId}: ${err.message}`));
                    else resolve();
                });
            });
        }
    }

    _bufToHex(buffer) {
        return Array.from(new Uint8Array(buffer.buffer || buffer))
            .map(b => b.toString(16).padStart(2, '0'))
            .join('');
    }
}

// [FIX K] Use defineProperty so the global cannot be overwritten by later scripts.
if (typeof window !== 'undefined') {
    Object.defineProperty(window, 'GhostBLE', {
        value: GhostBLE,
        writable: false,
        configurable: false,
        enumerable: true,
    });
}