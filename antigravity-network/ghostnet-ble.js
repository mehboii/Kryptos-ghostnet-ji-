/**
 * GhostNet BLE Transport Layer
 * Browser (WebBluetooth) + Node.js (@abandonware/noble)
 *
 * REFACTORED TO ES MODULE (ESM)
 */

let noble = null;

// Dynamically import noble if in Node.js environment
if (typeof process !== 'undefined' && process.versions && process.versions.node) {
    try {
        // We use dynamic import to avoid breaking when bundled for browser
        // Assuming environment supports top-level await or we handle init async
        // BUT strict ESM requires top-level imports. 
        // If we are mostly CJS/ESM hybrid, we can use createRequire or dynamic import.

        // Simulating the user's request for "import noble from ..." but making it safe
        const _imported = await import('@abandonware/noble');
        noble = _imported.default || _imported;
    } catch (e) {
        console.warn("GhostBLE: @abandonware/noble not found or import failed. BLE backend disabled.");
    }
}

const SERVICE_UUID = "67686f73-746e-6574-2d6d-657368000000"; // "ghostnet-mesh" padded
const CHAR_PEER_ID = "67686f73-746e-6574-2d69-640000000000"; // "ghostnet-id"
const CHAR_PUB_KEY = "67686f73-746e-6574-2d6b-657900000000"; // "ghostnet-key"
const CHAR_DATA = "67686f73-746e-6574-2d64-617461000000"; // "ghostnet-data"

const MAX_BLE_PAYLOAD = 4096;

export default class GhostBLE {
    constructor(identity) {
        this.identity = identity; // { nodeId, publicKey, privateKey }
        this.peers = new Map(); // peerId -> { device, gatt, characteristics }

        // Auto-detect environment
        this.mode = (typeof navigator !== 'undefined' && navigator.bluetooth) ? 'browser' :
            (noble ? 'node' : 'none');

        this.isScanning = false;

        // Event Handlers
        this.onMessage = (msg, from) => {};
        this.onPeer = (peer) => {};

        if (this.mode === 'node') {
            this.noble = noble;
        }
    }

    _validateBleMessage(raw) {
        if (typeof raw !== 'string' || raw.length > MAX_BLE_PAYLOAD) return null;
        try {
            const msg = JSON.parse(raw);
            if (!msg || typeof msg !== 'object') return null;
            if (typeof msg.type !== 'string') return null;
            return msg;
        } catch {
            return null;
        }
    }

    async _verifyPeerIdentity(peerId, peerKeyHex) {
        if (!peerId || typeof peerId !== 'string' || peerId.length > 128) return false;
        if (!peerKeyHex || typeof peerKeyHex !== 'string' || peerKeyHex.length < 16) return false;
        if (!/^[0-9a-f]+$/i.test(peerKeyHex)) return false;
        try {
            const keyBytes = new Uint8Array(peerKeyHex.match(/.{1,2}/g).map(b => parseInt(b, 16)));
            const hashBuf = await crypto.subtle.digest('SHA-256', keyBytes);
            const expectedId = '0x' + Array.from(new Uint8Array(hashBuf))
                .map(b => b.toString(16).padStart(2, '0')).join('').substring(0, 40);
            if (peerId.startsWith('0x') && peerId !== expectedId) return false;
        } catch {
            return false;
        }
        return true;
    }

    async init() {
        if (this.mode === 'browser') {
            if (!navigator.bluetooth) {
                const isSecure = window.isSecureContext;
                if (!isSecure) {
                    console.error("WebBluetooth Failed: Not a Secure Context (HTTPS required).");
                    alert("⚠️ Bluetooth Error: Devices cannot be searched because the connection is not secure.\n\nPlease use localhost or HTTPS.\n(IP addresses like 192.168.x.x block Bluetooth for security)");
                } else {
                    console.error("WebBluetooth not supported or disabled in this browser.");
                    alert("⚠️ Bluetooth Error: WebBluetooth is not supported or disabled in this browser.");
                }
                return false;
            }
            console.log("GhostBLE: Browser Mode Initialized");
            return true;
        } else if (this.mode === 'node') {
            if (!this.noble) return false;
            this.setupNodeBLE();
            console.log("GhostBLE: Node Mode Initialized");
            return true;
        }
        return false;
    }

    // --- BROWSER IMPLEMENTATION ---

    async scanBrowser() {
        if (this.mode !== 'browser') return;
        try {
            console.log("GhostBLE: Requesting Device (All Devices)...");
            // User requested broad access. We use acceptAllDevices but must specify optionalServices to access them later.
            const device = await navigator.bluetooth.requestDevice({
                acceptAllDevices: true,
                optionalServices: [SERVICE_UUID]
            });

            await this.connectDeviceBrowser(device);
        } catch (e) {
            console.error("BLE Browser Scan Error:", e);
            if (e.message.includes("No Services found") || e.name === 'NotFoundError') {
                // User cancelled or no device found
                console.log("User cancelled scan or no device selected.");
            } else if (e.name === 'SecurityError') {
                alert("⚠️ Security Error: Interaction needs to be triggered by a user gesture (click).");
            } else {
                alert("BLE Error: " + e.message);
            }
        }
    }

    async connectDeviceBrowser(device) {
        device.addEventListener('gattserverdisconnected', this.onDisconnected.bind(this));
        console.log("Connecting to GATT Server...");
        const server = await device.gatt.connect();
        console.log("Getting Service...");

        // Try-catch for service discovery failure
        let service;
        try {
            service = await server.getPrimaryService(SERVICE_UUID);
        } catch (err) {
            console.error("Service not found:", err);
            alert("⚠️ Device Connected but 'GhostNet' service not found.\nEnsure the other device is running the GhostNet app.");
            device.gatt.disconnect();
            return;
        }

        console.log("Getting Characteristics...");
        const charId = await service.getCharacteristic(CHAR_PEER_ID);
        const charKey = await service.getCharacteristic(CHAR_PUB_KEY);
        const charData = await service.getCharacteristic(CHAR_DATA);

        // Read Peer Info
        const peerIdVal = await charId.readValue();
        const peerId = new TextDecoder().decode(peerIdVal);

        const peerKeyVal = await charKey.readValue();
        const peerKey = this._bufToHex(peerKeyVal);

        if (!await this._verifyPeerIdentity(peerId, peerKey)) {
            console.warn(`GhostBLE: Peer identity verification failed — disconnecting`);
            device.gatt.disconnect();
            return;
        }

        const peer = {
            id: peerId,
            key: peerKey,
            device: device,
            server: server,
            transport: 'ble',
            writeChar: charData,
            verified: false
        };

        this.peers.set(peerId, peer);
        this.onPeer(peer);

        // Setup Listeners
        await charData.startNotifications();
        charData.addEventListener('characteristicvaluechanged', (event) => {
            const val = new TextDecoder().decode(event.target.value);
            const msg = this._validateBleMessage(val);
            if (msg) this.onMessage(msg, peerId);
        });
    }

    // --- NODE IMPLEMENTATION ---

    setupNodeBLE() {
        this.noble.on('stateChange', (state) => {
            if (state === 'poweredOn') {
                console.log("GhostBLE: Bluetooth Powered On. Scanning for ALL devices...");
                // Scanning for [] ensures we see devices even if they don't advertise the UUID in the initial packet
                this.noble.startScanning([], true);
            } else {
                this.noble.stopScanning();
            }
        });

        this.noble.on('discover', async (peripheral) => {
            const adv = peripheral.advertisement;
            const localName = adv.localName || "";
            const serviceUuids = adv.serviceUuids || [];

            // Debug log to see what we are finding (comment out if too noisy)
            // console.log(`[BLE Scan] Saw: ${localName} [${serviceUuids.join(', ')}] RSSI: ${peripheral.rssi}`);

            // Check if it matches our App
            // Match by UUID OR by Name convention (fallback)
            const isMatch = serviceUuids.includes(SERVICE_UUID) || localName.includes("GhostNode");

            if (!isMatch) return;

            const peerId = localName || peripheral.id;
            // De-duplicate
            if (this.peers.has(peerId)) return;

            console.log(`GhostBLE: Discovered Target ${peerId}`);

            peripheral.connect(err => {
                if (err) {
                    console.error(`Connection error to ${peerId}:`, err);
                    return;
                }
                console.log(`Connected to ${peerId}. Discovering Services...`);

                peripheral.discoverServices([SERVICE_UUID], (err, services) => {
                    if (err || !services || services.length === 0) {
                        console.warn(`Service discovery failed for ${peerId}`);
                        peripheral.disconnect();
                        return;
                    }

                    const service = services[0];
                    service.discoverCharacteristics([], (err, chars) => {
                        if (err) return;

                        // Map characteristics
                        let charData, charId, charKey;
                        chars.forEach(c => {
                            if (c.uuid === CHAR_DATA.replace(/-/g, '')) charData = c;
                            if (c.uuid === CHAR_PEER_ID.replace(/-/g, '')) charId = c;
                            if (c.uuid === CHAR_PUB_KEY.replace(/-/g, '')) charKey = c;
                        });

                        if (charData && charId && charKey) {
                            charId.read((err, data) => {
                                if (err) return;
                                const idStr = data.toString('utf-8');

                                charKey.read(async (err, keyData) => {
                                    const keyHex = keyData ? this._bufToHex(keyData) : '';
                                    if (!await this._verifyPeerIdentity(idStr, keyHex)) {
                                        console.warn(`GhostBLE: Peer identity verification failed`);
                                        peripheral.disconnect();
                                        return;
                                    }

                                    this.peers.set(idStr, {
                                        id: idStr,
                                        key: keyHex,
                                        peripheral: peripheral,
                                        writeChar: charData,
                                        transport: 'ble',
                                        verified: false
                                    });

                                    charData.subscribe(err => {
                                        if (err) console.error("Subscribe error:", err);
                                    });
                                    charData.on('data', (data, isNotification) => {
                                        const raw = data.toString('utf-8');
                                        const msg = this._validateBleMessage(raw);
                                        if (msg) this.onMessage(msg, idStr);
                                    });
                                })
                            });
                        } else {
                            console.warn(`Missing characteristics on ${peerId}`);
                            peripheral.disconnect();
                        }
                    });
                });
            });
        });
    }

    // --- SHARED ---

    async send(peerId, payload) {
        const peer = this.peers.get(peerId);
        if (!peer) throw new Error("Peer not connected");

        const dataStr = JSON.stringify(payload);
        if (dataStr.length > MAX_BLE_PAYLOAD) throw new Error("Payload too large for BLE");
        const dataBytes = new TextEncoder().encode(dataStr);

        if (this.mode === 'browser') {
            // WebBluetooth writes are limited in size (MTU). 
            // Simple implementation assumes small packets or handled by browser.
            await peer.writeChar.writeValue(dataBytes);
        } else {
            // Node
            // Noble write logic would go here
        }
    }

    onDisconnected(event) {
        const device = event.target;
        console.log(`Device ${device.name} disconnected`);
        // Remove from peers...
        this.peers.forEach((v, k) => {
            if (v.device === device) this.peers.delete(k);
        });
    }

    _bufToHex(buffer) {
        return Array.from(new Uint8Array(buffer.buffer || buffer))
            .map(b => b.toString(16).padStart(2, '0'))
            .join('');
    }
}

// Expose to window for browser (legacy/HTML import support)
if (typeof window !== 'undefined') {
    window.GhostBLE = GhostBLE;
}
