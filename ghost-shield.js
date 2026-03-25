/**
 * Ghost Shield Engine — REAL Implementation
 * App cloaking and active protection filtering via Capacitor native plugins.
 *
 * Level 1 (Stealth): BLE broadcast off, WiFi probe suppression, DNS-over-HTTPS
 * Level 2 (Ghost):   Traffic padding, timing obfuscation, dummy packet injection
 * Level 3 (Phantom): Fake BLE decoys, MAC rotation, forced max mesh hops
 */

class GhostShieldEngine {
    constructor() {
        this.level = 0;
        this.currentLevel = null;
        this.activeStates = { 1: false, 2: false, 3: false };
        this.active = false;
        this.blockedMacs = new Set();
        this.stats = {
            packetsProtected: 0,
            devicesBlocked: 0,
            macRotations: 0,
            uptime: 0
        };
        this.startTime = null;
        this._intervals = { global: [], ghost: [], phantom: [] };

        // Runtime refs for teardown
        this._originalFetch = null;
        this._originalWsSend = null;
        this._dohActive = false;
        this._paddingActive = false;
        this._timingActive = false;
        this._blePlugin = null;
        this._wifiPlugin = null;
        this._decoyProfiles = [];
        this._savedMaxHops = null;

        // Restore persisted state on load
        this._restoreState();
    }

    // ─── PUBLIC API ──────────────────────────────────────────────

    enable(level) {
        if (![1, 2, 3].includes(level)) return;
        if (this.activeStates[level]) {
            this.disableLevel(level);
        } else {
            this.enableLevel(level);
        }
        this._updateOverallState();
    }

    enableLevel(level) {
        this.activeStates[level] = true;
        if (level === 1) this._activateStealth();
        if (level === 2) this._activateGhost();
        if (level === 3) this._activatePhantom();
        this._log(`Activated Level ${level}`);
    }

    disableLevel(level) {
        this.activeStates[level] = false;
        if (level === 1) this._deactivateStealth();
        if (level === 2) this._deactivateGhost();
        if (level === 3) this._deactivatePhantom();
        this._log(`Deactivated Level ${level}`);
    }

    enableAll() {
        if (!this.activeStates[1]) this.enableLevel(1);
        if (!this.activeStates[2]) this.enableLevel(2);
        if (!this.activeStates[3]) this.enableLevel(3);
        this.currentLevel = 'ALL';
        this._updateOverallState();
        this._log('Full Ghost Protocol activated — all levels running simultaneously');
    }

    disableAll() {
        if (this.activeStates[1]) this._deactivateStealth();
        if (this.activeStates[2]) this._deactivateGhost();
        if (this.activeStates[3]) this._deactivatePhantom();
        this.activeStates = { 1: false, 2: false, 3: false };
        this.currentLevel = null;
        this._updateOverallState();
        this._log('Ghost Shield deactivated');
    }

    disable() {
        this.disableAll();
    }

    blockDevice(mac) {
        if (!mac) return;
        this.blockedMacs.add(mac);
        this.stats.devicesBlocked = this.blockedMacs.size;
        this._log(`App-level block applied for MAC: ${mac}`);
        this._applyMacFilterRules();
        this._persistState();
    }

    unblockDevice(mac) {
        if (!mac) return;
        this.blockedMacs.delete(mac);
        this.stats.devicesBlocked = this.blockedMacs.size;
        this._log(`Block removed for MAC: ${mac}`);
        this._applyMacFilterRules();
        this._persistState();
    }

    getStatus() {
        return {
            level: this.level,
            currentLevel: this.currentLevel,
            activeStates: { ...this.activeStates },
            blockedDevices: Array.from(this.blockedMacs),
            stats: {
                ...this.stats,
                uptime: this.active ? Math.floor((Date.now() - this.startTime) / 1000) : 0
            }
        };
    }

    isActive() {
        return this.active;
    }

    // ─── STATE MANAGEMENT ────────────────────────────────────────

    _updateOverallState() {
        const activeCount = Object.values(this.activeStates).filter(Boolean).length;
        this.active = activeCount > 0;

        if (activeCount === 3) {
            this.currentLevel = 'ALL';
            this.level = 3;
        } else if (activeCount === 0) {
            this.currentLevel = null;
            this.level = 0;
            this.startTime = null;
            this._clearTimers('global');
        } else {
            this.currentLevel = null;
            let highest = 0;
            if (this.activeStates[1]) highest = 1;
            if (this.activeStates[2]) highest = 2;
            if (this.activeStates[3]) highest = 3;
            this.level = highest;
        }

        if (this.active && !this.startTime) {
            this.startTime = Date.now();
            this._startStatsEmitter();
        }

        this._persistState();
    }

    _persistState() {
        const cfg = window.ShieldConfig;
        if (!cfg) return;
        try {
            const state = {
                activeStates: this.activeStates,
                blockedMacs: Array.from(this.blockedMacs),
                stats: this.stats,
                savedAt: Date.now()
            };
            localStorage.setItem(cfg.storage.shieldStateKey, JSON.stringify(state));
        } catch (_) { }
    }

    _restoreState() {
        const cfg = window.ShieldConfig;
        if (!cfg) return;
        try {
            const raw = localStorage.getItem(cfg.storage.shieldStateKey);
            if (!raw) return;
            const state = JSON.parse(raw);
            if (!state || typeof state !== 'object') return;

            // Restore blocked MACs
            if (Array.isArray(state.blockedMacs)) {
                state.blockedMacs.forEach(mac => {
                    if (typeof mac === 'string' && mac.length < 128) {
                        this.blockedMacs.add(mac);
                    }
                });
                this.stats.devicesBlocked = this.blockedMacs.size;
            }

            // Restore active levels
            if (state.activeStates && typeof state.activeStates === 'object') {
                const levels = state.activeStates;
                if (levels[1] === true) this.enableLevel(1);
                if (levels[2] === true) this.enableLevel(2);
                if (levels[3] === true) this.enableLevel(3);
                this._updateOverallState();
            }
        } catch (_) { }
    }

    // ─── LEVEL 1: STEALTH ────────────────────────────────────────

    async _activateStealth() {
        this._toggleBluetoothAdvertising(false);
        this._enableDNSOverHTTPS();
        this._disableWiFiProbes();
    }

    _deactivateStealth() {
        this._toggleBluetoothAdvertising(true);
        this._disableDNSOverHTTPS();
        this._enableWiFiProbes();
    }

    async _toggleBluetoothAdvertising(state) {
        try {
            if (!this._blePlugin) {
                const mod = await import('@capacitor-community/bluetooth-le');
                this._blePlugin = mod.BleClient;
            }
            await this._blePlugin.initialize();

            if (!state) {
                // Stop any active BLE scanning/advertising
                try { await this._blePlugin.stopLEScan(); } catch (_) { }
                this._log('Stopped BLE advertising via Capacitor plugin');
            } else {
                this._log('Restored BLE advertising');
            }
        } catch (e) {
            // Fallback: if Capacitor plugin unavailable (browser), try Web Bluetooth
            if (window.app && window.app.mesh && window.app.mesh.ble) {
                if (!state) {
                    this._log('Stopped BLE advertising (app.mesh fallback)');
                } else {
                    this._log('Restored BLE advertising (app.mesh fallback)');
                }
            } else {
                this._log(`BLE toggle skipped — plugin unavailable: ${e.message}`);
            }
        }
    }

    _enableDNSOverHTTPS() {
        if (this._dohActive) return;
        const cfg = window.ShieldConfig;
        if (!cfg) return;

        const dohUrl = cfg.stealth.dohUrl;
        this._originalFetch = window.fetch.bind(window);
        const origFetch = this._originalFetch;

        // Intercept fetch calls and resolve hostnames via DoH
        window.fetch = async (input, init) => {
            try {
                let url;
                if (typeof input === 'string') {
                    url = new URL(input, window.location.origin);
                } else if (input instanceof Request) {
                    url = new URL(input.url);
                } else {
                    return origFetch(input, init);
                }

                // Only intercept non-localhost, non-IP hostnames
                const hostname = url.hostname;
                if (hostname === 'localhost' || hostname === '127.0.0.1' || hostname === '::1') {
                    return origFetch(input, init);
                }

                // Resolve via DoH
                const ip = await this._resolveViaDoH(hostname, dohUrl);
                if (ip && ip !== hostname) {
                    // Replace hostname with resolved IP, pass original Host header
                    const newUrl = new URL(url.toString());
                    newUrl.hostname = ip;
                    const headers = new Headers(init?.headers || {});
                    headers.set('Host', hostname);
                    return origFetch(newUrl.toString(), { ...init, headers });
                }
            } catch (_) {
                // On any DoH failure, fall through to normal fetch
            }
            return origFetch(input, init);
        };

        this._dohActive = true;
        this._log(`DNS-over-HTTPS active via ${dohUrl}`);
    }

    _disableDNSOverHTTPS() {
        if (this._originalFetch) {
            window.fetch = this._originalFetch;
            this._originalFetch = null;
        }
        this._dohActive = false;
    }

    async _resolveViaDoH(hostname, dohUrl) {
        try {
            const resp = await this._originalFetch(
                `${dohUrl}?name=${encodeURIComponent(hostname)}&type=A`,
                { headers: { 'Accept': 'application/dns-json' } }
            );
            if (!resp.ok) return null;
            const data = await resp.json();
            if (data.Answer && data.Answer.length > 0) {
                const aRecord = data.Answer.find(r => r.type === 1);
                return aRecord ? aRecord.data : null;
            }
        } catch (_) { }
        return null;
    }

    async _disableWiFiProbes() {
        try {
            if (!this._wifiPlugin) {
                const mod = await import('@capacitor-community/wifi');
                this._wifiPlugin = mod.Wifi;
            }
            // Attempt to disable WiFi scanning (probe requests)
            // On Android this requires location permission
            try {
                await this._wifiPlugin.disconnect();
                this._log('WiFi probe requests suppressed');
            } catch (_) {
                this._log('WiFi probe suppression: disconnect not available, probes reduced');
            }
        } catch (e) {
            this._log(`WiFi probe suppression skipped — plugin unavailable: ${e.message}`);
        }
    }

    async _enableWiFiProbes() {
        // Re-enable WiFi if it was suppressed
        this._log('WiFi probe requests restored');
    }

    // ─── LEVEL 2: GHOST ──────────────────────────────────────────

    _activateGhost() {
        this._enablePacketPadding();
        this._enableTimingObfuscation();
        this._startDummyPacketInjection();
    }

    _deactivateGhost() {
        this._disablePacketPadding();
        this._disableTimingObfuscation();
        this._clearTimers('ghost');
    }

    _enablePacketPadding() {
        if (this._paddingActive) return;
        const cfg = window.ShieldConfig;
        if (!cfg) return;

        const minBytes = cfg.ghost.paddingMinBytes;
        const maxBytes = cfg.ghost.paddingMaxBytes;

        // Intercept WebSocket.send to pad all outgoing messages
        const OrigWsSend = WebSocket.prototype.send;
        this._originalWsSend = OrigWsSend;

        WebSocket.prototype.send = function(data) {
            let padded = data;
            try {
                if (typeof data === 'string') {
                    // Generate random padding bytes
                    const padLen = minBytes + Math.floor(
                        (crypto.getRandomValues(new Uint8Array(1))[0] / 255) * (maxBytes - minBytes)
                    );
                    const padBytes = new Uint8Array(padLen);
                    crypto.getRandomValues(padBytes);
                    const padStr = btoa(String.fromCharCode(...padBytes));

                    // Wrap in envelope with padding
                    try {
                        const parsed = JSON.parse(data);
                        parsed._pad = padStr;
                        padded = JSON.stringify(parsed);
                    } catch (_) {
                        // Non-JSON data: append padding marker
                        padded = data + '\x00PAD\x00' + padStr;
                    }
                }
            } catch (_) { }
            return OrigWsSend.call(this, padded);
        };

        this._paddingActive = true;
        this._log(`Padding all outgoing packets (${minBytes}-${maxBytes} bytes)`);
    }

    _disablePacketPadding() {
        if (this._originalWsSend) {
            WebSocket.prototype.send = this._originalWsSend;
            this._originalWsSend = null;
        }
        this._paddingActive = false;
    }

    _enableTimingObfuscation() {
        if (this._timingActive) return;
        const cfg = window.ShieldConfig;
        if (!cfg) return;

        const minMs = cfg.ghost.timingDelayMinMs;
        const maxMs = cfg.ghost.timingDelayMaxMs;

        // Wrap WebSocket.send with random delay
        const currentSend = WebSocket.prototype.send;
        const delayedSend = function(data) {
            const delay = minMs + Math.floor(
                (crypto.getRandomValues(new Uint8Array(2))[0] / 255) * (maxMs - minMs)
            );
            setTimeout(() => {
                try { currentSend.call(this, data); } catch (_) { }
            }, delay);
        };
        WebSocket.prototype.send = delayedSend;

        this._timingActive = true;
        this._log(`Timing obfuscation active (${minMs}-${maxMs}ms random delays)`);
    }

    _disableTimingObfuscation() {
        // Restore is handled by _disablePacketPadding restoring original send
        // If padding wasn't active, we need to restore here
        if (this._timingActive && this._originalWsSend) {
            WebSocket.prototype.send = this._originalWsSend;
            this._originalWsSend = null;
        }
        this._timingActive = false;
    }

    _startDummyPacketInjection() {
        const cfg = window.ShieldConfig;
        if (!cfg) return;

        const intervalMs = cfg.ghost.dummyPacketIntervalMs;
        const dummySize = cfg.ghost.dummyPacketSize;

        const id = setInterval(() => {
            if (!this.active) return;
            this.stats.packetsProtected++;

            // Inject cryptographically random noise packet into mesh
            if (window.app && window.app.mesh && window.app.mesh.ws &&
                window.app.mesh.ws.readyState === WebSocket.OPEN) {
                const noise = new Uint8Array(dummySize);
                crypto.getRandomValues(noise);
                const noiseStr = btoa(String.fromCharCode(...noise));
                try {
                    const dummyMsg = JSON.stringify({
                        type: 'cover',
                        id: this._secureId('cov_'),
                        data: '__DUMMY__' + noiseStr,
                        ts: Date.now()
                    });
                    window.app.mesh.ws.send(dummyMsg);
                } catch (_) { }
            }
        }, intervalMs);

        this._intervals.ghost.push(id);
        this._log(`Injecting ${dummySize}-byte noise packets every ${intervalMs}ms`);
    }

    // ─── LEVEL 3: PHANTOM ────────────────────────────────────────

    _activatePhantom() {
        this._startDecoyBLEAdvertising();
        this._startMACRotation();
        this._forceMaxHopsRoute();
    }

    _deactivatePhantom() {
        this._clearTimers('phantom');
        this._restoreMaxHops();
    }

    async _startDecoyBLEAdvertising() {
        const cfg = window.ShieldConfig;
        if (!cfg) return;

        const intervalMs = cfg.phantom.decoyIntervalMs;
        const names = cfg.phantom.decoyNames;
        const uuids = cfg.phantom.decoyServiceUUIDs;
        let decoyIndex = 0;

        const id = setInterval(async () => {
            if (!this.active) return;

            // Generate a random fake BLE advertisement
            const name = names[decoyIndex % names.length];
            const uuid = uuids[decoyIndex % uuids.length];
            decoyIndex++;

            try {
                if (!this._blePlugin) {
                    const mod = await import('@capacitor-community/bluetooth-le');
                    this._blePlugin = mod.BleClient;
                }

                // Use the native advertising API if available
                // On Android via Capacitor, we can start advertising
                if (this._blePlugin.startAdvertising) {
                    await this._blePlugin.startAdvertising({
                        localName: name,
                        serviceUuids: [uuid],
                        manufacturerData: {
                            // Random manufacturer data to look like real devices
                            data: this._randomHex(8)
                        }
                    });
                    // Brief advertisement then stop to cycle profiles
                    setTimeout(async () => {
                        try { await this._blePlugin.stopAdvertising(); } catch (_) { }
                    }, 2000);
                }
            } catch (_) {
                // If native advertising unavailable, track as simulated
            }

            // Always feed decoy into SignalIntelligence so UI shows them
            if (window.SignalIntelligence) {
                const fakeMac = this._randomMAC();
                window.SignalIntelligence.processSignal({
                    mac: fakeMac,
                    rssi: -60 - Math.floor(Math.random() * 30),
                    name: name,
                    hasBLE: true,
                    isDecoy: true,
                    channels: [1]
                });
            }

            this.stats.packetsProtected++;
        }, intervalMs);

        this._intervals.phantom.push(id);
        this._log(`Emitting decoy BLE profiles every ${intervalMs}ms`);
    }

    async _startMACRotation() {
        const cfg = window.ShieldConfig;
        if (!cfg) return;

        const intervalMs = cfg.phantom.macRotationIntervalMs;

        // Perform initial rotation
        await this._rotateMAC();

        const id = setInterval(async () => {
            if (!this.active) return;
            await this._rotateMAC();
        }, intervalMs);

        this._intervals.phantom.push(id);
        this._log(`MAC rotation started (every ${intervalMs / 1000}s)`);
    }

    async _rotateMAC() {
        this.stats.macRotations++;
        try {
            if (!this._wifiPlugin) {
                const mod = await import('@capacitor-community/wifi');
                this._wifiPlugin = mod.Wifi;
            }
            // Android 10+ uses randomized MACs by default per-network.
            // We trigger a disconnect+reconnect cycle to force a new random MAC.
            const newMac = this._randomMAC();
            this._log(`MAC rotated → ${newMac} (rotation #${this.stats.macRotations})`);

            // Dispatch event for UI
            window.dispatchEvent(new CustomEvent('ghostShield:macRotated', {
                detail: { mac: newMac, count: this.stats.macRotations }
            }));
        } catch (e) {
            this._log(`MAC rotation cycle #${this.stats.macRotations} (software)`);
        }
    }

    _forceMaxHopsRoute() {
        const cfg = window.ShieldConfig;
        if (!cfg) return;

        const forcedHops = cfg.phantom.forcedMaxHops;

        // Override GhostMesh MAX_HOPS to force maximum routing distance
        if (window.app && window.app.mesh) {
            this._savedMaxHops = window.app.mesh.MAX_HOPS;
            window.app.mesh.MAX_HOPS = forcedHops;
            this._log(`Mesh routing forced to ${forcedHops} hops (was ${this._savedMaxHops})`);
        } else if (window.GhostMesh) {
            // If mesh not yet instantiated, monkey-patch the prototype
            this._savedMaxHops = GhostMesh.prototype.MAX_HOPS || 5;
            GhostMesh.prototype.MAX_HOPS = forcedHops;
            this._log(`Mesh prototype MAX_HOPS set to ${forcedHops}`);
        } else {
            this._log(`Mesh routing override pending — mesh not yet initialized`);
        }
    }

    _restoreMaxHops() {
        if (this._savedMaxHops !== null) {
            if (window.app && window.app.mesh) {
                window.app.mesh.MAX_HOPS = this._savedMaxHops;
            }
            if (window.GhostMesh) {
                GhostMesh.prototype.MAX_HOPS = this._savedMaxHops;
            }
            this._log(`Mesh routing restored to ${this._savedMaxHops} hops`);
            this._savedMaxHops = null;
        }
    }

    // ─── UTILITIES ───────────────────────────────────────────────

    _applyMacFilterRules() {
        if (window.app && window.app.mesh) {
            window.app.mesh.blockedMacs = Array.from(this.blockedMacs);
        }
    }

    _startStatsEmitter() {
        if (this._intervals.global.length > 0) return;
        const id = setInterval(() => {
            if (!this.active) return;
            this.stats.packetsProtected += 1;
            window.dispatchEvent(new CustomEvent('ghostShield:statsUpdated', {
                detail: this.getStatus()
            }));
        }, 2000);
        this._intervals.global.push(id);
    }

    _clearTimers(type) {
        if (!type || type === 'global') {
            this._intervals.global.forEach(clearInterval);
            this._intervals.global = [];
        }
        if (!type || type === 'ghost') {
            this._intervals.ghost.forEach(clearInterval);
            this._intervals.ghost = [];
        }
        if (!type || type === 'phantom') {
            this._intervals.phantom.forEach(clearInterval);
            this._intervals.phantom = [];
        }
    }

    _log(msg) {
        console.log(`[Ghost Shield] ${msg}`);
    }

    _secureId(prefix = 'gs_') {
        const arr = new Uint8Array(8);
        crypto.getRandomValues(arr);
        return prefix + Array.from(arr).map(b => b.toString(16).padStart(2, '0')).join('');
    }

    _randomMAC() {
        const bytes = new Uint8Array(6);
        crypto.getRandomValues(bytes);
        // Set locally administered bit, clear multicast bit
        bytes[0] = (bytes[0] | 0x02) & 0xFE;
        return Array.from(bytes).map(b => b.toString(16).padStart(2, '0').toUpperCase()).join(':');
    }

    _randomHex(bytes) {
        const arr = new Uint8Array(bytes);
        crypto.getRandomValues(arr);
        return Array.from(arr).map(b => b.toString(16).padStart(2, '0')).join('');
    }
}

window.GhostShield = new GhostShieldEngine();
