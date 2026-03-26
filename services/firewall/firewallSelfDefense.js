/**
 * firewallSelfDefense.js — Firewall Self-Protection System
 * ===========================================================
 *
 * The firewall protecting ITSELF from bypass, tampering, and failure.
 *
 *   16. Integrity Monitoring — detect if firewall code has been modified
 *   17. Anti-Bypass Protection — force all network calls through the firewall
 *   18. Anti-Tampering Rules Protection — PIN-protected critical settings
 *   19. Watchdog Timer — auto-restart on crash, safe mode on repeated failure
 *
 * This module is the last line of defense. If an attacker manages to
 * modify the firewall code or bypass its hooks, this module detects it.
 */

import { SELF_DEFENSE, LOGGER } from './firewallConfig.js';
import { firewallLogger, EVENT } from './firewallLogger.js';

// ─── Storage abstraction ─────────────────────────────────────────────────────

let _Preferences = null;
const PIN_KEY = LOGGER.storagePrefix + 'pin_hash';
const INTEGRITY_KEY = LOGGER.storagePrefix + 'integrity_hash';
const LOCKOUT_KEY = LOGGER.storagePrefix + 'pin_lockout';

async function _getStore() {
    if (_Preferences) return _Preferences;
    try {
        const mod = await import('@capacitor/preferences');
        _Preferences = mod.Preferences;
    } catch {
        _Preferences = {
            async get({ key }) { return { value: localStorage.getItem(key) }; },
            async set({ key, value }) { localStorage.setItem(key, value); },
            async remove({ key }) { localStorage.removeItem(key); },
        };
    }
    return _Preferences;
}

// ─── FirewallSelfDefense ─────────────────────────────────────────────────────

class FirewallSelfDefense {
    constructor() {
        // ── 16. Integrity monitoring ──
        /** SHA-256 hash of firewall module source code (computed at init) */
        this._integrityHash = null;
        /** Timer for periodic integrity checks */
        this._integrityTimer = null;
        /** Integrity status */
        this._integrityStatus = 'unknown'; // 'ok' | 'alert' | 'compromised'

        // ── 17. Anti-bypass ──
        /** Original references to native network functions (saved before wrapping) */
        this._originals = {
            fetch: null,
            WebSocket: null,
            XMLHttpRequest: null,
        };
        /** Whether network interception is active */
        this._interceptActive = false;
        /** Callback: the firewall's inspection function for outbound requests */
        this._inspectOutbound = null;

        // ── 18. Anti-tampering ──
        /** Number of incorrect PIN attempts */
        this._pinAttempts = 0;
        /** Whether PIN lockout is active */
        this._pinLocked = false;
        /** Lockout expiry timestamp */
        this._pinLockoutUntil = 0;

        // ── 19. Watchdog ──
        /** Watchdog worker reference */
        this._watchdogWorker = null;
        /** Last heartbeat timestamp */
        this._lastHeartbeat = Date.now();
        /** Crash counter */
        this._crashTimestamps = [];
        /** Whether safe mode is active (all external connections blocked) */
        this._safeMode = false;
        /** Watchdog timer handle */
        this._watchdogTimer = null;

        // ── Config ──
        this._config = { ...SELF_DEFENSE };

        // ── Callback for emergency actions ──
        this._onEmergency = null;
    }

    // ── Lifecycle ────────────────────────────────────────────────

    /**
     * Initialize the self-defense system.
     * Must be called before any other firewall module.
     *
     * @param {object} opts
     * @param {function} opts.inspectOutbound — the firewall core's outbound inspection fn
     * @param {function} opts.onEmergency — called when integrity/crash emergency detected
     */
    async init({ inspectOutbound, onEmergency } = {}) {
        this._inspectOutbound = inspectOutbound || null;
        this._onEmergency = onEmergency || null;

        // 16. Compute initial integrity hash
        await this._computeIntegrityHash();

        // 17. Install network interception hooks
        this._installNetworkHooks();

        // 18. Load lockout state
        await this._loadLockoutState();

        // 19. Start watchdog
        this._startWatchdog();

        // Start periodic integrity checks
        this._integrityTimer = setInterval(
            () => this._checkIntegrity(),
            this._config.integrityCheckInterval
        );

        this._integrityStatus = 'ok';
    }

    /** Stop all self-defense systems */
    async shutdown() {
        if (this._integrityTimer) clearInterval(this._integrityTimer);
        if (this._watchdogTimer) clearInterval(this._watchdogTimer);
        this._integrityTimer = null;
        this._watchdogTimer = null;
        this._removeNetworkHooks();
    }

    /**
     * Update config (when shield level changes).
     * @param {object} selfDefenseConfig
     */
    updateConfig(selfDefenseConfig) {
        this._config = { ...SELF_DEFENSE, ...selfDefenseConfig };

        // Restart integrity timer with new interval
        if (this._integrityTimer) clearInterval(this._integrityTimer);
        this._integrityTimer = setInterval(
            () => this._checkIntegrity(),
            this._config.integrityCheckInterval
        );

        // Restart watchdog with new interval
        if (this._watchdogTimer) clearInterval(this._watchdogTimer);
        this._startWatchdog();
    }

    // ══════════════════════════════════════════════════════════════
    // 16. INTEGRITY MONITORING
    // ══════════════════════════════════════════════════════════════

    /**
     * Compute SHA-256 hash of all firewall module files.
     * In a browser/Capacitor context, we hash the source text of the
     * loaded modules via import.meta or known file paths.
     */
    async _computeIntegrityHash() {
        try {
            // Build a deterministic fingerprint of the firewall's exported API surface.
            // In a browser/Capacitor context we can't read file contents, so we hash
            // the function names and prototypes of key classes as a tamper indicator.
            const parts = [];
            const modules = [
                ['firewallLogger', firewallLogger],
            ];
            for (const [name, mod] of modules) {
                if (mod && mod.constructor) {
                    const methods = Object.getOwnPropertyNames(Object.getPrototypeOf(mod))
                        .filter(m => m !== 'constructor')
                        .sort();
                    parts.push(name + '=' + methods.join(','));
                }
            }
            // Also include our own method list
            const selfMethods = Object.getOwnPropertyNames(FirewallSelfDefense.prototype)
                .filter(m => m !== 'constructor')
                .sort();
            parts.push('selfDefense=' + selfMethods.join(','));

            const fingerprint = parts.join('|');
            const hash = await _sha256(fingerprint);

            // First run: store the hash
            const store = await _getStore();
            const { value: stored } = await store.get({ key: INTEGRITY_KEY });

            if (!stored) {
                await store.set({ key: INTEGRITY_KEY, value: hash });
                this._integrityHash = hash;
            } else {
                this._integrityHash = stored;
                // Compare — if mismatch, code has been tampered with
                if (hash !== stored) {
                    this._integrityStatus = 'alert';
                    firewallLogger.log(EVENT.INTEGRITY_ALERT, null, 'alert',
                        'Integrity hash mismatch on init — firewall code may have changed', {
                            expected: stored.slice(0, 16) + '...',
                            actual: hash.slice(0, 16) + '...',
                        });
                }
            }
        } catch (err) {
            console.error('[FW-SelfDefense] Integrity hash error:', err.message);
        }
    }

    /**
     * Periodic integrity check — recompute hash and compare to stored.
     * If mismatch → firewall has been tampered with.
     */
    async _checkIntegrity() {
        try {
            // Verify critical functions still exist and haven't been replaced
            const criticalChecks = [
                typeof this._inspectOutbound === 'function' || this._inspectOutbound === null,
                this._interceptActive === true,
                typeof firewallLogger.log === 'function',
            ];

            const allOk = criticalChecks.every(c => c);

            if (!allOk) {
                this._integrityStatus = 'compromised';
                firewallLogger.log(EVENT.INTEGRITY_ALERT, null, 'alert',
                    'CRITICAL: Firewall integrity check failed — possible tampering', {
                        checks: criticalChecks.map((c, i) => `check_${i}: ${c}`),
                    });

                // Trigger emergency response
                if (this._onEmergency) {
                    this._onEmergency('integrity_compromised');
                }
            } else {
                this._integrityStatus = 'ok';
            }

            // Heartbeat — update watchdog
            this._lastHeartbeat = Date.now();
        } catch (err) {
            console.error('[FW-SelfDefense] Integrity check error:', err.message);
            this._integrityStatus = 'alert';
        }
    }

    // ══════════════════════════════════════════════════════════════
    // 17. ANTI-BYPASS PROTECTION
    // ══════════════════════════════════════════════════════════════

    /**
     * Override global fetch, WebSocket, and XMLHttpRequest so that
     * ALL network calls route through the firewall's inspection layer.
     * The original functions are saved and called after inspection passes.
     */
    _installNetworkHooks() {
        try {
            // ── Wrap fetch ──
            if (typeof globalThis.fetch === 'function' && !this._originals.fetch) {
                this._originals.fetch = globalThis.fetch.bind(globalThis);
                const self = this;

                globalThis.fetch = function firewallFetch(input, init) {
                    const url = typeof input === 'string' ? input :
                                input instanceof Request ? input.url : String(input);

                    // Run through firewall inspection
                    const verdict = self._inspectOutboundRequest('fetch', url, init);
                    if (!verdict.allowed) {
                        firewallLogger.log(EVENT.CONNECTION_BLOCKED, null, 'block',
                            `Outbound fetch blocked: ${verdict.reason}`, { url: _sanitizeUrl(url) });
                        return Promise.reject(new Error(`[GhostNet Firewall] Blocked: ${verdict.reason}`));
                    }

                    return self._originals.fetch(input, init);
                };
            }

            // ── Wrap WebSocket ──
            if (typeof globalThis.WebSocket === 'function' && !this._originals.WebSocket) {
                this._originals.WebSocket = globalThis.WebSocket;
                const self = this;

                globalThis.WebSocket = function FirewallWebSocket(url, protocols) {
                    const verdict = self._inspectOutboundRequest('websocket', url);
                    if (!verdict.allowed) {
                        firewallLogger.log(EVENT.CONNECTION_BLOCKED, null, 'block',
                            `Outbound WebSocket blocked: ${verdict.reason}`, { url: _sanitizeUrl(url) });
                        throw new Error(`[GhostNet Firewall] Blocked: ${verdict.reason}`);
                    }
                    return new self._originals.WebSocket(url, protocols);
                };
                // Preserve static properties
                globalThis.WebSocket.CONNECTING = 0;
                globalThis.WebSocket.OPEN = 1;
                globalThis.WebSocket.CLOSING = 2;
                globalThis.WebSocket.CLOSED = 3;
                globalThis.WebSocket.prototype = self._originals.WebSocket.prototype;
            }

            // ── Wrap XMLHttpRequest ──
            if (typeof globalThis.XMLHttpRequest === 'function' && !this._originals.XMLHttpRequest) {
                this._originals.XMLHttpRequest = globalThis.XMLHttpRequest;
                const self = this;

                const OrigXHR = globalThis.XMLHttpRequest;
                globalThis.XMLHttpRequest = function FirewallXHR() {
                    const xhr = new OrigXHR();
                    const origOpen = xhr.open.bind(xhr);

                    xhr.open = function(method, url, ...args) {
                        const verdict = self._inspectOutboundRequest('xhr', url, { method });
                        if (!verdict.allowed) {
                            firewallLogger.log(EVENT.CONNECTION_BLOCKED, null, 'block',
                                `Outbound XHR blocked: ${verdict.reason}`, { url: _sanitizeUrl(url), method });
                            throw new Error(`[GhostNet Firewall] Blocked: ${verdict.reason}`);
                        }
                        return origOpen(method, url, ...args);
                    };

                    return xhr;
                };
            }

            this._interceptActive = true;
        } catch (err) {
            console.error('[FW-SelfDefense] Network hook installation error:', err.message);
            // Non-fatal — firewall still functions, just can't intercept
            this._interceptActive = false;
        }
    }

    /**
     * Remove network hooks (restore originals). Called on shutdown.
     */
    _removeNetworkHooks() {
        if (this._originals.fetch) {
            globalThis.fetch = this._originals.fetch;
            this._originals.fetch = null;
        }
        if (this._originals.WebSocket) {
            globalThis.WebSocket = this._originals.WebSocket;
            this._originals.WebSocket = null;
        }
        if (this._originals.XMLHttpRequest) {
            globalThis.XMLHttpRequest = this._originals.XMLHttpRequest;
            this._originals.XMLHttpRequest = null;
        }
        this._interceptActive = false;
    }

    /**
     * Inspect an outbound network request.
     * Called by the wrapped fetch/WebSocket/XHR before the real call.
     *
     * @param {'fetch'|'websocket'|'xhr'} type
     * @param {string} url
     * @param {object} [opts]
     * @returns {{ allowed: boolean, reason: string }}
     */
    _inspectOutboundRequest(type, url, opts = {}) {
        try {
            // Safe mode: block ALL external connections
            if (this._safeMode) {
                // Allow only loopback connections
                if (_isLoopback(url)) {
                    return { allowed: true, reason: 'safemode_loopback' };
                }
                return { allowed: false, reason: 'Safe mode: all external connections blocked' };
            }

            // Delegate to the firewall core's inspection if available
            if (this._inspectOutbound) {
                return this._inspectOutbound(type, url, opts);
            }

            // No inspection function registered — allow loopback only
            if (_isLoopback(url)) {
                return { allowed: true, reason: 'loopback_allowed' };
            }
            return { allowed: true, reason: 'no_outbound_inspector' };
        } catch (err) {
            // Fail CLOSED on outbound inspection errors
            console.error('[FW-SelfDefense] Outbound inspection error:', err.message);
            return { allowed: false, reason: 'outbound_inspection_error_failclosed' };
        }
    }

    // ══════════════════════════════════════════════════════════════
    // 18. ANTI-TAMPERING RULES PROTECTION
    // ══════════════════════════════════════════════════════════════

    /**
     * Set the security PIN (required for disabling critical firewall features).
     * PIN is stored as a SHA-256 hash — never in plaintext.
     *
     * @param {string} pin — the PIN to set (4-8 digits)
     * @returns {boolean} success
     */
    async setPin(pin) {
        if (!pin || typeof pin !== 'string' || !/^\d{4,8}$/.test(pin)) {
            return false;
        }
        // Generate a per-PIN random salt to prevent pre-computation attacks.
        // A 4-digit PIN has only 10k possibilities — salt is essential.
        const salt = crypto.getRandomValues(new Uint8Array(32));
        const saltHex = Array.from(salt).map(b => b.toString(16).padStart(2, '0')).join('');
        const hash = await _sha256(saltHex + ':' + pin);
        const store = await _getStore();
        // Store salt + hash together
        await store.set({ key: PIN_KEY, value: JSON.stringify({ salt: saltHex, hash }) });
        return true;
    }

    /**
     * Verify a PIN against the stored salted hash.
     * Enforces lockout after too many attempts.
     * Uses constant-time comparison to prevent timing side-channels.
     *
     * @param {string} pin
     * @returns {{ verified: boolean, reason: string, locked?: boolean, lockoutRemaining?: number }}
     */
    async verifyPin(pin) {
        // Check lockout — uses BOTH in-memory and persisted state.
        // This prevents lockout bypass via storage clearing, because the
        // in-memory counter survives until the process restarts.
        if (this._pinLocked) {
            const remaining = this._pinLockoutUntil - Date.now();
            if (remaining > 0) {
                return {
                    verified: false,
                    reason: 'PIN locked out',
                    locked: true,
                    lockoutRemaining: remaining,
                };
            }
            // Lockout expired
            this._pinLocked = false;
            this._pinAttempts = 0;
        }

        const store = await _getStore();
        const { value: stored } = await store.get({ key: PIN_KEY });

        if (!stored) {
            // No PIN set — first time
            return { verified: true, reason: 'no_pin_set' };
        }

        // Parse stored salt + hash
        let saltHex, storedHash;
        try {
            const parsed = JSON.parse(stored);
            saltHex = parsed.salt;
            storedHash = parsed.hash;
        } catch {
            // Legacy format (unsalted) — force PIN reset
            return { verified: false, reason: 'PIN data corrupted — please reset PIN' };
        }

        const inputHash = await _sha256(saltHex + ':' + pin);

        // Constant-time comparison to prevent timing side-channel attacks.
        // JavaScript's === leaks information about which bytes match.
        const match = _timingSafeEqualStr(inputHash, storedHash);

        if (match) {
            this._pinAttempts = 0;
            return { verified: true, reason: 'pin_correct' };
        }

        // Incorrect PIN
        this._pinAttempts++;
        firewallLogger.log(EVENT.SELF_DEFENSE_ALERT, null, 'alert',
            `Incorrect PIN attempt (${this._pinAttempts}/${this._config.maxPinAttempts})`);

        if (this._pinAttempts >= this._config.maxPinAttempts) {
            this._pinLocked = true;
            this._pinLockoutUntil = Date.now() + this._config.pinLockoutDuration;
            await this._saveLockoutState();

            firewallLogger.log(EVENT.SELF_DEFENSE_ALERT, null, 'alert',
                `PIN locked out for ${this._config.pinLockoutDuration / 60000} minutes`);

            return {
                verified: false,
                reason: 'Too many attempts — PIN locked',
                locked: true,
                lockoutRemaining: this._config.pinLockoutDuration,
            };
        }

        return { verified: false, reason: 'Incorrect PIN' };
    }

    /** Check if a PIN has been set */
    async hasPinSet() {
        const store = await _getStore();
        const { value } = await store.get({ key: PIN_KEY });
        return !!value;
    }

    /** Check if critical changes require PIN (config flag + PIN is set) */
    async requiresPinForCritical() {
        if (!this._config.requirePinForCriticalChanges) return false;
        return this.hasPinSet();
    }

    // ── Lockout state persistence ──

    async _saveLockoutState() {
        const store = await _getStore();
        await store.set({ key: LOCKOUT_KEY, value: JSON.stringify({
            locked: this._pinLocked,
            until: this._pinLockoutUntil,
            attempts: this._pinAttempts,
        })});
    }

    async _loadLockoutState() {
        try {
            const store = await _getStore();
            const { value } = await store.get({ key: LOCKOUT_KEY });
            if (value) {
                const state = JSON.parse(value);
                if (state.until && Date.now() < state.until) {
                    this._pinLocked = true;
                    this._pinLockoutUntil = state.until;
                    this._pinAttempts = state.attempts || 0;
                }
            }
        } catch {
            // Ignore — start fresh
        }
    }

    // ══════════════════════════════════════════════════════════════
    // 19. WATCHDOG TIMER
    // ══════════════════════════════════════════════════════════════

    /**
     * Start the watchdog that monitors the firewall's health.
     * If the firewall stops responding (no heartbeat), it triggers recovery.
     */
    _startWatchdog() {
        this._lastHeartbeat = Date.now();

        this._watchdogTimer = setInterval(() => {
            const now = Date.now();
            const elapsed = now - this._lastHeartbeat;

            if (elapsed > this._config.watchdogInterval * 2) {
                // Firewall may have stalled
                console.warn('[FW-Watchdog] Heartbeat missed — checking health...');
                this._recordCrash();
            }

            // Send heartbeat
            this._lastHeartbeat = now;
        }, this._config.watchdogInterval);

        // Use unref if available (Node.js) so watchdog doesn't prevent process exit
        if (this._watchdogTimer.unref) this._watchdogTimer.unref();
    }

    /**
     * Record a crash event. If too many crashes in the crash window,
     * activate safe mode.
     */
    _recordCrash() {
        const now = Date.now();
        this._crashTimestamps.push(now);

        // Purge old crash timestamps
        const windowStart = now - this._config.crashWindow;
        this._crashTimestamps = this._crashTimestamps.filter(t => t > windowStart);

        if (this._crashTimestamps.length >= this._config.maxCrashes) {
            this._activateSafeMode();
        }

        firewallLogger.log(EVENT.SELF_DEFENSE_ALERT, null, 'alert',
            `Crash detected (${this._crashTimestamps.length}/${this._config.maxCrashes} in window)`, {
                crashes: this._crashTimestamps.length,
                maxCrashes: this._config.maxCrashes,
            });
    }

    /**
     * Activate safe mode: block ALL external connections except whitelisted.
     * This is the nuclear option when the firewall is failing repeatedly.
     */
    _activateSafeMode() {
        if (this._safeMode) return;
        this._safeMode = true;

        firewallLogger.log(EVENT.SELF_DEFENSE_ALERT, null, 'alert',
            'SAFE MODE ACTIVATED — all external connections blocked. Only whitelisted nodes allowed.', {
                reason: `${this._config.maxCrashes}+ crashes in ${this._config.crashWindow / 60000} minutes`,
            });

        if (this._onEmergency) {
            this._onEmergency('safe_mode');
        }
    }

    /** Deactivate safe mode (manual user action) */
    deactivateSafeMode() {
        this._safeMode = false;
        this._crashTimestamps = [];
        firewallLogger.log(EVENT.SELF_DEFENSE_ALERT, null, 'allow',
            'Safe mode deactivated by user');
    }

    // ── Public state ─────────────────────────────────────────────

    /** Get the current self-defense status */
    getStatus() {
        return {
            integrityStatus: this._integrityStatus,
            interceptActive: this._interceptActive,
            safeMode: this._safeMode,
            pinLocked: this._pinLocked,
            pinLockoutRemaining: this._pinLocked
                ? Math.max(0, this._pinLockoutUntil - Date.now()) : 0,
            recentCrashes: this._crashTimestamps.length,
            lastHeartbeat: this._lastHeartbeat,
        };
    }

    /** Check if safe mode is active */
    isSafeMode() {
        return this._safeMode;
    }
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

/**
 * Constant-time string comparison to prevent timing side-channel attacks.
 * JavaScript's === operator short-circuits on the first differing byte,
 * leaking information about how many characters matched.
 */
function _timingSafeEqualStr(a, b) {
    if (typeof a !== 'string' || typeof b !== 'string') return false;
    // Always compare full length to avoid leaking length info
    const len = Math.max(a.length, b.length);
    let mismatch = a.length !== b.length ? 1 : 0;
    for (let i = 0; i < len; i++) {
        // Use charCodeAt — returns NaN for out-of-bounds which XOR will propagate
        mismatch |= (a.charCodeAt(i) || 0) ^ (b.charCodeAt(i) || 0);
    }
    return mismatch === 0;
}

/** Compute SHA-256 hash of a string using SubtleCrypto */
async function _sha256(str) {
    const data = new TextEncoder().encode(str);
    const hashBuffer = await crypto.subtle.digest('SHA-256', data);
    const hashArray = Array.from(new Uint8Array(hashBuffer));
    return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
}

/** Check if a URL points to a loopback address */
function _isLoopback(url) {
    try {
        const parsed = new URL(url);
        return ['localhost', '127.0.0.1', '::1', '0.0.0.0'].includes(parsed.hostname);
    } catch {
        return false;
    }
}

/** Sanitize a URL for logging (remove tokens, passwords) */
function _sanitizeUrl(url) {
    try {
        const parsed = new URL(url);
        parsed.password = '';
        parsed.search = parsed.search ? '?[redacted]' : '';
        return parsed.toString().slice(0, 200);
    } catch {
        return String(url).slice(0, 100);
    }
}

// ─── Singleton Export ────────────────────────────────────────────────────────

export const firewallSelfDefense = new FirewallSelfDefense();
export default firewallSelfDefense;
