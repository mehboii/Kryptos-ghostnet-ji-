/**
 * quarantine.js — Node Isolation System
 * =======================================
 *
 * Quarantined nodes are completely isolated — zero traffic in or out.
 * Quarantine can be triggered automatically (behavior detection, hostile
 * reputation) or manually by the user.
 *
 * Auto-quarantine escalation:
 *   1st offense → 1 hour
 *   2nd offense → 24 hours
 *   3rd offense → permanent (until manual release)
 *
 * Data persists across sessions in Capacitor Preferences / localStorage.
 */

import { QUARANTINE, LOGGER } from './firewallConfig.js';
import { firewallLogger, EVENT } from './firewallLogger.js';

const STORAGE_KEY = LOGGER.storagePrefix + 'quarantine';

// ─── Storage abstraction ─────────────────────────────────────────────────────

let _Preferences = null;

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

// ─── QuarantineManager ───────────────────────────────────────────────────────

class QuarantineManager {
    constructor() {
        /**
         * Map: nodeId → {
         *   reason: 'auto'|'manual',
         *   quarantinedAt: number,
         *   expiresAt: number|null,   (null = permanent)
         *   offenseCount: number,
         *   details: string
         * }
         * @type {Map<string, object>}
         */
        this._quarantined = new Map();
        /** Timer for periodic expiry checks */
        this._expiryTimer = null;
        this._dirty = false;
    }

    // ── Lifecycle ────────────────────────────────────────────────

    /** Load persisted quarantine list from storage */
    async init() {
        try {
            const store = await _getStore();
            const { value } = await store.get({ key: STORAGE_KEY });
            if (value) {
                const parsed = JSON.parse(value);
                for (const [id, data] of Object.entries(parsed)) {
                    this._quarantined.set(id, data);
                }
            }
        } catch (err) {
            console.warn('[FW-Quarantine] Failed to load:', err.message);
        }

        // Check for expired quarantines every 30 seconds
        this._expiryTimer = setInterval(() => this._checkExpired(), 30000);
        // Immediately check on init
        this._checkExpired();
    }

    /** Stop the expiry checker and flush */
    async shutdown() {
        if (this._expiryTimer) clearInterval(this._expiryTimer);
        this._expiryTimer = null;
        await this._persist();
    }

    // ── Public API ───────────────────────────────────────────────

    /**
     * Check if a node is currently quarantined.
     * Also handles auto-expiration of timed quarantines.
     *
     * @param {string} nodeId
     * @returns {boolean}
     */
    isQuarantined(nodeId) {
        const record = this._quarantined.get(nodeId);
        if (!record) return false;

        // Check if timed quarantine has expired
        if (record.expiresAt && Date.now() >= record.expiresAt) {
            this._quarantined.delete(nodeId);
            this._dirty = true;
            firewallLogger.log(EVENT.QUARANTINE_RELEASED, nodeId, 'allow',
                'Auto-quarantine expired', { offenseCount: record.offenseCount });
            this._persist();
            return false;
        }
        return true;
    }

    /**
     * Quarantine a node automatically (triggered by firewall detection).
     * Duration escalates with each offense.
     *
     * @param {string} nodeId
     * @param {string} reason — why this quarantine was triggered
     * @returns {{ quarantined: boolean, duration: number|null, offenseCount: number }}
     */
    autoQuarantine(nodeId, reason) {
        // Get prior offense count
        const prior = this._quarantined.get(nodeId);
        const offenseCount = prior ? (prior.offenseCount || 0) + 1 : 1;

        let duration;
        if (offenseCount >= QUARANTINE.maxAutoQuarantines) {
            duration = null; // permanent
        } else if (offenseCount === 2) {
            duration = QUARANTINE.secondDuration;
        } else {
            duration = QUARANTINE.firstDuration;
        }

        const record = {
            reason: 'auto',
            quarantinedAt: Date.now(),
            expiresAt: duration ? Date.now() + duration : null,
            offenseCount,
            details: String(reason).slice(0, 512),
        };

        this._quarantined.set(nodeId, record);
        this._dirty = true;

        firewallLogger.log(EVENT.QUARANTINE_ACTIVATED, nodeId, 'quarantine',
            `Auto-quarantined: ${reason}`, {
                offenseCount,
                duration: duration ? `${Math.round(duration / 60000)}min` : 'permanent',
            });

        this._persist();

        return {
            quarantined: true,
            duration,
            offenseCount,
        };
    }

    /**
     * Quarantine a node manually (user action).
     * Manual quarantines are always permanent until explicitly released.
     *
     * @param {string} nodeId
     * @param {string} reason
     */
    manualQuarantine(nodeId, reason = 'User-initiated') {
        const prior = this._quarantined.get(nodeId);
        const record = {
            reason: 'manual',
            quarantinedAt: Date.now(),
            expiresAt: null, // permanent
            offenseCount: prior ? (prior.offenseCount || 0) + 1 : 1,
            details: String(reason).slice(0, 512),
        };

        this._quarantined.set(nodeId, record);
        this._dirty = true;

        firewallLogger.log(EVENT.QUARANTINE_ACTIVATED, nodeId, 'quarantine',
            `Manual quarantine: ${reason}`, { offenseCount: record.offenseCount });

        this._persist();
    }

    /**
     * Release a node from quarantine.
     * Can release both auto and manual quarantines.
     *
     * @param {string} nodeId
     * @returns {boolean} true if the node was quarantined and is now released
     */
    release(nodeId) {
        if (!this._quarantined.has(nodeId)) return false;

        const record = this._quarantined.get(nodeId);
        this._quarantined.delete(nodeId);
        this._dirty = true;

        firewallLogger.log(EVENT.QUARANTINE_RELEASED, nodeId, 'allow',
            'Released from quarantine', {
                wasType: record.reason,
                offenseCount: record.offenseCount,
            });

        this._persist();
        return true;
    }

    /**
     * Get list of all currently quarantined nodes.
     * @returns {Array<{ nodeId: string, reason: string, quarantinedAt: number, expiresAt: number|null, offenseCount: number, details: string }>}
     */
    getQuarantinedList() {
        const list = [];
        for (const [nodeId, record] of this._quarantined) {
            // Skip expired (will be cleaned up by _checkExpired)
            if (record.expiresAt && Date.now() >= record.expiresAt) continue;
            list.push({ nodeId, ...record });
        }
        return list;
    }

    /**
     * Get count of quarantined nodes.
     * @returns {number}
     */
    getCount() {
        return this.getQuarantinedList().length;
    }

    // ── Internal ─────────────────────────────────────────────────

    /** Evict expired quarantines */
    _checkExpired() {
        const now = Date.now();
        let changed = false;
        for (const [nodeId, record] of this._quarantined) {
            if (record.expiresAt && now >= record.expiresAt) {
                this._quarantined.delete(nodeId);
                changed = true;
                firewallLogger.log(EVENT.QUARANTINE_RELEASED, nodeId, 'allow',
                    'Auto-quarantine expired', { offenseCount: record.offenseCount });
            }
        }
        if (changed) {
            this._dirty = true;
            this._persist();
        }
    }

    /** Persist quarantine list to storage */
    async _persist() {
        if (!this._dirty) return;
        try {
            const obj = {};
            for (const [id, data] of this._quarantined) {
                obj[id] = data;
            }
            const store = await _getStore();
            await store.set({ key: STORAGE_KEY, value: JSON.stringify(obj) });
            this._dirty = false;
        } catch (err) {
            console.error('[FW-Quarantine] Persist error:', err.message);
        }
    }
}

// ─── Singleton Export ────────────────────────────────────────────────────────

export const quarantineManager = new QuarantineManager();
export default quarantineManager;
