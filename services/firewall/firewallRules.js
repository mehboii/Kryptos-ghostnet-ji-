/**
 * firewallRules.js — User-Configurable Rules Engine
 * ====================================================
 *
 * The user-facing configuration layer. Users can:
 *   - Block/whitelist specific node IDs or GhostTags
 *   - Block by country (geographic filter)
 *   - Set custom rate limits
 *   - Enable/disable specific detection layers
 *   - Set auto-quarantine aggressiveness
 *   - Export/import rules as encrypted JSON
 *
 * Rules are persisted in encrypted local storage and applied to
 * the firewall layers at runtime. Changes take effect immediately.
 *
 * Critical rule changes (disabling firewall, disabling self-defense)
 * require PIN verification via firewallSelfDefense.
 */

import { LOGGER } from './firewallConfig.js';
import { firewallLogger, EVENT } from './firewallLogger.js';

const STORAGE_KEY = LOGGER.storagePrefix + 'rules';

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

// ─── Default Rules ───────────────────────────────────────────────────────────

/**
 * Factory function for the default rules object.
 * Every field here is user-configurable through the UI.
 */
function _defaultRules() {
    return {
        /** Master switch — if false, firewall passes all traffic (requires PIN) */
        enabled: true,
        /** Self-defense enabled — if false, no integrity/bypass protection (requires PIN) */
        selfDefenseEnabled: true,

        // ── Node-level rules ──
        /** Manually blocked node IDs */
        blockedNodes: [],
        /** Manually blocked GhostTags */
        blockedGhostTags: [],
        /** Manually whitelisted node IDs (bypass checks except encryption) */
        whitelistedNodes: [],

        // ── Geographic filtering ──
        /** Blocked country codes (ISO 3166-1 alpha-2) */
        blockedCountries: [],

        // ── Rate limits ──
        /** Custom per-node rate limit override (null = use shield default) */
        customPerNodeLimit: null,
        /** Custom global rate limit override (null = use shield default) */
        customGlobalLimit: null,

        // ── Detection layer toggles ──
        /** Enable/disable injection pattern scanning */
        injectionDetection: true,
        /** Enable/disable replay attack prevention */
        replayPrevention: true,
        /** Enable/disable timing analysis detection */
        timingAnalysis: true,
        /** Enable/disable session hijack detection */
        sessionProtection: true,
        /** Enable/disable DDoS detection */
        ddosDetection: true,
        /** Enable/disable mesh poisoning detection */
        meshPoisonDetection: true,
        /** Enable/disable deep packet inspection */
        deepPacketInspection: true,
        /** Enable/disable anomaly detection */
        anomalyDetection: true,

        // ── Aggressiveness ──
        /**
         * Auto-quarantine aggressiveness level.
         *  'low'    — lenient thresholds (2x the defaults)
         *  'medium' — default thresholds
         *  'high'   — aggressive (0.5x the defaults, triggers faster)
         */
        aggressiveness: 'medium',

        // ── Metadata ──
        /** When rules were last modified */
        lastModified: Date.now(),
        /** Version for future migration support */
        version: 1,
    };
}

// ─── Critical rule names that require PIN ────────────────────────────────────

const CRITICAL_RULES = new Set(['enabled', 'selfDefenseEnabled']);

// ─── FirewallRules ───────────────────────────────────────────────────────────

class FirewallRules {
    constructor() {
        /** @type {object} the current rules */
        this._rules = _defaultRules();
        /** Callback to notify the firewall core of rule changes */
        this._onChange = null;
    }

    // ── Lifecycle ────────────────────────────────────────────────

    /**
     * Load persisted rules from storage.
     * @param {function} onChange — called with the full rules object whenever rules change
     */
    async init(onChange) {
        this._onChange = onChange || null;
        try {
            const store = await _getStore();
            const { value } = await store.get({ key: STORAGE_KEY });
            if (value) {
                const loaded = JSON.parse(value);
                if (typeof loaded !== 'object' || loaded === null || Array.isArray(loaded)) {
                    console.warn('[FW-Rules] Corrupted rules in storage — using defaults');
                } else {
                    // Sanitize: strip prototype pollution keys and validate types
                    const defaults = _defaultRules();
                    const safe = { ...defaults };
                    for (const key of Object.keys(loaded)) {
                        // Block prototype pollution vectors
                        if (key === '__proto__' || key === 'constructor' || key === 'prototype') continue;
                        // Only accept keys that exist in the default schema
                        if (!(key in defaults)) continue;
                        // Validate type matches the default
                        if (!_validateRuleValue(key, loaded[key])) continue;
                        safe[key] = loaded[key];
                    }
                    // Critical rules from storage can never override to disabled
                    // without explicit user action (prevents storage poisoning)
                    // If storage says enabled=false but no PIN was verified, force true
                    if (safe.enabled === false || safe.selfDefenseEnabled === false) {
                        console.warn('[FW-Rules] Critical rules were disabled in storage — forcing enabled');
                        safe.enabled = true;
                        safe.selfDefenseEnabled = true;
                    }
                    this._rules = safe;
                }
            }
        } catch (err) {
            console.warn('[FW-Rules] Failed to load rules:', err.message);
        }
    }

    // ── Read API ─────────────────────────────────────────────────

    /** Get the complete current rules object (read-only copy) */
    getRules() {
        return { ...this._rules };
    }

    /** Check if the firewall is enabled */
    isEnabled() {
        return this._rules.enabled;
    }

    /** Check if self-defense is enabled */
    isSelfDefenseEnabled() {
        return this._rules.selfDefenseEnabled;
    }

    /** Check if a specific node is blocked by the user */
    isNodeBlocked(nodeId) {
        return this._rules.blockedNodes.includes(nodeId);
    }

    /** Check if a GhostTag is blocked */
    isGhostTagBlocked(tag) {
        return this._rules.blockedGhostTags.includes(tag);
    }

    /** Check if a specific node is whitelisted by the user */
    isNodeWhitelisted(nodeId) {
        return this._rules.whitelistedNodes.includes(nodeId);
    }

    /** Check if a specific detection layer is enabled */
    isLayerEnabled(layerName) {
        return this._rules[layerName] !== false;
    }

    /** Get the aggressiveness multiplier */
    getAggressivenessMultiplier() {
        switch (this._rules.aggressiveness) {
            case 'low': return 2.0;    // lenient — thresholds doubled
            case 'high': return 0.5;   // aggressive — thresholds halved
            default: return 1.0;       // medium — default
        }
    }

    // ── Write API ────────────────────────────────────────────────

    /**
     * Update one or more rules. For critical rules (enabled, selfDefenseEnabled),
     * the caller must verify the PIN first via firewallSelfDefense.verifyPin().
     *
     * @param {object} updates — key/value pairs to update
     * @param {boolean} [pinVerified=false] — whether PIN was verified for this change
     * @returns {{ success: boolean, reason?: string }}
     */
    async setRules(updates, pinVerified = false) {
        // Check if any critical rules are being changed
        const hasCritical = Object.keys(updates).some(k => CRITICAL_RULES.has(k));
        if (hasCritical && !pinVerified) {
            return { success: false, reason: 'Critical rule change requires PIN verification' };
        }

        // Validate and apply updates
        const oldRules = { ...this._rules };
        for (const [key, value] of Object.entries(updates)) {
            if (key === '__proto__' || key === 'constructor' || key === 'prototype') continue;
            if (!(key in this._rules)) continue; // ignore unknown fields

            // Type validation
            if (!_validateRuleValue(key, value)) {
                return { success: false, reason: `Invalid value for rule: ${key}` };
            }

            this._rules[key] = value;
        }

        this._rules.lastModified = Date.now();
        await this._persist();

        // Log the change
        const changedKeys = Object.keys(updates).filter(k => k in this._rules);
        firewallLogger.log(EVENT.RULE_CHANGED, null, 'allow',
            `Rules updated: ${changedKeys.join(', ')}`, {
                changes: changedKeys.map(k => `${k}: ${JSON.stringify(oldRules[k])} → ${JSON.stringify(this._rules[k])}`),
            });

        // Notify the core to re-apply config
        if (this._onChange) this._onChange(this._rules);

        return { success: true };
    }

    // ── Node management shortcuts ────────────────────────────────

    /** Block a node */
    async blockNode(nodeId) {
        if (!this._rules.blockedNodes.includes(nodeId)) {
            this._rules.blockedNodes.push(nodeId);
            // Remove from whitelist if present
            this._rules.whitelistedNodes = this._rules.whitelistedNodes.filter(n => n !== nodeId);
            await this._persist();
            if (this._onChange) this._onChange(this._rules);
        }
    }

    /** Unblock a node */
    async unblockNode(nodeId) {
        this._rules.blockedNodes = this._rules.blockedNodes.filter(n => n !== nodeId);
        await this._persist();
        if (this._onChange) this._onChange(this._rules);
    }

    /** Whitelist a node */
    async whitelistNode(nodeId) {
        if (!this._rules.whitelistedNodes.includes(nodeId)) {
            this._rules.whitelistedNodes.push(nodeId);
            // Remove from blocklist if present
            this._rules.blockedNodes = this._rules.blockedNodes.filter(n => n !== nodeId);
            await this._persist();
            if (this._onChange) this._onChange(this._rules);
        }
    }

    /** Remove a node from the whitelist */
    async unwhitelistNode(nodeId) {
        this._rules.whitelistedNodes = this._rules.whitelistedNodes.filter(n => n !== nodeId);
        await this._persist();
        if (this._onChange) this._onChange(this._rules);
    }

    /** Block a GhostTag */
    async blockGhostTag(tag) {
        if (!this._rules.blockedGhostTags.includes(tag)) {
            this._rules.blockedGhostTags.push(tag);
            await this._persist();
            if (this._onChange) this._onChange(this._rules);
        }
    }

    /** Unblock a GhostTag */
    async unblockGhostTag(tag) {
        this._rules.blockedGhostTags = this._rules.blockedGhostTags.filter(t => t !== tag);
        await this._persist();
        if (this._onChange) this._onChange(this._rules);
    }

    // ── Export / Import ──────────────────────────────────────────

    /**
     * Export rules as a JSON string for backup or multi-device sync.
     * @returns {string} JSON string of rules
     */
    exportRules() {
        return JSON.stringify(this._rules, null, 2);
    }

    /**
     * Import rules from a JSON string.
     * Validates structure before applying.
     *
     * @param {string} jsonStr
     * @param {boolean} [pinVerified=false]
     * @returns {{ success: boolean, reason?: string }}
     */
    async importRules(jsonStr, pinVerified = false) {
        try {
            const imported = JSON.parse(jsonStr);
            if (typeof imported !== 'object' || imported === null || Array.isArray(imported)) {
                return { success: false, reason: 'Invalid rules format' };
            }

            // Check for ANY critical rule being changed to a disabling value
            const hasCritical = [...CRITICAL_RULES].some(key =>
                key in imported && imported[key] === false
            );
            if (hasCritical && !pinVerified) {
                return { success: false, reason: 'Import contains critical changes — PIN required' };
            }

            // Sanitize imported data — strip prototype pollution, validate types
            const defaults = _defaultRules();
            const safe = { ...defaults };
            for (const key of Object.keys(imported)) {
                if (key === '__proto__' || key === 'constructor' || key === 'prototype') continue;
                if (!(key in defaults)) continue;
                if (!_validateRuleValue(key, imported[key])) continue;
                safe[key] = imported[key];
            }
            safe.lastModified = Date.now();
            this._rules = safe;
            await this._persist();

            firewallLogger.log(EVENT.RULE_CHANGED, null, 'allow',
                'Rules imported from external source');

            if (this._onChange) this._onChange(this._rules);
            return { success: true };
        } catch (err) {
            return { success: false, reason: `Import failed: ${err.message}` };
        }
    }

    /** Reset all rules to defaults */
    async resetToDefaults(pinVerified = false) {
        if (!pinVerified) {
            return { success: false, reason: 'Reset requires PIN verification' };
        }
        this._rules = _defaultRules();
        await this._persist();

        firewallLogger.log(EVENT.RULE_CHANGED, null, 'allow',
            'Rules reset to factory defaults');

        if (this._onChange) this._onChange(this._rules);
        return { success: true };
    }

    // ── Internal ─────────────────────────────────────────────────

    /** Persist rules to storage */
    async _persist() {
        try {
            const store = await _getStore();
            await store.set({ key: STORAGE_KEY, value: JSON.stringify(this._rules) });
        } catch (err) {
            console.error('[FW-Rules] Persist error:', err.message);
        }
    }
}

// ─── Validation helpers ──────────────────────────────────────────────────────

/** Validate that a rule value is the expected type */
function _validateRuleValue(key, value) {
    const booleanFields = new Set([
        'enabled', 'selfDefenseEnabled', 'injectionDetection',
        'replayPrevention', 'timingAnalysis', 'sessionProtection',
        'ddosDetection', 'meshPoisonDetection', 'deepPacketInspection',
        'anomalyDetection',
    ]);
    const arrayFields = new Set([
        'blockedNodes', 'blockedGhostTags', 'whitelistedNodes', 'blockedCountries',
    ]);
    const numberFields = new Set(['customPerNodeLimit', 'customGlobalLimit']);
    const enumFields = { aggressiveness: ['low', 'medium', 'high'] };

    if (booleanFields.has(key)) return typeof value === 'boolean';
    if (arrayFields.has(key)) return Array.isArray(value) && value.every(v => typeof v === 'string');
    if (numberFields.has(key)) return value === null || (typeof value === 'number' && value > 0 && Number.isFinite(value));
    if (key in enumFields) return enumFields[key].includes(value);

    return true; // unknown field — allow
}

// ─── Singleton Export ────────────────────────────────────────────────────────

export const firewallRules = new FirewallRules();
export default firewallRules;
