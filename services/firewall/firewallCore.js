/**
 * firewallCore.js — GhostNet Firewall Core Engine
 * ==================================================
 *
 * Central orchestrator for the entire GhostNet firewall system.
 * Initializes all layers, routes traffic through the inspection
 * pipeline, and provides a unified public API.
 *
 * ┌─────────────────────────────────────────────────────────┐
 * │                  FIREWALL ARCHITECTURE                  │
 * │                                                         │
 * │   Incoming Traffic                                      │
 * │        │                                                │
 * │        ▼                                                │
 * │   ┌─────────────┐  Rules Engine checks user-defined     │
 * │   │ Rules Check  │  blocks (node IDs, GhostTags, etc.)  │
 * │   └──────┬──────┘                                       │
 * │          ▼                                              │
 * │   ┌─────────────┐  Whitelist/blacklist, rate limit,     │
 * │   │   Layer 1   │  reputation gate, geo filter,         │
 * │   │ Connection  │  challenge-response handshake         │
 * │   └──────┬──────┘                                       │
 * │          ▼                                              │
 * │   ┌─────────────┐  Size, schema, encryption, replay,   │
 * │   │   Layer 2   │  injection scan, deep inspection      │
 * │   │   Packet    │                                       │
 * │   └──────┬──────┘                                       │
 * │          ▼                                              │
 * │   ┌─────────────┐  Traffic anomaly, timing analysis,   │
 * │   │   Layer 3   │  session hijack, DDoS, mesh poison   │
 * │   │  Behavior   │                                       │
 * │   └──────┬──────┘                                       │
 * │          ▼                                              │
 * │   ┌─────────────┐  Integrity monitor, anti-bypass,     │
 * │   │ Self-Defense │  watchdog, PIN protection            │
 * │   └──────┬──────┘                                       │
 * │          ▼                                              │
 * │       ALLOW  or   BLOCK                             │
 * └─────────────────────────────────────────────────────────┘
 *
 * Exports:
 *   initFirewall()          — start the firewall (call on app boot)
 *   shutdownFirewall()      — stop all layers cleanly
 *   inspectInbound()        — full pipeline for incoming traffic
 *   inspectOutbound()       — inspect outgoing network requests
 *   setShieldLevel()        — adjust all layers to a Ghost Shield level
 *   getFirewallStatus()     — dashboard snapshot
 *   getThreats()            — recent threat events
 *   getThreatLog()          — full audit log
 *   getNodeReputation()     — query a node's trust score
 *   quarantineNode()        — manually quarantine a node
 *   releaseNode()           — release a node from quarantine
 *   exportLogs()            — export encrypted logs as JSON
 *   setFirewallRules()      — update user rules
 *   getFirewallRules()      — get current rules
 */

import { resolveConfig } from './firewallConfig.js';
import { firewallLogger, EVENT } from './firewallLogger.js';
import { reputationEngine } from './reputationEngine.js';
import { quarantineManager } from './quarantine.js';
import { connectionFirewall } from './connectionFirewall.js';
import { packetFirewall } from './packetFirewall.js';
import { behaviorFirewall } from './behaviorFirewall.js';
import { firewallSelfDefense } from './firewallSelfDefense.js';
import { firewallRules } from './firewallRules.js';

// ─── State ───────────────────────────────────────────────────────────────────

let _initialized = false;
let _shieldLevel = 'off';
let _config = resolveConfig('off');
let _startedAt = 0;

// ─── Initialization ─────────────────────────────────────────────────────────

/**
 * Initialize the entire firewall system. Must be called once on app startup,
 * BEFORE any network connections are established.
 *
 * @param {object} [opts]
 * @param {'off'|'stealth'|'ghost'|'phantom'} [opts.shieldLevel='off'] — initial shield level
 * @param {string} [opts.sessionKey] — user session key for log encryption
 * @returns {Promise<{ success: boolean, status: object }>}
 */
export async function initFirewall(opts = {}) {
    if (_initialized) {
        console.warn('[FW-Core] Firewall already initialized');
        return { success: true, status: getFirewallStatus() };
    }

    try {
        _startedAt = Date.now();
        _shieldLevel = opts.shieldLevel || 'off';
        _config = resolveConfig(_shieldLevel);

        // 1. Initialize the logger first (everything else logs to it)
        await firewallLogger.init(opts.sessionKey);

        // 2. Load user rules
        await firewallRules.init(_onRulesChanged);

        // 3. Load persisted reputation data
        await reputationEngine.init();

        // 4. Load persisted quarantine list
        await quarantineManager.init();

        // 5. Initialize Layer 1 (connection control)
        connectionFirewall.init();
        connectionFirewall.updateConfig(_config.connection, _config.minReputationForAccess);

        // Apply user-defined whitelist/blacklist from rules
        _applyUserRules(firewallRules.getRules());

        // 6. Initialize Layer 2 (packet inspection)
        packetFirewall.init();
        packetFirewall.updateConfig(_config.packet);

        // 7. Initialize Layer 3 (behavior analysis)
        behaviorFirewall.init();
        behaviorFirewall.updateConfig(_config.behavior);

        // 8. Initialize Self-Defense (installs network hooks)
        await firewallSelfDefense.init({
            inspectOutbound: _inspectOutboundInternal,
            onEmergency: _handleEmergency,
        });

        _initialized = true;

        firewallLogger.log(EVENT.FIREWALL_STARTED, null, 'allow',
            `Firewall initialized at shield level: ${_shieldLevel}`, {
                shieldLevel: _shieldLevel,
                rulesEnabled: firewallRules.isEnabled(),
                selfDefense: firewallRules.isSelfDefenseEnabled(),
            });

        return { success: true, status: getFirewallStatus() };

    } catch (err) {
        console.error('[FW-Core] Initialization error:', err.message);
        // Fail open — firewall failed to start but app should still work
        _initialized = true; // mark as initialized to prevent retry loops
        return { success: false, status: getFirewallStatus() };
    }
}

/**
 * Cleanly shut down the firewall and flush all persisted data.
 */
export async function shutdownFirewall() {
    if (!_initialized) return;

    firewallLogger.log(EVENT.FIREWALL_STOPPED, null, 'allow', 'Firewall shutting down');

    connectionFirewall.shutdown();
    packetFirewall.shutdown();
    behaviorFirewall.shutdown();
    await firewallSelfDefense.shutdown();
    await reputationEngine.shutdown();
    await quarantineManager.shutdown();
    await firewallLogger.shutdown();

    _initialized = false;
}

// ─── Main Inspection Pipeline ────────────────────────────────────────────────

/**
 * Full inbound inspection pipeline. Every incoming message, packet, or
 * connection attempt should pass through this function.
 *
 * @param {object} params
 * @param {string} params.nodeId — source node ID
 * @param {object} params.packet — the raw packet/message data
 * @param {'message'|'file'|'control'} [params.packetType='message']
 * @param {object} [params.meta] — { ip, country, fingerprint, endpoint, byteCount }
 * @returns {{ allowed: boolean, reason: string, details?: object }}
 */
export function inspectInbound({ nodeId, packet, packetType = 'message', meta = {} }) {
    // Fast path: if firewall is disabled by user rules, pass everything
    if (!firewallRules.isEnabled()) {
        return { allowed: true, reason: 'firewall_disabled' };
    }

    try {
        // ── Pre-check: user-defined node/tag blocks ──
        if (firewallRules.isNodeBlocked(nodeId)) {
            firewallLogger.log(EVENT.CONNECTION_BLOCKED, nodeId, 'block',
                'Blocked by user rule');
            return { allowed: false, reason: 'blocked_by_user_rule' };
        }

        // ── Layer 1: Connection Control ──
        const l1 = connectionFirewall.evaluate(nodeId, meta);
        if (!l1.allowed) {
            return {
                allowed: false,
                reason: `L1: ${l1.reason}`,
                requiresChallenge: l1.requiresChallenge,
                nonce: l1.nonce,
            };
        }

        // ── Layer 2: Packet Inspection ──
        if (packet) {
            const l2 = packetFirewall.inspect(packet, nodeId, packetType);
            if (!l2.allowed) {
                return { allowed: false, reason: `L2: ${l2.reason}`, details: l2.details };
            }
        }

        // ── Layer 3: Behavior Analysis ──
        const l3 = behaviorFirewall.analyze(nodeId, {
            ip: meta.ip,
            fingerprint: meta.fingerprint,
            endpoint: meta.endpoint,
            byteCount: meta.byteCount || (packet ? JSON.stringify(packet).length : 0),
        });
        if (!l3.allowed) {
            return { allowed: false, reason: `L3: ${l3.reason}` };
        }

        // Record successful exchange for reputation
        reputationEngine.recordSuccess(nodeId);

        // If timing noise is requested, include it in the response
        if (l3.addNoise) {
            return {
                allowed: true,
                reason: 'passed_with_noise',
                details: { addNoise: true, noiseMs: l3.noiseMs },
            };
        }

        return { allowed: true, reason: 'all_layers_passed' };

    } catch (err) {
        // Fail CLOSED — errors must not become bypass vectors
        console.error('[FW-Core] inspectInbound error:', err.message);
        firewallLogger.log(EVENT.SELF_DEFENSE_ALERT, null, 'block',
            'Core inspection error — failing closed', { error: err.message });
        return { allowed: false, reason: 'inspection_error_failclosed' };
    }
}

/**
 * Verify a challenge response from a node (delegates to Layer 1).
 *
 * @param {string} nodeId
 * @param {string} nonce — the nonce the node sent back
 * @returns {{ verified: boolean, reason: string }}
 */
export function verifyChallenge(nodeId, nonce) {
    return connectionFirewall.verifyChallenge(nodeId, nonce);
}

/**
 * Check a routing table change (delegates to Layer 3 mesh poisoning detection).
 *
 * @param {string} nodeId
 * @param {object} change — { type, target, via }
 * @returns {{ allowed: boolean, reason: string }}
 */
export function checkRoutingChange(nodeId, change) {
    if (!firewallRules.isLayerEnabled('meshPoisonDetection')) {
        return { allowed: true, reason: 'mesh_poison_detection_disabled' };
    }
    return behaviorFirewall.checkRoutingChange(nodeId, change);
}

// ─── Shield Level Control ────────────────────────────────────────────────────

/**
 * Change the Ghost Shield level. Reconfigures all firewall layers.
 *
 * @param {'off'|'stealth'|'ghost'|'phantom'} level
 */
export function setShieldLevel(level) {
    if (!['off', 'stealth', 'ghost', 'phantom'].includes(level)) {
        console.warn('[FW-Core] Invalid shield level:', level);
        return;
    }

    _shieldLevel = level;
    _config = resolveConfig(level);

    // Re-apply aggressiveness multiplier from user rules
    const aggMultiplier = firewallRules.getAggressivenessMultiplier();

    connectionFirewall.updateConfig(
        {
            ..._config.connection,
            perNodeLimit: firewallRules.getRules().customPerNodeLimit || _config.connection.perNodeLimit,
        },
        _config.minReputationForAccess
    );

    packetFirewall.updateConfig(_config.packet);

    behaviorFirewall.updateConfig({
        ..._config.behavior,
        anomalyMultiplierWarn: _config.behavior.anomalyMultiplierWarn * aggMultiplier,
        anomalyMultiplierBlock: _config.behavior.anomalyMultiplierBlock * aggMultiplier,
    });

    firewallSelfDefense.updateConfig(_config.selfDefense);

    firewallLogger.log(EVENT.RULE_CHANGED, null, 'allow',
        `Shield level changed to: ${level}`, { level });
}

/**
 * Get the current shield level.
 * @returns {'off'|'stealth'|'ghost'|'phantom'}
 */
export function getShieldLevel() {
    return _shieldLevel;
}

// ─── Status & Monitoring ─────────────────────────────────────────────────────

/**
 * Get a comprehensive firewall status snapshot for the UI dashboard.
 *
 * @returns {object}
 */
export function getFirewallStatus() {
    const selfDefenseStatus = firewallSelfDefense.getStatus();
    return {
        enabled: firewallRules.isEnabled(),
        initialized: _initialized,
        shieldLevel: _shieldLevel,
        uptime: _initialized ? Date.now() - _startedAt : 0,
        activeThreats: quarantineManager.getCount(),
        blockedToday: firewallLogger.getBlockedToday(),
        quarantinedNodes: quarantineManager.getQuarantinedList(),
        selfDefenseStatus: selfDefenseStatus.integrityStatus,
        safeMode: selfDefenseStatus.safeMode,
        emergencyMode: behaviorFirewall.isEmergencyMode(),
        lastIntegrityCheck: selfDefenseStatus.lastHeartbeat,
        layers: {
            connection: connectionFirewall.getStats(),
            packet: packetFirewall.getStats(),
            behavior: behaviorFirewall.getStats(),
            selfDefense: selfDefenseStatus,
        },
        eventCounts: firewallLogger.getDayCounts(),
    };
}

/**
 * Get recent threat events.
 * @param {number} [limit=50]
 * @returns {Array<object>}
 */
export function getThreats(limit = 50) {
    return firewallLogger.getRecent(limit).filter(
        e => e.action === 'block' || e.action === 'quarantine' || e.action === 'alert'
    );
}

/**
 * Get the full audit log.
 * @param {number} [limit=200]
 * @returns {Array<object>}
 */
export function getThreatLog(limit = 200) {
    return firewallLogger.getRecent(limit);
}

/**
 * Export all logs as a JSON string.
 * @returns {string}
 */
export function exportLogs() {
    return firewallLogger.exportLogs();
}

// ─── Reputation ──────────────────────────────────────────────────────────────

/**
 * Get a node's reputation data.
 * @param {string} nodeId
 * @returns {{ score: number, classification: string, record: object|null }}
 */
export function getNodeReputation(nodeId) {
    return {
        score: reputationEngine.getScore(nodeId),
        classification: reputationEngine.classify(nodeId),
        record: reputationEngine.getRecord(nodeId),
    };
}

/**
 * Get all nodes grouped by reputation classification.
 * @returns {{ trusted: string[], neutral: string[], suspicious: string[], hostile: string[] }}
 */
export function getAllReputations() {
    return reputationEngine.getAll();
}

// ─── Quarantine ──────────────────────────────────────────────────────────────

/**
 * Manually quarantine a node.
 * @param {string} nodeId
 * @param {string} [reason='Manual quarantine']
 */
export function quarantineNode(nodeId, reason = 'Manual quarantine') {
    quarantineManager.manualQuarantine(nodeId, reason);
}

/**
 * Release a node from quarantine.
 * @param {string} nodeId
 * @returns {boolean}
 */
export function releaseNode(nodeId) {
    return quarantineManager.release(nodeId);
}

// ─── Rules ───────────────────────────────────────────────────────────────────

/**
 * Get the current firewall rules.
 * @returns {object}
 */
export function getFirewallRules() {
    return firewallRules.getRules();
}

/**
 * Update firewall rules.
 * @param {object} updates
 * @param {boolean} [pinVerified=false]
 * @returns {Promise<{ success: boolean, reason?: string }>}
 */
export async function setFirewallRules(updates, pinVerified = false) {
    return firewallRules.setRules(updates, pinVerified);
}

/**
 * Export rules as JSON.
 * @returns {string}
 */
export function exportRules() {
    return firewallRules.exportRules();
}

/**
 * Import rules from JSON.
 * @param {string} jsonStr
 * @param {boolean} [pinVerified=false]
 * @returns {Promise<{ success: boolean, reason?: string }>}
 */
export async function importRules(jsonStr, pinVerified = false) {
    return firewallRules.importRules(jsonStr, pinVerified);
}

// ─── Whitelist / Blacklist management (pass-through to Layer 1) ──────────────

export function addToWhitelist(nodeId) { connectionFirewall.addToWhitelist(nodeId); }
export function removeFromWhitelist(nodeId) { connectionFirewall.removeFromWhitelist(nodeId); }
export function getWhitelist() { return connectionFirewall.getWhitelist(); }
export function addToBlacklist(nodeId, reason, duration) { connectionFirewall.addToBlacklist(nodeId, reason, duration); }
export function removeFromBlacklist(nodeId) { connectionFirewall.removeFromBlacklist(nodeId); }
export function getBlacklist() { return connectionFirewall.getBlacklist(); }

// ─── Self-Defense pass-through ───────────────────────────────────────────────

export async function setSecurityPin(pin) { return firewallSelfDefense.setPin(pin); }
export async function verifySecurityPin(pin) { return firewallSelfDefense.verifyPin(pin); }
export async function hasSecurityPin() { return firewallSelfDefense.hasPinSet(); }
export function deactivateSafeMode() { firewallSelfDefense.deactivateSafeMode(); }

// ─── Internal ────────────────────────────────────────────────────────────────

/**
 * Internal outbound inspection callback (used by firewallSelfDefense
 * to inspect all outgoing fetch/WS/XHR requests).
 */
function _inspectOutboundInternal(type, url, opts) {
    if (!firewallRules.isEnabled()) {
        return { allowed: true, reason: 'firewall_disabled' };
    }

    // In safe mode, only loopback is allowed (handled by selfDefense)
    // Here we do basic outbound checks:

    try {
        // Block outbound requests to obviously malicious destinations
        const parsed = new URL(url);

        // Block data: URIs in fetch (potential exfiltration)
        if (parsed.protocol === 'data:') {
            return { allowed: false, reason: 'data: URI fetch blocked' };
        }

        // Block file: URIs (shouldn't be fetching local files via network API)
        if (parsed.protocol === 'file:') {
            return { allowed: false, reason: 'file: URI fetch blocked' };
        }

        return { allowed: true, reason: 'outbound_ok' };
    } catch {
        // Can't parse URL — allow (may be a relative URL)
        return { allowed: true, reason: 'unparseable_url_allowed' };
    }
}

/**
 * Handle emergency events from the self-defense system.
 * @param {'integrity_compromised'|'safe_mode'} type
 */
function _handleEmergency(type) {
    if (type === 'integrity_compromised') {
        // Activate full ghost protocol if the shield engine is available
        setShieldLevel('phantom');
        firewallLogger.log(EVENT.SELF_DEFENSE_ALERT, null, 'alert',
            'INTEGRITY COMPROMISED — Full Ghost Protocol activated');
    }
    if (type === 'safe_mode') {
        firewallLogger.log(EVENT.SELF_DEFENSE_ALERT, null, 'alert',
            'SAFE MODE — all external connections blocked');
    }
}

/**
 * Called when user rules change. Re-applies rules to all layers.
 * @param {object} rules — the full rules object
 */
function _onRulesChanged(rules) {
    _applyUserRules(rules);
    // Re-resolve config with current shield level
    setShieldLevel(_shieldLevel);
}

/**
 * Apply user-defined rules to the connection firewall.
 * @param {object} rules
 */
function _applyUserRules(rules) {
    // Whitelist
    for (const nodeId of rules.whitelistedNodes || []) {
        connectionFirewall.addToWhitelist(nodeId);
    }

    // Blacklist
    for (const nodeId of rules.blockedNodes || []) {
        connectionFirewall.addToBlacklist(nodeId, 'User rule', Infinity);
    }

    // Geographic filtering
    connectionFirewall.setBlockedCountries(rules.blockedCountries || []);
}

// ─── Default Export ──────────────────────────────────────────────────────────

export default {
    initFirewall,
    shutdownFirewall,
    inspectInbound,
    verifyChallenge,
    checkRoutingChange,
    setShieldLevel,
    getShieldLevel,
    getFirewallStatus,
    getThreats,
    getThreatLog,
    getNodeReputation,
    getAllReputations,
    quarantineNode,
    releaseNode,
    exportLogs,
    getFirewallRules,
    setFirewallRules,
    exportRules,
    importRules,
    addToWhitelist,
    removeFromWhitelist,
    getWhitelist,
    addToBlacklist,
    removeFromBlacklist,
    getBlacklist,
    setSecurityPin,
    verifySecurityPin,
    hasSecurityPin,
    deactivateSafeMode,
};
