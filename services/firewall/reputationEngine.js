/**
 * reputationEngine.js — Node Trust Scoring System
 * =================================================
 *
 * Every node that interacts with Kryptos has a trust score between
 * minScore (-50) and maxScore (100). The score determines what the
 * firewall allows the node to do:
 *
 *   80-100  Trusted   — full access, bypass verification queue
 *   50-79   Neutral   — normal firewall rules
 *   20-49   Suspicious — increased monitoring, reduced rate limits
 *   0-19    Hostile    — auto-quarantine, all traffic blocked
 *
 * Scores persist across sessions via encrypted Capacitor Preferences
 * (or localStorage fallback). Positive events raise the score;
 * negative events lower it.
 */

import { REPUTATION, LOGGER } from './firewallConfig.js';
import { firewallLogger, EVENT } from './firewallLogger.js';

// ─── Storage abstraction ─────────────────────────────────────────────────────

let _Preferences = null;
const STORAGE_KEY = LOGGER.storagePrefix + 'reputation';

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

// ─── ReputationEngine ────────────────────────────────────────────────────────

class ReputationEngine {
    constructor() {
        /**
         * Map: nodeId → { score, lastSeen, firstSeen, uptimeHours,
         *                  violations, offenseCount, ghostTagVerified }
         * @type {Map<string, object>}
         */
        this._nodes = new Map();
        /** Dirty flag — set after any mutation, cleared after persist */
        this._dirty = false;
        /** Persist timer handle */
        this._persistTimer = null;
    }

    // ── Lifecycle ────────────────────────────────────────────────

    /** Load persisted reputation data from storage */
    async init() {
        try {
            const store = await _getStore();
            const { value } = await store.get({ key: STORAGE_KEY });
            if (value) {
                const parsed = JSON.parse(value);
                // Rebuild Map from plain object
                for (const [id, data] of Object.entries(parsed)) {
                    if (typeof id === 'string' && id.length > 0 && id.length <= 512) {
                        this._nodes.set(id, data);
                    }
                }
            }
        } catch (err) {
            console.warn('[FW-Reputation] Failed to load persisted data:', err.message);
        }
        // Auto-persist every 60 seconds
        this._persistTimer = setInterval(() => this._persist(), 60000);
    }

    /** Flush and stop auto-persist */
    async shutdown() {
        if (this._persistTimer) clearInterval(this._persistTimer);
        this._persistTimer = null;
        await this._persist();
    }

    // ── Score queries ────────────────────────────────────────────

    /**
     * Get the trust score for a node.
     * Returns initialScore (50) if the node has never been seen.
     *
     * @param {string} nodeId
     * @returns {number} score between minScore and maxScore
     */
    getScore(nodeId) {
        const record = this._nodes.get(nodeId);
        return record ? record.score : REPUTATION.initialScore;
    }

    /**
     * Get the full reputation record for a node.
     * @param {string} nodeId
     * @returns {object|null}
     */
    getRecord(nodeId) {
        return this._nodes.get(nodeId) || null;
    }

    /**
     * Classify a node's trust tier.
     * @param {string} nodeId
     * @returns {'trusted'|'neutral'|'suspicious'|'hostile'}
     */
    classify(nodeId) {
        const score = this.getScore(nodeId);
        if (score >= REPUTATION.trustedThreshold) return 'trusted';
        if (score > REPUTATION.suspiciousThreshold) return 'neutral';
        if (score > REPUTATION.hostileThreshold) return 'suspicious';
        return 'hostile';
    }

    /**
     * Check if a node meets a minimum reputation threshold.
     * @param {string} nodeId
     * @param {number} minScore
     * @returns {boolean}
     */
    meetsThreshold(nodeId, minScore) {
        return this.getScore(nodeId) >= minScore;
    }

    /**
     * Get all nodes grouped by classification.
     * @returns {{ trusted: string[], neutral: string[], suspicious: string[], hostile: string[] }}
     */
    getAll() {
        const result = { trusted: [], neutral: [], suspicious: [], hostile: [] };
        for (const [id] of this._nodes) {
            result[this.classify(id)].push(id);
        }
        return result;
    }

    // ── Score adjustments (positive events) ──────────────────────

    /**
     * Record a successful message exchange with a node.
     * @param {string} nodeId
     */
    recordSuccess(nodeId) {
        this._adjust(nodeId, REPUTATION.successfulExchange, 'successful_exchange');
    }

    /**
     * Record one hour of consistent uptime for a node.
     * @param {string} nodeId
     */
    recordUptime(nodeId) {
        const record = this._ensureRecord(nodeId);
        record.uptimeHours = (record.uptimeHours || 0) + 1;
        this._adjust(nodeId, REPUTATION.consistentUptime, 'uptime_hour');
    }

    /**
     * Record that a node has a verified GhostTag.
     * Only awards the bonus once.
     * @param {string} nodeId
     */
    recordGhostTagVerified(nodeId) {
        const record = this._ensureRecord(nodeId);
        if (record.ghostTagVerified) return; // already awarded
        record.ghostTagVerified = true;
        this._adjust(nodeId, REPUTATION.verifiedGhostTag, 'ghosttag_verified');
    }

    // ── Score adjustments (negative events) ──────────────────────

    /**
     * Record a failed handshake attempt.
     * @param {string} nodeId
     */
    recordFailedHandshake(nodeId) {
        this._adjust(nodeId, REPUTATION.failedHandshake, 'failed_handshake');
    }

    /**
     * Record a rate-limit violation.
     * @param {string} nodeId
     */
    recordRateLimitViolation(nodeId) {
        const record = this._ensureRecord(nodeId);
        record.violations = (record.violations || 0) + 1;
        this._adjust(nodeId, REPUTATION.rateLimitViolation, 'rate_limit_violation');
    }

    /**
     * Record a malformed packet from a node.
     * @param {string} nodeId
     */
    recordMalformedPacket(nodeId) {
        this._adjust(nodeId, REPUTATION.malformedPacket, 'malformed_packet');
    }

    /**
     * Record a detected attack pattern (injection, replay, etc.).
     * @param {string} nodeId
     * @param {string} [attackType] — optional label
     */
    recordAttackPattern(nodeId, attackType = 'unknown') {
        const record = this._ensureRecord(nodeId);
        record.offenseCount = (record.offenseCount || 0) + 1;
        this._adjust(nodeId, REPUTATION.attackPattern, `attack_${attackType}`);
    }

    /**
     * Apply a custom score delta. Use this for penalty/reward amounts
     * not covered by the named methods above.
     * @param {string} nodeId
     * @param {number} delta — positive raises, negative lowers
     * @param {string} reason
     */
    applyDelta(nodeId, delta, reason) {
        this._adjust(nodeId, delta, reason);
    }

    // ── Admin ────────────────────────────────────────────────────

    /**
     * Reset a node's reputation to initialScore (e.g. after manual review).
     * @param {string} nodeId
     */
    reset(nodeId) {
        const record = this._ensureRecord(nodeId);
        record.score = REPUTATION.initialScore;
        record.violations = 0;
        record.offenseCount = 0;
        this._dirty = true;
        firewallLogger.log(EVENT.REPUTATION_CHANGE, nodeId, 'allow',
            `Reputation reset to ${REPUTATION.initialScore}`, { newScore: record.score });
    }

    /**
     * Remove all reputation data (factory reset).
     */
    async clearAll() {
        this._nodes.clear();
        this._dirty = false;
        const store = await _getStore();
        await store.remove({ key: STORAGE_KEY });
    }

    // ── Internal ─────────────────────────────────────────────────

    /**
     * Ensure a reputation record exists for a node, creating a default
     * one if necessary.
     * @param {string} nodeId
     * @returns {object} the record
     */
    _ensureRecord(nodeId) {
        if (!this._nodes.has(nodeId)) {
            this._nodes.set(nodeId, {
                score: REPUTATION.initialScore,
                firstSeen: Date.now(),
                lastSeen: Date.now(),
                uptimeHours: 0,
                violations: 0,
                offenseCount: 0,
                ghostTagVerified: false,
            });
        }
        const record = this._nodes.get(nodeId);
        record.lastSeen = Date.now();
        return record;
    }

    /**
     * Apply a score delta, clamped to [minScore, maxScore].
     * @param {string} nodeId
     * @param {number} delta
     * @param {string} reason
     */
    _adjust(nodeId, delta, reason) {
        const record = this._ensureRecord(nodeId);
        const oldScore = record.score;
        record.score = Math.max(
            REPUTATION.minScore,
            Math.min(REPUTATION.maxScore, record.score + delta)
        );
        this._dirty = true;

        // Log significant changes (threshold crossings)
        const oldClass = _classifyScore(oldScore);
        const newClass = _classifyScore(record.score);
        if (oldClass !== newClass || Math.abs(delta) >= 10) {
            firewallLogger.log(EVENT.REPUTATION_CHANGE, nodeId,
                delta < 0 ? 'flag' : 'allow',
                `Score ${oldScore} → ${record.score} (${reason})`,
                { delta, oldClass, newClass, newScore: record.score });
        }
    }

    /** Persist reputation data to encrypted storage */
    async _persist() {
        if (!this._dirty) return;
        try {
            const obj = {};
            for (const [id, data] of this._nodes) {
                obj[id] = data;
            }
            // Cap total entries to prevent unbounded growth
            const MAX_NODES = 10000;
            if (this._nodes.size > MAX_NODES) {
                // Evict oldest entries by lastSeen
                const sorted = [...this._nodes.entries()]
                    .sort((a, b) => a[1].lastSeen - b[1].lastSeen);
                const toRemove = sorted.slice(0, this._nodes.size - MAX_NODES);
                for (const [id] of toRemove) {
                    this._nodes.delete(id);
                    delete obj[id];
                }
            }
            const store = await _getStore();
            await store.set({ key: STORAGE_KEY, value: JSON.stringify(obj) });
            this._dirty = false;
        } catch (err) {
            console.error('[FW-Reputation] Persist error:', err.message);
        }
    }
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

function _classifyScore(score) {
    if (score >= REPUTATION.trustedThreshold) return 'trusted';
    if (score > REPUTATION.suspiciousThreshold) return 'neutral';
    if (score > REPUTATION.hostileThreshold) return 'suspicious';
    return 'hostile';
}

// ─── Singleton Export ────────────────────────────────────────────────────────

export const reputationEngine = new ReputationEngine();
export default reputationEngine;
