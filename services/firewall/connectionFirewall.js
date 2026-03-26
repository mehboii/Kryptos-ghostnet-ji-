/**
 * connectionFirewall.js — Layer 1: Connection Control
 * =====================================================
 *
 * First line of defense. Every incoming connection passes through here
 * before any data is processed. Responsible for:
 *
 *   1. Whitelist / blacklist enforcement
 *   2. Challenge-response handshake for unknown nodes
 *   3. Per-node and global rate limiting with burst detection
 *   4. Auto-blacklist on repeated violations
 *   5. Geographic filtering (optional, user-configurable)
 *   6. Reputation-based access control (integrates with reputationEngine)
 *
 * All decisions are logged via firewallLogger.
 */

import { CONNECTION } from './firewallConfig.js';
import { firewallLogger, EVENT } from './firewallLogger.js';
import { reputationEngine } from './reputationEngine.js';
import { quarantineManager } from './quarantine.js';

// ─── ConnectionFirewall ──────────────────────────────────────────────────────

class ConnectionFirewall {
    constructor() {
        // ── Whitelist / Blacklist ──
        /** @type {Set<string>} Permanently trusted node IDs */
        this._whitelist = new Set();
        /** @type {Map<string, { until: number, reason: string }>} Banned nodes */
        this._blacklist = new Map();

        // ── Rate limiting state ──
        /** Per-node: nodeId → { timestamps: number[], violations: number, violationTimestamps: number[] } */
        this._perNode = new Map();
        /** Global request counter */
        this._globalTimestamps = [];
        /** Burst tracker: nodeId → { timestamps: number[] } */
        this._burstTracker = new Map();

        // ── Verification queue (challenge-response) ──
        /** nodeId → { nonce, createdAt, attempts } */
        this._verificationQueue = new Map();

        // ── Geographic filter ──
        /** Set of blocked country codes (ISO 3166-1 alpha-2) */
        this._blockedCountries = new Set();

        // ── Config overrides (shield-level aware) ──
        this._config = { ...CONNECTION };
        /** Min reputation score required to connect (set by shield level) */
        this._minReputation = 0;

        // ── Cleanup timer ──
        this._cleanupTimer = null;
    }

    // ── Lifecycle ────────────────────────────────────────────────

    init() {
        // Periodic cleanup of expired blacklist entries and stale rate-limit data
        this._cleanupTimer = setInterval(() => this._cleanup(), 60000);
    }

    shutdown() {
        if (this._cleanupTimer) clearInterval(this._cleanupTimer);
        this._cleanupTimer = null;
    }

    /**
     * Update config values when shield level changes.
     * @param {object} connectionConfig — merged CONNECTION config
     * @param {number} minReputation — minimum reputation score for access
     */
    updateConfig(connectionConfig, minReputation) {
        this._config = { ...CONNECTION, ...connectionConfig };
        this._minReputation = minReputation;
    }

    // ── Main entry point ─────────────────────────────────────────

    /**
     * Evaluate whether an incoming connection should be allowed.
     * This is the single function every incoming request/message calls.
     *
     * @param {string} nodeId — the connecting node's ID
     * @param {object} [meta] — optional metadata { ip, country, deviceFingerprint }
     * @returns {{ allowed: boolean, reason: string, requiresChallenge?: boolean, nonce?: string }}
     */
    evaluate(nodeId, meta = {}) {
        try {
            // 1. Quarantine check — absolute block
            if (quarantineManager.isQuarantined(nodeId)) {
                firewallLogger.log(EVENT.CONNECTION_BLOCKED, nodeId, 'block',
                    'Node is quarantined');
                return { allowed: false, reason: 'quarantined' };
            }

            // 2. Blacklist check
            const blacklistEntry = this._blacklist.get(nodeId);
            if (blacklistEntry) {
                if (Date.now() < blacklistEntry.until) {
                    firewallLogger.log(EVENT.CONNECTION_BLOCKED, nodeId, 'block',
                        `Blacklisted: ${blacklistEntry.reason}`);
                    return { allowed: false, reason: 'blacklisted' };
                }
                // Blacklist expired — remove
                this._blacklist.delete(nodeId);
            }

            // 3. Reputation check — enforce minimum score for current shield level
            const score = reputationEngine.getScore(nodeId);
            if (score < this._minReputation) {
                firewallLogger.log(EVENT.CONNECTION_BLOCKED, nodeId, 'block',
                    `Reputation too low: ${score} < ${this._minReputation}`);
                return { allowed: false, reason: 'reputation_too_low' };
            }

            // 4. Hostile score → auto-quarantine
            if (reputationEngine.classify(nodeId) === 'hostile') {
                quarantineManager.autoQuarantine(nodeId, 'Hostile reputation score');
                return { allowed: false, reason: 'hostile_reputation' };
            }

            // 5. Geographic filtering (if configured and IP available)
            if (meta.country && this._blockedCountries.has(meta.country.toUpperCase())) {
                firewallLogger.log(EVENT.CONNECTION_BLOCKED, nodeId, 'block',
                    `Blocked country: ${meta.country}`);
                return { allowed: false, reason: 'geo_blocked' };
            }

            // 6. Global rate limit
            if (this._isGlobalLimited()) {
                firewallLogger.log(EVENT.CONNECTION_BLOCKED, nodeId, 'block',
                    'Global rate limit exceeded');
                return { allowed: false, reason: 'global_rate_limit' };
            }

            // 7. Per-node rate limit
            if (this._isNodeLimited(nodeId)) {
                this._recordViolation(nodeId);
                return { allowed: false, reason: 'per_node_rate_limit' };
            }

            // 8. Burst detection
            if (this._isBurstLimited(nodeId)) {
                firewallLogger.log(EVENT.CONNECTION_BLOCKED, nodeId, 'block',
                    'Burst rate limit exceeded');
                return { allowed: false, reason: 'burst_limit' };
            }

            // 9. Whitelist bypass — skip verification
            if (this._whitelist.has(nodeId)) {
                this._recordRequest(nodeId);
                return { allowed: true, reason: 'whitelisted' };
            }

            // 10. Trusted nodes bypass verification
            if (reputationEngine.classify(nodeId) === 'trusted') {
                this._recordRequest(nodeId);
                return { allowed: true, reason: 'trusted_reputation' };
            }

            // 11. Unknown node → challenge-response required
            if (!this._verificationQueue.has(nodeId)) {
                const nonce = this._generateNonce();
                this._verificationQueue.set(nodeId, {
                    nonce,
                    createdAt: Date.now(),
                    attempts: 0,
                });
                return {
                    allowed: false,
                    reason: 'verification_required',
                    requiresChallenge: true,
                    nonce,
                };
            }

            // Node is in verification queue but hasn't completed challenge
            const pending = this._verificationQueue.get(nodeId);
            if (Date.now() - pending.createdAt > this._config.handshakeTimeout) {
                // Timed out
                this._verificationQueue.delete(nodeId);
                reputationEngine.recordFailedHandshake(nodeId);
                firewallLogger.log(EVENT.CONNECTION_BLOCKED, nodeId, 'block',
                    'Handshake timeout');
                return { allowed: false, reason: 'handshake_timeout' };
            }

            // Still waiting for challenge response
            return {
                allowed: false,
                reason: 'awaiting_challenge_response',
                requiresChallenge: true,
                nonce: pending.nonce,
            };
        } catch (err) {
            // Fail CLOSED — errors must not become bypass vectors
            console.error('[FW-L1] evaluate error:', err.message);
            firewallLogger.log(EVENT.SELF_DEFENSE_ALERT, nodeId, 'block',
                'L1 evaluation error — failing closed', { error: err.message });
            return { allowed: false, reason: 'firewall_error_failclosed' };
        }
    }

    /**
     * Verify a node's challenge response.
     * The node must return the exact nonce that was sent to it.
     *
     * @param {string} nodeId
     * @param {string} responseNonce — the nonce the node sent back
     * @returns {{ verified: boolean, reason: string }}
     */
    verifyChallenge(nodeId, responseNonce) {
        const pending = this._verificationQueue.get(nodeId);
        if (!pending) {
            return { verified: false, reason: 'no_pending_challenge' };
        }

        pending.attempts++;

        // Timeout check
        if (Date.now() - pending.createdAt > this._config.handshakeTimeout) {
            this._verificationQueue.delete(nodeId);
            reputationEngine.recordFailedHandshake(nodeId);
            return { verified: false, reason: 'handshake_timeout' };
        }

        // Too many attempts
        if (pending.attempts > this._config.maxVerificationAttempts) {
            this._verificationQueue.delete(nodeId);
            reputationEngine.recordFailedHandshake(nodeId);
            firewallLogger.log(EVENT.CONNECTION_BLOCKED, nodeId, 'block',
                'Max verification attempts exceeded');
            return { verified: false, reason: 'max_attempts_exceeded' };
        }

        // Constant-time comparison to prevent timing attacks
        if (!_timingSafeEqual(responseNonce, pending.nonce)) {
            reputationEngine.recordFailedHandshake(nodeId);
            return { verified: false, reason: 'invalid_nonce' };
        }

        // Success — node is verified
        this._verificationQueue.delete(nodeId);
        this._recordRequest(nodeId);
        reputationEngine.recordSuccess(nodeId);
        return { verified: true, reason: 'challenge_passed' };
    }

    // ── Whitelist / Blacklist management ─────────────────────────

    /** Add a node to the permanent whitelist */
    addToWhitelist(nodeId) {
        this._whitelist.add(nodeId);
        this._blacklist.delete(nodeId); // remove from blacklist if present
    }

    /** Remove a node from the whitelist */
    removeFromWhitelist(nodeId) {
        this._whitelist.delete(nodeId);
    }

    /** Get the current whitelist */
    getWhitelist() {
        return [...this._whitelist];
    }

    /** Manually blacklist a node for a given duration */
    addToBlacklist(nodeId, reason, durationMs = CONNECTION.autoBlacklistDuration) {
        this._blacklist.set(nodeId, {
            until: Date.now() + durationMs,
            reason: String(reason).slice(0, 256),
        });
        this._whitelist.delete(nodeId);
        firewallLogger.log(EVENT.CONNECTION_BLOCKED, nodeId, 'block',
            `Blacklisted: ${reason}`, { duration: durationMs });
    }

    /** Remove a node from the blacklist */
    removeFromBlacklist(nodeId) {
        this._blacklist.delete(nodeId);
    }

    /** Get the current blacklist */
    getBlacklist() {
        const list = [];
        for (const [nodeId, data] of this._blacklist) {
            if (Date.now() < data.until) {
                list.push({ nodeId, ...data });
            }
        }
        return list;
    }

    // ── Geographic filtering ─────────────────────────────────────

    /** Block connections from a country (ISO 3166-1 alpha-2 code) */
    blockCountry(code) {
        this._blockedCountries.add(code.toUpperCase());
    }

    /** Unblock a country */
    unblockCountry(code) {
        this._blockedCountries.delete(code.toUpperCase());
    }

    /** Get blocked countries list */
    getBlockedCountries() {
        return [...this._blockedCountries];
    }

    /** Set all blocked countries at once (replaces current list) */
    setBlockedCountries(codes) {
        this._blockedCountries.clear();
        for (const c of codes) this._blockedCountries.add(c.toUpperCase());
    }

    // ── Rate limiting internals ──────────────────────────────────

    /** Record a successful request from a node (for rate tracking) */
    _recordRequest(nodeId) {
        const now = Date.now();

        // Global
        this._globalTimestamps.push(now);

        // Per-node
        if (!this._perNode.has(nodeId)) {
            this._perNode.set(nodeId, { timestamps: [], violations: 0, violationTimestamps: [] });
        }
        this._perNode.get(nodeId).timestamps.push(now);

        // Burst
        if (!this._burstTracker.has(nodeId)) {
            this._burstTracker.set(nodeId, { timestamps: [] });
        }
        this._burstTracker.get(nodeId).timestamps.push(now);
    }

    /** Check if the global rate limit is exceeded */
    _isGlobalLimited() {
        const now = Date.now();
        const windowStart = now - 60000;
        this._globalTimestamps = this._globalTimestamps.filter(t => t > windowStart);
        return this._globalTimestamps.length >= this._config.globalLimit;
    }

    /**
     * Check if a specific node has exceeded its per-node rate limit.
     * Suspicious nodes get a reduced limit (half the normal).
     */
    _isNodeLimited(nodeId) {
        const now = Date.now();
        const windowStart = now - 60000;
        const record = this._perNode.get(nodeId);
        if (!record) return false;

        record.timestamps = record.timestamps.filter(t => t > windowStart);

        // Suspicious nodes get reduced limits
        let limit = this._config.perNodeLimit;
        if (reputationEngine.classify(nodeId) === 'suspicious') {
            limit = Math.floor(limit / 2);
        }

        return record.timestamps.length >= limit;
    }

    /** Check if a node is in a burst (too many requests per second) */
    _isBurstLimited(nodeId) {
        const now = Date.now();
        const tracker = this._burstTracker.get(nodeId);
        if (!tracker) return false;

        const burstStart = now - this._config.burstWindow;
        tracker.timestamps = tracker.timestamps.filter(t => t > burstStart);

        const maxBurstTotal = this._config.burstLimit * (this._config.burstWindow / 1000);
        return tracker.timestamps.length >= maxBurstTotal;
    }

    /**
     * Record a rate-limit violation for a node.
     * If violations exceed the threshold → auto-blacklist.
     */
    _recordViolation(nodeId) {
        const now = Date.now();
        if (!this._perNode.has(nodeId)) {
            this._perNode.set(nodeId, { timestamps: [], violations: 0, violationTimestamps: [] });
        }
        const record = this._perNode.get(nodeId);
        record.violations++;
        record.violationTimestamps.push(now);

        // Count violations within the violation window
        const windowStart = now - this._config.violationWindow;
        record.violationTimestamps = record.violationTimestamps.filter(t => t > windowStart);

        reputationEngine.recordRateLimitViolation(nodeId);

        firewallLogger.log(EVENT.CONNECTION_BLOCKED, nodeId, 'block',
            `Rate limit violated (${record.violationTimestamps.length}/${this._config.autoBlacklistThreshold})`,
            { violations: record.violationTimestamps.length });

        // Auto-blacklist if threshold exceeded
        if (record.violationTimestamps.length >= this._config.autoBlacklistThreshold) {
            this.addToBlacklist(nodeId,
                'Auto-blacklisted: repeated rate limit violations',
                this._config.autoBlacklistDuration);
            record.violationTimestamps = []; // reset counter
        }
    }

    /** Generate a cryptographically secure nonce for challenge-response */
    _generateNonce() {
        const bytes = new Uint8Array(32);
        crypto.getRandomValues(bytes);
        return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
    }

    /** Periodic cleanup of stale data */
    _cleanup() {
        const now = Date.now();
        const MAX_TRACKED_NODES = 10000;

        // Purge expired blacklist entries
        for (const [nodeId, data] of this._blacklist) {
            if (now >= data.until) this._blacklist.delete(nodeId);
        }

        // Purge timed-out verification queue entries
        for (const [nodeId, data] of this._verificationQueue) {
            if (now - data.createdAt > this._config.handshakeTimeout * 2) {
                this._verificationQueue.delete(nodeId);
            }
        }

        // Purge stale per-node records (no activity in 10 minutes)
        const staleThreshold = now - 600000;
        for (const [nodeId, record] of this._perNode) {
            if (record.timestamps.length === 0 ||
                record.timestamps[record.timestamps.length - 1] < staleThreshold) {
                this._perNode.delete(nodeId);
                this._burstTracker.delete(nodeId);
            }
        }

        // Hard cap on Map sizes to prevent memory exhaustion from sustained attacks
        if (this._perNode.size > MAX_TRACKED_NODES) {
            const excess = this._perNode.size - MAX_TRACKED_NODES;
            const iter = this._perNode.keys();
            for (let i = 0; i < excess; i++) {
                const key = iter.next().value;
                this._perNode.delete(key);
                this._burstTracker.delete(key);
            }
        }
        if (this._blacklist.size > MAX_TRACKED_NODES) {
            // Evict oldest entries (first inserted = first in Map iteration order)
            let toRemove = this._blacklist.size - MAX_TRACKED_NODES;
            for (const key of this._blacklist.keys()) {
                if (toRemove-- <= 0) break;
                this._blacklist.delete(key);
            }
        }

        // Trim global timestamps
        const windowStart = now - 60000;
        this._globalTimestamps = this._globalTimestamps.filter(t => t > windowStart);
    }

    /** Get connection firewall stats for the status dashboard */
    getStats() {
        return {
            whitelistedNodes: this._whitelist.size,
            blacklistedNodes: this._blacklist.size,
            pendingVerification: this._verificationQueue.size,
            blockedCountries: this._blockedCountries.size,
            currentGlobalRate: this._globalTimestamps.length,
        };
    }
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

/**
 * Constant-time string comparison to prevent timing side-channels.
 * Compares character-by-character even if lengths differ.
 */
function _timingSafeEqual(a, b) {
    if (typeof a !== 'string' || typeof b !== 'string') return false;
    const maxLen = Math.max(a.length, b.length);
    let result = a.length === b.length ? 0 : 1;
    for (let i = 0; i < maxLen; i++) {
        const ca = i < a.length ? a.charCodeAt(i) : 0;
        const cb = i < b.length ? b.charCodeAt(i) : 0;
        result |= ca ^ cb;
    }
    return result === 0;
}

// ─── Singleton Export ────────────────────────────────────────────────────────

export const connectionFirewall = new ConnectionFirewall();
export default connectionFirewall;
