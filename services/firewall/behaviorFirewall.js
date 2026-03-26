/**
 * behaviorFirewall.js — Layer 3: Behavior Analysis
 * ===================================================
 *
 * Third and deepest defense layer. Analyzes traffic patterns over time
 * to detect threats that individual packet inspection cannot catch.
 * Responsible for:
 *
 *   10. Traffic anomaly detection (baseline vs. current)
 *   11. Timing analysis detection (automated/surveillance traffic)
 *   12. Session hijack detection (IP/fingerprint changes mid-session)
 *   13. Distributed attack detection (DDoS-like connection spikes)
 *   14. Mesh poisoning detection (false routing information)
 *
 * This layer maintains rolling windows of traffic data per node and
 * global connection metrics.
 */

import { BEHAVIOR } from './firewallConfig.js';
import { firewallLogger, EVENT } from './firewallLogger.js';
import { reputationEngine } from './reputationEngine.js';
import { quarantineManager } from './quarantine.js';

// ─── BehaviorFirewall ────────────────────────────────────────────────────────

class BehaviorFirewall {
    constructor() {
        // ── 10. Traffic anomaly detection ──
        /**
         * Per-node traffic tracker.
         * nodeId → { timestamps: number[], byteCounts: number[], endpoints: Set<string> }
         * @type {Map<string, object>}
         */
        this._trafficProfiles = new Map();

        // ── 11. Timing analysis detection ──
        /**
         * Per-node packet arrival intervals for timing analysis.
         * nodeId → { intervals: number[], lastArrival: number, flagged: boolean }
         * @type {Map<string, object>}
         */
        this._timingProfiles = new Map();

        // ── 12. Session hijack detection ──
        /**
         * Session metadata tracker.
         * nodeId → { ip: string, fingerprint: string, establishedAt: number }
         * @type {Map<string, object>}
         */
        this._sessions = new Map();

        // ── 13. DDoS detection ──
        /** Global connection rate: array of timestamps */
        this._connectionTimestamps = [];
        /** Baseline average connections per detection window */
        this._connectionBaseline = 0;
        /** Whether emergency mode is active */
        this._emergencyMode = false;
        /** When emergency mode was activated */
        this._emergencyActivatedAt = 0;

        // ── 14. Mesh poisoning detection ──
        /**
         * Routing table change tracker.
         * nodeId → { changeCount: number, firstChangeAt: number }
         * @type {Map<string, object>}
         */
        this._routingChanges = new Map();
        /** Total routing changes in current window */
        this._totalRoutingChanges = 0;

        // ── Config (shield-level aware) ──
        this._config = { ...BEHAVIOR };

        // ── Timers ──
        this._cleanupTimer = null;
        this._baselineTimer = null;
    }

    // ── Lifecycle ────────────────────────────────────────────────

    init() {
        // Cleanup stale data every 60 seconds
        this._cleanupTimer = setInterval(() => this._cleanup(), 60000);
        // Recalculate connection baseline every 5 minutes
        this._baselineTimer = setInterval(() => this._recalcBaseline(), 300000);
    }

    shutdown() {
        if (this._cleanupTimer) clearInterval(this._cleanupTimer);
        if (this._baselineTimer) clearInterval(this._baselineTimer);
        this._cleanupTimer = null;
        this._baselineTimer = null;
    }

    /**
     * Update config values when shield level changes.
     * @param {object} behaviorConfig — merged BEHAVIOR config
     */
    updateConfig(behaviorConfig) {
        this._config = { ...BEHAVIOR, ...behaviorConfig };
    }

    // ── Main entry point ─────────────────────────────────────────

    /**
     * Analyze a traffic event from a node. Called after Layer 1 and 2 pass.
     * Feeds into all behavior detection subsystems.
     *
     * @param {string} nodeId — source node
     * @param {object} meta — { ip, fingerprint, endpoint, byteCount }
     * @returns {{ allowed: boolean, reason: string, addNoise?: boolean, noiseMs?: number }}
     */
    analyze(nodeId, meta = {}) {
        try {
            // 13. DDoS check (global) — runs first
            const ddosResult = this._checkDDoS(nodeId);
            if (!ddosResult.allowed) return ddosResult;

            // 12. Session hijack detection
            if (this._config.enableSessionProtection && meta.ip) {
                const sessionResult = this._checkSessionHijack(nodeId, meta);
                if (!sessionResult.allowed) return sessionResult;
            }

            // Record traffic data for this node
            this._recordTraffic(nodeId, meta);

            // 10. Traffic anomaly detection
            const anomalyResult = this._checkAnomaly(nodeId);
            if (!anomalyResult.allowed) return anomalyResult;

            // 11. Timing analysis
            const timingResult = this._checkTimingAnalysis(nodeId);
            if (timingResult.addNoise) {
                // Don't block — just flag that responses should be delayed
                return {
                    allowed: true,
                    reason: 'timing_noise_added',
                    addNoise: true,
                    noiseMs: timingResult.noiseMs,
                };
            }

            return { allowed: true, reason: 'behavior_clean' };

        } catch (err) {
            // Fail CLOSED — errors must not become bypass vectors
            console.error('[FW-L3] analyze error:', err.message);
            return { allowed: false, reason: 'behavior_error_failclosed' };
        }
    }

    // ── 10. Traffic Anomaly Detection ─────────────────────────────

    /**
     * Record a traffic event for a node (for baseline computation).
     */
    _recordTraffic(nodeId, meta) {
        if (!this._trafficProfiles.has(nodeId)) {
            this._trafficProfiles.set(nodeId, {
                timestamps: [],
                byteCounts: [],
                endpoints: new Set(),
            });
        }
        const profile = this._trafficProfiles.get(nodeId);
        const now = Date.now();
        profile.timestamps.push(now);
        profile.byteCounts.push(meta.byteCount || 0);
        if (meta.endpoint) profile.endpoints.add(meta.endpoint);

        // Record global connection timestamp for DDoS detection
        this._connectionTimestamps.push(now);
    }

    /**
     * Check if a node's current traffic rate is anomalous compared
     * to its rolling baseline.
     */
    _checkAnomaly(nodeId) {
        const profile = this._trafficProfiles.get(nodeId);
        if (!profile || profile.timestamps.length < 10) {
            return { allowed: true, reason: 'insufficient_data' };
        }

        const now = Date.now();

        // Compute baseline: average packets per detection window over the baseline window
        const baselineStart = now - this._config.baselineWindow;
        const baselineTimestamps = profile.timestamps.filter(t => t > baselineStart);
        const baselineWindows = this._config.baselineWindow / this._config.detectionWindow;
        const baselineRate = baselineTimestamps.length / Math.max(baselineWindows, 1);

        // Compute current rate in the detection window
        const detectionStart = now - this._config.detectionWindow;
        const currentRate = profile.timestamps.filter(t => t > detectionStart).length;

        // Skip anomaly detection if baseline is too low (node is new)
        if (baselineRate < 5) {
            return { allowed: true, reason: 'baseline_too_low' };
        }

        // 10x baseline → auto-quarantine
        if (currentRate >= baselineRate * this._config.anomalyMultiplierBlock) {
            quarantineManager.autoQuarantine(nodeId,
                `Traffic anomaly: ${currentRate} packets in ${this._config.detectionWindow / 60000}min (baseline: ${Math.round(baselineRate)})`);
            firewallLogger.log(EVENT.ANOMALY_DETECTED, nodeId, 'quarantine',
                `Traffic spike ${Math.round(currentRate / baselineRate)}x baseline → quarantined`, {
                    currentRate, baselineRate: Math.round(baselineRate),
                    multiplier: Math.round(currentRate / baselineRate),
                });
            return { allowed: false, reason: 'traffic_anomaly_quarantined' };
        }

        // 5x baseline → warning flag
        if (currentRate >= baselineRate * this._config.anomalyMultiplierWarn) {
            reputationEngine.applyDelta(nodeId, -5, 'traffic_anomaly_warning');
            firewallLogger.log(EVENT.ANOMALY_DETECTED, nodeId, 'flag',
                `Traffic spike ${Math.round(currentRate / baselineRate)}x baseline — monitoring`, {
                    currentRate, baselineRate: Math.round(baselineRate),
                });
        }

        return { allowed: true, reason: 'traffic_normal' };
    }

    // ── 11. Timing Analysis Detection ────────────────────────────

    /**
     * Monitor for suspiciously regular packet intervals.
     * Automated/surveillance traffic tends to arrive at exact intervals.
     */
    _checkTimingAnalysis(nodeId) {
        const now = Date.now();

        if (!this._timingProfiles.has(nodeId)) {
            this._timingProfiles.set(nodeId, {
                intervals: [],
                lastArrival: now,
                flagged: false,
            });
            return { addNoise: false };
        }

        const profile = this._timingProfiles.get(nodeId);
        const interval = now - profile.lastArrival;
        profile.lastArrival = now;
        profile.intervals.push(interval);

        // Only analyze after collecting enough samples in the detection window
        const windowStart = now - this._config.timingDetectionWindow;
        // Keep only recent intervals (approximate by keeping last N)
        if (profile.intervals.length > 200) {
            profile.intervals = profile.intervals.slice(-200);
        }

        if (profile.intervals.length < 20) {
            return { addNoise: false };
        }

        // Compute how many intervals are "suspiciously similar"
        // Group intervals by similarity (within timingVarianceThreshold ms)
        const sorted = [...profile.intervals].sort((a, b) => a - b);
        const median = sorted[Math.floor(sorted.length / 2)];

        // Count how many intervals are within threshold of the median
        const threshold = this._config.timingVarianceThreshold;
        const regularCount = profile.intervals.filter(
            i => Math.abs(i - median) <= threshold
        ).length;

        const regularPercent = (regularCount / profile.intervals.length) * 100;

        if (regularPercent >= this._config.timingRegularityPercent) {
            // Timing analysis detected — add noise to responses
            profile.flagged = true;
            const noiseMs = this._config.noiseDelayMin +
                Math.floor(Math.random() * (this._config.noiseDelayMax - this._config.noiseDelayMin));

            if (!profile._lastLogged || now - profile._lastLogged > 60000) {
                firewallLogger.log(EVENT.TIMING_ANALYSIS, nodeId, 'flag',
                    `Regular timing detected: ${Math.round(regularPercent)}% of packets at ~${Math.round(median)}ms intervals`, {
                        regularPercent: Math.round(regularPercent),
                        medianInterval: Math.round(median),
                        noiseMs,
                    });
                profile._lastLogged = now;
            }

            return { addNoise: true, noiseMs };
        }

        profile.flagged = false;
        return { addNoise: false };
    }

    // ── 12. Session Hijack Detection ─────────────────────────────

    /**
     * Track session metadata (IP + device fingerprint). If either changes
     * mid-session, flag as potential hijack.
     */
    _checkSessionHijack(nodeId, meta) {
        const existing = this._sessions.get(nodeId);

        if (!existing) {
            // First time seeing this node — establish session
            this._sessions.set(nodeId, {
                ip: meta.ip,
                fingerprint: meta.fingerprint || null,
                establishedAt: Date.now(),
            });
            return { allowed: true, reason: 'session_established' };
        }

        // Check for IP change
        if (meta.ip && existing.ip && meta.ip !== existing.ip) {
            firewallLogger.log(EVENT.SESSION_HIJACK, nodeId, 'block',
                `IP changed mid-session: ${_truncate(existing.ip)} → ${_truncate(meta.ip)}`, {
                    oldIp: _truncate(existing.ip),
                    newIp: _truncate(meta.ip),
                    sessionAge: Date.now() - existing.establishedAt,
                });

            reputationEngine.recordAttackPattern(nodeId, 'session_hijack');

            // Invalidate the session — node must re-authenticate
            this._sessions.delete(nodeId);

            return {
                allowed: false,
                reason: 'Session hijack detected: IP changed. Re-authentication required.',
            };
        }

        // Check for fingerprint change
        if (meta.fingerprint && existing.fingerprint &&
            meta.fingerprint !== existing.fingerprint) {
            firewallLogger.log(EVENT.SESSION_HIJACK, nodeId, 'block',
                'Device fingerprint changed mid-session', {
                    sessionAge: Date.now() - existing.establishedAt,
                });

            reputationEngine.recordAttackPattern(nodeId, 'session_hijack_fingerprint');
            this._sessions.delete(nodeId);

            return {
                allowed: false,
                reason: 'Session hijack detected: device fingerprint changed.',
            };
        }

        return { allowed: true, reason: 'session_valid' };
    }

    // ── 13. Distributed Attack Detection (DDoS) ──────────────────

    /**
     * Detect DDoS-like connection spikes from multiple nodes.
     * Activates emergency mode if connections spike above the threshold.
     */
    _checkDDoS(nodeId) {
        const now = Date.now();

        // Check if emergency mode should be deactivated
        if (this._emergencyMode) {
            if (now - this._emergencyActivatedAt > this._config.emergencyDuration) {
                this._emergencyMode = false;
                firewallLogger.log(EVENT.EMERGENCY_MODE, null, 'allow',
                    'Emergency mode deactivated — traffic normalized');
            } else {
                // Emergency mode active: only allow trusted/whitelisted nodes
                const classification = reputationEngine.classify(nodeId);
                if (classification !== 'trusted') {
                    return {
                        allowed: false,
                        reason: 'Emergency mode: only trusted nodes allowed',
                    };
                }
                return { allowed: true, reason: 'emergency_trusted_pass' };
            }
        }

        // Count unique nodes in the detection window
        const windowStart = now - this._config.detectionWindow;
        const recentConnections = this._connectionTimestamps.filter(t => t > windowStart);

        if (this._connectionBaseline > 0 &&
            recentConnections.length >= this._connectionBaseline * this._config.ddosMultiplier) {
            // Activate emergency mode
            this._emergencyMode = true;
            this._emergencyActivatedAt = now;

            firewallLogger.log(EVENT.DDOS_DETECTED, null, 'alert',
                `DDoS detected: ${recentConnections.length} connections in ${this._config.detectionWindow / 60000}min (baseline: ${Math.round(this._connectionBaseline)})`, {
                    currentRate: recentConnections.length,
                    baseline: Math.round(this._connectionBaseline),
                    multiplier: Math.round(recentConnections.length / this._connectionBaseline),
                });

            // In emergency mode, check if this specific node is trusted
            const classification = reputationEngine.classify(nodeId);
            if (classification !== 'trusted') {
                return {
                    allowed: false,
                    reason: 'Emergency mode activated: only trusted nodes allowed',
                };
            }
        }

        return { allowed: true, reason: 'no_ddos' };
    }

    // ── 14. Mesh Poisoning Detection ─────────────────────────────

    /**
     * Detect if a single node is injecting false routing information.
     * Call this whenever a routing table change is triggered by a node.
     *
     * @param {string} nodeId — the node that proposed the routing change
     * @param {object} routingChange — { type: 'add'|'remove'|'update', target, via }
     * @returns {{ allowed: boolean, reason: string }}
     */
    checkRoutingChange(nodeId, routingChange) {
        try {
            const now = Date.now();
            this._totalRoutingChanges++;

            if (!this._routingChanges.has(nodeId)) {
                this._routingChanges.set(nodeId, { changeCount: 0, firstChangeAt: now });
            }
            const record = this._routingChanges.get(nodeId);
            record.changeCount++;

            // Check if this node has caused too many routing changes
            const windowStart = now - this._config.meshPoisonWindow;
            if (record.firstChangeAt < windowStart) {
                // Reset window
                record.changeCount = 1;
                record.firstChangeAt = now;
                this._totalRoutingChanges = 1;
            }

            // Calculate percentage of total changes from this node
            if (this._totalRoutingChanges > 10) { // need minimum sample
                const pct = (record.changeCount / this._totalRoutingChanges) * 100;
                if (pct > this._config.meshPoisonThreshold) {
                    // Mesh poisoning detected
                    quarantineManager.autoQuarantine(nodeId,
                        `Mesh poisoning: ${Math.round(pct)}% of routing changes from this node`);

                    firewallLogger.log(EVENT.MESH_POISON_DETECTED, nodeId, 'quarantine',
                        `Mesh poisoning detected: ${Math.round(pct)}% of routing changes`, {
                            nodeChanges: record.changeCount,
                            totalChanges: this._totalRoutingChanges,
                            percentage: Math.round(pct),
                        });

                    return {
                        allowed: false,
                        reason: `Mesh poisoning detected: node responsible for ${Math.round(pct)}% of routing changes`,
                    };
                }
            }

            return { allowed: true, reason: 'routing_change_ok' };
        } catch (err) {
            console.error('[FW-L3] checkRoutingChange error:', err.message);
            return { allowed: false, reason: 'routing_check_error_failclosed' };
        }
    }

    // ── Public state queries ─────────────────────────────────────

    /** Check if emergency mode is currently active */
    isEmergencyMode() {
        return this._emergencyMode;
    }

    /** Check if a node has been flagged for timing analysis */
    isTimingFlagged(nodeId) {
        const profile = this._timingProfiles.get(nodeId);
        return profile?.flagged || false;
    }

    /** Manually clear a session (force re-authentication) */
    clearSession(nodeId) {
        this._sessions.delete(nodeId);
    }

    /** Get stats for the status dashboard */
    getStats() {
        return {
            trackedNodes: this._trafficProfiles.size,
            activeSessions: this._sessions.size,
            emergencyMode: this._emergencyMode,
            connectionBaseline: Math.round(this._connectionBaseline),
            timingFlagged: [...this._timingProfiles.values()].filter(p => p.flagged).length,
        };
    }

    // ── Internal ─────────────────────────────────────────────────

    /** Recalculate the connection baseline (called periodically) */
    _recalcBaseline() {
        const now = Date.now();
        const windowStart = now - this._config.baselineWindow;
        this._connectionTimestamps = this._connectionTimestamps.filter(t => t > windowStart);

        const windows = this._config.baselineWindow / this._config.detectionWindow;
        this._connectionBaseline = this._connectionTimestamps.length / Math.max(windows, 1);
    }

    /** Cleanup stale per-node data */
    _cleanup() {
        const now = Date.now();
        const staleThreshold = now - this._config.baselineWindow;
        const MAX_TRACKED_NODES = 10000;

        // Purge traffic profiles with no recent activity
        for (const [nodeId, profile] of this._trafficProfiles) {
            profile.timestamps = profile.timestamps.filter(t => t > staleThreshold);
            if (profile.timestamps.length === 0) {
                this._trafficProfiles.delete(nodeId);
            }
        }

        // Purge old timing data
        for (const [nodeId, profile] of this._timingProfiles) {
            if (now - profile.lastArrival > this._config.timingDetectionWindow * 2) {
                this._timingProfiles.delete(nodeId);
            }
        }

        // Hard cap on Map sizes to prevent memory exhaustion
        for (const map of [this._trafficProfiles, this._timingProfiles, this._sessions]) {
            if (map.size > MAX_TRACKED_NODES) {
                let toRemove = map.size - MAX_TRACKED_NODES;
                for (const key of map.keys()) {
                    if (toRemove-- <= 0) break;
                    map.delete(key);
                }
            }
        }

        // Trim global connection timestamps
        this._connectionTimestamps = this._connectionTimestamps.filter(
            t => t > now - this._config.baselineWindow
        );
        // Cap global timestamps array length
        if (this._connectionTimestamps.length > 100000) {
            this._connectionTimestamps = this._connectionTimestamps.slice(-50000);
        }

        // Purge expired routing change records
        const poisonWindowStart = now - this._config.meshPoisonWindow;
        for (const [nodeId, record] of this._routingChanges) {
            if (record.firstChangeAt < poisonWindowStart) {
                this._routingChanges.delete(nodeId);
            }
        }
    }
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

/** Truncate an IP address for safe logging (no full IPs in logs) */
function _truncate(str) {
    if (!str || typeof str !== 'string') return 'unknown';
    if (str.length <= 8) return str;
    return str.slice(0, 8) + '***';
}

// ─── Singleton Export ────────────────────────────────────────────────────────

export const behaviorFirewall = new BehaviorFirewall();
export default behaviorFirewall;
