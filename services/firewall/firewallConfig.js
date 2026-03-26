/**
 * firewallConfig.js — All configurable constants for the GhostNet Firewall
 * =========================================================================
 *
 * Every tunable value in the firewall system lives here. No magic numbers
 * anywhere else. Values are grouped by the layer/module that consumes them.
 *
 * Shield-level overrides are in SHIELD_PROFILES at the bottom — when the
 * user activates a Ghost Shield level, the firewall merges the corresponding
 * profile on top of these defaults.
 */

// ─── Layer 1: Connection Firewall ────────────────────────────────────────────

export const CONNECTION = Object.freeze({
    /** Seconds a node has to complete the challenge-response handshake */
    handshakeTimeout: 5000,
    /** Max failed handshakes before permanent reject */
    maxVerificationAttempts: 3,
    /** Per-node: max requests per minute (baseline) */
    perNodeLimit: 60,
    /** Global: max total incoming requests per minute */
    globalLimit: 500,
    /** Burst: max requests per second for short burst */
    burstLimit: 10,
    /** Burst: how long the burst window lasts (ms) */
    burstWindow: 5000,
    /** How many rate-limit violations before auto-blacklist */
    autoBlacklistThreshold: 3,
    /** How long an auto-blacklisted node stays banned (ms) — 30 min */
    autoBlacklistDuration: 1800000,
    /** Window to count rate-limit violations (ms) — 10 min */
    violationWindow: 600000,
});

// ─── Layer 2: Packet Firewall ────────────────────────────────────────────────

export const PACKET = Object.freeze({
    /** Max message payload in bytes — 1 MB */
    maxMessageSize: 1 * 1024 * 1024,
    /** Max vault file payload in bytes — 50 MB */
    maxFileSize: 50 * 1024 * 1024,
    /** Enable injection pattern detection */
    enableInjectionDetection: true,
    /** Rolling nonce cache capacity */
    nonceCacheSize: 10000,
    /** How long nonces are remembered (ms) — 1 hour */
    nonceCacheTTL: 3600000,
    /** Max age of a packet timestamp before it's rejected (ms) — 30 s */
    maxTimestampAge: 30000,
    /** Reputation penalty for a missing/invalid packet field */
    malformedPenalty: 5,
    /** Reputation penalty for detected injection */
    injectionPenalty: 30,
    /** Reputation penalty for suspicious deep-inspection result */
    suspiciousPenalty: 5,
});

/**
 * Injection detection patterns — compiled once at import time.
 * Each entry: { name, regex, severity }
 * severity: 'critical' (block + blacklist), 'high' (block), 'medium' (flag)
 */
export const INJECTION_PATTERNS = Object.freeze([
    // SQL injection
    { name: 'sql_union',       regex: /\bUNION\s+(ALL\s+)?SELECT\b/i,              severity: 'critical' },
    { name: 'sql_drop',        regex: /\bDROP\s+(TABLE|DATABASE|INDEX)\b/i,         severity: 'critical' },
    { name: 'sql_insert',      regex: /\bINSERT\s+INTO\b/i,                        severity: 'high' },
    { name: 'sql_delete',      regex: /\bDELETE\s+FROM\b/i,                        severity: 'high' },
    { name: 'sql_comment',     regex: /--\s|\/\*[\s\S]*?\*\//,                     severity: 'medium' },
    { name: 'sql_semicolon',   regex: /;\s*(DROP|DELETE|UPDATE|INSERT|ALTER)\b/i,   severity: 'critical' },
    // XSS
    { name: 'xss_script',      regex: /<\s*script[\s>]/i,                          severity: 'critical' },
    { name: 'xss_event',       regex: /\bon(click|error|load|mouseover|focus)\s*=/i, severity: 'high' },
    { name: 'xss_javascript',  regex: /javascript\s*:/i,                           severity: 'critical' },
    { name: 'xss_eval',        regex: /\beval\s*\(/i,                              severity: 'high' },
    { name: 'xss_iframe',      regex: /<\s*iframe[\s>]/i,                          severity: 'high' },
    { name: 'xss_svg_onload',  regex: /<\s*svg[^>]*\bon\w+\s*=/i,                 severity: 'critical' },
    // Command injection
    { name: 'cmd_pipe',        regex: /\|\s*\w/,                                   severity: 'medium' },
    { name: 'cmd_chain',       regex: /&&\s*\w/,                                   severity: 'medium' },
    { name: 'cmd_subshell',    regex: /\$\(.*\)/,                                  severity: 'high' },
    { name: 'cmd_backtick',    regex: /`[^`]+`/,                                   severity: 'high' },
    // Path traversal
    { name: 'path_traversal',  regex: /(\.\.[\/\\]){2,}/,                          severity: 'critical' },
    { name: 'path_encoded',    regex: /%2e%2e[%2f%5c]/i,                           severity: 'critical' },
    { name: 'path_null_byte',  regex: /%00/,                                       severity: 'critical' },
]);

// ─── Layer 3: Behavior Firewall ──────────────────────────────────────────────

export const BEHAVIOR = Object.freeze({
    /** Traffic spike multiplier that triggers a warning */
    anomalyMultiplierWarn: 5,
    /** Traffic spike multiplier that triggers auto-quarantine */
    anomalyMultiplierBlock: 10,
    /** Window (ms) for computing the traffic baseline — 1 hour */
    baselineWindow: 3600000,
    /** Window (ms) for detecting a traffic spike — 5 min */
    detectionWindow: 300000,
    /** Timing variance threshold (ms) — packets arriving within this of each
     *  other are "suspiciously regular" */
    timingVarianceThreshold: 50,
    /** Window for timing-analysis detection (ms) — 5 min */
    timingDetectionWindow: 300000,
    /** Percentage of packets at identical intervals to trigger flag */
    timingRegularityPercent: 80,
    /** Min random delay added to responses for flagged timing nodes (ms) */
    noiseDelayMin: 200,
    /** Max random delay added to responses for flagged timing nodes (ms) */
    noiseDelayMax: 1000,
    /** Enable session-hijack detection */
    enableSessionProtection: true,
    /** DDoS multiplier over normal connection rate */
    ddosMultiplier: 3,
    /** How long emergency mode lasts (ms) — 10 min */
    emergencyDuration: 600000,
    /** % of routing table changes from one node to flag mesh poisoning */
    meshPoisonThreshold: 30,
    /** Window for mesh poisoning detection (ms) — 10 min */
    meshPoisonWindow: 600000,
});

// ─── Reputation Engine ──────────────────────────────────────────────────────

export const REPUTATION = Object.freeze({
    /** Starting trust score for every new node */
    initialScore: 50,
    /** Score at/above which a node is "trusted" */
    trustedThreshold: 80,
    /** Score at/below which a node is "suspicious" */
    suspiciousThreshold: 20,
    /** Score at/below which a node is "hostile" → auto-quarantine */
    hostileThreshold: 0,
    /** Max score cap */
    maxScore: 100,
    /** Min score floor */
    minScore: -50,

    // ── Score adjustments ──
    successfulExchange: 1,
    consistentUptime: 2,       // per hour of uptime
    verifiedGhostTag: 10,
    failedHandshake: -5,
    rateLimitViolation: -10,
    malformedPacket: -15,
    attackPattern: -30,
});

// ─── Quarantine ─────────────────────────────────────────────────────────────

export const QUARANTINE = Object.freeze({
    /** First auto-quarantine duration (ms) — 1 hour */
    firstDuration: 3600000,
    /** Second auto-quarantine duration (ms) — 24 hours */
    secondDuration: 86400000,
    /** Max auto-quarantines before permanent ban */
    maxAutoQuarantines: 3,
});

// ─── Self-Defense ───────────────────────────────────────────────────────────

export const SELF_DEFENSE = Object.freeze({
    /** How often to recheck firewall module integrity (ms) — 5 min */
    integrityCheckInterval: 300000,
    /** Require a PIN for disabling critical features */
    requirePinForCriticalChanges: true,
    /** Max incorrect PIN attempts before lockout */
    maxPinAttempts: 5,
    /** Lockout duration after max PIN attempts (ms) — 5 min */
    pinLockoutDuration: 300000,
    /** Watchdog: how often to check if core is alive (ms) */
    watchdogInterval: 10000,
    /** How many crashes in the crash window triggers safe mode */
    maxCrashes: 3,
    /** Window for counting crashes (ms) — 5 min */
    crashWindow: 300000,
});

// ─── Audit Logger ───────────────────────────────────────────────────────────

export const LOGGER = Object.freeze({
    /** Max log size in bytes before rotation — 10 MB */
    maxLogSize: 10 * 1024 * 1024,
    /** Number of rotated log files to keep */
    maxLogFiles: 2,
    /** Storage key prefix */
    storagePrefix: 'ghostnet_fw_',
});

// ─── Ghost Shield Integration ───────────────────────────────────────────────
/**
 * Each shield level overrides specific config values. The firewall merges
 * the profile on top of the defaults when the shield level changes.
 *
 * Fields listed here are the ONLY values that change per level.
 * Anything not listed keeps its default from the objects above.
 */
export const SHIELD_PROFILES = Object.freeze({
    off: {
        perNodeLimit: 60,
        minReputationForAccess: 0,        // anyone can connect
        anomalyMultiplierWarn: 5,
        anomalyMultiplierBlock: 10,
        ddosMultiplier: 3,
        watchdogInterval: 10000,
        integrityCheckInterval: 300000,
        addTimingNoise: false,
    },
    stealth: {
        perNodeLimit: 30,
        minReputationForAccess: 50,       // neutral+ only
        anomalyMultiplierWarn: 5,
        anomalyMultiplierBlock: 10,
        ddosMultiplier: 3,
        watchdogInterval: 10000,
        integrityCheckInterval: 300000,
        addTimingNoise: false,
    },
    ghost: {
        perNodeLimit: 15,
        minReputationForAccess: 80,       // trusted only
        anomalyMultiplierWarn: 3,
        anomalyMultiplierBlock: 6,
        ddosMultiplier: 3,
        watchdogInterval: 10000,
        integrityCheckInterval: 300000,
        addTimingNoise: false,
    },
    phantom: {
        perNodeLimit: 5,
        minReputationForAccess: 90,       // highly trusted only
        anomalyMultiplierWarn: 2,
        anomalyMultiplierBlock: 4,
        ddosMultiplier: 2,
        watchdogInterval: 5000,
        integrityCheckInterval: 60000,
        addTimingNoise: true,
    },
});

/**
 * Return the active config for a given shield level, with all defaults
 * merged in. This is what the rest of the firewall reads at runtime.
 *
 * @param {'off'|'stealth'|'ghost'|'phantom'} level
 * @returns {object} merged config snapshot
 */
export function resolveConfig(level = 'off') {
    const profile = SHIELD_PROFILES[level] || SHIELD_PROFILES.off;
    return {
        connection: { ...CONNECTION, perNodeLimit: profile.perNodeLimit },
        packet: { ...PACKET },
        behavior: {
            ...BEHAVIOR,
            anomalyMultiplierWarn: profile.anomalyMultiplierWarn,
            anomalyMultiplierBlock: profile.anomalyMultiplierBlock,
            ddosMultiplier: profile.ddosMultiplier,
        },
        reputation: { ...REPUTATION },
        quarantine: { ...QUARANTINE },
        selfDefense: {
            ...SELF_DEFENSE,
            watchdogInterval: profile.watchdogInterval,
            integrityCheckInterval: profile.integrityCheckInterval,
        },
        logger: { ...LOGGER },
        shieldLevel: level,
        minReputationForAccess: profile.minReputationForAccess,
        addTimingNoise: profile.addTimingNoise,
    };
}
