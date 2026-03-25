/**
 * Ghost Shield Configuration
 * All tunable constants for the 3 cloaking levels + Signal Intelligence.
 * Touch ONLY this file to adjust thresholds — no magic numbers in engine code.
 */

const ShieldConfig = {

    // ─── Level 1: STEALTH ────────────────────────────────────────
    stealth: {
        /** DNS-over-HTTPS resolver endpoint */
        dohUrl: 'https://cloudflare-dns.com/dns-query',
        /** Fallback DoH resolver */
        dohFallbackUrl: 'https://dns.google/dns-query',
        /** BLE scan duration (ms) before stopping advertising */
        bleScanTimeout: 5000,
    },

    // ─── Level 2: GHOST ──────────────────────────────────────────
    ghost: {
        /** Min padding bytes added to outgoing packets */
        paddingMinBytes: 128,
        /** Max padding bytes added to outgoing packets */
        paddingMaxBytes: 512,
        /** Min random delay injected before send (ms) */
        timingDelayMinMs: 100,
        /** Max random delay injected before send (ms) */
        timingDelayMaxMs: 2000,
        /** Interval between dummy/noise packets (ms) */
        dummyPacketIntervalMs: 3000,
        /** Size of dummy noise packets (bytes) */
        dummyPacketSize: 256,
    },

    // ─── Level 3: PHANTOM ────────────────────────────────────────
    phantom: {
        /** Interval between fake BLE decoy advertisements (ms) */
        decoyIntervalMs: 5000,
        /** Number of fake BLE device profiles to cycle through */
        decoyProfileCount: 6,
        /** MAC rotation interval (ms) — default 5 minutes */
        macRotationIntervalMs: 300000,
        /** Forced mesh hop count — overrides GhostMesh.MAX_HOPS */
        forcedMaxHops: 7,
        /** Decoy BLE service UUIDs to advertise (common device types) */
        decoyServiceUUIDs: [
            '0000fe2c-0000-1000-8000-00805f9b34fb', // Apple Nearby
            '0000fd6f-0000-1000-8000-00805f9b34fb', // Exposure Notification
            '0000180d-0000-1000-8000-00805f9b34fb', // Heart Rate
            '0000180f-0000-1000-8000-00805f9b34fb', // Battery Service
            '00001812-0000-1000-8000-00805f9b34fb', // HID
            '0000110b-0000-1000-8000-00805f9b34fb', // A2DP Audio
        ],
        /** Decoy device name pool */
        decoyNames: [
            'AirPods Pro', 'Galaxy Buds2', 'Pixel Buds', 'Fitbit Charge',
            'Apple Watch', 'Mi Band 7', 'JBL Flip 6', 'Bose QC45',
            'Surface Earbuds', 'Sony WH-1000XM5', 'Tile Mate', 'AirTag'
        ],
    },

    // ─── Signal Intelligence ─────────────────────────────────────
    signalIntel: {
        /** How often to run a full hardware scan (ms) */
        scanIntervalMs: 15000,
        /** BLE scan window duration per cycle (ms) */
        bleScanDurationMs: 8000,
        /** Signal considered stale after this many ms */
        signalStaleMs: 120000,
        /** RSSI threshold for "dangerously close" classification */
        dangerRssiThreshold: -30,
    },

    // ─── Persistence Keys (localStorage) ─────────────────────────
    storage: {
        shieldStateKey: 'ghostshield_state',
        blockedMacsKey: 'ghostshield_blocked_macs',
    },
};

// Freeze to prevent runtime mutation
Object.freeze(ShieldConfig);
Object.freeze(ShieldConfig.stealth);
Object.freeze(ShieldConfig.ghost);
Object.freeze(ShieldConfig.phantom);
Object.freeze(ShieldConfig.signalIntel);
Object.freeze(ShieldConfig.storage);

window.ShieldConfig = ShieldConfig;
