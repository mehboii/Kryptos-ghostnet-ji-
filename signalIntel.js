/**
 * Signal Intelligence Service — Real BLE/WiFi Hardware Bridge
 * Connects GhostRadar (hardware scanner) → SignalIntelligence (threat engine).
 *
 * This service runs periodic scans via GhostRadar, feeds results into
 * SignalIntelligence for classification, and dispatches UI update events.
 */

class SignalIntelService {
    constructor() {
        this._scanTimer = null;
        this._active = false;
        this._lastScanResults = [];
    }

    /**
     * Start the signal intelligence scanning loop.
     * Requires window.GhostRadar and window.SignalIntelligence to be loaded.
     */
    start() {
        if (this._active) return;
        this._active = true;

        const cfg = window.ShieldConfig;
        const intervalMs = cfg ? cfg.signalIntel.scanIntervalMs : 15000;

        this._log('Signal Intelligence service started');

        // Run initial scan immediately
        this._runScan();

        // Then repeat on interval
        this._scanTimer = setInterval(() => {
            if (this._active) this._runScan();
        }, intervalMs);
    }

    stop() {
        this._active = false;
        if (this._scanTimer) {
            clearInterval(this._scanTimer);
            this._scanTimer = null;
        }
        this._log('Signal Intelligence service stopped');
    }

    isActive() {
        return this._active;
    }

    getLastResults() {
        return this._lastScanResults;
    }

    async _runScan() {
        const radar = window.GhostRadar;
        const intel = window.SignalIntelligence;

        if (!radar || !intel) {
            this._log('Waiting for GhostRadar and SignalIntelligence to load...');
            return;
        }

        // Don't start a new scan if one is already running
        if (radar.scanning) return;

        try {
            const results = await radar.startScan();
            if (!Array.isArray(results)) return;

            // Feed each real hardware result into the threat classification engine
            for (const device of results) {
                const signal = this._mapRadarToSignal(device);
                if (signal) {
                    intel.processSignal(signal);
                }
            }

            this._lastScanResults = results;

            // Dispatch event for UI to pick up
            window.dispatchEvent(new CustomEvent('signalIntel:scanComplete', {
                detail: {
                    deviceCount: results.length,
                    threatLevel: intel.getThreatLevel(),
                    timestamp: Date.now()
                }
            }));

        } catch (e) {
            console.warn('[SignalIntel] Scan cycle failed:', e.message);
        }
    }

    /**
     * Map a GhostRadar result to a SignalIntelligence-compatible signal object.
     */
    _mapRadarToSignal(device) {
        if (!device || !device.id) return null;

        return {
            mac: device.id,
            rssi: device.rssi || -100,
            name: device.name || '',
            hasBLE: device.type === 'bluetooth_device' || device.type === 'apple_device' ||
                    device.type === 'samsung_device' || device.type === 'wearable' ||
                    device.type === 'windows_device',
            hasWiFi: device.type === 'wifi',
            isAP: device.security != null,
            channel: device.channel || null,
            channels: device.channel ? [device.channel] : [],
            isGhostNode: device.isGhostNode || false,
            isRandomizedMac: this._isRandomizedMAC(device.id),
            audioServiceUUID: device.type === 'apple_device' || device.type === 'samsung_device',
            source: device.source || 'unknown'
        };
    }

    /**
     * Check if a MAC address is locally administered (randomized).
     * Bit 1 of the first octet is the "locally administered" flag.
     */
    _isRandomizedMAC(mac) {
        if (!mac || typeof mac !== 'string') return false;
        const firstOctet = parseInt(mac.substring(0, 2), 16);
        if (isNaN(firstOctet)) return false;
        return (firstOctet & 0x02) !== 0;
    }

    _log(msg) {
        console.log(`[SignalIntel] ${msg}`);
    }
}

// Initialize and expose
window.SignalIntelService = new SignalIntelService();

// Auto-start when DOM is ready and dependencies are loaded
document.addEventListener('DOMContentLoaded', () => {
    // Wait a tick for other scripts to initialize
    setTimeout(() => {
        if (window.GhostRadar && window.SignalIntelligence) {
            window.SignalIntelService.start();
        } else {
            // Retry after a short delay if deps aren't ready yet
            const retryTimer = setInterval(() => {
                if (window.GhostRadar && window.SignalIntelligence) {
                    clearInterval(retryTimer);
                    window.SignalIntelService.start();
                }
            }, 1000);
            // Give up after 30s
            setTimeout(() => clearInterval(retryTimer), 30000);
        }
    }, 500);
});
