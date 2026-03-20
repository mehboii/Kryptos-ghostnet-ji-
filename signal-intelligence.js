/**
 * Signal Intelligence Engine
 * Advanced signal classification and threat detection for GhostNet.
 */

class SignalIntelligenceEngine {
    constructor() {
        this.signals = new Map();
        this.classificationHistory = [];
        this.ghostNetChannel = 6; // Example default mesh channel
    }

    // Process an raw detected signal object
    processSignal(device) {
        if (!device || typeof device !== 'object') return null;
        if (!device.mac) return null;
        
        const timestamp = Date.now();
        const prevData = this.signals.get(device.mac);
        
        // Calculate velocity of signal strength
        let rssiVelocity = 0;
        let macRotationHistory = prevData ? prevData.macRotationHistory : [];
        if (prevData) {
            rssiVelocity = Math.abs(device.rssi - prevData.rssi) / (Math.max(1, timestamp - prevData.timestamp) / 1000);
            if (device.mac !== prevData.mac) {
                macRotationHistory.push(timestamp);
            }
        }

        const enrichedSignal = {
            ...prevData,
            ...device,
            timestamp,
            rssiVelocity,
            macRotationHistory
        };

        const signalAnalysis = this._analyzeSignal(enrichedSignal);
        
        this.signals.set(device.mac, signalAnalysis);
        return signalAnalysis;
    }

    _hasHighInterference(signal) {
        // Returns true if signal is causing interference
        // Check: signal strength below -80 dBm OR channel collision with GhostNet
        return (signal.rssi && signal.rssi < -80) || 
               (signal.channel && this._isChannelCollision(signal.channel));
    }

    _isChannelCollision(channel) {
        // GhostNet typically uses channels 1, 6, 11
        // Interference if another strong signal is on same channel
        const ghostnetChannels = [1, 6, 11];
        return ghostnetChannels.includes(channel);
    }

    _analyzeSignal(device) {
        // 1. Signal Quality Rating
        let quality = 'POOR';
        if (device.rssi > -50) quality = 'STRONG';
        else if (device.rssi >= -80) quality = 'WEAK';
        
        // Check for 'OPTIMAL' condition (usable for GhostNet path)
        if (quality === 'STRONG' && !this._hasHighInterference(device) && device.isGhostNode) {
            quality = 'OPTIMAL';
        }

        // 2. Interference Flags
        const interferenceFlags = [];
        if (device.channel === this.ghostNetChannel) {
            interferenceFlags.push('CHANNEL_COLLISION');
        }
        if (device.rssi > -40 && (!device.name || device.name.trim() === '')) {
            interferenceFlags.push('POTENTIAL_JAMMER');
        }
        if (device.rssiVelocity > 10) { // dBm change per second
            interferenceFlags.push('RAPID_MOVEMENT');
        }
        if (device.channels && device.channels.length > 2) {
            interferenceFlags.push('MULTI_CHANNEL_BROADCAST');
        }
        if (device.shouldRandomize && !device.isRandomizedMac) {
            interferenceFlags.push('STATIC_MAC_TRACKING');
        }

        // 3. Threat Score Calculation
        let threatScore = 0;
        if (!device.name || device.name === '') threatScore += 20;
        
        // Fast MAC rotation check (more than 2 times in a minute)
        const recentRotations = device.macRotationHistory ? device.macRotationHistory.filter(t => Date.now() - t < 60000).length : 0;
        if (recentRotations > 2) threatScore += 30;
        
        if (device.channels && device.channels.length > 1) threatScore += 25;
        if (device.rssi > -30 && (!device.name || device.name === '')) threatScore += 20;
        
        const surveillanceOUIs = ['00:11:22', '00:25:90', '00:1A:11']; // Example OUIs
        const oui = device.mac.substring(0, 8).toUpperCase();
        if (surveillanceOUIs.includes(oui)) threatScore += 40;

        threatScore = Math.min(100, threatScore);
        
        let threatLevel = 'SAFE';
        if (threatScore > 60) threatLevel = 'THREAT';
        else if (threatScore > 30) threatLevel = 'MONITOR';

        // 4. Device Type Classification
        let type = 'UNKNOWN';
        if (device.isGhostNode) {
            type = 'GhostNet Node';
            threatScore = 0; // Override threat score for trusted nodes
            threatLevel = 'SAFE';
        } else if (threatScore > 60 && interferenceFlags.includes('MULTI_CHANNEL_BROADCAST') && interferenceFlags.includes('POTENTIAL_JAMMER')) {
            type = 'Surveillance Device';
        } else if (threatScore > 40 && interferenceFlags.includes('RAPID_MOVEMENT')) {
            type = 'Suspicious Tracker';
        } else if (device.hasBLE && device.hasWiFi) {
            type = 'Smartphone';
        } else if (device.hasWiFi && !device.hasBLE && device.isAP) {
            type = 'Router/AP';
        } else if (device.hasWiFi && !device.isAP) {
            type = 'Laptop/Client';
        } else if (device.hasBLE && device.audioServiceUUID) {
            type = 'Audio Device';
        } else if (device.hasBLE && device.healthServiceUUID) {
            type = 'Wearable';
        }

        return {
            ...device,
            quality,
            interferenceFlags,
            threatScore,
            threatLevel,
            type,
            lastUpdated: Date.now()
        };
    }

    getSignalReport() {
        return Array.from(this.signals.values()).sort((a, b) => b.rssi - a.rssi);
    }

    getThreatLevel() {
        const activeDevices = this.getSignalReport().filter(d => Date.now() - d.lastUpdated < 120000);
        const threats = activeDevices.filter(d => d.threatLevel === 'THREAT');
        if (threats.length > 0) return 'DANGER';
        const monitors = activeDevices.filter(d => d.threatLevel === 'MONITOR');
        if (monitors.length > 0) return 'ELEVATED';
        return 'NORMAL';
    }

    getInterference() {
        const activeDevices = this.getSignalReport().filter(d => Date.now() - d.lastUpdated < 120000);
        const interferences = activeDevices.filter(d => d.interferenceFlags && d.interferenceFlags.length > 0);
        return interferences.map(i => ({ mac: i.mac, flags: i.interferenceFlags, type: i.type }));
    }

    getBestPath() {
        const activeDevices = this.getSignalReport().filter(d => Date.now() - d.lastUpdated < 120000);
        const optimalNodes = activeDevices.filter(d => d.quality === 'OPTIMAL' && d.threatLevel === 'SAFE');
        if (optimalNodes.length > 0) {
            // Pick highest RSSI optimal node
            return optimalNodes[0];
        }
        return null;
    }
}

window.SignalIntelligence = new SignalIntelligenceEngine();

// Hook into existing GhostMesh / Radar dynamically if present
if (window.app && !window.app.signalIntelligence) {
    window.app.signalIntelligence = window.SignalIntelligence;
}
