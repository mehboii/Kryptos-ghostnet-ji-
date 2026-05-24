/**
 * GhostNet Reputation
 * Universal Module
 */

(function (root, factory) {
    if (typeof module === 'object' && module.exports) {
        module.exports = factory();
    } else {
        root.GhostReputation = factory();
    }
}(typeof self !== 'undefined' ? self : this, function () {

    class GhostReputation {
        constructor() {
            this.peers = new Map();
            this.WEIGHTS = {
                bandwidth: 0.5,
                storage: 2.0,
                uptime: 1.0
            };
            this.DECAY_RATE = 0.98;
            setInterval(() => this._applyDecay(), 60000);
        }

        _getPeer(peerId) {
            if (!this._validatePeerId(peerId)) return null;
            if (!this.peers.has(peerId)) {
                // [FIX 23] Cap total tracked peers to prevent memory exhaustion
                if (this.peers.size >= 10000) return null;
                this.peers.set(peerId, {
                    scores: { bandwidth: 0, storage: 0, uptime: 0 },
                    credits: 0,
                    lastActive: Date.now()
                });
            }
            return this.peers.get(peerId);
        }

        // [FIX 23] Validate peerId format to prevent prototype pollution / injection
        _validatePeerId(peerId) {
            if (typeof peerId !== 'string' || peerId.length === 0 || peerId.length > 128) return false;
            if (peerId === '__proto__' || peerId === 'constructor' || peerId === 'prototype') return false;
            return true;
        }

        onRelayPacket(peerId, bytes) {
            if (!this._validatePeerId(peerId)) return;
            // [FIX 23] Cap per-event score increment to prevent inflation
            const safeBytes = Math.max(0, Math.min(bytes, 10 * 1024 * 1024));
            const peer = this._getPeer(peerId);
            peer.scores.bandwidth += (safeBytes / 1024);
            // [FIX 23] Cap individual scores to prevent unbounded growth
            peer.scores.bandwidth = Math.min(peer.scores.bandwidth, 100000);
            peer.lastActive = Date.now();
            this._recalcCredits(peer);
        }

        onStoreChunk(peerId, chunkSize) {
            if (!this._validatePeerId(peerId)) return;
            const safeSize = Math.max(0, Math.min(chunkSize, 256 * 1024 * 1024));
            const peer = this._getPeer(peerId);
            peer.scores.storage += (safeSize / (1024 * 1024)) * 10;
            peer.scores.storage = Math.min(peer.scores.storage, 100000);
            peer.lastActive = Date.now();
            this._recalcCredits(peer);
        }

        onHeartbeat(peerId, latencyMs) {
            if (!this._validatePeerId(peerId)) return;
            const safeLatency = Math.max(0, Math.min(latencyMs, 60000));
            const peer = this._getPeer(peerId);
            const latencyBonus = Math.max(0, (1000 - safeLatency) / 100);
            peer.scores.uptime += (1 + latencyBonus);
            peer.scores.uptime = Math.min(peer.scores.uptime, 100000);
            peer.lastActive = Date.now();
            this._recalcCredits(peer);
        }

        _recalcCredits(peer) {
            peer.credits =
                (peer.scores.bandwidth * this.WEIGHTS.bandwidth) +
                (peer.scores.storage * this.WEIGHTS.storage) +
                (peer.scores.uptime * this.WEIGHTS.uptime);
        }

        canConsumeResource(peerId, cost) {
            if (!this._validatePeerId(peerId)) return false;
            if (typeof cost !== 'number' || cost < 0) return false;
            const peer = this.peers.get(peerId);
            if (!peer) return false;

            if (peer.credits >= cost) {
                peer.credits -= cost;
                return true;
            }
            return false;
        }

        getPriority(peerId) {
            if (!this._validatePeerId(peerId)) return 0;
            const peer = this.peers.get(peerId);
            if (!peer) return 0;
            return Math.min(100, Math.log10(peer.credits + 1) * 20);
        }

        _applyDecay() {
            for (const [id, peer] of this.peers) {
                peer.scores.bandwidth *= this.DECAY_RATE;
                peer.scores.storage *= this.DECAY_RATE;
                peer.scores.uptime *= this.DECAY_RATE;

                if (Date.now() - peer.lastActive > 86400000) {
                    this.peers.delete(id);
                } else {
                    this._recalcCredits(peer);
                }
            }
        }

        getReputationReport(peerId) {
            const peer = this.peers.get(peerId);
            if (!peer) return null;
            return {
                peerId,
                ...peer.scores,
                totalCredits: peer.credits.toFixed(2),
                priority: this.getPriority(peerId).toFixed(0)
            };
        }
    }

    return GhostReputation;
}));
