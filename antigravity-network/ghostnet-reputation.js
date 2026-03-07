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
            if (!this.peers.has(peerId)) {
                this.peers.set(peerId, {
                    scores: { bandwidth: 0, storage: 0, uptime: 0 },
                    credits: 0,
                    lastActive: Date.now()
                });
            }
            return this.peers.get(peerId);
        }

        onRelayPacket(peerId, bytes) {
            const peer = this._getPeer(peerId);
            peer.scores.bandwidth += (bytes / 1024);
            peer.lastActive = Date.now();
            this._recalcCredits(peer);
        }

        onStoreChunk(peerId, chunkSize) {
            const peer = this._getPeer(peerId);
            peer.scores.storage += (chunkSize / (1024 * 1024)) * 10;
            peer.lastActive = Date.now();
            this._recalcCredits(peer);
        }

        onHeartbeat(peerId, latencyMs) {
            const peer = this._getPeer(peerId);
            const latencyBonus = Math.max(0, (1000 - latencyMs) / 100);
            peer.scores.uptime += (1 + latencyBonus);
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
            const peer = this.peers.get(peerId);
            if (!peer) return false;

            if (peer.credits >= cost) {
                peer.credits -= cost;
                return true;
            }
            return false;
        }

        getPriority(peerId) {
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
