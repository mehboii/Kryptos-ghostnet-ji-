/**
 * GhostNet Discovery
 * Universal Module
 */

(function (root, factory) {
    if (typeof module === 'object' && module.exports) {
        module.exports = factory();
    } else {
        root.GhostDiscovery = factory();
    }
}(typeof self !== 'undefined' ? self : this, function () {

    class GhostDiscovery {
        constructor(chat, myPeerId) {
            this.chat = chat;
            this.myPeerId = myPeerId;
            this.knownPeers = new Map();
            this.MAX_PEERS = 50;
            this.GOSSIP_INTERVAL = 15000;
            this.PRUNE_TIMEOUT = 300000;

            setInterval(() => this.exchangePeers(), this.GOSSIP_INTERVAL);
            setInterval(() => this.prunePeers(), this.PRUNE_TIMEOUT);
        }

        addPeer(peerId, meta = {}) {
            if (peerId === this.myPeerId) return;

            if (!this.knownPeers.has(peerId)) {
                this.knownPeers.set(peerId, {
                    id: peerId,
                    address: meta.address || null,
                    firstSeen: Date.now(),
                    lastSeen: Date.now(),
                    isConnected: meta.isConnected || false
                });
                console.log(`[Discovery] New Peer Discovered: ${peerId}`);
                if (this.chat && this.chat.peers.size < 5) {
                    // Try connect
                }
            } else {
                const p = this.knownPeers.get(peerId);
                p.lastSeen = Date.now();
                if (meta.isConnected !== undefined) p.isConnected = meta.isConnected;
            }
        }

        removePeer(peerId) {
            if (this.knownPeers.has(peerId)) {
                this.knownPeers.delete(peerId);
                if (this.chat) this.chat.removePeer(peerId);
            }
        }

        async exchangePeers() {
            const allPeers = Array.from(this.knownPeers.values());
            const subset = allPeers
                .filter(p => p.isConnected)
                .sort(() => 0.5 - Math.random())
                .slice(0, 5)
                .map(p => ({
                    id: p.id,
                    address: p.address,
                }));

            if (subset.length === 0) return;

            const pexMsg = {
                type: 'PEX_GOSSIP',
                peers: subset,
                from: this.myPeerId
            };

            try {
                // this.chat.sendMessage(pexMsg, "broadcast");
            } catch (e) { }
        }

        prunePeers() {
            const now = Date.now();
            for (const [id, peer] of this.knownPeers) {
                if (now - peer.lastSeen > this.PRUNE_TIMEOUT) {
                    if (this.chat && this.chat.peers.has(id)) {
                        peer.lastSeen = now;
                    } else {
                        this.knownPeers.delete(id);
                    }
                }
            }
        }
    }

    return GhostDiscovery;
}));
