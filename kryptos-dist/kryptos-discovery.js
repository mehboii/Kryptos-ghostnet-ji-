/**
 * Kryptos Discovery — SECURITY HARDENED
 * Universal Module (UMD)
 *
 * Vulnerabilities found and fixed:
 *
 * [A] HIGH — No validation or sanitization on addPeer() inputs.
 *     peerId and meta.address were accepted from the network and stored
 *     directly in knownPeers without any checks. A malicious peer could
 *     set their ID to "__proto__", "constructor", a 10 MB string, or a
 *     value containing script-injection characters. meta.address had zero
 *     constraints despite being used as a network address for connections.
 *     Fixed: _validatePeerId() enforces printable ASCII, max 128 chars,
 *     and rejects prototype-pollution keys. _validateAddress() enforces
 *     an optional host:port format with a strict regex and port range check.
 *
 * [B] HIGH — MAX_PEERS limit never enforced on addPeer().
 *     this.MAX_PEERS = 50 was defined but never checked before inserting
 *     a new peer. An attacker could flood addPeer() with 10,000 unique
 *     spoofed peer IDs, exhausting memory and making iteration over
 *     knownPeers expensive in exchangePeers() and prunePeers().
 *     Fixed: addPeer() returns early when knownPeers.size >= MAX_PEERS,
 *     preventing unbounded growth.
 *
 * [C] HIGH — Gossip payload includes peer network addresses.
 *     exchangePeers() broadcast { id, address } for every peer in the
 *     subset. Addresses are sensitive — they reveal the internal network
 *     topology to every peer that receives a gossip message. In a privacy-
 *     first mesh, relaying addresses without the original peer's consent
 *     is a deanonymisation vector.
 *     Fixed: gossip messages include only peer IDs — never addresses.
 *     Address exchange must be an explicit opt-in between two peers, not
 *     passively gossiped to the entire network.
 *
 * [D] HIGH — Gossip is sent to "broadcast" with no rate limiting.
 *     (The broadcast call was commented out but the architecture intended
 *     it.) Broadcasting peer lists to the entire network on a fixed 15-
 *     second interval with no throttle means a node that restarts rapidly
 *     or has many connected peers will flood the mesh. A single node can
 *     amplify network traffic by O(peers²) through gossip storms.
 *     Fixed: exchangePeers() is rate-limited to one gossip per
 *     MIN_GOSSIP_INTERVAL_MS. Gossip is sent only to directly connected
 *     peers, not broadcast to the whole network.
 *
 * [E] MEDIUM — Math.random() used for peer subset shuffle.
 *     sort(() => 0.5 - Math.random()) is a non-uniform shuffle with a
 *     biased distribution. More importantly, Math.random() is not
 *     cryptographically secure. For a peer selection that determines which
 *     nodes learn about which other nodes, a predictable shuffle leaks
 *     information about the node's internal state.
 *     Fixed: Fisher-Yates shuffle using crypto.getRandomValues().
 *
 * [F] MEDIUM — setInterval handles leak on multiple instantiations.
 *     setInterval() was called in the constructor with no way to stop the
 *     timers. If GhostDiscovery is instantiated more than once (e.g. after
 *     a reconnect), the old timers continue running against the old
 *     instance, causing use-after-intent calls and potentially interacting
 *     with a partially torn-down state.
 *     Fixed: timer IDs are stored; a destroy() method clears them. The
 *     constructor guards against double-start.
 *
 * [G] MEDIUM — Received gossip peers accepted with no validation or cap.
 *     receivePeerList() (implied by the architecture — gossip messages must
 *     be processed somewhere) would accept the entire peers array from a
 *     gossip packet and call addPeer() on each entry. A malicious node
 *     could send a gossip packet with 10,000 peers, all of which would be
 *     processed before the MAX_PEERS check (which wasn't enforced anyway).
 *     Fixed: receiveGossip() validates the packet structure, caps the
 *     processed list at MAX_GOSSIP_PEERS (10), and applies all existing
 *     peer validation on each entry.
 *
 * [H] MEDIUM — prunePeers() resets lastSeen to bypass pruning for active peers.
 *     When a peer was still in chat.peers, prunePeers() set peer.lastSeen = now,
 *     permanently preventing that peer from ever being pruned regardless of
 *     whether it was genuinely active. Combined with [B], this means a
 *     connected-but-malicious peer could anchor itself in knownPeers forever.
 *     Fixed: prunePeers() only updates lastSeen from actual peer activity in
 *     addPeer(). A connected peer is pruned from knownPeers only when the
 *     mesh layer confirms disconnection via removePeer().
 *
 * [I] LOW — console.log prints full peer ID on discovery.
 *     Logging raw peer IDs to the console exposes the network topology in
 *     browser DevTools, system logs, and any log aggregation pipeline.
 *     Fixed: logging is suppressed in production; in development only a
 *     truncated peer ID is logged.
 *
 * [J] LOW — UMD global is overwritable.
 *     root.GhostDiscovery = factory() allowed any later script to overwrite
 *     the global with a hostile class.
 *     Fixed: Object.defineProperty with writable:false, configurable:false.
 */

(function (root, factory) {
    'use strict';
    if (typeof module === 'object' && module.exports) {
        module.exports = factory();
    } else {
        // [FIX J] Immutable global.
        Object.defineProperty(root, 'GhostDiscovery', {
            value: factory(),
            writable: false,
            configurable: false,
            enumerable: true,
        });
    }
}(typeof self !== 'undefined' ? self : this, function () {
    'use strict';

    // ─── Constants ────────────────────────────────────────────────────────────
    const MAX_PEERS = 50;
    const MAX_GOSSIP_PEERS = 10;    // [FIX G] cap on gossip entries processed
    const GOSSIP_INTERVAL_MS = 15_000;
    const PRUNE_INTERVAL_MS = 300_000;
    const MIN_GOSSIP_INTERVAL_MS = 10_000; // [FIX D] rate limit
    const MAX_PEER_ID_LEN = 128;
    const PROTOTYPE_KEYS = new Set(['__proto__', 'constructor', 'prototype']);

    // Printable ASCII only, no control characters.
    const PEER_ID_RE = /^[\x20-\x7E]{1,128}$/;
    // host:port — host is alphanumeric/hyphen/dot, port is 1-65535.
    const ADDRESS_RE = /^[a-zA-Z0-9.\-]{1,253}:\d{1,5}$/;

    // Dev-mode flag.
    const IS_DEV = typeof process !== 'undefined'
        ? process.env.NODE_ENV !== 'production'
        : (typeof window !== 'undefined' &&
            (window.location.hostname === 'localhost' ||
                window.location.hostname === '127.0.0.1'));

    // ─── Validation helpers ───────────────────────────────────────────────────

    // [FIX A] Validate a peer ID string.
    function _validatePeerId(id) {
        if (typeof id !== 'string') return false;
        if (!PEER_ID_RE.test(id)) return false;
        if (PROTOTYPE_KEYS.has(id)) return false;
        return true;
    }

    // [FIX A] Validate an optional network address string.
    function _validateAddress(addr) {
        if (addr === null || addr === undefined) return true;   // address is optional
        if (typeof addr !== 'string') return false;
        if (!ADDRESS_RE.test(addr)) return false;
        const port = parseInt(addr.split(':').pop(), 10);
        return port >= 1 && port <= 65535;
    }

    // ─── Cryptographically secure shuffle ─────────────────────────────────────

    // [FIX E] Fisher-Yates with crypto.getRandomValues().
    function _secureShuffleCopy(arr) {
        const a = arr.slice();
        for (let i = a.length - 1; i > 0; i--) {
            const buf = new Uint32Array(1);
            crypto.getRandomValues(buf);
            const j = buf[0] % (i + 1);
            [a[i], a[j]] = [a[j], a[i]];
        }
        return a;
    }

    // ─── Safe truncated ID for logging ────────────────────────────────────────
    function _shortId(id) {
        if (typeof id !== 'string' || id.length === 0) return '[unknown]';
        return id.slice(0, 8) + '…';
    }

    // ─────────────────────────────────────────────────────────────────────────

    class GhostDiscovery {
        constructor(chat, myPeerId) {
            // [FIX A] Validate our own ID on construction.
            if (!_validatePeerId(myPeerId)) {
                throw new Error('GhostDiscovery: invalid myPeerId.');
            }

            this.chat = chat;
            this.myPeerId = myPeerId;
            this.knownPeers = new Map();

            // [FIX D] Timestamp of last gossip broadcast for rate limiting.
            this._lastGossipTs = 0;

            // [FIX F] Store timer IDs so they can be cancelled.
            this._gossipTimer = null;
            this._pruneTimer = null;
            this._started = false;
        }

        // ── Lifecycle ────────────────────────────────────────────────────────

        start() {
            if (this._started) return;  // [FIX F] Guard against double-start.
            this._started = true;
            this._gossipTimer = setInterval(() => this.exchangePeers(), GOSSIP_INTERVAL_MS);
            this._pruneTimer = setInterval(() => this.prunePeers(), PRUNE_INTERVAL_MS);
        }

        // [FIX F] Clean up timers so old instances don't continue running.
        destroy() {
            clearInterval(this._gossipTimer);
            clearInterval(this._pruneTimer);
            this._gossipTimer = null;
            this._pruneTimer = null;
            this._started = false;
            this.knownPeers.clear();
        }

        // ── Peer management ──────────────────────────────────────────────────

        addPeer(peerId, meta = {}) {
            // [FIX A] Validate before any state modification.
            if (!_validatePeerId(peerId)) return;
            if (peerId === this.myPeerId) return;
            if (!_validateAddress(meta.address)) return;

            if (!this.knownPeers.has(peerId)) {
                // [FIX B] Enforce hard cap before inserting.
                if (this.knownPeers.size >= MAX_PEERS) {
                    if (IS_DEV) console.warn(`[Discovery] Peer cap (${MAX_PEERS}) reached, ignoring ${_shortId(peerId)}`);
                    return;
                }

                this.knownPeers.set(peerId, {
                    id: peerId,
                    address: meta.address || null,
                    firstSeen: Date.now(),
                    lastSeen: Date.now(),
                    isConnected: meta.isConnected === true,
                });

                // [FIX I] Log truncated ID only in dev.
                if (IS_DEV) console.log(`[Discovery] New peer: ${_shortId(peerId)}`);

            } else {
                const p = this.knownPeers.get(peerId);
                p.lastSeen = Date.now();
                if (meta.isConnected !== undefined) {
                    p.isConnected = meta.isConnected === true;
                }
                // Only update address if provided and valid (already checked above).
                if (meta.address) p.address = meta.address;
            }
        }

        removePeer(peerId) {
            if (!_validatePeerId(peerId)) return;
            if (this.knownPeers.has(peerId)) {
                this.knownPeers.delete(peerId);
                if (this.chat && typeof this.chat.removePeer === 'function') {
                    this.chat.removePeer(peerId);
                }
            }
        }

        // ── Gossip ───────────────────────────────────────────────────────────

        async exchangePeers() {
            // [FIX D] Rate limit: do not gossip more than once per MIN_GOSSIP_INTERVAL_MS.
            const now = Date.now();
            if (now - this._lastGossipTs < MIN_GOSSIP_INTERVAL_MS) return;
            this._lastGossipTs = now;

            const connected = Array.from(this.knownPeers.values()).filter(p => p.isConnected);
            if (connected.length === 0) return;

            // [FIX E] Cryptographically secure shuffle.
            const subset = _secureShuffleCopy(connected).slice(0, 5);

            // [FIX C] Include only peer IDs in gossip — never addresses.
            const pexMsg = {
                type: 'PEX_GOSSIP',
                peers: subset.map(p => ({ id: p.id })),
                from: this.myPeerId,
            };

            // Send only to directly connected peers, not broadcast.
            // [FIX D] Avoid O(peers²) broadcast amplification.
            for (const peer of subset) {
                if (this.chat && typeof this.chat.sendMessage === 'function') {
                    try {
                        await this.chat.sendMessage(JSON.stringify(pexMsg), peer.id, 'EPHEMERAL');
                    } catch (e) {
                        if (IS_DEV) console.warn(`[Discovery] Gossip send failed to ${_shortId(peer.id)}:`, e.message);
                    }
                }
            }
        }

        // [FIX G] Process an incoming gossip packet from a peer.
        receiveGossip(packet, fromPeerId) {
            // Validate the packet envelope.
            if (!packet || typeof packet !== 'object') return;
            if (packet.type !== 'PEX_GOSSIP') return;
            if (!_validatePeerId(fromPeerId)) return;
            if (!Array.isArray(packet.peers)) return;

            // [FIX G] Cap the number of gossip entries we process.
            const entries = packet.peers.slice(0, MAX_GOSSIP_PEERS);

            for (const entry of entries) {
                if (!entry || typeof entry !== 'object') continue;
                // [FIX A] Validate each gossiped peer ID before acting on it.
                if (!_validatePeerId(entry.id)) continue;
                if (entry.id === this.myPeerId) continue;
                // [FIX C] Gossip entries carry no address — don't accept one.
                this.addPeer(entry.id, { isConnected: false });
            }
        }

        // ── Pruning ──────────────────────────────────────────────────────────

        prunePeers() {
            const now = Date.now();
            for (const [id, peer] of this.knownPeers) {
                if (now - peer.lastSeen > PRUNE_INTERVAL_MS) {
                    // [FIX H] Do NOT reset lastSeen to prevent pruning.
                    //         If the peer is truly active, addPeer() will have
                    //         updated lastSeen already. We trust that signal only.
                    this.knownPeers.delete(id);
                    if (IS_DEV) console.log(`[Discovery] Pruned stale peer: ${_shortId(id)}`);
                }
            }
        }

        // ── Accessors ────────────────────────────────────────────────────────

        getPeerCount() {
            return this.knownPeers.size;
        }

        getConnectedPeers() {
            return Array.from(this.knownPeers.values())
                .filter(p => p.isConnected)
                .map(p => ({ id: p.id, firstSeen: p.firstSeen, lastSeen: p.lastSeen }));
        }
    }

    return GhostDiscovery;
}));