/**
 * Kryptos Reputation — HARDENED
 * Universal Module (UMD)
 *
 * Security fixes:
 *  [A] CRITICAL — peerId accepted with no validation; prototype-poisoning keys like
 *                 "__proto__" or "constructor" could reach downstream object code.
 *                 → validatePeerId() enforces alphanumeric + hyphen/underscore, max 128 chars.
 *  [B] CRITICAL — setInterval() in constructor leaked forever; no handle stored, no way to
 *                 stop it, preventing GC and eventually crashing long-running processes.
 *                 → _decayTimer stored; destroy() method clears it.
 *  [C] HIGH     — onRelayPacket() accepted negative / NaN / Infinity bytes, corrupting scores.
 *                 → assertPositiveFinite() guard on all numeric inputs.
 *  [D] HIGH     — onStoreChunk() same unvalidated numeric input issue.
 *                 → assertPositiveFinite() guard.
 *  [E] HIGH     — onHeartbeat() accepted negative latency, giving unbounded latency bonus.
 *                 → latencyMs clamped to [0, 60 000] before bonus calculation.
 *  [F] HIGH     — canConsumeResource() accepted negative cost, which *added* credits
 *                 (free credit exploit: cost = -1000 → peer gains 1000 credits).
 *                 → assertPositiveFinite() guard; cost must be > 0.
 *  [G] HIGH     — Scores and credits grew without bound; credits could reach Infinity,
 *                 breaking toFixed() and priority math.
 *                 → MAX_SCORE cap per dimension; credits clamped after every recalc.
 *  [H] MEDIUM   — getReputationReport() spread peer.scores directly into the return value,
 *                 giving callers a live reference into internal state.
 *                 → Shallow copy returned; internal object never exposed.
 *  [I] MEDIUM   — _applyDecay() deleted from the Map while iterating it with for..of,
 *                 which is technically safe in JS but still confusing and fragile.
 *                 → Collect IDs to delete first, then delete after iteration completes.
 *  [J] MEDIUM   — No maximum peer count; an attacker could call _getPeer() with millions
 *                 of unique IDs, exhausting memory (Map-based DoS).
 *                 → MAX_PEERS = 10 000; new peers rejected when limit is reached.
 *  [K] MEDIUM   — Syntax error in original: "credits: 0,a" — stray identifier after comma.
 *                 → Fixed (removed stray `a`).
 *  [L] LOW      — WEIGHTS and DECAY_RATE were public instance properties; any caller could
 *                 write `rep.WEIGHTS.bandwidth = 9999` to inflate their own score.
 *                 → Moved to frozen private-convention constants (Object.freeze).
 *  [M] LOW      — getPriority() called Math.log10(credits + 1) but credits could be
 *                 slightly negative due to floating-point; log10 of a negative is NaN.
 *                 → Math.max(0, credits) before log10.
 *  [N] LOW      — New peers had lastActive = Date.now() at creation time, making a peer
 *                 that was only created but never used appear "recently active" and survive
 *                 the 24-hour eviction window indefinitely.
 *                 → lastActive initialised to 0 (epoch); only set on real activity.
 */

(function (root, factory) {
    if (typeof module === 'object' && module.exports) {
        module.exports = factory();
    } else {
        root.GhostReputation = factory();
    }
}(typeof self !== 'undefined' ? self : this, function () {
    'use strict';

    // ── Constants ────────────────────────────────────────────────────────────

    // [L] Frozen — callers cannot mutate scoring parameters
    const WEIGHTS = Object.freeze({
        bandwidth: 0.5,
        storage: 2.0,
        uptime: 1.0,
    });

    const DECAY_RATE = 0.98;        // [L]
    const DECAY_INTERVAL = 60_000;      // ms
    const MAX_PEERS = 10_000;      // [J] hard cap
    const MAX_SCORE = 1_000_000;   // [G] per-dimension score ceiling
    const MAX_CREDITS = 1_000_000;   // [G] total credits ceiling
    const EVICT_AFTER_MS = 86_400_000;  // 24 h

    // [A] Peer ID allowlist: alphanumeric, hyphen, underscore; 1–128 chars
    const PEER_ID_RE = /^[a-zA-Z0-9_\-]{1,128}$/;

    // ── Helpers ──────────────────────────────────────────────────────────────

    /**
     * [A] Validate a peerId. Returns the id if valid, throws otherwise.
     * Blocks prototype-poisoning keys and excessively long strings.
     */
    function validatePeerId(peerId) {
        if (typeof peerId !== 'string' || !PEER_ID_RE.test(peerId)) {
            throw new TypeError(
                `Invalid peerId: must be 1–128 alphanumeric/hyphen/underscore characters`
            );
        }
        return peerId;
    }

    /**
     * [C][D][E][F] Assert a value is a finite number > 0.
     * name is used only in the error message (never reaches the network).
     */
    function assertPositiveFinite(value, name) {
        if (typeof value !== 'number' || !Number.isFinite(value) || value <= 0) {
            throw new RangeError(`${name} must be a positive finite number, got: ${value}`);
        }
    }

    // ── Class ────────────────────────────────────────────────────────────────

    class GhostReputation {
        constructor() {
            this.peers = new Map();
            this._decayTimer = null; // [B]
            this._startDecay();
        }

        // ── Lifecycle ────────────────────────────────────────────────────────

        /** [B] Start the decay timer. Called once from constructor. */
        _startDecay() {
            // [B] Store handle so destroy() can clear it
            this._decayTimer = setInterval(() => this._applyDecay(), DECAY_INTERVAL);

            // Allow the process to exit even if this timer is still running
            if (this._decayTimer.unref) this._decayTimer.unref();
        }

        /**
         * [B] Stop the decay timer and release all peer state.
         * Call when you are done with this instance to prevent memory leaks.
         */
        destroy() {
            if (this._decayTimer !== null) {
                clearInterval(this._decayTimer);
                this._decayTimer = null;
            }
            this.peers.clear();
        }

        // ── Internal ─────────────────────────────────────────────────────────

        _getPeer(peerId) {
            // [J] Enforce maximum peer count before creating a new entry
            if (!this.peers.has(peerId) && this.peers.size >= MAX_PEERS) {
                throw new Error(
                    `Peer limit reached (${MAX_PEERS}). Cannot register new peer: ${peerId}`
                );
            }

            if (!this.peers.has(peerId)) {
                this.peers.set(peerId, {
                    scores: { bandwidth: 0, storage: 0, uptime: 0 },
                    credits: 0,   // [K] fixed syntax error (original had stray `a`)
                    lastActive: 0,   // [N] 0 = never active; only real events set this
                });
            }
            return this.peers.get(peerId);
        }

        _recalcCredits(peer) {
            const raw =
                (peer.scores.bandwidth * WEIGHTS.bandwidth) +  // [L] frozen WEIGHTS
                (peer.scores.storage * WEIGHTS.storage) +
                (peer.scores.uptime * WEIGHTS.uptime);
            // [G] Clamp credits so they never reach Infinity or overflow toFixed()
            peer.credits = Math.min(MAX_CREDITS, Math.max(0, raw));
        }

        // ── Public API ───────────────────────────────────────────────────────

        /**
         * Record that peerId relayed `bytes` bytes.
         * @param {string} peerId
         * @param {number} bytes  — must be a positive finite number
         */
        onRelayPacket(peerId, bytes) {
            validatePeerId(peerId);           // [A]
            assertPositiveFinite(bytes, 'bytes'); // [C]

            const peer = this._getPeer(peerId);
            // [G] Cap per-dimension score before storing
            peer.scores.bandwidth = Math.min(MAX_SCORE, peer.scores.bandwidth + (bytes / 1024));
            peer.lastActive = Date.now();     // [N]
            this._recalcCredits(peer);
        }

        /**
         * Record that peerId stored a chunk of `chunkSize` bytes.
         * @param {string} peerId
         * @param {number} chunkSize  — must be a positive finite number
         */
        onStoreChunk(peerId, chunkSize) {
            validatePeerId(peerId);                    // [A]
            assertPositiveFinite(chunkSize, 'chunkSize'); // [D]

            const peer = this._getPeer(peerId);
            peer.scores.storage = Math.min(
                MAX_SCORE,
                peer.scores.storage + (chunkSize / (1024 * 1024)) * 10
            ); // [G]
            peer.lastActive = Date.now(); // [N]
            this._recalcCredits(peer);
        }

        /**
         * Record a heartbeat from peerId with the given round-trip latency.
         * @param {string} peerId
         * @param {number} latencyMs  — must be a positive finite number
         */
        onHeartbeat(peerId, latencyMs) {
            validatePeerId(peerId);                      // [A]
            assertPositiveFinite(latencyMs, 'latencyMs'); // [E]

            // [E] Clamp to [0, 60 000] — negative values already blocked above;
            //     cap prevents a 0 ms latency from giving an unfairly huge bonus.
            const clamped = Math.min(latencyMs, 60_000);
            const latencyBonus = Math.max(0, (1000 - clamped) / 100);

            const peer = this._getPeer(peerId);
            peer.scores.uptime = Math.min(MAX_SCORE, peer.scores.uptime + (1 + latencyBonus)); // [G]
            peer.lastActive = Date.now(); // [N]
            this._recalcCredits(peer);
        }

        /**
         * Attempt to consume `cost` credits from peerId's account.
         * Returns true and deducts only if the peer has sufficient balance.
         * @param {string} peerId
         * @param {number} cost  — must be a positive finite number
         */
        canConsumeResource(peerId, cost) {
            validatePeerId(peerId);             // [A]
            assertPositiveFinite(cost, 'cost'); // [F] blocks negative-cost exploit

            const peer = this.peers.get(peerId);
            if (!peer) return false;

            if (peer.credits >= cost) {
                peer.credits -= cost;
                return true;
            }
            return false;
        }

        /**
         * Returns a 0–100 priority score for peerId.
         * Returns 0 if the peer is unknown.
         */
        getPriority(peerId) {
            validatePeerId(peerId); // [A]
            const peer = this.peers.get(peerId);
            if (!peer) return 0;
            // [M] Math.max(0, ...) guards against floating-point slightly-negative credits
            return Math.min(100, Math.log10(Math.max(0, peer.credits) + 1) * 20);
        }

        // ── Internal: decay & eviction ───────────────────────────────────────

        _applyDecay() {
            // [I] Collect eviction candidates first; never mutate while iterating
            const toEvict = [];

            for (const [id, peer] of this.peers) {
                peer.scores.bandwidth *= DECAY_RATE; // [L]
                peer.scores.storage *= DECAY_RATE;
                peer.scores.uptime *= DECAY_RATE;

                if (Date.now() - peer.lastActive > EVICT_AFTER_MS) {
                    toEvict.push(id); // [I]
                } else {
                    this._recalcCredits(peer);
                }
            }

            // [I] Safe to delete now that iteration is complete
            for (const id of toEvict) {
                this.peers.delete(id);
            }
        }

        // ── Reporting ────────────────────────────────────────────────────────

        /**
         * Returns a snapshot report for peerId, or null if unknown.
         * The returned object is a copy — mutating it does not affect internal state.
         */
        getReputationReport(peerId) {
            validatePeerId(peerId); // [A]
            const peer = this.peers.get(peerId);
            if (!peer) return null;

            // [H] Shallow copy of scores — never return a live reference to internal state
            return {
                peerId,
                bandwidth: peer.scores.bandwidth,
                storage: peer.scores.storage,
                uptime: peer.scores.uptime,
                totalCredits: peer.credits.toFixed(2),
                priority: this.getPriority(peerId).toFixed(0),
            };
        }
    }

    return GhostReputation;
}));