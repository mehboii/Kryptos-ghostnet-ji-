/**
 * Kryptos Mesh Hardening — Step 2
 *
 * [2.1] Adaptive BLE Scan Scheduler (exponential backoff + motion reset)
 * [2.2] Split-Brain Reconciliation (Merkle-tree-based ledger sync)
 * [2.3] Zero-Route Queue (encrypted store-and-forward)
 */

'use strict';

// ═══════════════════════════════════════════════════════════════════════════
// [2.1] ADAPTIVE BLE SCAN SCHEDULER
// ═══════════════════════════════════════════════════════════════════════════
//
// Exponential backoff: 10s → 30s → 180s based on peer discovery results.
// Instantly resets to 10s on device motion or network ping.

class AdaptiveScanScheduler {
    constructor(scanFn) {
        this._scanFn = scanFn;
        this._timer = null;
        this._running = false;
        this._motionWatcher = null;

        // Backoff tiers
        this.FAST_INTERVAL    = 10_000;   // 10 seconds — active scanning
        this.MEDIUM_INTERVAL  = 30_000;   // 30 seconds — no peers after 2 min
        this.SLOW_INTERVAL    = 180_000;  // 3 minutes  — no peers after 10 min

        this.MEDIUM_THRESHOLD = 120_000;  // 2 minutes of no peers → medium
        this.SLOW_THRESHOLD   = 600_000;  // 10 minutes of no peers → slow

        this._currentInterval = this.FAST_INTERVAL;
        this._emptyStreakStart = null;     // when the no-peer streak began
        this._lastPeerSeen = null;
        this._scanCount = 0;
        this._listeners = {};
    }

    on(event, fn) {
        if (!this._listeners[event]) this._listeners[event] = [];
        this._listeners[event].push(fn);
    }

    _emit(event, data) {
        (this._listeners[event] || []).forEach(fn => fn(data));
    }

    start() {
        if (this._running) return;
        this._running = true;
        this._emptyStreakStart = Date.now();
        this._scheduleNext(this.FAST_INTERVAL);
        this._watchMotion();
        this._watchNetwork();
        console.log('[ScanScheduler] Started — interval: 10s');
    }

    stop() {
        this._running = false;
        if (this._timer) { clearTimeout(this._timer); this._timer = null; }
        this._unwatchMotion();
        this._unwatchNetwork();
        console.log('[ScanScheduler] Stopped');
    }

    // Called by the scan function when peers are found (or not)
    reportScanResult(peersFound) {
        this._scanCount++;

        if (peersFound > 0) {
            this._lastPeerSeen = Date.now();
            this._emptyStreakStart = null;
            if (this._currentInterval !== this.FAST_INTERVAL) {
                this._currentInterval = this.FAST_INTERVAL;
                console.log('[ScanScheduler] Peers found — reset to 10s');
                this._emit('intervalChange', { interval: this.FAST_INTERVAL, reason: 'peers_found' });
            }
        } else {
            if (!this._emptyStreakStart) this._emptyStreakStart = Date.now();
            this._escalate();
        }

        if (this._running) this._scheduleNext(this._currentInterval);
    }

    _escalate() {
        const elapsed = Date.now() - this._emptyStreakStart;
        let newInterval = this.FAST_INTERVAL;

        if (elapsed >= this.SLOW_THRESHOLD) {
            newInterval = this.SLOW_INTERVAL;
        } else if (elapsed >= this.MEDIUM_THRESHOLD) {
            newInterval = this.MEDIUM_INTERVAL;
        }

        if (newInterval !== this._currentInterval) {
            this._currentInterval = newInterval;
            const label = newInterval === this.SLOW_INTERVAL ? '3m' : newInterval === this.MEDIUM_INTERVAL ? '30s' : '10s';
            console.log(`[ScanScheduler] No peers for ${Math.round(elapsed / 1000)}s — backoff to ${label}`);
            this._emit('intervalChange', { interval: newInterval, reason: 'backoff' });
        }
    }

    resetToFast(reason) {
        if (!this._running) return;
        this._emptyStreakStart = null;
        this._currentInterval = this.FAST_INTERVAL;
        if (this._timer) { clearTimeout(this._timer); this._timer = null; }
        this._scheduleNext(0); // scan immediately
        console.log(`[ScanScheduler] Reset to 10s — reason: ${reason}`);
        this._emit('intervalChange', { interval: this.FAST_INTERVAL, reason });
    }

    _scheduleNext(delayMs) {
        if (this._timer) clearTimeout(this._timer);
        this._timer = setTimeout(async () => {
            if (!this._running) return;
            try {
                const results = await this._scanFn();
                const count = Array.isArray(results) ? results.length : (results || 0);
                this.reportScanResult(count);
            } catch (err) {
                console.warn('[ScanScheduler] Scan error:', err.message);
                this.reportScanResult(0);
            }
        }, delayMs);
    }

    // Motion detection — reset scan rate when user is moving
    _watchMotion() {
        if (typeof DeviceMotionEvent === 'undefined') return;
        const ACCEL_THRESHOLD = 1.5; // m/s² — moderate movement
        let lastReset = 0;

        this._motionHandler = (event) => {
            const a = event.accelerationIncludingGravity;
            if (!a) return;
            const magnitude = Math.sqrt(a.x * a.x + a.y * a.y + a.z * a.z);
            // Subtract gravity (~9.8) and check if remaining acceleration exceeds threshold
            if (Math.abs(magnitude - 9.8) > ACCEL_THRESHOLD) {
                const now = Date.now();
                if (now - lastReset > 30_000) { // max 1 reset per 30s from motion
                    lastReset = now;
                    this.resetToFast('motion');
                }
            }
        };

        window.addEventListener('devicemotion', this._motionHandler, { passive: true });
    }

    _unwatchMotion() {
        if (this._motionHandler) {
            window.removeEventListener('devicemotion', this._motionHandler);
            this._motionHandler = null;
        }
    }

    // Network ping — reset when connectivity changes (wifi/cell toggle)
    _watchNetwork() {
        this._onlineHandler = () => this.resetToFast('network_change');
        window.addEventListener('online', this._onlineHandler);
    }

    _unwatchNetwork() {
        if (this._onlineHandler) {
            window.removeEventListener('online', this._onlineHandler);
            this._onlineHandler = null;
        }
    }

    getStatus() {
        return {
            running: this._running,
            interval: this._currentInterval,
            scanCount: this._scanCount,
            lastPeerSeen: this._lastPeerSeen,
            emptyStreak: this._emptyStreakStart ? Date.now() - this._emptyStreakStart : 0,
        };
    }
}


// ═══════════════════════════════════════════════════════════════════════════
// [2.2] SPLIT-BRAIN RECONCILIATION — Merkle Ledger Sync
// ═══════════════════════════════════════════════════════════════════════════
//
// When mesh islands re-merge, nodes exchange Merkle roots of their message
// ledgers. Mismatched roots trigger a delta sync — only missing messages
// are transferred, deduplicated by message ID + timestamp.

class MerkleLedgerSync {
    constructor() {
        this._messages = new Map(); // msgId → { id, from, to, ts, payload, hash }
        this._treeCache = null;     // cached root — invalidated on insert
    }

    // Add a message to the local ledger
    addMessage(msg) {
        if (!msg.id) return;
        if (this._messages.has(msg.id)) return; // dedup
        const entry = {
            id: msg.id,
            from: msg.from || msg.senderId,
            to: msg.to || msg.receiverId,
            ts: msg.ts || msg.timestamp || Date.now(),
            payloadHash: null, // computed lazily
        };
        this._messages.set(msg.id, entry);
        this._treeCache = null; // invalidate
    }

    // Get the Merkle root of the current ledger
    async getRoot() {
        if (this._treeCache) return this._treeCache;
        const ids = [...this._messages.keys()].sort();
        if (ids.length === 0) return '0'.repeat(64);
        this._treeCache = await this._buildRoot(ids);
        return this._treeCache;
    }

    // Build Merkle root from sorted message IDs
    async _buildRoot(sortedIds) {
        let hashes = await Promise.all(
            sortedIds.map(id => this._hashString(id))
        );

        while (hashes.length > 1) {
            const next = [];
            for (let i = 0; i < hashes.length; i += 2) {
                const left = hashes[i];
                const right = hashes[i + 1] || left; // duplicate last if odd
                next.push(await this._hashString(left + right));
            }
            hashes = next;
        }
        return hashes[0];
    }

    // Get all message IDs for delta calculation
    getMessageIds() {
        return new Set(this._messages.keys());
    }

    // Calculate what the remote peer is missing
    getDelta(remoteIds) {
        const missing = [];
        for (const [id, entry] of this._messages) {
            if (!remoteIds.has(id)) missing.push(entry);
        }
        return missing.sort((a, b) => a.ts - b.ts);
    }

    // Merge incoming messages from a reconnected island
    mergeRemoteMessages(remoteMsgs) {
        let added = 0;
        for (const msg of remoteMsgs) {
            if (!this._messages.has(msg.id)) {
                this._messages.set(msg.id, msg);
                added++;
            }
        }
        if (added > 0) this._treeCache = null;
        console.log(`[MerkleSync] Merged ${added} messages from reconnected island`);
        return added;
    }

    // Full sync protocol — called when a previously-lost peer reconnects
    async initSync(sendFn, receiveFn) {
        // Step 1: Exchange roots
        const localRoot = await this.getRoot();
        const remoteRoot = await sendFn({ type: 'MERKLE_ROOT', root: localRoot });

        if (remoteRoot === localRoot) {
            console.log('[MerkleSync] Ledgers in sync — no delta needed');
            return 0;
        }

        // Step 2: Exchange ID sets
        const localIds = this.getMessageIds();
        const remoteIds = await sendFn({ type: 'MERKLE_IDS', ids: [...localIds] });

        // Step 3: Send our delta to the remote
        const remoteIdSet = new Set(remoteIds);
        const ourDelta = this.getDelta(remoteIdSet);
        if (ourDelta.length > 0) {
            await sendFn({ type: 'MERKLE_DELTA', messages: ourDelta });
        }

        // Step 4: Receive their delta
        const theirDelta = await receiveFn('MERKLE_DELTA');
        const merged = theirDelta ? this.mergeRemoteMessages(theirDelta) : 0;

        console.log(`[MerkleSync] Sync complete — sent ${ourDelta.length}, received ${merged}`);
        return merged;
    }

    // SHA-256 hash of a string
    async _hashString(str) {
        const data = new TextEncoder().encode(str);
        const buf = await crypto.subtle.digest('SHA-256', data);
        return Array.from(new Uint8Array(buf)).map(b => b.toString(16).padStart(2, '0')).join('');
    }

    getStats() {
        return {
            messageCount: this._messages.size,
            hasRoot: !!this._treeCache,
        };
    }
}


// ═══════════════════════════════════════════════════════════════════════════
// [2.3] ZERO-ROUTE QUEUE — Encrypted Store-and-Forward
// ═══════════════════════════════════════════════════════════════════════════
//
// When the target node is offline/unreachable, messages are encrypted with
// the recipient's Ed25519 public key (converted to X25519 for ECDH), wrapped
// in AES-256-GCM, and held in local storage. When a relay node is detected,
// the encrypted package is offloaded for mesh traversal.

class ZeroRouteQueue {
    constructor() {
        this._queue = new Map();  // recipientId → [{ id, encryptedPayload, targetPubKey, createdAt, attempts }]
        this.MAX_QUEUE_PER_RECIPIENT = 200;
        this.MAX_TOTAL_QUEUED = 2000;
        this.MAX_AGE_MS = 24 * 60 * 60 * 1000; // 24 hours TTL
        this.STORAGE_KEY = 'kryptos_zero_route_queue';
        this._totalQueued = 0;
        this._listeners = {};

        this._loadFromStorage();
        this._startCleanupTimer();
    }

    on(event, fn) {
        if (!this._listeners[event]) this._listeners[event] = [];
        this._listeners[event].push(fn);
    }

    _emit(event, data) {
        (this._listeners[event] || []).forEach(fn => fn(data));
    }

    // Encrypt and queue a message for an offline recipient
    async enqueue(recipientId, targetPubKeyHex, plaintext, messageId) {
        if (!recipientId || !targetPubKeyHex || !plaintext) {
            throw new Error('recipientId, targetPubKeyHex, and plaintext are required');
        }

        // Enforce queue limits
        const recipientQueue = this._queue.get(recipientId) || [];
        if (recipientQueue.length >= this.MAX_QUEUE_PER_RECIPIENT) {
            recipientQueue.shift(); // drop oldest
            this._totalQueued--;
        }
        if (this._totalQueued >= this.MAX_TOTAL_QUEUED) {
            this._evictOldest();
        }

        // Generate ephemeral ECDH keypair for forward secrecy
        const ephemeral = await crypto.subtle.generateKey(
            { name: 'ECDH', namedCurve: 'P-256' },
            true, // extractable — we need to send the public key
            ['deriveBits']
        );

        // Import recipient's public key
        const recipientPub = await this._importPublicKey(targetPubKeyHex);

        // ECDH shared secret
        const sharedBits = await crypto.subtle.deriveBits(
            { name: 'ECDH', public: recipientPub },
            ephemeral.privateKey,
            256
        );

        // Derive AES-256-GCM key from shared secret via HKDF
        const ikm = await crypto.subtle.importKey('raw', sharedBits, 'HKDF', false, ['deriveKey']);
        const salt = crypto.getRandomValues(new Uint8Array(16));
        const aesKey = await crypto.subtle.deriveKey(
            { name: 'HKDF', hash: 'SHA-256', salt, info: new TextEncoder().encode('Kryptos-ZRQ-v1') },
            ikm,
            { name: 'AES-GCM', length: 256 },
            false,
            ['encrypt']
        );

        // Encrypt the payload
        const iv = crypto.getRandomValues(new Uint8Array(12));
        const encoded = new TextEncoder().encode(plaintext);
        const ciphertext = await crypto.subtle.encrypt(
            { name: 'AES-GCM', iv },
            aesKey,
            encoded
        );

        // Export ephemeral public key so recipient can derive the same shared secret
        const ephPubRaw = await crypto.subtle.exportKey('raw', ephemeral.publicKey);
        const ephPubHex = this._bufToHex(ephPubRaw);

        const packet = {
            id: messageId || this._generateId(),
            recipientId,
            ephemeralPubKey: ephPubHex,
            salt: this._bufToHex(salt),
            iv: this._bufToHex(iv),
            ciphertext: this._bufToHex(new Uint8Array(ciphertext)),
            createdAt: Date.now(),
            attempts: 0,
        };

        recipientQueue.push(packet);
        this._queue.set(recipientId, recipientQueue);
        this._totalQueued++;
        this._persistToStorage();

        this._emit('enqueued', { recipientId, messageId: packet.id, queueSize: recipientQueue.length });
        console.log(`[ZeroRoute] Queued message ${packet.id} for offline ${recipientId} (${recipientQueue.length} pending)`);
        return packet.id;
    }

    // Called when a relay node or the target comes into range
    async drainTo(recipientId, sendFn) {
        const queue = this._queue.get(recipientId);
        if (!queue || queue.length === 0) return 0;

        let sent = 0;
        const remaining = [];

        for (const packet of queue) {
            try {
                await sendFn({
                    type: 'ZERO_ROUTE_DELIVERY',
                    targetId: recipientId,
                    payload: {
                        id: packet.id,
                        ephemeralPubKey: packet.ephemeralPubKey,
                        salt: packet.salt,
                        iv: packet.iv,
                        ciphertext: packet.ciphertext,
                    }
                });
                sent++;
                this._totalQueued--;
                this._emit('delivered', { recipientId, messageId: packet.id });
            } catch (err) {
                packet.attempts++;
                if (packet.attempts < 5) {
                    remaining.push(packet);
                } else {
                    this._totalQueued--;
                    console.warn(`[ZeroRoute] Dropped ${packet.id} after 5 failed delivery attempts`);
                    this._emit('dropped', { recipientId, messageId: packet.id, reason: 'max_attempts' });
                }
            }
        }

        if (remaining.length > 0) {
            this._queue.set(recipientId, remaining);
        } else {
            this._queue.delete(recipientId);
        }
        this._persistToStorage();

        if (sent > 0) {
            console.log(`[ZeroRoute] Delivered ${sent} queued messages to ${recipientId}`);
        }
        return sent;
    }

    // Drain all queues to any available relay
    async drainAllViaRelay(relayNodeId, sendFn) {
        let totalSent = 0;
        for (const [recipientId, queue] of this._queue) {
            if (queue.length === 0) continue;
            const sent = await this.drainTo(recipientId, async (msg) => {
                msg.relayVia = relayNodeId;
                return sendFn(msg);
            });
            totalSent += sent;
        }
        return totalSent;
    }

    // Check if there are queued messages for a specific recipient
    hasPending(recipientId) {
        const q = this._queue.get(recipientId);
        return q && q.length > 0;
    }

    getPendingCount(recipientId) {
        return recipientId
            ? (this._queue.get(recipientId) || []).length
            : this._totalQueued;
    }

    // Persistence — survive app restarts
    _persistToStorage() {
        try {
            const serializable = {};
            for (const [rid, queue] of this._queue) {
                serializable[rid] = queue;
            }
            localStorage.setItem(this.STORAGE_KEY, JSON.stringify(serializable));
        } catch (err) {
            console.warn('[ZeroRoute] Storage persist failed:', err.message);
        }
    }

    _loadFromStorage() {
        try {
            const raw = localStorage.getItem(this.STORAGE_KEY);
            if (!raw) return;
            const parsed = JSON.parse(raw);
            for (const [rid, queue] of Object.entries(parsed)) {
                if (!Array.isArray(queue)) continue;
                // Filter expired
                const valid = queue.filter(p => Date.now() - p.createdAt < this.MAX_AGE_MS);
                if (valid.length > 0) {
                    this._queue.set(rid, valid);
                    this._totalQueued += valid.length;
                }
            }
            if (this._totalQueued > 0) {
                console.log(`[ZeroRoute] Restored ${this._totalQueued} queued messages from storage`);
            }
        } catch (err) {
            console.warn('[ZeroRoute] Storage load failed:', err.message);
        }
    }

    // Evict oldest entry across all recipients
    _evictOldest() {
        let oldestTime = Infinity;
        let oldestRid = null;
        for (const [rid, queue] of this._queue) {
            if (queue.length > 0 && queue[0].createdAt < oldestTime) {
                oldestTime = queue[0].createdAt;
                oldestRid = rid;
            }
        }
        if (oldestRid) {
            const q = this._queue.get(oldestRid);
            q.shift();
            this._totalQueued--;
            if (q.length === 0) this._queue.delete(oldestRid);
        }
    }

    // Periodic cleanup of expired messages
    _startCleanupTimer() {
        setInterval(() => {
            let expired = 0;
            const now = Date.now();
            for (const [rid, queue] of this._queue) {
                const before = queue.length;
                const valid = queue.filter(p => now - p.createdAt < this.MAX_AGE_MS);
                if (valid.length < before) {
                    expired += before - valid.length;
                    this._totalQueued -= (before - valid.length);
                }
                if (valid.length > 0) {
                    this._queue.set(rid, valid);
                } else {
                    this._queue.delete(rid);
                }
            }
            if (expired > 0) {
                console.log(`[ZeroRoute] Expired ${expired} stale queued messages`);
                this._persistToStorage();
            }
        }, 5 * 60 * 1000).unref?.(); // every 5 minutes
    }

    async _importPublicKey(hexKey) {
        const raw = this._hexToBuf(hexKey);
        return crypto.subtle.importKey(
            'raw', raw,
            { name: 'ECDH', namedCurve: 'P-256' },
            false, []
        );
    }

    _generateId() {
        const arr = new Uint8Array(12);
        crypto.getRandomValues(arr);
        return 'zrq_' + Array.from(arr).map(b => b.toString(16).padStart(2, '0')).join('');
    }

    _bufToHex(buf) {
        return Array.from(new Uint8Array(buf.buffer || buf))
            .map(b => b.toString(16).padStart(2, '0')).join('');
    }

    _hexToBuf(hex) {
        const clean = hex.startsWith('0x') ? hex.slice(2) : hex;
        const bytes = new Uint8Array(clean.match(/.{1,2}/g).map(b => parseInt(b, 16)));
        return bytes.buffer;
    }

    getStats() {
        const perRecipient = {};
        for (const [rid, queue] of this._queue) {
            perRecipient[rid] = queue.length;
        }
        return {
            totalQueued: this._totalQueued,
            recipients: this._queue.size,
            perRecipient,
        };
    }

    destroy() {
        this._persistToStorage();
        this._queue.clear();
        this._totalQueued = 0;
    }
}


// ═══════════════════════════════════════════════════════════════════════════
// EXPORTS
// ═══════════════════════════════════════════════════════════════════════════

if (typeof window !== 'undefined') {
    window.AdaptiveScanScheduler = AdaptiveScanScheduler;
    window.MerkleLedgerSync = MerkleLedgerSync;
    window.ZeroRouteQueue = ZeroRouteQueue;
}

if (typeof module !== 'undefined' && module.exports) {
    module.exports = { AdaptiveScanScheduler, MerkleLedgerSync, ZeroRouteQueue };
}
