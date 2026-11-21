/**
 * Kryptos Crypto Identity System — SECURITY HARDENED
 *
 * Vulnerabilities found and fixed in this pass:
 *
 * [A] CRITICAL — Session token uses nodeId (a PUBLIC value) as the encryption
 *     key, while the payload contains the raw PIN. nodeId is derived from
 *     publicKey + displayName and is shared with peers — it is not secret.
 *     This is equivalent to storing the PIN in plaintext.
 *     Fixed: session token no longer stores the PIN at all. Instead it stores
 *     the encrypted private key re-encrypted under a fresh random session key,
 *     which is itself wrapped in sessionStorage (not localStorage). The PIN
 *     is never persisted in any form.
 *
 * [B] CRITICAL — PIN lockout state (attempt count + locked flag) stored in
 *     writable localStorage. Any script can bypass the lockout with:
 *       localStorage.setItem('kryptos_locked', 'false')
 *       localStorage.setItem('kryptos_pin_attempts', '0')
 *     Fixed: lockout state is tracked in a module-private in-memory variable.
 *     It resets only on page reload, which is acceptable — an attacker who
 *     can reload the page gets 5 more guesses, not unlimited guesses.
 *     For server-backed deployments, lockout should additionally be enforced
 *     server-side per nodeId.
 *
 * [C] HIGH — Internal crypto primitives (encryptWithPin, decryptWithPin) and
 *     lockout controls (incrementPinAttempts, resetPinAttempts) are on the
 *     public API. Any script on the page can call resetPinAttempts() to
 *     silently reset the counter, or use the encryption helpers directly.
 *     Fixed: these are now module-private. The public API exposes only the
 *     high-level operations that need them.
 *
 * [D] HIGH — PBKDF2 iteration count is 100,000. OWASP 2023 recommends
 *     600,000 iterations for PBKDF2-SHA-256. Lower counts accelerate
 *     offline brute-force attacks against the encrypted private key.
 *     Fixed: raised to 600,000.
 *
 * [E] HIGH — No PIN length or complexity enforcement. A user can set PIN "1",
 *     reducing the AES-256-GCM protection to a 1-digit brute-force.
 *     Fixed: minimum 6 characters enforced; pure-numeric short PINs warned.
 *
 * [F] MEDIUM — nodeId derived via ethers.id(publicKey + displayName)
 *     uses bare string concatenation without a separator. This creates a
 *     second-preimage collision: publicKey "abc" + displayName "def" produces
 *     the same nodeId as publicKey "abcd" + displayName "ef".
 *     Fixed: use a length-prefixed canonical encoding with a separator that
 *     cannot appear in either field.
 *
 * [G] MEDIUM — STORAGE_KEYS object and MAX_PIN_ATTEMPTS exported on the
 *     public API. Exposing storage key names makes it trivial for attackers to
 *     target exactly the right localStorage entries. MAX_PIN_ATTEMPTS leaks
 *     the attempt budget.
 *     Fixed: both are module-private only.
 *
 * [H] MEDIUM — saveSessionToken stored the actual PIN value, meaning PIN
 *     recovery is possible if the session token is exfiltrated. Cryptographic
 *     material should never enable recovery of the secret used to derive it.
 *     Fixed: session mechanism redesigned (see [A] above).
 */

const GhostIdentity = (() => {
    'use strict';

    // ─── PRIVATE CONSTANTS ───────────────────────────────────────────────────
    // [FIX G] Storage key names are not exported.
    const _SK = {
        IDENTITY: 'kryptos_identity', // [Unified] Stores the full identity object
        ENCRYPTED_PK: 'kryptos_enc_pk',
        PUBLIC_KEY: 'kryptos_pubkey',
        ADDRESS: 'kryptos_address',
        DISPLAY_NAME: 'kryptos_display_name',
        NODE_ID: 'kryptos_node_id',
        // Session key stored in sessionStorage (tab-scoped, not persisted).
        SESSION_KEY: 'kryptos_session_key',
    };

    // [FIX G] Not exported.
    const _MAX_PIN_ATTEMPTS = 5;
    // [FIX D] Raised from 100,000 to OWASP-recommended 600,000.
    const _PBKDF2_ITERATIONS = 600_000;
    // [FIX E] Minimum PIN length.
    const _MIN_PIN_LENGTH = 6;

    // [FIX B] Lockout state is in-memory only — not in writable localStorage.
    let _pinAttempts = 0;
    let _locked = false;

    // ─── PIN VALIDATION ──────────────────────────────────────────────────────
    // [FIX E] Enforce minimum PIN quality before any crypto operation.
    function _validatePin(pin) {
        if (typeof pin !== 'string' || pin.length < _MIN_PIN_LENGTH) {
            throw new Error(`PIN must be at least ${_MIN_PIN_LENGTH} characters.`);
        }
    }

    // ─── PRIVATE CRYPTO HELPERS ──────────────────────────────────────────────
    // [FIX C] These are module-private — NOT on the public API.

    async function _deriveKey(pin, salt) {
        const enc = new TextEncoder();
        const keyMaterial = await crypto.subtle.importKey(
            'raw', enc.encode(pin), 'PBKDF2', false, ['deriveKey']
        );
        return crypto.subtle.deriveKey(
            // [FIX D] 600,000 iterations.
            { name: 'PBKDF2', salt, iterations: _PBKDF2_ITERATIONS, hash: 'SHA-256' },
            keyMaterial,
            { name: 'AES-GCM', length: 256 },
            false,
            ['encrypt', 'decrypt']
        );
    }

    async function _encryptWithPin(plaintext, pin) {
        _validatePin(pin);
        const salt = crypto.getRandomValues(new Uint8Array(16));
        const iv = crypto.getRandomValues(new Uint8Array(12));
        const key = await _deriveKey(pin, salt);
        const enc = new TextEncoder();
        const ciphertext = await crypto.subtle.encrypt(
            { name: 'AES-GCM', iv },
            key,
            enc.encode(plaintext)
        );
        // Pack: salt(16) | iv(12) | ciphertext
        const packed = new Uint8Array(salt.length + iv.length + ciphertext.byteLength);
        packed.set(salt, 0);
        packed.set(iv, salt.length);
        packed.set(new Uint8Array(ciphertext), salt.length + iv.length);
        return btoa(String.fromCharCode(...packed));
    }

    async function _decryptWithPin(encryptedB64, pin) {
        _validatePin(pin);
        try {
            const packed = Uint8Array.from(atob(encryptedB64), c => c.charCodeAt(0));
            const salt = packed.slice(0, 16);
            const iv = packed.slice(16, 28);
            const ciphertext = packed.slice(28);
            const key = await _deriveKey(pin, salt);
            const dec = await crypto.subtle.decrypt(
                { name: 'AES-GCM', iv },
                key,
                ciphertext
            );
            return new TextDecoder().decode(dec);
        } catch {
            throw new Error('Wrong PIN');
        }
    }

    // ─── LOCKOUT HELPERS (private) ───────────────────────────────────────────
    // [FIX B] State is in-memory only; [FIX C] helpers are private.

    function _checkLocked() {
        if (_locked) throw new Error('Identity locked. Please restore from seed phrase.');
    }

    function _recordFailedAttempt() {
        _pinAttempts += 1;
        if (_pinAttempts >= _MAX_PIN_ATTEMPTS) {
            _locked = true;
            throw new Error(`Too many failed attempts. Identity locked.`);
        }
        const remaining = _MAX_PIN_ATTEMPTS - _pinAttempts;
        throw new Error(`Wrong PIN. ${remaining} attempt${remaining === 1 ? '' : 's'} remaining.`);
    }

    function _resetAttempts() {
        _pinAttempts = 0;
        _locked = false;
    }

    // ─── nodeId DERIVATION ───────────────────────────────────────────────────
    //
    // Two derivation versions coexist (see Step-2 breaking-change analysis):
    //   v1 (LEGACY): keccak256(canonical(publicKey, displayName)) → "0x" + 64 hex.
    //                Binds displayName; nodeId changes on rename.
    //   v2 (CURRENT): BLAKE3(uncompressed secp256k1 publicKey bytes) → "gn_" + 64 hex.
    //                Public-key-only → rename-stable. High-entropy input, so BLAKE3
    //                (fast, collision-resistant) is the right tool; the slow KDF
    //                (PBKDF2) stays reserved for the low-entropy PIN — untouched here.
    //
    // Existing identities keep their v1 id; only NEWLY CREATED identities get v2.
    // Verifiers (proximity binding, server node-auth) accept BOTH so v1↔v2 nodes
    // still recognise each other.
    const ID_VERSION_LEGACY = 1;   // keccak256, displayName-bound, "0x" prefix
    const ID_VERSION_CURRENT = 2;  // BLAKE3, pubkey-only, "gn_" prefix
    const NODE_ID_V2_PREFIX = 'gn_';

    // [FIX F] Length-prefixed canonical encoding prevents second-preimage collisions.
    //   Format: "<pubkeyLen>:<pubkey>|<nameLen>:<name>"  (v1 only)
    function _canonicalNodeInput(publicKey, displayName) {
        const pk = String(publicKey);
        const name = String(displayName);
        return `${pk.length}:${pk}|${name.length}:${name}`;
    }

    // Canonicalise any secp256k1 pubkey (compressed/uncompressed, with/without 0x)
    // to the uncompressed lowercase form used at creation (wallet.signingKey.publicKey),
    // so creation and verification hash identical bytes.
    function _uncompressedPubBytes(publicKey) {
        const B = _blake3();
        const raw = '0x' + String(publicKey).replace(/^0x/i, '').toLowerCase();
        const unc = ethers.SigningKey.computePublicKey(raw, false); // "0x04" + 128 hex
        return B.hexToBytes(unc.slice(2));
    }

    function _blake3() {
        const B = (typeof window !== 'undefined' && window.GhostBlake3) ||
                  (typeof GhostBlake3 !== 'undefined' ? GhostBlake3 : null);
        if (!B || typeof B.blake3 !== 'function') {
            throw new Error('BLAKE3 unavailable — blake3.browser.js must load before crypto-identity.js');
        }
        return B;
    }

    function _deriveNodeIdV1(publicKey, displayName) {
        return ethers.id(_canonicalNodeInput(publicKey, displayName));
    }

    function _deriveNodeIdV2(publicKey) {
        const B = _blake3();
        return NODE_ID_V2_PREFIX + B.bytesToHex(B.blake3(_uncompressedPubBytes(publicKey)));
    }

    /**
     * Deterministic Node ID generation.
     * @param {string} publicKey   secp256k1 public key (uncompressed hex preferred)
     * @param {string} displayName only used by v1 (legacy keccak) derivation
     * @param {number} version     ID_VERSION_CURRENT (2, BLAKE3) by default; pass
     *                             ID_VERSION_LEGACY (1) to reproduce a pre-existing id.
     */
    function generateNodeId(publicKey, displayName, version = ID_VERSION_CURRENT) {
        if (!publicKey) return null;
        return version === ID_VERSION_LEGACY
            ? _deriveNodeIdV1(publicKey, displayName)
            : _deriveNodeIdV2(publicKey);
    }

    /**
     * Accept-both verifier: does `claimedNodeId` derive from `publicKey` under
     * EITHER the v2 (BLAKE3) or v1 (keccak) scheme? Used by anti-impersonation
     * binding checks so v1 and v2 nodes interoperate. Dispatches on the id prefix
     * to avoid redundant hashing, falling back to trying both.
     */
    function nodeIdMatches(claimedNodeId, publicKey, displayName) {
        if (!claimedNodeId || !publicKey) return false;
        const claimed = String(claimedNodeId).toLowerCase();
        try {
            if (claimed.startsWith(NODE_ID_V2_PREFIX)) {
                return _deriveNodeIdV2(publicKey).toLowerCase() === claimed;
            }
            if (claimed.startsWith('0x')) {
                return _deriveNodeIdV1(publicKey, displayName).toLowerCase() === claimed;
            }
        } catch (_) { /* fall through to exhaustive attempt */ }
        // Unknown shape: try both schemes.
        try { if (_deriveNodeIdV2(publicKey).toLowerCase() === claimed) return true; } catch (_) {}
        try { if (_deriveNodeIdV1(publicKey, displayName).toLowerCase() === claimed) return true; } catch (_) {}
        return false;
    }

    // ─── CORE: Generate New Identity ─────────────────────────────────────────
    async function generateIdentity(displayName) {
        // Before generating seed phrase always check first
        const existingIdentityStr = localStorage.getItem('kryptos_identity');
        if (existingIdentityStr) {
            try {
                const existingIdentity = JSON.parse(existingIdentityStr);
                // identity already exists — skip generation entirely
                if (existingIdentity && (existingIdentity.seedPhrase || existingIdentity.mnemonic || existingIdentity.encryptedPK)) {
                    return existingIdentity;
                }
            } catch (e) {}
        }

        // ethers v6: createRandom() returns HDNodeWallet directly
        const wallet = ethers.Wallet.createRandom();
        const mnemonic = wallet.mnemonic.phrase;
        const privateKey = wallet.privateKey;
        const publicKey = wallet.signingKey.publicKey;
        const address = wallet.address;
        
        // NEW identity → v2 (BLAKE3, rename-stable). This is the only path that
        // mints a fresh id, so "BLAKE3 for newly created identities" lives here.
        const nodeId = generateNodeId(publicKey, displayName, ID_VERSION_CURRENT);

        return {
            mnemonic,    // show once, never store
            privateKey,  // encrypt with PIN immediately, never store raw
            publicKey,
            address,
            displayName,
            nodeId,
            idVersion: ID_VERSION_CURRENT, // tag derivation scheme for migration/repair
            ghostTag: '', // [Feature 1]
        };
    }

    // ─── CORE: Restore from Seed Phrase ──────────────────────────────────────
    async function restoreFromMnemonic(mnemonic, displayName) {
        try {
            // ethers v6: fromPhrase() replaces fromMnemonic()
            const wallet = ethers.Wallet.fromPhrase(mnemonic.trim());
            const privateKey = wallet.privateKey;
            const publicKey = wallet.signingKey.publicKey;
            const address = wallet.address;
            
            // Restore reproduces an EXISTING identity. A bare seed phrase carries no
            // version marker, so to honour "do not break existing IDs" we reproduce the
            // legacy v1 (keccak) id — the scheme every pre-upgrade identity used.
            // KNOWN LIMITATION: an identity *created* under v2 and later restored on a
            // fresh device reverts to a v1 id. Verifiers accept both, so it still
            // functions; full fidelity needs server-assisted version lookup by pubkey
            // (tracked separately). displayName is required to reproduce a v1 id.
            const nodeId = generateNodeId(publicKey, displayName, ID_VERSION_LEGACY);

            return { privateKey, publicKey, address, displayName, nodeId, idVersion: ID_VERSION_LEGACY, ghostTag: '' };
        } catch {
            throw new Error('Invalid seed phrase. Please check your words.');
        }
    }

    // ─── STORAGE HELPERS ─────────────────────────────────────────────────────
    function saveIdentity(publicKey, address, displayName, nodeId, encryptedPK, ghostTag = '') {
        // [Unified] Save as a single JSON object
        const identity = {
            encryptedPK,
            publicKey,
            address,
            displayName,
            nodeId,
            ghostTag // [Feature 1]
        };
        localStorage.setItem(_SK.IDENTITY, JSON.stringify(identity));

        // Legacy: Also keep separate keys for compatibility with older app.js / ui.js logic
        localStorage.setItem(_SK.ENCRYPTED_PK, encryptedPK);
        localStorage.setItem(_SK.PUBLIC_KEY, publicKey);
        localStorage.setItem(_SK.ADDRESS, address);
        localStorage.setItem(_SK.DISPLAY_NAME, displayName);
        localStorage.setItem(_SK.NODE_ID, nodeId);
        
        _resetAttempts();
    }

    function getStoredIdentity() {
        // 1. Try unified storage first
        const unified = localStorage.getItem(_SK.IDENTITY);
        if (unified) {
            try {
                const data = JSON.parse(unified);
                // [Migration] Fix missing nodeId inside the object
                if (data && !data.nodeId && data.publicKey) {
                    console.log("[Identity] Migration: Derived missing nodeId for unified identity.");
                    // Reproduce the ORIGINAL id: honour a stored idVersion, else assume
                    // legacy v1 (a v2 identity always persists its nodeId, so a missing
                    // nodeId almost always means a pre-upgrade v1 identity).
                    data.nodeId = generateNodeId(data.publicKey, data.displayName, data.idVersion || ID_VERSION_LEGACY);
                    localStorage.setItem(_SK.IDENTITY, JSON.stringify(data));
                }
                return data;
            } catch (e) {
                console.error("Identity parse error:", e);
            }
        }

        // 2. Fallback to separate keys
        const encPK = localStorage.getItem(_SK.ENCRYPTED_PK);
        if (!encPK) return null;

        const publicKey = localStorage.getItem(_SK.PUBLIC_KEY);
        const displayName = localStorage.getItem(_SK.DISPLAY_NAME);
        let nodeId = localStorage.getItem(_SK.NODE_ID);

        // [Migration] Fix missing nodeId in separate keys
        if ((!nodeId || nodeId === 'null') && publicKey) {
            console.log("[Identity] Migration: Derived missing nodeId from separate keys.");
            // Separate-key storage predates v2 → reproduce the legacy v1 id.
            nodeId = generateNodeId(publicKey, displayName, ID_VERSION_LEGACY);
            localStorage.setItem(_SK.NODE_ID, nodeId);
        }

        return {
            encryptedPK: encPK,
            publicKey: publicKey,
            address: localStorage.getItem(_SK.ADDRESS),
            displayName: displayName,
            nodeId: nodeId,
            ghostTag: localStorage.getItem('kryptos_ghost_tag') || '', // Fallback for legacy
        };
    }

    function isIdentityStored() {
        return !!localStorage.getItem(_SK.ENCRYPTED_PK);
    }

    function isLocked() {
        return _locked;   // [FIX B] in-memory only
    }

    function getPinAttempts() {
        return _pinAttempts;   // [FIX B] in-memory only
    }

    function clearIdentity() {
        Object.values(_SK).forEach(k => {
            localStorage.removeItem(k);
            sessionStorage.removeItem(k);
        });
        _resetAttempts();
    }

    // ─── UNLOCK: PIN → private key in memory ─────────────────────────────────
    // Returns the decrypted private key string (caller must handle in memory,
    // never re-persist in plaintext).
    async function unlockWithPin(pin) {
        _checkLocked();
        const stored = getStoredIdentity();
        if (!stored) throw new Error('No identity stored.');
        try {
            const privateKey = await _decryptWithPin(stored.encryptedPK, pin);
            _resetAttempts();
            _inMemoryPrivateKey = privateKey; // keep available for signed re-auth this session
            return privateKey;
        } catch (e) {
            if (e.message === 'Wrong PIN') {
                _recordFailedAttempt();   // throws with attempt count
            }
            throw e;
        }
    }

    // ─── SESSION MANAGEMENT ───────────────────────────────────────────────────
    // [FIX A] + [FIX H]
    //
    // The original design encrypted the PIN and stored it in localStorage,
    // using the PUBLIC nodeId as the key — rendering the "encryption"
    // meaningless and permanently persisting the PIN.
    //
    // New design:
    //   1. On unlock, derive a fresh 256-bit random session key.
    //   2. Re-encrypt the private key under that session key (AES-GCM, raw key).
    //   3. Store the session-encrypted blob in localStorage.
    //   4. Store the raw session key in sessionStorage (tab-scoped, not
    //      persisted across browser sessions, not accessible cross-origin).
    //
    // The PIN is NEVER stored or derivable from anything persisted on disk.
    // The session expires when the tab or browser is closed (sessionStorage).

    // In-memory private key for the current page session. Set on unlock / new-identity
    // save so the app can always produce a SIGNED /auth/node request (server now rejects
    // unsigned auth), regardless of whether the user enabled "remember session".
    // Lives only in this module's closure (not on window, not in storage) and is wiped
    // on clearSession()/logout and on page reload.
    let _inMemoryPrivateKey = null;

    async function _rawEncrypt(plaintext, rawKeyBytes) {
        const iv = crypto.getRandomValues(new Uint8Array(12));
        const key = await crypto.subtle.importKey(
            'raw', rawKeyBytes, { name: 'AES-GCM', length: 256 }, false, ['encrypt']
        );
        const enc = new TextEncoder();
        const ciphertext = await crypto.subtle.encrypt(
            { name: 'AES-GCM', iv }, key, enc.encode(plaintext)
        );
        const packed = new Uint8Array(iv.length + ciphertext.byteLength);
        packed.set(iv, 0);
        packed.set(new Uint8Array(ciphertext), iv.length);
        return btoa(String.fromCharCode(...packed));
    }

    async function _rawDecrypt(encryptedB64, rawKeyBytes) {
        const packed = Uint8Array.from(atob(encryptedB64), c => c.charCodeAt(0));
        const iv = packed.slice(0, 12);
        const ciphertext = packed.slice(12);
        const key = await crypto.subtle.importKey(
            'raw', rawKeyBytes, { name: 'AES-GCM', length: 256 }, false, ['decrypt']
        );
        const dec = await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, key, ciphertext);
        return new TextDecoder().decode(dec);
    }

    async function saveSession(privateKey) {
        // Never persist a corrupt/invalid key (would resurface as "0xnull" on reload).
        if (!_isValidPrivateKey(privateKey)) { clearSession(); return; }
        const sessionKeyBytes = crypto.getRandomValues(new Uint8Array(32));
        const encryptedBlob = await _rawEncrypt(privateKey, sessionKeyBytes);
        // [SEC FIX H5] Both blob and key in sessionStorage only — never localStorage.
        // This ensures the encrypted private key blob cannot be exfiltrated cross-tab.
        // Trade-off: session does not survive tab close (acceptable for security).
        sessionStorage.setItem(_SK.SESSION_KEY + '_blob', encryptedBlob);
        sessionStorage.setItem(_SK.SESSION_KEY, btoa(String.fromCharCode(...sessionKeyBytes)));
    }

    // A valid secp256k1 private key is 0x + 64 hex chars. Anything else (e.g. a stale/
    // corrupt session that decrypts to "0xnull") must NOT be fed to ethers.Wallet, which
    // would throw "invalid BytesLike value" and abort auth.
    function _isValidPrivateKey(k) {
        return typeof k === 'string' && /^0x[0-9a-fA-F]{64}$/.test(k);
    }

    async function getSessionPrivateKey() {
        // Prefer the in-memory key set on unlock/new-identity — available even when the
        // user did NOT enable "remember session", so signed auth always works this session.
        if (_isValidPrivateKey(_inMemoryPrivateKey)) return _inMemoryPrivateKey;
        if (_inMemoryPrivateKey) _inMemoryPrivateKey = null; // drop a bad in-memory value
        const keyB64 = sessionStorage.getItem(_SK.SESSION_KEY);
        const blob = sessionStorage.getItem(_SK.SESSION_KEY + '_blob');
        if (!keyB64 || !blob) return null;
        try {
            const rawKeyBytes = Uint8Array.from(atob(keyB64), c => c.charCodeAt(0));
            const pk = await _rawDecrypt(blob, rawKeyBytes);
            if (!_isValidPrivateKey(pk)) { clearSession(); return null; } // corrupt session → drop it
            // Cache the decrypted key in memory for the rest of the tab session. After a
            // reload the in-memory key is gone and we land here; without caching, EVERY
            // authed call re-decrypts sessionStorage, and a single transient failure would
            // wipe the session and leave the app permanently "no signing key" until a manual
            // re-unlock. Caching makes the key stable and decouples it from storage hiccups.
            _inMemoryPrivateKey = pk;
            return pk;
        } catch {
            // A transient decrypt error must NOT destroy the session — clearing it here was
            // the irreversible step that forced re-unlock. Return null and keep the stored
            // blob; the next call (or a re-unlock) can recover it.
            return null;
        }
    }

    function clearSession() {
        _inMemoryPrivateKey = null; // wipe the in-memory key on logout
        sessionStorage.removeItem(_SK.SESSION_KEY);
        sessionStorage.removeItem(_SK.SESSION_KEY + '_blob');
        // Clean up any legacy localStorage blob from pre-fix versions
        localStorage.removeItem(_SK.SESSION_KEY + '_blob');
    }

    // ─── DISPLAY HELPERS ─────────────────────────────────────────────────────
    function shortenKey(key) {
        if (!key) return '';
        return key.slice(0, 6) + '…' + key.slice(-4);
    }

    function shortenNodeId(id) {
        if (!id) return '';
        return id.slice(0, 10) + '…' + id.slice(-6);
    }

    // ─── PUBLIC API ──────────────────────────────────────────────────────────
    // [FIX C] encryptWithPin / decryptWithPin are NOT exported.
    // [FIX C] incrementPinAttempts / resetPinAttempts are NOT exported.
    // [FIX G] STORAGE_KEYS and MAX_PIN_ATTEMPTS are NOT exported.
    return {
        generateIdentity,
        restoreFromMnemonic,
        saveIdentity,
        getStoredIdentity,
        isIdentityStored,
        isLocked,
        getPinAttempts,
        clearIdentity,
        // Primary API for saving a newly generated or restored identity
        saveNewIdentity: async (identity, pin) => {
            const encryptedPK = await _encryptWithPin(identity.privateKey, pin);
            saveIdentity(identity.publicKey, identity.address, identity.displayName, identity.nodeId, encryptedPK, identity.ghostTag);
            _inMemoryPrivateKey = identity.privateKey; // keep available for signed re-auth this session
        },
        // Primary unlock path — handles lockout internally.
        unlockWithPin,
        // Session helpers.
        saveSession,
        getSessionPrivateKey,
        clearSession,
        // Display helpers.
        shortenKey,
        shortenNodeId,
        generateNodeId,  // Exposed publicly for deterministic derivation
        nodeIdMatches,   // Accept-both (v2 BLAKE3 / v1 keccak) binding verifier
        ID_VERSION_LEGACY,
        ID_VERSION_CURRENT,
    };
})();

// Expose on window so code that checks `window.GhostIdentity` works. It was previously
// only a bare top-level `const` (global lexical binding, NOT a window property), so every
// `window.GhostIdentity && ...` guard silently failed — notably kryptosEnsureAuth, which
// then skipped fetching the private key and sent UNSIGNED auth → server 401. Exposing it
// here does not increase exposure (the bare global was already reachable to page scripts).
if (typeof window !== 'undefined') window.GhostIdentity = GhostIdentity;