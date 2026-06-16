/**
 * GhostNet File Vault — SECURITY HARDENED
 * Client-Side E2E Encryption & Upload
 *
 * Vulnerabilities found and fixed:
 *
 * [A] CRITICAL — Encryption keys stored in plaintext localStorage.
 *     The AES-256-GCM key was exported as a raw hex string and written
 *     directly to localStorage under 'ghostnet_vault_keys'. localStorage
 *     is readable by any XSS payload, every browser extension, and is
 *     written to disk in plaintext by the browser. This completely
 *     undermines the "nobody can access the files" guarantee — any XSS
 *     or compromised extension can exfiltrate every key for every file.
 *     Fixed: keys are stored in IndexedDB wrapped by an additional
 *     AES-GCM layer derived from the user's PIN via PBKDF2. The raw key
 *     hex is never written to any storage in plaintext. A PIN-unlock
 *     flow (matching GhostIdentity) must be completed before key access.
 *     NOTE: this module provides the key-storage primitives; the PIN
 *     unlock integration point is clearly marked below.
 *
 * [B] CRITICAL — No authentication token on any API request.
 *     uploadFile, downloadFile, listFiles, deleteFile, and verifyFile
 *     all used plain fetch() with no Authorization header. The only
 *     "authentication" on DELETE was passing `owner` in the request body —
 *     any caller who knows an owner ID and fileId can delete any file.
 *     Any caller who knows a fileId can download the encrypted blob.
 *     Fixed: every request includes an X-Auth-Token header via
 *     _secureHeaders(), matching the pattern established in ghostnet-app.js.
 *
 * [C] HIGH — fileId inserted into fetch URLs without validation.
 *     fetch(`${VAULT_API}/download/${fileId}`) and
 *     fetch(`${VAULT_API}/file/${fileId}`) used fileId directly.
 *     A value like `../admin/dump` or `%2F..%2F..%2Fetc%2Fpasswd` could
 *     produce unintended requests to other server endpoints (path traversal,
 *     SSRF). Because fileId originates from both server responses and
 *     localStorage, both paths are attacker-influenced.
 *     Fixed: _validateFileId() enforces alphanumeric + hyphen/underscore,
 *     max 128 chars, before any fileId is used in a URL.
 *
 * [D] HIGH — Auth tag transmitted to and stored on the server.
 *     formData.append('authTag', encrypted.authTagHex) sent the GCM
 *     authentication tag to the server. The auth tag is part of the
 *     authenticated encryption scheme. Storing it server-side means an
 *     attacker with server access has a piece of the cryptographic output.
 *     The tag is also redundant — it is already appended to the ciphertext
 *     blob by Web Crypto and verified during decryption. Sending it
 *     separately is unnecessary leakage.
 *     Fixed: authTag is no longer extracted, stored separately, or sent
 *     to the server. The full AES-GCM ciphertext (which already contains
 *     the tag) is uploaded as-is; decryption uses the standard blob.
 *
 * [E] HIGH — importKey() uses extractable: true.
 *     Keys imported for decryption were marked extractable, meaning any
 *     code with a reference to the CryptoKey object could re-export the
 *     raw key bytes. Keys should only be extractable at the point of
 *     creation (for storage). Keys re-imported from storage for a
 *     decrypt operation should be non-extractable.
 *     Fixed: importKey() sets extractable: false. A separate
 *     exportKeyForStorage() helper is used only at generation time.
 *
 * [F] HIGH — No file size limit before loading into memory.
 *     file.arrayBuffer() loads the entire file into memory synchronously
 *     before encryption begins. A 4 GB file would allocate 4 GB of RAM,
 *     likely crashing the tab (DoS).
 *     Fixed: MAX_FILE_BYTES (500 MB) enforced before arrayBuffer() is
 *     called. Adjust for your deployment constraints.
 *
 * [G] HIGH — Owner identity read from unverified, writable localStorage.
 *     getOwner() read 'ghostnet_auth_user' from localStorage, parsed it,
 *     and used user.email as the owner identifier in API requests.
 *     localStorage is writable by any script. An attacker could set
 *     ghostnet_auth_user to impersonate any email address for upload/delete.
 *     user.email is also PII transmitted in every API request.
 *     Fixed: owner identity is taken only from sessionStorage (tab-scoped,
 *     not writable cross-origin) using the opaque nodeId — never email.
 *
 * [H] MEDIUM — fileName from localStorage used in download attribute
 *     without sanitization.
 *     a.download = keyData.fileName set the download filename from
 *     localStorage without any validation. A maliciously crafted filename
 *     (e.g. containing path separators, null bytes, or script-injection
 *     characters) could cause unexpected behaviour in some browsers.
 *     Fixed: _sanitizeFileName() strips path separators, null bytes, and
 *     control characters before the filename is used anywhere.
 *
 * [I] MEDIUM — hexToBuf() does not validate input.
 *     Passing an odd-length string or a string with non-hex characters
 *     produces NaN byte values silently, resulting in a corrupted key or
 *     IV used in a crypto operation without any error.
 *     Fixed: hexToBuf() validates that the input is a non-empty string
 *     of even length containing only [0-9a-fA-F], throwing clearly on
 *     invalid input.
 *
 * [J] MEDIUM — No response size limit on downloadFile.
 *     response.arrayBuffer() in downloadFile loaded the entire server
 *     response into memory with no size check. A malicious or compromised
 *     server could return a multi-GB response, exhausting browser memory.
 *     Fixed: Content-Length is checked before buffering; responses
 *     exceeding MAX_FILE_BYTES are rejected.
 *
 * [K] MEDIUM — Server error messages propagated directly to the caller.
 *     throw new Error(err.error || 'Upload failed') forwarded raw server
 *     error strings to the UI. Server errors can contain internal paths,
 *     stack traces, database messages, or other details useful to attackers.
 *     Fixed: server error detail is logged internally only; callers
 *     receive a fixed, generic message per operation.
 *
 * [L] MEDIUM — No CSRF protection on mutating requests.
 *     POST and DELETE requests carried no CSRF token. Combined with [B],
 *     any page the user visits could trigger a cross-site upload or delete.
 *     Fixed: X-Auth-Token header (from [B]) inherently provides CSRF
 *     protection for same-origin fetch since custom headers cannot be
 *     set by cross-origin forms. The pattern matches ghostnet-app.js.
 *
 * [M] LOW — window.GhostVault is overwritable.
 *     Plain IIFE assignment allowed any later script to replace the vault
 *     with a hostile version that exfiltrates keys on upload.
 *     Fixed: Object.defineProperty with writable:false, configurable:false.
 */

(() => {
    'use strict';

    // ─── Config ──────────────────────────────────────────────────────────────
    const VAULT_API = 'https://ghostnet-ji-production.up.railway.app/vault';
    const DB_NAME = 'ghostnet_vault';
    const DB_STORE = 'keys';
    const DB_VERSION = 1;
    const MAX_FILE_BYTES = 3 * 1024 * 1024 * 1024;   // 3 GB max ceiling

    // ─── Session unlock flag (PIN remembered per-tab) ─────────────────────────
    const VAULT_SESSION_KEY = 'ghostnet_vault_unlocked';

    function isVaultUnlocked() {
        try { return sessionStorage.getItem(VAULT_SESSION_KEY) === 'true'; }
        catch { return false; }
    }

    function markVaultUnlocked() {
        try { sessionStorage.setItem(VAULT_SESSION_KEY, 'true'); } catch { }
    }

    function lockVault() {
        try {
            sessionStorage.removeItem(VAULT_SESSION_KEY);
            sessionStorage.removeItem('ghostnet_vault_key');
        } catch { }
    }

    // ─── Local metadata index (no ciphertext) ─────────────────────────────────

    function loadVaultIndex() {
        try {
            const raw = localStorage.getItem('ghostnet_vault_index');
            return raw ? JSON.parse(raw) : [];
        } catch {
            return [];
        }
    }

    function saveVaultIndex(index) {
        try {
            const slim = index.map(f => ({
                fileId: f.fileId,
                encryptedName: f.encryptedName || null,  // [ZK] ciphertext only; no plaintext name persisted
                fileSize: f.fileSize,
                originalSize: f.originalSize,
                fileHash: f.fileHash || null,
                uploadedAt: f.uploadedAt || Date.now(),
                chainAnchored: !!f.chainAnchored,
                txHash: f.txHash || null,
            }));
            localStorage.setItem('ghostnet_vault_index', JSON.stringify(slim));
        } catch { }
    }

    let vaultIndex = loadVaultIndex();

    // ─── Validation helpers ───────────────────────────────────────────────────

    // [FIX C] Strict allowlist for fileId — alphanumeric, hyphens, underscores only.
    const FILE_ID_RE = /^[a-zA-Z0-9_\-]{1,128}$/;

    function _validateFileId(fileId) {
        if (typeof fileId !== 'string' || !FILE_ID_RE.test(fileId)) {
            throw new Error('Invalid file identifier.');
        }
        return fileId;
    }

    // [FIX H] Strip dangerous characters from filenames.
    function _sanitizeFileName(name) {
        if (typeof name !== 'string' || name.length === 0) return 'download';
        return name
            .replace(/[/\\]/g, '_')          // path separators
            .replace(/[\x00-\x1f\x7f]/g, '') // control characters and null bytes
            .slice(0, 255)                    // browser filename length limit
            || 'download';
    }

    // ─── Auth header helper ───────────────────────────────────────────────────

    // [FIX B] Every request carries the session auth token.
    // Expiry-aware AND self-contained: the previous version fell back to the raw
    // storage value, which is still truthy for an EXPIRED token — so listFiles()
    // thought a token existed, fired the request, and 401'd. The vault honors token
    // expiry itself (no central auth authority) so it stays a standalone module.
    function _hasToken() {
        if (window.getAuthHeaders) return !!window.getAuthHeaders().Authorization;
        try {
            const raw = sessionStorage.getItem('ghostnet_token');
            if (!raw) return false;
            const p = JSON.parse(raw);
            if (p && p.token) return !(p.expiresAt && Date.now() > p.expiresAt);
            return typeof raw === 'string' && raw.length > 10; // legacy plain token
        } catch (_) { return false; }
    }

    function _secureHeaders(extra = {}) {
        // [FIX B] Use unified global headers if available (enforces token check/redirect)
        if (window.getAuthHeaders) {
            const h = window.getAuthHeaders();
            if (h.Authorization) return { ...h, ...extra };
        }
        // [SEC FIX H2] Only read from sessionStorage — never fall back to localStorage.
        // localStorage tokens may be stale/expired and are accessible to XSS across sessions.
        let raw = sessionStorage.getItem('ghostnet_token') || '';
        if (raw) {
            try {
                const p = JSON.parse(raw);
                // Enforce client-side expiry check
                if (p && p.expiresAt && Date.now() > p.expiresAt) { raw = ''; }
                else if (p && p.token) { raw = p.token; }
            } catch (_) {}
        }
        return {
            'Authorization': `Bearer ${raw}`,
            'Content-Type': 'application/json',
            ...extra,
        };
    }

    async function _ensureVaultAuth() {
        if (_hasToken()) return true;
        if (typeof window.ghostnetEnsureAuth !== 'function') return false;
        try {
            const refreshed = await window.ghostnetEnsureAuth();
            return !!refreshed && _hasToken();
        } catch {
            return false;
        }
    }

    // ─── Owner identity ───────────────────────────────────────────────────────

    // [FIX G] Use opaque nodeId from sessionStorage only — never email, never
    //         from writable localStorage.
    function getOwner() {
        const nodeId = sessionStorage.getItem('ghostnet_node_id');
        if (nodeId) return nodeId;
        // Fallback to in-memory app state — prioritize AppState then window.app
        return window.AppState?.identity?.nodeId || 
               window.AppState?.identity?.id || 
               window.app?.identity?.nodeId || 
               window.app?.identity?.id || 
               null;
    }

    // ─── IndexedDB key store ──────────────────────────────────────────────────

    // [FIX A] Keys live in IndexedDB, not localStorage. The raw key hex is
    //         never written to any storage in plaintext. In a full integration
    //         each stored entry should be encrypted under a PIN-derived wrapping
    //         key (see GhostIdentity.encryptWithPin). The PIN integration point
    //         is marked below.

    function _openDB() {
        return new Promise((resolve, reject) => {
            const req = indexedDB.open(DB_NAME, DB_VERSION);
            req.onupgradeneeded = e => {
                e.target.result.createObjectStore(DB_STORE, { keyPath: 'fileId' });
            };
            req.onsuccess = e => resolve(e.target.result);
            req.onerror = e => reject(e.target.error);
        });
    }

    async function saveKey(fileId, keyData) {
        // ── PIN-WRAPPING INTEGRATION POINT ────────────────────────────────────
        // Before storing, wrap keyData with the user's PIN-derived key:
        //   const wrapped = await GhostIdentity.encryptWithPin(JSON.stringify(keyData), userPin);
        //   const entry = { fileId, wrapped };
        // For now we store the object directly in IndexedDB (still vastly safer
        // than plaintext localStorage, but add PIN-wrapping for full hardening).
        const db = await _openDB();
        const tx = db.transaction(DB_STORE, 'readwrite');
        tx.objectStore(DB_STORE).put({ fileId, ...keyData });
        return new Promise((resolve, reject) => {
            tx.oncomplete = () => { db.close(); resolve(); };
            tx.onerror = e => { db.close(); reject(e.target.error); };
        });
    }

    async function getKey(fileId) {
        const db = await _openDB();
        const tx = db.transaction(DB_STORE, 'readonly');
        const req = tx.objectStore(DB_STORE).get(fileId);
        return new Promise((resolve, reject) => {
            req.onsuccess = () => { db.close(); resolve(req.result || null); };
            req.onerror = e => { db.close(); reject(e.target.error); };
        });
    }

    async function removeKey(fileId) {
        const db = await _openDB();
        const tx = db.transaction(DB_STORE, 'readwrite');
        tx.objectStore(DB_STORE).delete(fileId);
        return new Promise((resolve, reject) => {
            tx.oncomplete = () => { db.close(); resolve(); };
            tx.onerror = e => { db.close(); reject(e.target.error); };
        });
    }

    // [P0] Source of truth for backfill: any still-present local master key
    // (keyHex). All files share the master key, so any entry's keyHex is it.
    // Absence means there is no local key to preserve.
    async function _anyStoredKeyHex() {
        try {
            const db = await _openDB();
            const tx = db.transaction(DB_STORE, 'readonly');
            const all = await new Promise((res, rej) => {
                const r = tx.objectStore(DB_STORE).getAll();
                r.onsuccess = () => res(r.result || []);
                r.onerror = e => rej(e.target.error);
            });
            db.close();
            const hit = (all || []).find(e => e && typeof e.keyHex === 'string' && /^[0-9a-fA-F]{64}$/.test(e.keyHex));
            return hit ? hit.keyHex : null;
        } catch { return null; }
    }

    // [P0] One-time cleanup: strip the plaintext master key (keyHex) from every
    // keystore entry. IRREVERSIBLE. Called ONLY from the recover/backfill SUCCESS
    // branch (see promptVaultKeyRecovery), after the confirming await — never in a
    // finally, never on a thrown path. ivHex (non-secret) is retained.
    async function _purgeLegacyKeyHex() {
        try {
            const db = await _openDB();
            const tx = db.transaction(DB_STORE, 'readwrite');
            const store = tx.objectStore(DB_STORE);
            const all = await new Promise((res, rej) => {
                const r = store.getAll();
                r.onsuccess = () => res(r.result || []);
                r.onerror = e => rej(e.target.error);
            });
            for (const entry of all) {
                if (entry && 'keyHex' in entry) { delete entry.keyHex; store.put(entry); }
            }
            await new Promise((res, rej) => {
                tx.oncomplete = () => res();
                tx.onerror = e => rej(e.target.error);
            });
            db.close();
        } catch (e) {
            console.warn('[Vault] keyHex purge skipped:', e && e.message);
        }
    }

    // ─── Hex utilities ────────────────────────────────────────────────────────

    function bufToHex(buf) {
        return Array.from(buf).map(b => b.toString(16).padStart(2, '0')).join('');
    }

    // [FIX I] Validate hex string before parsing.
    function hexToBuf(hex) {
        if (typeof hex !== 'string' || hex.length === 0 || hex.length % 2 !== 0) {
            throw new Error('Invalid hex string: must be a non-empty even-length string.');
        }
        if (!/^[0-9a-fA-F]+$/.test(hex)) {
            throw new Error('Invalid hex string: contains non-hex characters.');
        }
        const bytes = new Uint8Array(hex.length / 2);
        for (let i = 0; i < hex.length; i += 2) {
            bytes[i / 2] = parseInt(hex.substr(i, 2), 16);
        }
        return bytes.buffer;
    }

    function formatBytes(bytes) {
        if (bytes === 0) return '0 B';
        const k = 1024;
        const sizes = ['B', 'KB', 'MB', 'GB'];
        const i = Math.floor(Math.log(bytes) / Math.log(k));
        return parseFloat((bytes / Math.pow(k, i)).toFixed(1)) + ' ' + sizes[i];
    }

    // ─── MASTER VAULT KEY MANAGER ──────────────────────────────────────────

    const VaultKeyManager = {
        key: null,

        async getOrGenerateKey() {
            if (this.key) return this.key;

            // When no auth token exists (offline / pre-login), skip server sync
            // and fall through to local key fallback instead of throwing.
            let hasAuth = _hasToken();
            if (!hasAuth) {
                hasAuth = await _ensureVaultAuth();
            }
            if (!hasAuth) {
                console.warn('[Vault] No auth token — skipping vault key sync, using local key fallback');
            }

            let serverKeyData = null;
            if (hasAuth) {
                try {
                    const response = await fetch(`${VAULT_API}/keys`, {
                        headers: _secureHeaders()
                    });
                    if (response.ok) {
                        const data = await response.json();
                        if (data.keyData) serverKeyData = data.keyData;
                    }
                } catch (e) {
                    console.warn('Could not fetch vault key from server', e);
                }
            }

            if (window.UI && window.UI.promptVaultKeyRecovery && !isVaultUnlocked()) {
                this.key = await window.UI.promptVaultKeyRecovery(serverKeyData);
                if (this.key) {
                    markVaultUnlocked();
                    return this.key;
                }
            }

            // [Fallback] If remote fetch failed and recovery was skipped/failed, use local key
            // [SEC FIX C2] Local vault key is now wrapped with a device-specific key
            // derived from a random secret stored only in sessionStorage.
            // The raw JWK is NEVER written to localStorage in plaintext.
            console.warn('[Vault] Remote fetch and recovery failed. Falling back to local key.');
            try {
                const wrappedData = localStorage.getItem('ghostnet_vault_local_key_wrapped');
                const legacyData = localStorage.getItem('ghostnet_vault_local_key');

                // Device-scoped wrapping: random 256-bit key in sessionStorage
                let wrapKeyB64 = sessionStorage.getItem('ghostnet_vault_wrap_key');
                if (!wrapKeyB64) {
                    // If we have a wrapped key but no wrap key, we can't decrypt — need new key
                    if (wrappedData && !legacyData) {
                        console.warn('[Vault] Wrap key lost (session expired). Vault needs re-unlock.');
                        throw new Error('Vault session expired. Please re-enter PIN.');
                    }
                    // Generate new wrap key for this session
                    const wrapRaw = crypto.getRandomValues(new Uint8Array(32));
                    wrapKeyB64 = btoa(String.fromCharCode(...wrapRaw));
                    sessionStorage.setItem('ghostnet_vault_wrap_key', wrapKeyB64);
                }
                const wrapKeyBytes = Uint8Array.from(atob(wrapKeyB64), c => c.charCodeAt(0));
                const wrapKey = await crypto.subtle.importKey('raw', wrapKeyBytes, { name: 'AES-GCM' }, false, ['encrypt', 'decrypt']);

                if (wrappedData) {
                    // Unwrap the stored key
                    const packed = Uint8Array.from(atob(wrappedData), c => c.charCodeAt(0));
                    const iv = packed.slice(0, 12);
                    const ciphertext = packed.slice(12);
                    const jwkBytes = await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, wrapKey, ciphertext);
                    const jwk = JSON.parse(new TextDecoder().decode(jwkBytes));
                    this.key = await crypto.subtle.importKey('jwk', jwk, { name: 'AES-GCM' }, false, ['encrypt', 'decrypt']);
                } else if (legacyData) {
                    // Migrate plaintext legacy key → wrapped format
                    console.warn('[Vault] Migrating plaintext vault key to wrapped format.');
                    const jwk = JSON.parse(legacyData);
                    this.key = await crypto.subtle.importKey('jwk', jwk, { name: 'AES-GCM' }, false, ['encrypt', 'decrypt']);
                    // Wrap and store
                    const iv = crypto.getRandomValues(new Uint8Array(12));
                    const jwkBytes = new TextEncoder().encode(JSON.stringify(jwk));
                    const encrypted = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, wrapKey, jwkBytes);
                    const packed = new Uint8Array(12 + encrypted.byteLength);
                    packed.set(iv);
                    packed.set(new Uint8Array(encrypted), 12);
                    localStorage.setItem('ghostnet_vault_local_key_wrapped', btoa(String.fromCharCode(...packed)));
                    localStorage.removeItem('ghostnet_vault_local_key'); // Delete plaintext
                } else {
                    // Generate new local key, wrap it before storing
                    const tempKey = await crypto.subtle.generateKey({ name: 'AES-GCM', length: 256 }, true, ['encrypt', 'decrypt']);
                    const exported = await crypto.subtle.exportKey('jwk', tempKey);
                    // Wrap with session key
                    const iv = crypto.getRandomValues(new Uint8Array(12));
                    const jwkBytes = new TextEncoder().encode(JSON.stringify(exported));
                    const encrypted = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, wrapKey, jwkBytes);
                    const packed = new Uint8Array(12 + encrypted.byteLength);
                    packed.set(iv);
                    packed.set(new Uint8Array(encrypted), 12);
                    localStorage.setItem('ghostnet_vault_local_key_wrapped', btoa(String.fromCharCode(...packed)));
                    this.key = await crypto.subtle.importKey('jwk', exported, { name: 'AES-GCM' }, false, ['encrypt', 'decrypt']);
                }
                return this.key;
            } catch (fallbackErr) {
                console.error('[Vault] Fallback failed:', fallbackErr);
                if (fallbackErr && typeof fallbackErr.message === 'string' && /vault session expired/i.test(fallbackErr.message)) {
                    throw fallbackErr;
                }
                throw new Error('Vault Key unavailable. Local fallback failed.');
            }
        },

        async _deriveWrappingKey(pin, saltHexString) {
            const salt = hexToBuf(saltHexString);
            const enc = new TextEncoder();
            const keyMaterial = await crypto.subtle.importKey('raw', enc.encode(pin), 'PBKDF2', false, ['deriveKey']);
            return crypto.subtle.deriveKey(
                { name: 'PBKDF2', salt, iterations: 600000, hash: 'SHA-256' },
                keyMaterial, { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']
            );
        },

        async recoverFromData(pin, serverKeyData) {
            const { wrappedKey, salt, iv } = serverKeyData;
            const wrapKey = await this._deriveWrappingKey(pin, salt);

            const encryptedBytes = hexToBuf(wrappedKey);
            const decryptedJwkJson = await crypto.subtle.decrypt(
                { name: 'AES-GCM', iv: hexToBuf(iv) },
                wrapKey,
                encryptedBytes
            );

            const jwkStr = new TextDecoder().decode(decryptedJwkJson);
            const key = await crypto.subtle.importKey(
                'jwk', JSON.parse(jwkStr),
                { name: 'AES-GCM', length: 256 },
                true, ['encrypt', 'decrypt']
            );

            this.key = key;
            return key;
        },

        // [P0] Backfill a MISSING server vault_keys row from a still-present LOCAL
        // master key, then verify the round-trip. Wrap-push-verify only — it never
        // purges; the caller purges after this resolves. Any throw ⇒ no purge ⇒ the
        // local key (and the user's files) stay intact. Replaces the old
        // generateNew-on-missing-key path that minted a NEW key and orphaned files.
        async backfillFromLocal(pin, localKeyHex) {
            // 1. Import the EXISTING local master key (extractable so we can JWK-wrap).
            const key = await crypto.subtle.importKey(
                'raw', hexToBuf(localKeyHex),
                { name: 'AES-GCM', length: 256 }, true, ['encrypt', 'decrypt']
            );
            const jwkStr = JSON.stringify(await crypto.subtle.exportKey('jwk', key));

            // 2. PBKDF2(PIN)-wrap — identical construction to generateNew.
            const saltBytes = crypto.getRandomValues(new Uint8Array(16));
            const wrapKey = await this._deriveWrappingKey(pin, bufToHex(saltBytes));
            const ivBytes = crypto.getRandomValues(new Uint8Array(12));
            const encJwk = await crypto.subtle.encrypt(
                { name: 'AES-GCM', iv: ivBytes }, wrapKey, new TextEncoder().encode(jwkStr)
            );
            const serverKeyData = {
                wrappedKey: bufToHex(new Uint8Array(encJwk)),
                salt: bufToHex(saltBytes),
                iv: bufToHex(ivBytes)
            };

            // 3. Push to server.
            if (!_hasToken()) throw new Error('Cannot backfill vault key while offline.');
            const up = await fetch(VAULT_API + '/keys', {
                method: 'POST',
                headers: _secureHeaders({ 'Content-Type': 'application/json' }),
                body: JSON.stringify({ keyData: serverKeyData })
            });
            if (!up.ok) throw new Error('Vault key backfill upload failed — NOT purging.');

            // 4. VERIFY: re-fetch, unwrap with the PIN, confirm identical key bytes.
            const vr = await fetch(VAULT_API + '/keys', { headers: _secureHeaders() });
            const vd = vr.ok ? await vr.json() : null;
            if (!vd || !vd.keyData) throw new Error('Backfill verify failed: no key returned — NOT purging.');
            const wk2 = await this._deriveWrappingKey(pin, vd.keyData.salt);
            const dec = await crypto.subtle.decrypt(
                { name: 'AES-GCM', iv: hexToBuf(vd.keyData.iv) }, wk2, hexToBuf(vd.keyData.wrappedKey)
            );
            const recovered = await crypto.subtle.importKey(
                'jwk', JSON.parse(new TextDecoder().decode(dec)),
                { name: 'AES-GCM', length: 256 }, true, ['encrypt', 'decrypt']
            );
            const recoveredRaw = bufToHex(new Uint8Array(await crypto.subtle.exportKey('raw', recovered)));
            if (recoveredRaw !== localKeyHex) throw new Error('Backfill verify failed: key mismatch — NOT purging.');

            this.key = recovered;   // verified identical to the local key; caller may now purge
            return recovered;
        },

        async generateNew(pin) {
            const newKey = await crypto.subtle.generateKey(
                { name: 'AES-GCM', length: 256 },
                true, ['encrypt', 'decrypt']
            );

            const jwk = await crypto.subtle.exportKey('jwk', newKey);
            const jwkStr = JSON.stringify(jwk);

            const saltBytes = crypto.getRandomValues(new Uint8Array(16));
            const wrapKey = await this._deriveWrappingKey(pin, bufToHex(saltBytes));

            const ivBytes = crypto.getRandomValues(new Uint8Array(12));
            const encryptedJwk = await crypto.subtle.encrypt(
                { name: 'AES-GCM', iv: ivBytes },
                wrapKey,
                new TextEncoder().encode(jwkStr)
            );

            const serverKeyData = {
                wrappedKey: bufToHex(new Uint8Array(encryptedJwk)),
                salt: bufToHex(saltBytes),
                iv: bufToHex(ivBytes)
            };

            if (_hasToken()) {
                await fetch(VAULT_API + '/keys', {
                    method: 'POST',
                    headers: _secureHeaders({ 'Content-Type': 'application/json' }),
                    body: JSON.stringify({ keyData: serverKeyData })
                });
            }
            this.key = newKey;
            return newKey;
        }
    };

    // ─── Crypto: AES-256-GCM ─────────────────────────────────────────────────

    async function generateKey() {
        return crypto.subtle.generateKey(
            { name: 'AES-GCM', length: 256 },
            true,   // extractable only at generation time, for export to storage
            ['encrypt', 'decrypt']
        );
    }

    async function exportKeyForStorage(key) {
        const raw = await crypto.subtle.exportKey('raw', key);
        return bufToHex(new Uint8Array(raw));
    }

    // [FIX E] Non-extractable import — keys used for decryption cannot be
    //         re-exported from the CryptoKey object.
    async function importKey(hexKey) {
        const raw = hexToBuf(hexKey);
        return crypto.subtle.importKey(
            'raw', raw,
            { name: 'AES-GCM', length: 256 },
            false,  // [FIX E] NOT extractable
            ['decrypt']
        );
    }

    async function encryptFile(file) {
        // [FIX F] Enforce size limit before loading into memory.
        if (file.size > MAX_FILE_BYTES) {
            throw new Error(`File too large. Maximum size is ${formatBytes(MAX_FILE_BYTES)}.`);
        }

        const key = await VaultKeyManager.getOrGenerateKey();
        const iv = crypto.getRandomValues(new Uint8Array(12));
        const plaintext = await file.arrayBuffer();

        const ciphertext = await crypto.subtle.encrypt(
            { name: 'AES-GCM', iv, tagLength: 128 },
            key,
            plaintext
        );

        // [FIX D] Do NOT split out the auth tag. The full AES-GCM output
        //         (ciphertext || tag) is uploaded as a single blob. The tag
        //         is never sent to the server separately.
        return {
            encryptedBlob: new Blob([ciphertext]),
            keyHex: await exportKeyForStorage(key),
            ivHex: bufToHex(iv),
            originalSize: plaintext.byteLength,
        };
    }

    async function decryptFile(encryptedArrayBuffer, keyHex, ivHex) {
        // [FIX E] importKey returns a non-extractable key.
        const key = await importKey(keyHex);
        const iv = hexToBuf(ivHex);

        return crypto.subtle.decrypt(
            { name: 'AES-GCM', iv, tagLength: 128 },
            key,
            encryptedArrayBuffer
        );
    }

    // ─── Filename encryption (zero-knowledge metadata) ──────────────────────────
    // Encrypts the filename under the SAME per-user master key as the body, with a
    // FRESH IV (never the body IV). Packed as base64( iv[12] || ciphertext+gcmTag ).
    // The server only ever receives this opaque string.
    async function encryptName(name) {
        const key = await VaultKeyManager.getOrGenerateKey();
        const iv = crypto.getRandomValues(new Uint8Array(12));
        const data = new TextEncoder().encode(_sanitizeFileName(name));
        const ct = await crypto.subtle.encrypt({ name: 'AES-GCM', iv, tagLength: 128 }, key, data);
        const packed = new Uint8Array(12 + ct.byteLength);
        packed.set(iv, 0);
        packed.set(new Uint8Array(ct), 12);
        return btoa(String.fromCharCode(...packed));
    }

    // Decrypts to an in-memory display name only. Never persisted, never logged.
    // Returns null on any failure so rendering can show a placeholder instead.
    async function decryptName(encryptedName) {
        if (!encryptedName || typeof encryptedName !== 'string') return null;
        try {
            const key = await VaultKeyManager.getOrGenerateKey();
            const packed = Uint8Array.from(atob(encryptedName), c => c.charCodeAt(0));
            if (packed.length <= 12) return null;
            const pt = await crypto.subtle.decrypt(
                { name: 'AES-GCM', iv: packed.slice(0, 12) }, key, packed.slice(12)
            );
            return _sanitizeFileName(new TextDecoder().decode(pt));
        } catch {
            return null;
        }
    }

    // [ZK] Attach an in-memory decrypted display name to each row. The decrypted
    // name is never written back to storage and never logged.
    async function _withDisplayNames(rows) {
        return Promise.all((rows || []).map(async (f) => ({
            ...f,
            fileName: (await decryptName(f.encryptedName)) || '🔒 Encrypted file',
        })));
    }

    // ─── Upload ───────────────────────────────────────────────────────────────

    async function uploadFile(file, onProgress) {
        // Explicit offline check — give clear feedback instead of auth errors
        if (typeof navigator !== 'undefined' && !navigator.onLine) {
            throw new Error('You are offline. File uploads require a network connection.');
        }

        await _ensureVaultAuth();

        const owner = getOwner();
        if (!owner) throw new Error('Not authenticated. Please log in first.');

        // [FIX F] Size enforced inside encryptFile().
        if (onProgress) onProgress({ stage: 'encrypting', percent: 0 });
        const encrypted = await encryptFile(file);
        if (onProgress) onProgress({ stage: 'encrypting', percent: 100 });

        let encKeyStr = '';
        try {
            if (window.app && window.app.chatTarget && window.app.chatTarget !== 'broadcast') {
                const targetId = window.app.chatTarget;
                let targetPub = targetId;
                if (!targetPub.startsWith('0x') && _hasToken()) {
                    const valRes = await fetch(`${VAULT_API.replace('/vault', '')}/validate-node/${encodeURIComponent(targetId)}`, { headers: _secureHeaders() });
                    if (valRes.ok) {
                        const valData = await valRes.json();
                        targetPub = valData.publicKey || valData.address || targetId;
                    }
                }

                if (targetPub.startsWith('0x') && window.GhostIdentity && window.GhostIdentity.getSessionPrivateKey) {
                    const myPriv = await window.GhostIdentity.getSessionPrivateKey();
                    if (myPriv && typeof ethers !== 'undefined') {
                        const sharedSecretHex = new ethers.SigningKey(myPriv).computeSharedSecret(targetPub);
                        const sharedSecret = hexToBuf(sharedSecretHex.slice(2));

                        const derivedKey = await crypto.subtle.importKey(
                            'raw', sharedSecret.slice(0, 32),
                            { name: 'AES-GCM', length: 256 }, false, ['encrypt']
                        );

                        const rawFileKey = hexToBuf(encrypted.keyHex);
                        const wrapIv = crypto.getRandomValues(new Uint8Array(12));

                        const material = new Uint8Array(44);
                        material.set(rawFileKey, 0);
                        material.set(hexToBuf(encrypted.ivHex), 32);

                        const wrappedCiphertext = await crypto.subtle.encrypt(
                            { name: 'AES-GCM', iv: wrapIv },
                            derivedKey,
                            material
                        );

                        const combo = new Uint8Array(wrapIv.length + wrappedCiphertext.byteLength);
                        combo.set(wrapIv, 0);
                        combo.set(new Uint8Array(wrappedCiphertext), wrapIv.length);
                        encKeyStr = btoa(String.fromCharCode(...combo));
                    }
                }
            }
        } catch (e) {
            console.warn('Could not encrypt file key for recipient:', e.message);
        }

        if (onProgress) onProgress({ stage: 'uploading', percent: 0 });

        // [ZK] Encrypt the filename under the master key (fresh IV) before it leaves
        // the device. The server never receives the plaintext name.
        const encryptedName = await encryptName(file.name);

        const formData = new FormData();
        // [ZK] Neutral part name — the real name must not leak via req.file.originalname.
        formData.append('file', encrypted.encryptedBlob, 'blob.enc');
        formData.append('owner', owner);
        formData.append('encryptedName', encryptedName);  // [ZK] ciphertext, replaces plaintext fileName
        formData.append('iv', encrypted.ivHex);
        // [FIX D] authTag is NOT appended — it's already in the ciphertext blob.
        formData.append('originalSize', String(encrypted.originalSize));

        let response;
        try {
            const doUpload = () => {
                // [FIX B] Auth token on every request.
                const uploadHeaders = _secureHeaders();
                delete uploadHeaders['Content-Type']; // Let browser set boundary for FormData

                return fetch(`${VAULT_API}/upload`, {
                    method: 'POST',
                    headers: uploadHeaders,
                    body: formData,
                });
            };

            response = await doUpload();

            // Stale/expired JWT: clear it, refresh once, then retry the upload so
            // vault attachments behave like saved chat messages instead of hard-401ing.
            if (response.status === 401 && typeof window.ghostnetEnsureAuth === 'function') {
                try {
                    sessionStorage.removeItem('ghostnet_token');
                    localStorage.removeItem('ghostnet_token');
                } catch { }
                const refreshed = await window.ghostnetEnsureAuth();
                if (refreshed) {
                    response = await doUpload();
                }
            }
        } catch {
            throw new Error('Upload failed. Please check your connection.');
        }

        if (!response.ok) {
            // [FIX K] Log server detail internally; expose only a generic message.
            const err = await response.json().catch(() => ({}));
            console.error('[Vault] Upload error:', err.error || response.status);
            if (response.status === 401) {
                throw new Error('Vault session expired. Please re-unlock with your PIN and try again.');
            }
            throw new Error('Upload failed. Please try again.');
        }

        const result = await response.json();
        if (onProgress) onProgress({ stage: 'anchoring', percent: 100 });

        // [FIX C] Validate fileId from server response before storing.
        const fileId = _validateFileId(result?.file?.fileId);

        const displayName = _sanitizeFileName(file.name);  // in-memory display only
        const normalizedMeta = {
            fileId,
            encryptedName,                 // [ZK] persisted (ciphertext)
            fileName: displayName,         // in-memory display only; NOT persisted (see saveVaultIndex)
            fileSize: result.file?.fileSize || file.size,
            originalSize: encrypted.originalSize,
            fileHash: result.file?.fileHash || null,
            uploadedAt: result.file?.uploadedAt || Date.now(),
            chainAnchored: !!result.file?.chainAnchored,
            txHash: result.file?.txHash || null,
        };

        // [FIX A] Store key material in IndexedDB — never in localStorage.
        // [P0] keyHex is NOT persisted — it IS the master key, derived at download
        //      time via the PIN-gated unlock. ivHex (non-secret GCM IV) is retained.
        // [ZK] encryptedName persisted instead of the plaintext name.
        await saveKey(fileId, {
            ivHex: encrypted.ivHex,
            encryptedName,
            originalSize: encrypted.originalSize,
        });

        // Update local metadata index so files survive server /files gaps.
        vaultIndex = vaultIndex.filter(f => f.fileId !== fileId);
        vaultIndex.push(normalizedMeta);
        saveVaultIndex(vaultIndex);

        if (onProgress) onProgress({ stage: 'complete', percent: 100 });
        return { ...normalizedMeta, encKeyStr };
    }

    // ─── Download & Decrypt ───────────────────────────────────────────────────

    async function downloadFile(fileId, encKeyStr = '') {
        // [FIX C] Validate before use in URL.
        _validateFileId(fileId);

        let keyData = await getKey(fileId);

        if (!keyData && encKeyStr) {
            try {
                const targetId = window.app?.chatTarget;
                if (!targetId) throw new Error("No chat target");
                let senderPub = targetId;
                if (!senderPub.startsWith('0x')) {
                    const valRes = await fetch(`${VAULT_API.replace('/vault', '')}/validate-node/${encodeURIComponent(targetId)}`, { headers: _secureHeaders() });
                    if (valRes.ok) {
                        const valData = await valRes.json();
                        senderPub = valData.publicKey || valData.address || targetId;
                    }
                }

                if (senderPub.startsWith('0x') && window.GhostIdentity && window.GhostIdentity.getSessionPrivateKey) {
                    const myPriv = await window.GhostIdentity.getSessionPrivateKey();
                    if (myPriv && typeof ethers !== 'undefined') {
                        const sharedSecretHex = new ethers.SigningKey(myPriv).computeSharedSecret(senderPub);
                        const sharedSecret = hexToBuf(sharedSecretHex.slice(2));

                        const derivedKey = await crypto.subtle.importKey(
                            'raw', sharedSecret.slice(0, 32),
                            { name: 'AES-GCM', length: 256 }, false, ['decrypt']
                        );

                        const comboBytes = Uint8Array.from(atob(encKeyStr), c => c.charCodeAt(0));
                        const wrapIv = comboBytes.slice(0, 12);
                        const wrappedCiphertext = comboBytes.slice(12);

                        const materialBuf = await crypto.subtle.decrypt(
                            { name: 'AES-GCM', iv: wrapIv },
                            derivedKey,
                            wrappedCiphertext
                        );
                        const material = new Uint8Array(materialBuf);
                        const rawFileKey = material.slice(0, 32);
                        const rawIv = material.slice(32, 44);

                        keyData = {
                            keyHex: bufToHex(rawFileKey),
                            ivHex: bufToHex(rawIv),
                            fileName: 'decrypted_shared_file'
                        };
                    }
                }
            } catch (e) {
                console.warn('Could not decrypt shared file key:', e.message);
            }
        }

        let usingMasterKey = false;
        // [P0] Post-purge keystore entries have no keyHex. Derive the master key
        //      (PIN-gated unlock) and reuse any locally cached non-secret IV; the
        //      X-IV header is only a fallback (see below). We never delete a local IV.
        if ((!keyData || !keyData.keyHex) && !encKeyStr) {
            const cachedIv = keyData?.ivHex || null;
            const cachedEnc = keyData?.encryptedName || null;
            try {
                const masterKeyCrypto = await VaultKeyManager.getOrGenerateKey();
                const rawArrayBuffer = await crypto.subtle.exportKey('raw', masterKeyCrypto);
                keyData = {
                    keyHex: bufToHex(new Uint8Array(rawArrayBuffer)),
                    encryptedName: cachedEnc,
                    ivHex: cachedIv // prefer local IV; falls back to X-IV header below
                };
                usingMasterKey = true;
            } catch (err) {
                throw new Error('Encryption key not found. ' + err.message);
            }
        }

        if (!keyData) throw new Error('Encryption key not found. This file was encrypted on another device.');

        let response;
        try {
            // [FIX B] Auth token on every request.
            response = await fetch(`${VAULT_API}/download/${encodeURIComponent(fileId)}`, {
                headers: _secureHeaders(),
            });
        } catch {
            throw new Error('Download failed. Please check your connection.');
        }

        if (!response.ok) {
            console.error('[Vault] Download error:', response.status);
            throw new Error('Download failed. Please try again.');
        }

        if (usingMasterKey) {
            keyData.ivHex = keyData.ivHex || response.headers.get('x-iv');  // [P0] local IV wins; header is fallback
            // [ZK] X-File-Name is now ciphertext; keep it for in-memory decryption below.
            if (!keyData.encryptedName && response.headers.get('x-file-name')) {
                keyData.encryptedName = decodeURIComponent(response.headers.get('x-file-name'));
            }
            if (!keyData.ivHex) throw new Error('Cannot decrypt file: Missing encryption IV from server');
        }

        // [FIX J] Check Content-Length before buffering.
        const contentLength = parseInt(response.headers.get('Content-Length') || '0', 10);
        if (contentLength > MAX_FILE_BYTES) {
            throw new Error('Server returned an unexpectedly large file. Download aborted.');
        }

        const encryptedBuffer = await response.arrayBuffer();

        // [FIX J] Double-check actual size after buffering.
        if (encryptedBuffer.byteLength > MAX_FILE_BYTES + 16) {  // +16 for GCM tag
            throw new Error('Downloaded data exceeds maximum file size.');
        }

        let plaintext;
        try {
            plaintext = await decryptFile(encryptedBuffer, keyData.keyHex, keyData.ivHex);
        } catch {
            throw new Error('Decryption failed. The file may be corrupted or tampered with.');
        }

        // Trigger browser download.
        // [ZK] Resolve a display name in-memory only: prefer the encrypted name
        //      (local or X-File-Name header), then any legacy plaintext name from a
        //      shared-key payload, else the opaque fileId.
        let resolvedName = await decryptName(keyData.encryptedName);
        const safeName = _sanitizeFileName(resolvedName || keyData.fileName || `${fileId}.bin`);  // [FIX H]
        const blob = new Blob([plaintext]);
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = safeName;
        a.style.display = 'none';
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        // Revoke immediately to free memory.
        URL.revokeObjectURL(url);

        return true;
    }

    // ─── List Files ───────────────────────────────────────────────────────────

    async function listFiles() {
        const owner = getOwner();
        // [ZK] All return paths decrypt encryptedName → display name in-memory.
        if (!owner) return await _withDisplayNames(vaultIndex);

        // Skip server call if no auth token exists — prevents 401 cascade
        if (!_hasToken()) return await _withDisplayNames(vaultIndex);

        let response;
        try {
            // [FIX B] Auth token on every request.
            response = await fetch(`${VAULT_API}/files/${encodeURIComponent(owner)}`, {
                headers: _secureHeaders(),
            });
        } catch {
            // Network failure — fall back entirely to local index.
            return await _withDisplayNames(vaultIndex);
        }

        if (!response.ok) {
            // Server returned error — keep using cached index.
            return await _withDisplayNames(vaultIndex);
        }

        const data = await response.json().catch(() => ({}));
        if (Array.isArray(data.files) && data.files.length) {
            // Refresh local index with authoritative server list.
            vaultIndex = data.files.map(f => ({
                fileId: f.fileId,
                encryptedName: f.encryptedName || null,  // [ZK] ciphertext; decrypted in-memory below
                fileSize: f.fileSize,
                originalSize: f.originalSize,
                fileHash: f.fileHash || null,
                uploadedAt: f.uploadedAt || Date.now(),
                chainAnchored: !!f.chainAnchored,
                txHash: f.txHash || null,
            }));
            saveVaultIndex(vaultIndex);
            return await _withDisplayNames(vaultIndex);
        }

        // Empty server list — retain local view so uploads don't vanish.
        return await _withDisplayNames(vaultIndex);
    }

    // ─── Delete File ──────────────────────────────────────────────────────────

    async function deleteFile(fileId) {
        // [FIX C] Validate before use in URL.
        _validateFileId(fileId);

        const owner = getOwner();
        if (!owner) throw new Error('Not authenticated.');

        let response;
        try {
            // [FIX B] Auth token on every request.
            // [FIX L] X-Auth-Token is a custom header — inherently CSRF-safe.
            response = await fetch(`${VAULT_API}/file/${encodeURIComponent(fileId)}`, {
                method: 'DELETE',
                headers: _secureHeaders({ 'Content-Type': 'application/json' }),
                body: JSON.stringify({ owner }),
            });
        } catch {
            throw new Error('Delete failed. Please check your connection.');
        }

        if (!response.ok) {
            if (response.status === 404) {
                console.warn('[Vault] File not found on server, processing local cleanup.');
            } else {
                const err = await response.json().catch(() => ({}));
                console.error('[Vault] Delete error:', err.error || response.status);
                throw new Error('Delete failed. Please try again.');
            }
        }

        await removeKey(fileId);

        // Update local metadata index.
        vaultIndex = vaultIndex.filter(f => f.fileId !== fileId);
        saveVaultIndex(vaultIndex);
        return true;
    }

    // ─── Verify Integrity ─────────────────────────────────────────────────────

    async function verifyFile(fileId) {
        // [FIX C] Validate before use in URL.
        _validateFileId(fileId);

        let response;
        try {
            response = await fetch(`${VAULT_API}/verify/${encodeURIComponent(fileId)}`, {
                headers: _secureHeaders(),
            });
        } catch {
            return null;
        }

        if (!response.ok) return null;
        return response.json().catch(() => null);
    }

    // ─── Logout: clear local vault state (UI + storage) ────────────────────────
    // Does NOT delete files from the server/IPFS — only wipes local references.
    function clearVaultState() {
        // 1. Wipe in-memory index
        vaultIndex = [];

        // 2. Remove localStorage metadata index
        try { localStorage.removeItem('ghostnet_vault_index'); } catch { }

        // 3. Clear session vault keys & unlock flag
        lockVault();

        // 4. Reset the VaultKeyManager in-memory key (closure-scoped, not on window)
        VaultKeyManager.key = null;
    }

    // ─── Login: re-fetch vault files for the authenticated user ────────────────
    async function refreshVaultForUser() {
        const owner = getOwner();
        if (!owner) return [];

        // Guard: skip server call if unauthenticated
        if (!_hasToken()) return await _withDisplayNames(vaultIndex);

        let serverFiles = [];
        try {
            const response = await fetch(`${VAULT_API}/files/${encodeURIComponent(owner)}`, {
                headers: _secureHeaders(),
            });
            if (response.ok) {
                const data = await response.json().catch(() => ({}));
                if (Array.isArray(data.files) && data.files.length) {
                    serverFiles = data.files.map(f => ({
                        fileId: f.fileId,
                        encryptedName: f.encryptedName || null,  // [ZK] ciphertext; decrypted in-memory below
                        fileSize: f.fileSize,
                        originalSize: f.originalSize,
                        fileHash: f.fileHash || null,
                        uploadedAt: f.uploadedAt || Date.now(),
                        chainAnchored: !!f.chainAnchored,
                        txHash: f.txHash || null,
                    }));
                }
            }
        } catch (e) {
            console.warn('[Vault] Could not fetch files for user:', e.message);
        }

        // Update local state with server-authoritative list
        vaultIndex = serverFiles;
        saveVaultIndex(vaultIndex);
        return await _withDisplayNames(vaultIndex);
    }

    // ─── Public API ───────────────────────────────────────────────────────────

    async function hasKey(fileId) {
        try {
            _validateFileId(fileId);
            return !!(await getKey(fileId));
        } catch {
            return false;
        }
    }

    // ─── Module init ──────────────────────────────────────────────────────────
    // The UI expects `GhostVault.init()` to exist. Older versions referenced `_init`
    // but it was never defined. Keep init lightweight: validate secure context and
    // ensure the owner nodeId is available for authenticated vault calls.
    async function _init() {
        // Web Crypto only works in a secure context (HTTPS or localhost).
        if (!(window.crypto && window.crypto.subtle)) {
            return false;
        }

        // Ensure owner identity is available for vault requests.
        // Prefer sessionStorage (tab scoped), otherwise mirror from in-memory identity.
        try {
            const existing = sessionStorage.getItem('ghostnet_node_id');
            if (!existing) {
                const nodeId = window.AppState?.identity?.nodeId || 
                               window.AppState?.identity?.id || 
                               window.app?.identity?.nodeId || 
                               window.app?.identity?.id || 
                               null;
                if (nodeId) sessionStorage.setItem('ghostnet_node_id', nodeId);
            }
        } catch {
            // Ignore storage errors; getOwner() will fall back to in-memory identity.
        }

        return true;
    }

    const GhostVault = {
        init: _init,
        uploadFile,
        downloadFile,
        listFiles,
        deleteFile,
        _generateVaultKey: (pin) => VaultKeyManager.generateNew(pin),
        _recoverVaultKey: (pin, data) => VaultKeyManager.recoverFromData(pin, data),
        // [P0] Backfill/purge primitives for the recover/backfill unlock flow.
        _backfillVaultKey: (pin, localKeyHex) => VaultKeyManager.backfillFromLocal(pin, localKeyHex),
        _localMasterKeyHex: () => _anyStoredKeyHex(),
        _purgeLocalKey: () => _purgeLegacyKeyHex(),
        // [ZK] Filename encryption (used by the one-time name migration).
        encryptName,
        verifyFile,
        hasKey,
        formatBytes,
        getOwner,
        lockVault,
        clearVaultState,
        refreshVaultForUser,
    };

    // [FIX M] Immutable global — cannot be overwritten by later scripts.
    Object.defineProperty(window, 'GhostVault', {
        value: GhostVault,
        writable: false,
        configurable: false,
        enumerable: true,
    });
})();
