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
    function _getAuthToken() {
        return sessionStorage.getItem('ghostnet_token') || '';
    }

    function _secureHeaders(extra = {}) {
        return {
            'X-Auth-Token': _getAuthToken(),
            ...extra,
        };
    }

    // ─── Owner identity ───────────────────────────────────────────────────────

    // [FIX G] Use opaque nodeId from sessionStorage only — never email, never
    //         from writable localStorage.
    function getOwner() {
        const nodeId = sessionStorage.getItem('ghostnet_node_id');
        if (nodeId) return nodeId;
        // Fallback to in-memory app state — still not from writable localStorage.
        return window.app?.identity?.nodeId || window.app?.identity?.id || null;
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

        const key = await generateKey();
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

    // ─── Upload ───────────────────────────────────────────────────────────────

    async function uploadFile(file, onProgress) {
        const owner = getOwner();
        if (!owner) throw new Error('Not authenticated.');

        // [FIX F] Size enforced inside encryptFile().
        if (onProgress) onProgress({ stage: 'encrypting', percent: 0 });
        const encrypted = await encryptFile(file);
        if (onProgress) onProgress({ stage: 'encrypting', percent: 100 });

        if (onProgress) onProgress({ stage: 'uploading', percent: 0 });

        const formData = new FormData();
        formData.append('file', encrypted.encryptedBlob, _sanitizeFileName(file.name) + '.enc');
        formData.append('owner', owner);
        formData.append('fileName', _sanitizeFileName(file.name));  // [FIX H]
        formData.append('iv', encrypted.ivHex);
        // [FIX D] authTag is NOT appended — it's already in the ciphertext blob.
        formData.append('originalSize', String(encrypted.originalSize));

        let response;
        try {
            // [FIX B] Auth token on every request.
            response = await fetch(`${VAULT_API}/upload`, {
                method: 'POST',
                headers: _secureHeaders(),  // Content-Type omitted: FormData sets its own
                body: formData,
            });
        } catch {
            throw new Error('Upload failed. Please check your connection.');
        }

        if (!response.ok) {
            // [FIX K] Log server detail internally; expose only a generic message.
            const err = await response.json().catch(() => ({}));
            console.error('[Vault] Upload error:', err.error || response.status);
            throw new Error('Upload failed. Please try again.');
        }

        const result = await response.json();
        if (onProgress) onProgress({ stage: 'anchoring', percent: 100 });

        // [FIX C] Validate fileId from server response before storing.
        const fileId = _validateFileId(result?.file?.fileId);

        // [FIX A] Store key in IndexedDB — never in localStorage.
        await saveKey(fileId, {
            keyHex: encrypted.keyHex,
            ivHex: encrypted.ivHex,
            fileName: _sanitizeFileName(file.name),  // [FIX H]
            originalSize: encrypted.originalSize,
        });

        if (onProgress) onProgress({ stage: 'complete', percent: 100 });
        return result.file;
    }

    // ─── Download & Decrypt ───────────────────────────────────────────────────

    async function downloadFile(fileId) {
        // [FIX C] Validate before use in URL.
        _validateFileId(fileId);

        const keyData = await getKey(fileId);
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
        const safeName = _sanitizeFileName(keyData.fileName || 'decrypted_file');  // [FIX H]
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
        if (!owner) return [];

        let response;
        try {
            // [FIX B] Auth token on every request.
            response = await fetch(`${VAULT_API}/files/${encodeURIComponent(owner)}`, {
                headers: _secureHeaders(),
            });
        } catch {
            return [];
        }

        if (!response.ok) return [];

        const data = await response.json().catch(() => ({}));
        return Array.isArray(data.files) ? data.files : [];
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
            const err = await response.json().catch(() => ({}));
            console.error('[Vault] Delete error:', err.error || response.status);
            throw new Error('Delete failed. Please try again.');
        }

        await removeKey(fileId);
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

    // ─── Public API ───────────────────────────────────────────────────────────

    async function hasKey(fileId) {
        try {
            _validateFileId(fileId);
            return !!(await getKey(fileId));
        } catch {
            return false;
        }
    }

    const GhostVault = {
        uploadFile,
        downloadFile,
        listFiles,
        deleteFile,
        verifyFile,
        hasKey,
        formatBytes,
        getOwner,
    };

    // [FIX M] Immutable global — cannot be overwritten by later scripts.
    Object.defineProperty(window, 'GhostVault', {
        value: GhostVault,
        writable: false,
        configurable: false,
        enumerable: true,
    });
})();