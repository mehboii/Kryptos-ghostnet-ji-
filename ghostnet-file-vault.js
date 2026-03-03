/**
 * GhostNet File Vault — Client-Side E2E Encryption & Upload
 * ===========================================================
 * ALL encryption happens IN THE BROWSER. The server never sees
 * plaintext files or encryption keys.
 * 
 * Flow:
 *   1. User drops/selects a file
 *   2. Browser generates AES-256-GCM key + IV
 *   3. File is encrypted entirely in-browser
 *   4. Encrypted blob is uploaded to Vault Service
 *   5. Vault Service anchors hash on blockchain via Chain Service
 *   6. Encryption key is stored ONLY in the user's browser (localStorage)
 *   7. To download: fetch encrypted blob → decrypt in-browser → save
 * 
 * Nobody can access the files — not the server, not the blockchain,
 * not anyone without the user's local encryption keys.
 */

window.GhostVault = (() => {
    // ─── Config ──────────────────────────────────────────────
const VAULT_API = 'https://ghostnet-ji-production.up.railway.app/vault';
    const KEY_STORE = 'ghostnet_vault_keys';

    // ─── Key Management ──────────────────────────────────────
    function loadKeyStore() {
        try {
            return JSON.parse(localStorage.getItem(KEY_STORE) || '{}');
        } catch { return {}; }
    }

    function saveKey(fileId, keyData) {
        const store = loadKeyStore();
        store[fileId] = keyData;
        localStorage.setItem(KEY_STORE, JSON.stringify(store));
    }

    function getKey(fileId) {
        return loadKeyStore()[fileId] || null;
    }

    function removeKey(fileId) {
        const store = loadKeyStore();
        delete store[fileId];
        localStorage.setItem(KEY_STORE, JSON.stringify(store));
    }

    // ─── Crypto: AES-256-GCM ────────────────────────────────
    async function generateKey() {
        return await crypto.subtle.generateKey(
            { name: 'AES-GCM', length: 256 },
            true,  // extractable (for export/storage)
            ['encrypt', 'decrypt']
        );
    }

    async function exportKey(key) {
        const raw = await crypto.subtle.exportKey('raw', key);
        return bufToHex(new Uint8Array(raw));
    }

    async function importKey(hexKey) {
        const raw = hexToBuf(hexKey);
        return await crypto.subtle.importKey(
            'raw', raw,
            { name: 'AES-GCM', length: 256 },
            true,
            ['encrypt', 'decrypt']
        );
    }

    async function encryptFile(file) {
        const key = await generateKey();
        const iv = crypto.getRandomValues(new Uint8Array(12));  // 96-bit IV for GCM
        const plaintext = await file.arrayBuffer();

        const ciphertext = await crypto.subtle.encrypt(
            { name: 'AES-GCM', iv, tagLength: 128 },  // 128-bit auth tag
            key,
            plaintext
        );

        // Web Crypto appends the auth tag to the ciphertext
        // Split them for metadata storage
        const ctArray = new Uint8Array(ciphertext);
        const encryptedData = ctArray.slice(0, ctArray.length - 16);
        const authTag = ctArray.slice(ctArray.length - 16);

        return {
            encryptedBlob: new Blob([ciphertext]),  // Send full ciphertext (includes tag)
            keyHex: await exportKey(key),
            ivHex: bufToHex(iv),
            authTagHex: bufToHex(authTag),
            originalSize: plaintext.byteLength
        };
    }

    async function decryptFile(encryptedArrayBuffer, keyHex, ivHex) {
        const key = await importKey(keyHex);
        const iv = hexToBuf(ivHex);

        const plaintext = await crypto.subtle.decrypt(
            { name: 'AES-GCM', iv, tagLength: 128 },
            key,
            encryptedArrayBuffer
        );

        return plaintext;
    }

    // ─── Hex Utilities ───────────────────────────────────────
    function bufToHex(buf) {
        return Array.from(buf).map(b => b.toString(16).padStart(2, '0')).join('');
    }

    function hexToBuf(hex) {
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

    // ─── Upload Flow ─────────────────────────────────────────
    async function uploadFile(file, onProgress) {
        const owner = getOwner();
        if (!owner) throw new Error('Not authenticated');

        // Step 1: Encrypt in browser
        if (onProgress) onProgress({ stage: 'encrypting', percent: 0 });
        const encrypted = await encryptFile(file);
        if (onProgress) onProgress({ stage: 'encrypting', percent: 100 });

        // Step 2: Upload encrypted blob
        if (onProgress) onProgress({ stage: 'uploading', percent: 0 });
        const formData = new FormData();
        formData.append('file', encrypted.encryptedBlob, file.name + '.enc');
        formData.append('owner', owner);
        formData.append('fileName', file.name);
        formData.append('iv', encrypted.ivHex);
        formData.append('authTag', encrypted.authTagHex);
        formData.append('originalSize', encrypted.originalSize);

        const response = await fetch(`${VAULT_API}/upload`, {
            method: 'POST',
            body: formData
        });

        if (!response.ok) {
            const err = await response.json();
            throw new Error(err.error || 'Upload failed');
        }

        const result = await response.json();
        if (onProgress) onProgress({ stage: 'anchoring', percent: 100 });

        // Step 3: Store encryption key LOCALLY ONLY
        saveKey(result.file.fileId, {
            keyHex: encrypted.keyHex,
            ivHex: encrypted.ivHex,
            authTagHex: encrypted.authTagHex,
            fileName: file.name,
            originalSize: encrypted.originalSize
        });

        if (onProgress) onProgress({ stage: 'complete', percent: 100 });

        return result.file;
    }

    // ─── Download & Decrypt Flow ─────────────────────────────
    async function downloadFile(fileId) {
        const keyData = getKey(fileId);
        if (!keyData) throw new Error('Encryption key not found. This file was encrypted on another device.');

        // Fetch encrypted blob from server
        const response = await fetch(`${VAULT_API}/download/${fileId}`);
        if (!response.ok) throw new Error('Download failed');

        const encryptedBuffer = await response.arrayBuffer();

        // Decrypt in browser
        const plaintext = await decryptFile(encryptedBuffer, keyData.keyHex, keyData.ivHex);

        // Trigger download
        const blob = new Blob([plaintext]);
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = keyData.fileName || 'decrypted_file';
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        URL.revokeObjectURL(url);

        return true;
    }

    // ─── List Files ──────────────────────────────────────────
    async function listFiles() {
        const owner = getOwner();
        if (!owner) return [];

        const response = await fetch(`${VAULT_API}/files/${encodeURIComponent(owner)}`);
        if (!response.ok) return [];

        const data = await response.json();
        return data.files || [];
    }

    // ─── Delete File ─────────────────────────────────────────
    async function deleteFile(fileId) {
        const owner = getOwner();
        if (!owner) throw new Error('Not authenticated');

        const response = await fetch(`${VAULT_API}/file/${fileId}`, {
            method: 'DELETE',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ owner })
        });

        if (!response.ok) {
            const err = await response.json();
            throw new Error(err.error || 'Delete failed');
        }

        // Remove local encryption key
        removeKey(fileId);
        return true;
    }

    // ─── Verify File Integrity ───────────────────────────────
    async function verifyFile(fileId) {
        const response = await fetch(`${VAULT_API}/verify/${fileId}`);
        if (!response.ok) return null;
        return await response.json();
    }

    // ─── Helper ──────────────────────────────────────────────
    function getOwner() {
        // Try auth user first, then fallback to identity
        const authUser = localStorage.getItem('ghostnet_auth_user');
        if (authUser) {
            try {
                const user = JSON.parse(authUser);
                return user.email || user.id;
            } catch { }
        }
        return window.app?.identity?.id || localStorage.getItem('ghostnet_user_id');
    }

    function hasKey(fileId) {
        return !!getKey(fileId);
    }

    // ─── Public API ──────────────────────────────────────────
    return {
        uploadFile,
        downloadFile,
        listFiles,
        deleteFile,
        verifyFile,
        hasKey,
        formatBytes,
        getOwner
    };
})();
