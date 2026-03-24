/**
 * GhostNet Profile Sync System
 * Handles secure export/import of identity metadata + seed phrase.
 */

const GhostSync = (() => {
    'use strict';

    /**
     * Export the current identity as an encrypted sync string.
     * Format: AES-GCM(JSON({ mnemonic, displayName, ghostTag, address }), pin)
     */
    async function exportIdentity(pin) {
        try {
            // 1. Verify PIN and get private key (proves ownership)
            await GhostIdentity.unlockWithPin(pin);
            
            // 2. Get the full stored identity (includes mnemonic if we want to sync it)
            // Note: GhostIdentity.getStoredIdentity() usually doesn't store mnemonic.
            // We need to ask the user to provide the mnemonic or we have to store it encrypted.
            // However, looking at crypto-identity.js, mnemonic is NOT stored.
            // User rules: "Use the existing seed phrase infrastructure".
            
            // Let's check if the user has the mnemonic handy or if we should fetch it.
            // Actually, the prompt says "exports the identity object".
            // If mnemonic isn't in the object, we can't export it without prompting.
            
            return { success: false, error: 'Mnemonic required for full sync.' };
        } catch (e) {
            return { success: false, error: e.message };
        }
    }

    /**
     * Internal helper to pack sync data
     */
    async function packSyncData(mnemonic, displayName, ghostTag, pin) {
        const data = JSON.stringify({
            m: mnemonic,
            n: displayName,
            t: ghostTag,
            v: 1 // version
        });

        const enc = await _localEncrypt(data, pin);
        return `GNSyncV1:${enc}`;
    }

    async function unpackSyncData(syncString, pin) {
        if (!syncString || !syncString.startsWith('GNSyncV1:')) {
            throw new Error('Invalid sync format');
        }
        const encryptedB64 = syncString.split(':')[1];
        const decrypted = await _localDecrypt(encryptedB64, pin);
        return JSON.parse(decrypted);
    }

    // --- Local Crypto Helpers (Isolated) ---
    async function _deriveKey(pin, salt) {
        const enc = new TextEncoder();
        const keyMaterial = await crypto.subtle.importKey(
            'raw', enc.encode(pin), 'PBKDF2', false, ['deriveKey']
        );
        return crypto.subtle.deriveKey(
            { name: 'PBKDF2', salt, iterations: 600000, hash: 'SHA-256' },
            keyMaterial,
            { name: 'AES-GCM', length: 256 },
            false,
            ['encrypt', 'decrypt']
        );
    }

    async function _localEncrypt(plaintext, pin) {
        const salt = crypto.getRandomValues(new Uint8Array(16));
        const iv = crypto.getRandomValues(new Uint8Array(12));
        const key = await _deriveKey(pin, salt);
        const encoder = new TextEncoder();
        const ciphertext = await crypto.subtle.encrypt(
            { name: 'AES-GCM', iv },
            key,
            encoder.encode(plaintext)
        );
        const packed = new Uint8Array(16 + 12 + ciphertext.byteLength);
        packed.set(salt, 0);
        packed.set(iv, 16);
        packed.set(new Uint8Array(ciphertext), 28);
        return btoa(String.fromCharCode(...packed));
    }

    async function _localDecrypt(encryptedB64, pin) {
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
    }

    return {
        packSyncData,
        unpackSyncData
    };
})();
