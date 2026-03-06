/**
 * GhostNet Crypto Identity System
 * ================================
 * Client-side-only cryptographic identity management.
 *
 * - BIP39 mnemonic seed phrase (12 words)
 * - HD wallet key derivation (ethers.js)
 * - AES-256-GCM PIN-based encryption of private key
 * - All ops happen in-browser — nothing sent to any server
 */

const GhostIdentity = (() => {
    // ─── CONSTANTS ──────────────────────────────────────────
    const STORAGE_KEYS = {
        ENCRYPTED_PK: 'ghostnet_enc_pk',
        PUBLIC_KEY: 'ghostnet_pubkey',
        ADDRESS: 'ghostnet_address',
        DISPLAY_NAME: 'ghostnet_display_name',
        NODE_ID: 'ghostnet_node_id',
        PIN_ATTEMPTS: 'ghostnet_pin_attempts',
        LOCKED: 'ghostnet_locked',
        SESSION_TOKEN: 'ghostnet_session_token',
    };
    const MAX_PIN_ATTEMPTS = 5;

    // ─── BIP39 WORDLIST (English, 2048 words) ───────────────
    // We fetch it lazily from ethers
    function getWordlist() {
        if (window.ethers && window.ethers.wordlists) {
            return window.ethers.wordlists.en;
        }
        return null;
    }

    // ─── CORE: Generate New Identity ────────────────────────
    async function generateIdentity(displayName) {
        // 1. Generate 12-word mnemonic
        const wallet = ethers.Wallet.createRandom({ locale: ethers.wordlists.en });
        const mnemonic = wallet.mnemonic.phrase;
        const privateKey = wallet.privateKey;
        const publicKey = wallet.publicKey;
        const address = wallet.address;

        // 2. Derive Node ID = keccak256(publicKey + displayName)
        const nodeId = ethers.utils.id(publicKey + displayName);

        return {
            mnemonic,        // 12-word seed phrase — show once, never store
            privateKey,      // hex string — encrypt with PIN, never store raw
            publicKey,       // hex string — public identity
            address,         // ethereum-style address
            displayName,
            nodeId,
        };
    }

    // ─── CORE: Restore from Seed Phrase ─────────────────────
    async function restoreFromMnemonic(mnemonic, displayName) {
        try {
            const wallet = ethers.Wallet.fromMnemonic(mnemonic.trim());
            const privateKey = wallet.privateKey;
            const publicKey = wallet.publicKey;
            const address = wallet.address;
            const nodeId = ethers.utils.id(publicKey + displayName);

            return {
                privateKey,
                publicKey,
                address,
                displayName,
                nodeId,
            };
        } catch (e) {
            throw new Error('Invalid seed phrase. Please check your words.');
        }
    }

    // ─── PIN ENCRYPTION (AES-256-GCM via Web Crypto) ────────
    async function _deriveKey(pin, salt) {
        const enc = new TextEncoder();
        const keyMaterial = await crypto.subtle.importKey(
            'raw', enc.encode(pin), 'PBKDF2', false, ['deriveKey']
        );
        return crypto.subtle.deriveKey(
            { name: 'PBKDF2', salt, iterations: 100000, hash: 'SHA-256' },
            keyMaterial,
            { name: 'AES-GCM', length: 256 },
            false,
            ['encrypt', 'decrypt']
        );
    }

    async function encryptWithPin(privateKey, pin) {
        const salt = crypto.getRandomValues(new Uint8Array(16));
        const iv = crypto.getRandomValues(new Uint8Array(12));
        const key = await _deriveKey(pin, salt);
        const enc = new TextEncoder();
        const ciphertext = await crypto.subtle.encrypt(
            { name: 'AES-GCM', iv },
            key,
            enc.encode(privateKey)
        );
        // Pack: salt(16) + iv(12) + ciphertext
        const packed = new Uint8Array(salt.length + iv.length + ciphertext.byteLength);
        packed.set(salt, 0);
        packed.set(iv, salt.length);
        packed.set(new Uint8Array(ciphertext), salt.length + iv.length);
        return btoa(String.fromCharCode(...packed));
    }

    async function decryptWithPin(encryptedB64, pin) {
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
        } catch (e) {
            throw new Error('Wrong PIN');
        }
    }

    // ─── STORAGE HELPERS ────────────────────────────────────
    function saveIdentity(publicKey, address, displayName, nodeId, encryptedPK) {
        localStorage.setItem(STORAGE_KEYS.ENCRYPTED_PK, encryptedPK);
        localStorage.setItem(STORAGE_KEYS.PUBLIC_KEY, publicKey);
        localStorage.setItem(STORAGE_KEYS.ADDRESS, address);
        localStorage.setItem(STORAGE_KEYS.DISPLAY_NAME, displayName);
        localStorage.setItem(STORAGE_KEYS.NODE_ID, nodeId);
        localStorage.setItem(STORAGE_KEYS.PIN_ATTEMPTS, '0');
        localStorage.removeItem(STORAGE_KEYS.LOCKED);
    }

    function getStoredIdentity() {
        const encPK = localStorage.getItem(STORAGE_KEYS.ENCRYPTED_PK);
        if (!encPK) return null;
        return {
            encryptedPK: encPK,
            publicKey: localStorage.getItem(STORAGE_KEYS.PUBLIC_KEY),
            address: localStorage.getItem(STORAGE_KEYS.ADDRESS),
            displayName: localStorage.getItem(STORAGE_KEYS.DISPLAY_NAME),
            nodeId: localStorage.getItem(STORAGE_KEYS.NODE_ID),
        };
    }

    function isIdentityStored() {
        return !!localStorage.getItem(STORAGE_KEYS.ENCRYPTED_PK);
    }

    function isLocked() {
        return localStorage.getItem(STORAGE_KEYS.LOCKED) === 'true';
    }

    function getPinAttempts() {
        return parseInt(localStorage.getItem(STORAGE_KEYS.PIN_ATTEMPTS) || '0', 10);
    }

    function incrementPinAttempts() {
        const attempts = getPinAttempts() + 1;
        localStorage.setItem(STORAGE_KEYS.PIN_ATTEMPTS, String(attempts));
        if (attempts >= MAX_PIN_ATTEMPTS) {
            localStorage.setItem(STORAGE_KEYS.LOCKED, 'true');
        }
        return attempts;
    }

    function resetPinAttempts() {
        localStorage.setItem(STORAGE_KEYS.PIN_ATTEMPTS, '0');
        localStorage.removeItem(STORAGE_KEYS.LOCKED);
    }

    function clearIdentity() {
        Object.values(STORAGE_KEYS).forEach(k => localStorage.removeItem(k));
    }

    // ─── SESSION MANAGEMENT (7-Day Auto Unlock) ─────────────
    async function saveSessionToken(pin, nodeId) {
        const expiry = Date.now() + 7 * 24 * 60 * 60 * 1000; // 7 days
        const payload = JSON.stringify({ pin, expiry });
        const token = await encryptWithPin(payload, nodeId);
        localStorage.setItem(STORAGE_KEYS.SESSION_TOKEN, token);
    }

    async function getSessionPin(nodeId) {
        const token = localStorage.getItem(STORAGE_KEYS.SESSION_TOKEN);
        if (!token) return null;
        try {
            const payloadStr = await decryptWithPin(token, nodeId);
            const payload = JSON.parse(payloadStr);
            if (Date.now() > payload.expiry) {
                clearSessionToken();
                return null;
            }
            return payload.pin;
        } catch (e) {
            clearSessionToken();
            return null;
        }
    }

    function clearSessionToken() {
        if (STORAGE_KEYS && STORAGE_KEYS.SESSION_TOKEN) {
            localStorage.removeItem(STORAGE_KEYS.SESSION_TOKEN);
        }
    }

    function shortenKey(key) {
        if (!key) return '';
        return key.slice(0, 6) + '...' + key.slice(-4);
    }

    function shortenNodeId(id) {
        if (!id) return '';
        return id.slice(0, 10) + '...' + id.slice(-6);
    }

    // ─── PUBLIC API ─────────────────────────────────────────
    return {
        generateIdentity,
        restoreFromMnemonic,
        encryptWithPin,
        decryptWithPin,
        saveIdentity,
        getStoredIdentity,
        isIdentityStored,
        isLocked,
        getPinAttempts,
        incrementPinAttempts,
        resetPinAttempts,
        clearIdentity,
        saveSessionToken,
        getSessionPin,
        clearSessionToken,
        shortenKey,
        shortenNodeId,
        MAX_PIN_ATTEMPTS,
        STORAGE_KEYS,
    };
})();
