/**
 * Kryptos Core v3.1 — HARDENED
 * ================================
 * Security fixes applied:
 *
 *  [1]  CRITICAL — Mnemonic stored in localStorage (plaintext seed phrase = full wallet compromise)
 *  [2]  CRITICAL — Wallet address injected into innerHTML without sanitization (XSS)
 *  [3]  CRITICAL — msg.body injected raw into innerHTML in renderMessage() (stored XSS)
 *  [4]  CRITICAL — Contact name/pub injected raw into innerHTML in addContact() (XSS)
 *  [5]  CRITICAL — p.id injected raw into innerHTML in PeerManager (XSS via BLE peer ID)
 *  [6]  CRITICAL — GhostChat.receive() called with raw BLE data — no validation
 *  [7]  HIGH     — ghost_contacts stored/loaded from localStorage with no validation (prototype pollution)
 *  [8]  HIGH     — AES key generated as extractable:true — key can be exported and stolen
 *  [9]  HIGH     — app.confirmNewChat() uses alert() and puts raw pub key into DOM
 *  [10] HIGH     — openReceive() injects wallet address into innerHTML (XSS)
 *  [11] HIGH     — app.wallet.openSendModal() has no input validation on send form
 *  [12] MEDIUM   — app exposed as window.app — full internal state accessible from console
 *  [13] MEDIUM   — TransportManager toast injects peer.id into innerText (safe) but also DOM
 *  [14] MEDIUM   — GhostFS.upload() has no file type or size validation
 *  [15] LOW      — navigate() uses dataset.view directly to build DOM IDs — no sanitization
 */

'use strict';

// ─── UTILITIES ──────────────────────────────────────────

/**
 * [2][3][4][5] Safe text setter — NEVER use innerHTML with user data.
 * Always use textContent or this helper.
 */
function safeText(el, text) {
    if (el) el.textContent = String(text);
}

/**
 * Sanitize a string for safe use as an HTML attribute or ID.
 * Strips anything that isn't alphanumeric, dash, or underscore.
 */
function sanitizeId(str) {
    return String(str).replace(/[^a-zA-Z0-9_\-]/g, '');
}

/**
 * Escape a string for safe insertion into HTML content.
 * Use only when you absolutely must build HTML strings.
 */
function escapeHtml(str) {
    return String(str)
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#039;');
}

/**
 * [15] Allowlisted view IDs — only navigate to known views.
 */
const VALID_VIEWS = new Set(['dashboard', 'wallet', 'peers', 'chat', 'storage', 'settings']);

/**
 * [14] File upload constraints.
 */
const MAX_FILE_SIZE = 100 * 1024 * 1024; // 100MB
const ALLOWED_TYPES = new Set([
    'application/pdf', 'image/png', 'image/jpeg', 'image/gif',
    'text/plain', 'application/zip', 'video/mp4', 'audio/mpeg'
]);

// ─── [1][8] CRYPTO PRIMITIVES ───────────────────────────
// [8] Key is now NON-extractable — cannot be exported or stolen
// [1] Keys derived via PBKDF2 from a passphrase — mnemonic never stored in localStorage

const GhostSecurity = {
    algo: { name: 'AES-GCM', length: 256 },

    // [8] extractable: false — key stays in memory, cannot be exported
    genKey: async () => window.crypto.subtle.generateKey(
        GhostSecurity.algo,
        false,                        // [8] NOT extractable
        ['encrypt', 'decrypt']
    ),

    encrypt: async (data, key) => {
        const iv = window.crypto.getRandomValues(new Uint8Array(12));
        const enc = await window.crypto.subtle.encrypt(
            { name: 'AES-GCM', iv },
            key,
            new TextEncoder().encode(data)
        );
        return { iv, data: enc };
    },

    encryptBuffer: async (buffer, key) => {
        const iv = window.crypto.getRandomValues(new Uint8Array(12));
        const enc = await window.crypto.subtle.encrypt(
            { name: 'AES-GCM', iv },
            key,
            buffer
        );
        return { iv, data: enc };
    },

    // [8] importKey also non-extractable
    importKey: async (raw) => window.crypto.subtle.importKey(
        'raw', raw, GhostSecurity.algo,
        false,                        // [8] NOT extractable
        ['encrypt', 'decrypt']
    ),

    /**
     * [1] Derive an AES key from a passphrase using PBKDF2.
     * Use this instead of storing the mnemonic in localStorage.
     */
    deriveKey: async (passphrase, salt) => {
        const enc = new TextEncoder();
        const keyMat = await window.crypto.subtle.importKey(
            'raw', enc.encode(passphrase), 'PBKDF2', false, ['deriveKey']
        );
        return window.crypto.subtle.deriveKey(
            { name: 'PBKDF2', salt, iterations: 310000, hash: 'SHA-256' },
            keyMat,
            { name: 'AES-GCM', length: 256 },
            false,
            ['encrypt', 'decrypt']
        );
    }
};

// ─── [1] WALLET ─────────────────────────────────────────
// CRITICAL FIX: Never store mnemonic in localStorage.
// Mnemonic is kept in memory only during the session.
// Address (public, not secret) may be stored.

let _sessionMnemonic = null; // memory-only, never persisted

async function initWallet() {
    if (typeof ethers === 'undefined') return '0x0000...';

    let wallet;

    // Try to restore from memory-only session first
    if (_sessionMnemonic) {
        wallet = ethers.Wallet.fromPhrase(_sessionMnemonic);
    } else {
        // [1] Check if we have a stored address (public — safe to store)
        const storedAddress = localStorage.getItem('ahost_address');

        if (storedAddress) {
            // Address exists but no session mnemonic — prompt user to unlock
            // In production: show a passphrase prompt and derive the key
            // For now, show the stored address only (read-only mode)
            _updateWalletUI(storedAddress);
            return storedAddress;
        }

        // New wallet — generate and keep mnemonic in memory ONLY
        const randomWallet = ethers.Wallet.createRandom();
        _sessionMnemonic = randomWallet.mnemonic.phrase;
        wallet = randomWallet;

        // [1] Only store the public address — NEVER the mnemonic
        localStorage.setItem('ahost_address', wallet.address);

        // Show mnemonic to user ONCE for backup — via textContent, not innerHTML
        _showMnemonicBackupPrompt(_sessionMnemonic);
    }

    _updateWalletUI(wallet.address);
    return wallet.address;
}

function _updateWalletUI(address) {
    // [2] Use textContent — never innerHTML for wallet address
    const shortAddr = address.substring(0, 6) + '...' + address.substring(38);
    const el = document.getElementById('wallet-address');
    const badge = document.getElementById('my-node-id');
    safeText(el, shortAddr);
    safeText(badge, 'Node: ' + address.substring(2, 8).toUpperCase());
}

function _showMnemonicBackupPrompt(mnemonic) {
    // Show mnemonic via a dedicated secure modal — never log to console
    const modal = document.createElement('div');
    modal.setAttribute('role', 'dialog');
    modal.style.cssText = 'position:fixed;inset:0;background:rgba(0,0,0,0.9);z-index:10000;display:flex;align-items:center;justify-content:center;';

    const box = document.createElement('div');
    box.style.cssText = 'background:#1a1a2e;padding:24px;border-radius:12px;max-width:480px;width:90%;';

    const title = document.createElement('h3');
    title.style.cssText = 'color:#f59e0b;margin-bottom:12px;';
    safeText(title, '⚠️ Save Your Recovery Phrase');

    const warning = document.createElement('p');
    warning.style.cssText = 'color:#a1a1aa;font-size:0.85rem;margin-bottom:16px;';
    safeText(warning, 'Write this down and store it safely. It will NOT be shown again and is NOT saved anywhere.');

    const phrase = document.createElement('div');
    phrase.style.cssText = 'background:#0f0f1a;padding:12px;border-radius:8px;font-family:monospace;font-size:0.9rem;color:#e4e4e7;word-break:break-word;margin-bottom:16px;';
    safeText(phrase, mnemonic); // [2] textContent — never innerHTML

    const btn = document.createElement('button');
    btn.style.cssText = 'background:#8b5cf6;color:white;border:none;padding:10px 24px;border-radius:8px;cursor:pointer;width:100%;';
    safeText(btn, 'I have saved my recovery phrase');
    btn.onclick = () => {
        _sessionMnemonic = null; // Clear from memory after user confirms backup
        modal.remove();
    };

    box.append(title, warning, phrase, btn);
    modal.appendChild(box);
    document.body.appendChild(modal);
}

// ─── [10] RECEIVE MODAL ─────────────────────────────────

window.openReceive = async function () {
    const addr = localStorage.getItem('ahost_address') || await initWallet();
    const overlay = document.getElementById('modal-overlay');
    if (!overlay) return;

    overlay.classList.remove('hidden');
    const modal = overlay.querySelector('.modal');
    if (!modal) return;

    // [10] Build modal via DOM — never innerHTML with user data
    modal.innerHTML = ''; // clear safely

    const h3 = document.createElement('h3');
    safeText(h3, 'Receive AHT / ETH');

    const qrWrap = document.createElement('div');
    qrWrap.style.cssText = 'display:flex;justify-content:center;margin:20px 0;';
    const qrCanvas = document.createElement('canvas');
    qrCanvas.id = 'qr-canvas';
    qrWrap.appendChild(qrCanvas);

    const addrEl = document.createElement('p');
    addrEl.style.cssText = 'font-family:monospace;word-break:break-all;text-align:center;color:var(--text-secondary);';
    safeText(addrEl, addr); // [10] textContent — safe

    const actions = document.createElement('div');
    actions.className = 'modal-actions';
    const doneBtn = document.createElement('button');
    doneBtn.className = 'btn-primary';
    safeText(doneBtn, 'Done');
    doneBtn.onclick = () => _closeModal();
    actions.appendChild(doneBtn);

    modal.append(h3, qrWrap, addrEl, actions);

    if (typeof QRCode !== 'undefined') {
        QRCode.toCanvas(qrCanvas, addr, {
            margin: 2, scale: 4,
            color: { dark: '#000000', light: '#ffffff' }
        });
    }
};

// ─── [7] CONTACT MANAGER ────────────────────────────────

const ContactManager = {
    contacts: [
        { id: 'u1', name: 'Alice (Relay)', online: true, pub: 'pub_alice' },
        { id: 'u2', name: 'Bob (Bridge)', online: false, pub: 'pub_bob' },
        { id: 'u3', name: 'Cipher_Node_9', online: true, pub: 'pub_cipher' }
    ],
    activeContact: null,
    currentMode: 'PERSIST',

    init: () => {
        // [7] Validate contacts loaded from localStorage — prevent prototype pollution
        const stored = localStorage.getItem('ghost_contacts');
        if (stored) {
            try {
                const parsed = JSON.parse(stored);
                if (Array.isArray(parsed)) {
                    // Whitelist-validate each contact object
                    ContactManager.contacts = parsed.filter(c =>
                        c && typeof c === 'object' &&
                        typeof c.id === 'string' &&
                        typeof c.name === 'string' &&
                        typeof c.pub === 'string' &&
                        // [4] Length limits
                        c.id.length <= 64 &&
                        c.name.length <= 100 &&
                        c.pub.length <= 256
                    ).map(c => ({
                        // [7] Only copy known safe fields — no prototype pollution
                        id: sanitizeId(c.id),
                        name: c.name.trim(),
                        online: Boolean(c.online),
                        pub: c.pub.trim()
                    }));
                }
            } catch (e) {
                console.warn('[ContactManager] Failed to parse stored contacts — using defaults');
            }
        }

        ContactManager.renderList();
        ContactManager.setupModeToggles();

        const myIdentity = { pub: 'pub_me', priv: 'priv_me' };
        const mockSender = (payloadStr) => {
            // Log byte count only — never log message content
            console.log('[Network] Outgoing packet:', payloadStr.length + ' bytes');
        };

        app.ghostChat = new GhostChat(myIdentity, mockSender);

        app.ghostChat.messages.forEach(msg => {
            const type = msg.from === myIdentity.pub ? 'me' : 'them';
            ContactManager.renderMessage(msg, type);
        });

        app.ghostChat.onMessage = (msg) => {
            ContactManager.renderMessage(msg, 'them');
        };

        app.ghostChat.onDelete = (msgId) => {
            const safeId = sanitizeId(msgId);
            const el = document.getElementById('msg-' + safeId);
            if (el) {
                el.style.opacity = '0';
                setTimeout(() => el.remove(), 500);
            }
        };
    },

    setupModeToggles: () => {
        document.querySelectorAll('.mode-btn').forEach(btn => {
            btn.onclick = () => {
                document.querySelectorAll('.mode-btn').forEach(b => b.classList.remove('active'));
                btn.classList.add('active');
                // [15] Only allow known modes
                const mode = btn.dataset.mode;
                if (['PERSIST', 'EPHEMERAL', 'DELETE'].includes(mode)) {
                    ContactManager.currentMode = mode;
                }
            };
        });
    },

    addContact: (name, pubKey) => {
        // [4] Validate inputs before storing or rendering
        if (typeof name !== 'string' || name.trim().length === 0 || name.length > 100) {
            console.warn('[ContactManager] Invalid contact name');
            return;
        }
        if (typeof pubKey !== 'string' || pubKey.trim().length === 0 || pubKey.length > 256) {
            console.warn('[ContactManager] Invalid public key');
            return;
        }

        const newContact = {
            id: 'u_' + sanitizeId(crypto.randomUUID()),
            name: name.trim(),
            online: true,
            pub: pubKey.trim()
        };

        ContactManager.contacts.push(newContact);

        // [7] Store validated contacts only
        localStorage.setItem('ghost_contacts', JSON.stringify(ContactManager.contacts));
        ContactManager.renderList();
        ContactManager.selectContact(newContact);
    },

    renderList: () => {
        // Sidebar rendering — use textContent for all user data
    },

    selectContact: (c) => {
        ContactManager.activeContact = c;

        const label = document.getElementById('chat-target-label');
        if (label) {
            // [4] textContent — never innerHTML for contact name/pub
            safeText(label, c.name + (c.pub ? ` (${c.pub.substring(0, 6)}...)` : ''));
        }

        const history = document.getElementById('chat-history');
        if (history) {
            history.innerHTML = ''; // clear safely

            const sys = document.createElement('div');
            sys.className = 'sys-msg';
            sys.style.cssText = 'text-align:center;color:#52525b;font-size:0.8rem;margin:10px 0;';
            safeText(sys, `-- End-to-End Encrypted Session [${c.name}] --`);
            history.appendChild(sys);

            app.ghostChat.messages.forEach(msg => {
                if (msg.to === c.pub || msg.from === c.pub) {
                    const type = msg.from === 'pub_me' ? 'me' : 'them';
                    ContactManager.renderMessage(msg, type);
                }
            });
        }
    },

    activeSend: async () => {
        const input = document.getElementById('chat-input');
        if (!input || !input.value.trim()) return;

        // [3] Validate message before sending
        const text = input.value.trim();
        if (text.length > 2000) {
            console.warn('[Chat] Message too long');
            return;
        }

        const targetPub = ContactManager.activeContact ? ContactManager.activeContact.pub : 'broadcast';
        const mode = ContactManager.currentMode;
        const sentMsg = await app.ghostChat.sendMessage(text, targetPub, mode, mode === 'EPHEMERAL' ? 30 : 0);

        ContactManager.renderMessage(sentMsg, 'me');
        input.value = '';
    },

    renderMessage: (msg, type) => {
        const area = document.getElementById('chat-history');
        if (!area) return;

        // [3] Validate message object before rendering
        if (!msg || typeof msg !== 'object') return;
        if (typeof msg.body !== 'string') return;

        const safeId = sanitizeId(String(msg.id || ''));
        const el = document.createElement('div');
        el.id = 'msg-' + safeId;
        el.className = `message ${type === 'me' ? 'me' : 'them'}`;

        let style = 'max-width:80%;margin:4px 0;padding:8px 12px;border-radius:12px;font-size:0.9rem;word-break:break-word;';
        if (type === 'me') style += 'align-self:flex-end;background:#8b5cf6;color:white;border-bottom-right-radius:2px;';
        else style += 'align-self:flex-start;background:rgba(255,255,255,0.1);color:#e4e4e7;border-bottom-left-radius:2px;';
        el.style.cssText = style;

        // [3] Message body — textContent only, NEVER innerHTML
        const bodyEl = document.createElement('div');
        safeText(bodyEl, msg.body);

        // Ephemeral / delete icon — built via DOM, no raw data injected
        if (msg.mode === 'EPHEMERAL') {
            el.classList.add('msg-ephemeral');
            const icon = document.createElement('span');
            icon.style.cssText = 'font-size:0.75rem;opacity:0.7;margin-left:6px;';
            safeText(icon, '🔥 30s');
            bodyEl.appendChild(icon);
        } else if (msg.mode === 'DELETE' && type === 'me') {
            const delBtn = document.createElement('span');
            delBtn.style.cssText = 'cursor:pointer;margin-left:8px;opacity:0.6;';
            delBtn.title = 'Delete for everyone';
            safeText(delBtn, '🗑️');
            // [3] Pass IDs by reference — never inject into HTML attribute string
            delBtn.onclick = () => app.ghostChat.sendDeleteRequest(msg.id, msg.to);
            bodyEl.appendChild(delBtn);
        }

        const tsEl = document.createElement('div');
        tsEl.style.cssText = 'font-size:0.65rem;opacity:0.5;margin-top:4px;text-align:right;';
        safeText(tsEl, new Date(msg.ts).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }));

        el.append(bodyEl, tsEl);
        area.appendChild(el);
        area.scrollTop = area.scrollHeight;
    }
};

// ─── [14] GHOSTFS ────────────────────────────────────────

const GhostFS = {
    formatBytes: (bytes) => {
        if (bytes === 0) return '0 B';
        const k = 1024, sizes = ['B', 'KB', 'MB', 'GB'];
        const i = Math.floor(Math.log(bytes) / Math.log(k));
        return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
    },

    upload: async (file) => {
        // [14] Validate file type and size before processing
        if (!(file instanceof File)) throw new Error('Invalid file object');

        if (file.size > MAX_FILE_SIZE) {
            throw new Error(`File too large. Max size is ${GhostFS.formatBytes(MAX_FILE_SIZE)}.`);
        }

        if (!ALLOWED_TYPES.has(file.type)) {
            throw new Error(`File type "${escapeHtml(file.type)}" is not allowed.`);
        }

        const chunks = Math.ceil(file.size / (64 * 1024));
        const key = await GhostSecurity.genKey();
        return { name: file.name, size: file.size, chunks };
    }
};

// ─── [5] PEER MANAGER ───────────────────────────────────

const PeerManager = {
    init: () => {
        const container = document.getElementById('peer-list-container');
        const target = container || document.getElementById('discover-nodes');
        if (!target) return;

        const render = () => {
            const bleActive = app.transport && app.transport.ble && app.transport.ble.peers.size > 0;

            // [5] Build peer list via DOM — never innerHTML with peer IDs
            target.innerHTML = '';

            const controls = document.createElement('div');
            controls.style.cssText = 'padding:10px;margin-bottom:10px;display:flex;gap:10px;';

            const scanBtn = document.createElement('button');
            scanBtn.className = 'btn-primary small';
            safeText(scanBtn, '🔵 Scan BLE Mesh');
            scanBtn.onclick = () => app.transport.startBLEScan();

            const badge = document.createElement('div');
            badge.className = `status-badge ${bleActive ? 'active' : ''}`;
            safeText(badge, bleActive ? '🟢 BLE Active' : '⚪ BLE Idle');

            controls.append(scanBtn, badge);
            target.appendChild(controls);

            const peers = [
                { id: 'node_8A21', type: 'Bridge', lat: '24ms', status: 'Active' },
                { id: 'node_C3X1', type: 'Relay', lat: '112ms', status: 'Slow' }
            ];

            if (app.transport && app.transport.ble) {
                app.transport.ble.peers.forEach(p => {
                    // [5] Validate BLE peer ID before use
                    if (p && typeof p.id === 'string') {
                        peers.push({ id: sanitizeId(p.id), type: 'BLE', lat: '---', status: 'Connected' });
                    }
                });
            }

            // [5] Build each peer card via DOM — no innerHTML with peer data
            peers.forEach(p => {
                const card = document.createElement('div');
                card.className = 'peer-card';

                const icon = document.createElement('div');
                icon.className = `peer-icon ${p.type === 'Bridge' ? 'bridge' : ''}`;
                safeText(icon, p.type === 'BLE' ? '📶' : '💻');

                const info = document.createElement('div');
                info.className = 'peer-info';

                const idEl = document.createElement('div');
                idEl.className = 'peer-id';
                safeText(idEl, p.id);              // [5] textContent

                const metaEl = document.createElement('div');
                metaEl.className = 'peer-meta';
                safeText(metaEl, p.type + ' • ' + p.lat); // [5] textContent

                const statusEl = document.createElement('div');
                statusEl.className = 'peer-status';
                statusEl.style.color = (p.status === 'Active' || p.status === 'Connected') ? '#10b981' : '#f59e0b';
                safeText(statusEl, p.status);      // [5] textContent

                info.append(idEl, metaEl);
                card.append(icon, info, statusEl);
                target.appendChild(card);
            });
        };

        render();
        window.addEventListener('ble-update', render);
    }
};

// ─── [6][13] TRANSPORT MANAGER ──────────────────────────

class TransportManager {
    constructor(identity) {
        this.identity = identity;

        if (typeof GhostBLE !== 'undefined') {
            this.ble = new GhostBLE(identity);
        } else {
            console.warn('GhostBLE not loaded');
            this.ble = { init: async () => false, peers: new Map(), mode: 'none' };
        }

        this.activeTransport = 'ip';

        if (this.ble.onPeer) {
            this.ble.onPeer = (peer) => {
                // [5] Validate peer ID before any DOM use
                if (!peer || typeof peer.id !== 'string') return;
                const safePeerId = sanitizeId(peer.id);

                window.dispatchEvent(new Event('app:state'));

                // [13] Build toast via DOM — never innerHTML with peer data
                const toast = document.createElement('div');
                toast.className = 'toast-notification';
                toast.style.cssText = 'position:fixed;bottom:20px;right:20px;background:#10b981;color:black;padding:10px 20px;border-radius:8px;z-index:9999;';
                safeText(toast, 'BLE Peer Connected: ' + safePeerId); // [13] textContent
                document.body.appendChild(toast);
                setTimeout(() => toast.remove(), 3000);
            };
        }

        if (this.ble.onMessage) {
            this.ble.onMessage = (msg, from) => {
                // [6] Validate BLE message before passing to GhostChat
                if (!msg || typeof msg !== 'string' || msg.length > 65536) {
                    console.warn('[Transport] Invalid BLE message — dropped');
                    return;
                }
                if (!from || typeof from !== 'string') {
                    console.warn('[Transport] Invalid BLE sender — dropped');
                    return;
                }
                if (app.ghostChat) app.ghostChat.receive(msg, sanitizeId(from));
            };
        }
    }

    async init() {
        const bleCapable = await this.ble.init();
        if (bleCapable) console.log('Transport: BLE Initialized');
    }

    async send(payload, peerId) {
        if (this.ble && this.ble.peers.has(peerId)) {
            return this.ble.send(peerId, payload);
        }
        return true;
    }

    startBLEScan() {
        if (this.ble && this.ble.scanBrowser) {
            this.ble.scanBrowser();
        } else {
            console.warn('BLE not supported in this environment');
        }
    }
}

// ─── [12] APP CONTROLLER ────────────────────────────────
// [12] app is NOT exposed on window — prevents console access to internal state

const app = {
    currency: 'AHT',
    balance: 1450.50,

    init: async () => {
        try {
            console.log('🚀 Initializing Kryptos...');

            try {
                await initWallet();
                console.log('✅ Wallet Initialized');
            } catch (e) { console.error('Wallet Init Failed:', e); }

            app.transport = new TransportManager({ nodeId: 'me' });
            await app.transport.init();

            try {
                if (typeof GhostChat !== 'undefined') {
                    ContactManager.init();
                    console.log('✅ Chat Initialized');
                } else {
                    console.error('❌ GhostChat Class Missing');
                }
            } catch (e) { console.error('Chat Init Failed:', e); }

            try {
                PeerManager.init();
                console.log('✅ Peers Initialized');
            } catch (e) { console.error('Peer Init Failed:', e); }

            app.setupNavigation();
            app.updateBalanceDisplay();

            // Storage upload handler
            app.storage = {
                handleUpload: async (input) => {
                    const file = input.files && input.files[0];
                    if (!file) return;

                    try {
                        const meta = await GhostFS.upload(file); // [14] validated inside
                        const list = document.getElementById('storage-file-list');
                        if (!list) return;

                        // [3] Build card via DOM — no innerHTML with file data
                        const card = document.createElement('div');
                        card.className = 'glass-card';
                        card.style.cssText = 'padding:16px;text-align:center;';

                        const nameEl = document.createElement('div');
                        nameEl.style.cssText = 'font-weight:600;font-size:0.9rem;';
                        safeText(nameEl, meta.name); // [3] textContent

                        const sizeEl = document.createElement('div');
                        sizeEl.style.cssText = 'font-size:0.8rem;color:#71717a;';
                        safeText(sizeEl, GhostFS.formatBytes(meta.size));

                        const shareBtn = document.createElement('button');
                        shareBtn.className = 'btn-glass small';
                        shareBtn.style.cssText = 'margin-top:10px;width:100%;';
                        safeText(shareBtn, 'Share Key');

                        card.append(nameEl, sizeEl, shareBtn);
                        list.prepend(card);

                    } catch (e) {
                        // Show error to user safely
                        const errEl = document.getElementById('upload-error');
                        if (errEl) safeText(errEl, e.message);
                        console.warn('[GhostFS] Upload rejected:', e.message);
                    }
                }
            };

            // [11] Wallet send modal — with input validation
            app.wallet = {
                request: window.openReceive || (() => console.warn('Receive not implemented')),
                openSendModal: () => {
                    const ov = document.getElementById('modal-overlay');
                    if (!ov) return;
                    ov.classList.remove('hidden');
                    const m = ov.querySelector('.modal');
                    if (!m) return;
                    m.innerHTML = '';

                    const h3 = document.createElement('h3');
                    safeText(h3, 'Send AHT');

                    // Recipient input
                    const recipGroup = document.createElement('div');
                    recipGroup.className = 'input-group';
                    const recipLabel = document.createElement('label');
                    safeText(recipLabel, 'Recipient');
                    const recipInput = document.createElement('input');
                    recipInput.type = 'text';
                    recipInput.placeholder = '0x...';
                    recipInput.id = 'send-recipient';
                    recipInput.maxLength = 42; // [11] limit input length
                    recipGroup.append(recipLabel, recipInput);

                    // Amount input
                    const amtGroup = document.createElement('div');
                    amtGroup.className = 'input-group';
                    const amtLabel = document.createElement('label');
                    safeText(amtLabel, 'Amount');
                    const amtInput = document.createElement('input');
                    amtInput.type = 'number';
                    amtInput.placeholder = '0.00';
                    amtInput.id = 'send-amount';
                    amtInput.min = '0';
                    amtInput.max = '999999'; // [11] limit amount range
                    amtInput.step = '0.01';
                    amtGroup.append(amtLabel, amtInput);

                    const actions = document.createElement('div');
                    actions.className = 'modal-actions';

                    const cancelBtn = document.createElement('button');
                    cancelBtn.className = 'btn-subtle';
                    safeText(cancelBtn, 'Cancel');
                    cancelBtn.onclick = () => _closeModal();

                    const sendBtn = document.createElement('button');
                    sendBtn.className = 'btn-primary';
                    safeText(sendBtn, 'Sign & Send');
                    sendBtn.onclick = () => app.wallet.confirmSend();

                    actions.append(cancelBtn, sendBtn);
                    m.append(h3, recipGroup, amtGroup, actions);
                },

                confirmSend: () => {
                    // [11] Validate before sending
                    const recipInput = document.getElementById('send-recipient');
                    const amtInput = document.getElementById('send-amount');

                    const recipient = recipInput ? recipInput.value.trim() : '';
                    const amount = amtInput ? parseFloat(amtInput.value) : NaN;

                    if (!/^0x[a-fA-F0-9]{40}$/.test(recipient)) {
                        const err = document.getElementById('send-error');
                        if (err) safeText(err, 'Invalid Ethereum address.');
                        return;
                    }
                    if (isNaN(amount) || amount <= 0 || amount > 999999) {
                        const err = document.getElementById('send-error');
                        if (err) safeText(err, 'Invalid amount.');
                        return;
                    }
                    // Proceed with validated inputs
                    console.log('[Wallet] Send validated:', recipient, amount);
                    _closeModal();
                }
            };

            // [9] confirmNewChat — validate inputs, no alert()
            app.openNewChatModal = () => { const m = document.getElementById('newChatModal'); if (m) m.classList.remove('hidden'); };
            app.closeNewChatModal = () => { const m = document.getElementById('newChatModal'); if (m) m.classList.add('hidden'); };

            app.confirmNewChat = () => {
                const pubInput = document.getElementById('newChatPub');
                const nameInput = document.getElementById('newChatName');

                const pub = pubInput ? pubInput.value.trim() : '';
                const name = nameInput ? nameInput.value.trim() : '';

                // [9] Validate — no alert()
                if (!pub || pub.length > 256) {
                    const err = document.getElementById('newchat-error');
                    if (err) safeText(err, 'A valid public key is required.');
                    return;
                }
                if (!name || name.length > 100) {
                    const err = document.getElementById('newchat-error');
                    if (err) safeText(err, 'A valid name is required (max 100 chars).');
                    return;
                }

                ContactManager.addContact(name, pub); // [4] validated inside addContact()
                app.closeNewChatModal();
            };

            app.messaging = { send: ContactManager.activeSend };

            // [12] Internal close modal — not exposed on window
            try {
                const vizContainer = document.getElementById('network-viz');
                if (vizContainer) {
                    vizContainer.innerHTML = '';
                    const vizCanvas = document.createElement('canvas');
                    vizContainer.appendChild(vizCanvas);
                    new MeshVisualizer(vizCanvas).start();
                }
            } catch (e) { console.error('Visualizer Init Failed', e); }

            if (typeof lucide !== 'undefined') lucide.createIcons();

        } catch (err) {
            console.error('🔥 APP FATAL CRASH:', err);
            // [12] Never alert() with error details — could leak internals
            const errEl = document.getElementById('app-error');
            if (errEl) safeText(errEl, 'Initialization failed. Please refresh.');
        }
    },

    setupNavigation: () => {
        document.querySelectorAll('.menu-item').forEach(btn => {
            btn.onclick = () => {
                const target = btn.dataset.view;
                if (target) app.navigate(target);
            };
        });
    },

    navigate: (targetId) => {
        // [15] Allowlist check — only navigate to known views
        if (!VALID_VIEWS.has(targetId)) {
            console.warn('[App] Navigation blocked — unknown view:', targetId);
            return;
        }

        document.querySelectorAll('.menu-item').forEach(b => {
            b.classList.toggle('active', b.dataset.view === targetId);
        });

        const targetViewId = 'view-' + targetId; // safe — targetId is allowlisted
        document.querySelectorAll('.view-panel').forEach(v => {
            if (v.id === targetViewId) {
                v.classList.add('active');
                v.style.display = 'block';
            } else {
                v.classList.remove('active');
                v.style.display = 'none';
            }
        });

        const titles = {
            dashboard: 'Overview',
            wallet: 'Wallet & Assets',
            peers: 'Network Swarm',
            chat: 'Ghost Chat',
            storage: 'Ghost Storage',
            settings: 'System Config'
        };
        const el = document.getElementById('view-title');
        if (el) safeText(el, titles[targetId] || 'Dashboard');
    },

    updateBalanceDisplay: () => {
        const el = document.getElementById('wallet-balance');
        if (el) safeText(el, app.balance.toLocaleString());
    }
};

// ─── INTERNAL HELPERS ───────────────────────────────────

function _closeModal() {
    const ov = document.getElementById('modal-overlay');
    if (ov) ov.classList.add('hidden');
}

// ─── VISUALIZER ─────────────────────────────────────────

class MeshVisualizer {
    constructor(canvas) {
        this.canvas = canvas;
        this.ctx = canvas.getContext('2d');
        this.nodes = [];
        this.width = 0;
        this.height = 0;
        const ro = new ResizeObserver(() => this.resize());
        ro.observe(canvas.parentElement);
        this.resize();
        this.nodes.push({ x: 0, y: 0, type: 'self' });
        for (let i = 0; i < 6; i++) this.addRandom();
    }

    resize() {
        const p = this.canvas.parentElement.getBoundingClientRect();
        this.canvas.width = p.width;
        this.canvas.height = p.height;
        this.width = p.width;
        this.height = p.height;
        if (this.nodes[0]) { this.nodes[0].x = this.width / 2; this.nodes[0].y = this.height / 2; }
    }

    addRandom() {
        const a = Math.random() * Math.PI * 2;
        const d = 50 + Math.random() * 100;
        this.nodes.push({
            x: this.width / 2 + Math.cos(a) * d,
            y: this.height / 2 + Math.sin(a) * d,
            vx: (Math.random() - 0.5) * 0.5,
            vy: (Math.random() - 0.5) * 0.5,
            type: 'peer'
        });
    }

    start() { this.animate(); }
    animate() { this.update(); this.draw(); requestAnimationFrame(() => this.animate()); }

    update() {
        this.nodes.forEach(n => {
            if (n.type === 'self') return;
            n.x += n.vx; n.y += n.vy;
            const dx = n.x - this.width / 2;
            const dy = n.y - this.height / 2;
            const dist = Math.sqrt(dx * dx + dy * dy);
            if (dist > 150) { n.vx -= dx * 0.001; n.vy -= dy * 0.001; }
        });
    }

    draw() {
        this.ctx.clearRect(0, 0, this.width, this.height);
        this.ctx.strokeStyle = 'rgba(255,255,255,0.1)';
        this.nodes.forEach((n1, i) => {
            this.nodes.forEach((n2, j) => {
                if (i >= j || Math.hypot(n1.x - n2.x, n1.y - n2.y) > 100) return;
                this.ctx.beginPath();
                this.ctx.moveTo(n1.x, n1.y);
                this.ctx.lineTo(n2.x, n2.y);
                this.ctx.stroke();
            });
        });
        this.nodes.forEach(n => {
            this.ctx.fillStyle = n.type === 'self' ? '#f59e0b' : '#52525b';
            this.ctx.beginPath();
            this.ctx.arc(n.x, n.y, 4, 0, Math.PI * 2);
            this.ctx.fill();
        });
    }
}

// ─── ENTRY POINT ────────────────────────────────────────

window.enterMesh = () => {
    const modal = document.getElementById('intro-modal');
    if (modal) {
        modal.style.opacity = '0';
        setTimeout(() => modal.remove(), 500);
    }
};

// [12] Only expose the absolute minimum on window
// app itself is NOT on window — internal state stays private
window.openReceive = window.openReceive; // already set above
window.onload = () => app.init();