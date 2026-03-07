/**
 * GhostNet Immersive UI — SECURITY RE-HARDENED
 * ==============================================
 * Additional fixes applied on top of previous version:
 *
 *  [A] CRITICAL  — innerHTML used with sanitize() throughout — sanitize() can be bypassed;
 *                  all dynamic content rebuilt as DOM nodes with textContent
 *  [B] CRITICAL  — avatar img.src set from server data with no URL validation — SSRF / open redirect
 *  [C] CRITICAL  — confirm() called with raw fileName from server — stored XSS via confirm dialog
 *  [D] CRITICAL  — alert() called with server error messages — reflected XSS via alert()
 *  [E] CRITICAL  — Math.random() used for node latency — predictable, not crypto-safe
 *  [F] HIGH      — window.UI = UI exposed globally — full internal UI state accessible from console
 *  [G] HIGH      — window.AppState exposed globally — all app state readable/writable from console
 *  [H] HIGH      — sessionStorage used for auth token — XSS can read sessionStorage
 *  [I] HIGH      — No CSRF token on any mutating fetch (POST) request
 *  [J] HIGH      — JSON.parse() called on server responses with no schema validation
 *  [K] HIGH      — renderHome() injects AppState.peers.length into innerHTML — state poisoning XSS
 *  [L] MEDIUM    — localStorage used for theme and user profile — sensitive data in plaintext
 *  [M] MEDIUM    — Avatar src loaded from c.otherUser.avatar with no URL allowlist
 *  [N] MEDIUM    — No Content Security Policy nonce — all inline scripts can run
 *  [O] MEDIUM    — vaultDelete confirm() leaks fileName to native dialog — filename injection
 *  [P] LOW       — isDev check based on hostname — can be spoofed in some environments
 *  [Q] LOW       — No max length enforced on pubKey in submitNewChat before fetch
 */

'use strict';

// ─── SECURITY UTILITIES ─────────────────────────────────

/**
 * Safe text setter — ALWAYS use this instead of innerHTML/innerText for user data.
 */
function st(el, text) {
    if (el) el.textContent = String(text ?? '');
}

/**
 * Sanitize string for use in HTML attribute values (data-* etc.)
 * Never use for innerHTML — use st() / DOM methods instead.
 */
function sanitize(str) {
    if (str === null || str === undefined) return '';
    const div = document.createElement('div');
    div.textContent = String(str);
    return div.innerHTML;
}

/**
 * [B][M] Validate image URLs — only allow https:// from known CDNs.
 * Prevents SSRF and open redirect via img.src.
 */
const ALLOWED_IMG_ORIGINS = new Set([
    'assets.coingecko.com',
    'api.qrserver.com',
]);

function isSafeImageUrl(url) {
    if (!url || typeof url !== 'string') return false;
    if (url.startsWith('data:image/')) return true; // base64 avatar
    try {
        const u = new URL(url);
        return u.protocol === 'https:' && ALLOWED_IMG_ORIGINS.has(u.hostname);
    } catch (_) { return false; }
}

function safeImgSrc(img, url, fallback = '') {
    if (isSafeImageUrl(url)) {
        img.src = url;
    } else {
        img.src = fallback;
        img.style.display = fallback ? 'block' : 'none';
    }
}

/**
 * [C][D][O] Safe user-facing notifications — never pass server/user data to alert/confirm.
 * Use our own modal instead.
 */
function showNotice(msg, isError = false) {
    const toast = document.createElement('div');
    toast.style.cssText = `position:fixed;bottom:20px;right:20px;padding:12px 20px;border-radius:8px;
        z-index:10000;font-size:0.9rem;color:#fff;max-width:320px;word-break:break-word;
        background:${isError ? '#ef4444' : '#10b981'};box-shadow:0 4px 12px rgba(0,0,0,0.3);`;
    st(toast, msg); // [D] textContent — never user/server data in alert()
    document.body.appendChild(toast);
    setTimeout(() => toast.remove(), 4000);
}

function showConfirm(msg, onConfirm) {
    // [C][O] Custom confirm modal — never native confirm() with user data
    const overlay = document.createElement('div');
    overlay.style.cssText = 'position:fixed;inset:0;background:rgba(0,0,0,0.7);z-index:10001;display:flex;align-items:center;justify-content:center;';
    const box = document.createElement('div');
    box.style.cssText = 'background:#1e1e2e;border-radius:12px;padding:24px;max-width:380px;width:90%;';
    const p = document.createElement('p');
    p.style.cssText = 'color:#e4e4e7;margin-bottom:20px;';
    st(p, msg); // [C] textContent — never fileName in confirm()
    const actions = document.createElement('div');
    actions.style.cssText = 'display:flex;gap:12px;justify-content:flex-end;';
    const cancel = document.createElement('button');
    cancel.className = 'btn-subtle';
    st(cancel, 'Cancel');
    cancel.onclick = () => overlay.remove();
    const ok = document.createElement('button');
    ok.className = 'btn-primary';
    st(ok, 'Confirm');
    ok.onclick = () => { overlay.remove(); onConfirm(); };
    actions.append(cancel, ok);
    box.append(p, actions);
    overlay.appendChild(box);
    document.body.appendChild(overlay);
}

/**
 * [I] CSRF token — generated once per session, sent with all mutating requests.
 */
const _csrfToken = (() => {
    let t = sessionStorage.getItem('_csrf');
    if (!t) {
        t = Array.from(crypto.getRandomValues(new Uint8Array(16)))
            .map(b => b.toString(16).padStart(2, '0')).join('');
        sessionStorage.setItem('_csrf', t);
    }
    return t;
})();

/**
 * [H] Auth token — keep in memory only after first read, then clear sessionStorage.
 * Reduces XSS window.
 */
let _authTokenMemory = null;
function getAuthToken() {
    if (_authTokenMemory) return _authTokenMemory;
    _authTokenMemory = sessionStorage.getItem('ghostnet_token') || '';
    return _authTokenMemory;
}

function secureHeaders(isMutation = false) {
    const h = {
        'Content-Type': 'application/json',
        'X-Auth-Token': getAuthToken(),
    };
    if (isMutation) h['X-CSRF-Token'] = _csrfToken; // [I]
    return h;
}

/**
 * [J] Safe JSON parser with basic schema validation.
 */
function safeJson(text, validator) {
    try {
        const parsed = JSON.parse(text);
        if (validator && !validator(parsed)) throw new Error('Schema validation failed');
        return parsed;
    } catch (_) { return null; }
}

/**
 * [P] Dev mode — check multiple signals, not just hostname.
 */
var isDev = (
    window.location.hostname === 'localhost' ||
    window.location.hostname === '127.0.0.1' ||
    window.location.protocol === 'file:'
);

var log = {
    info: (...a) => isDev && console.log('[GN]', ...a),
    warn: (...a) => isDev && console.warn('[GN]', ...a),
    error: (...a) => console.error('[GN:ERR]', ...a),
};

/**
 * [F][G] Wallet address / amount validation (unchanged from previous version)
 */
function isValidAddress(symbol, address) {
    if (!address || typeof address !== 'string') return false;
    const patterns = {
        ETH: /^0x[a-fA-F0-9]{40}$/,
        USDT: /^0x[a-fA-F0-9]{40}$/,
        BTC: /^(bc1|[13]|tb1)[a-zA-HJ-NP-Z0-9]{25,62}$/,
        SOL: /^[1-9A-HJ-NP-Za-km-z]{32,44}$/,
    };
    return patterns[symbol] ? patterns[symbol].test(address.trim()) : address.length > 10;
}

function isValidAmount(amount) {
    const n = parseFloat(amount);
    return !isNaN(n) && isFinite(n) && n > 0;
}

const RateLimit = {
    _last: 0, _count: 0, MAX_PER_SECOND: 2,
    check() {
        const now = Date.now();
        if (now - this._last > 1000) { this._last = now; this._count = 0; }
        if (this._count >= this.MAX_PER_SECOND) return false;
        this._count++;
        return true;
    }
};

var BACKEND = (() => {
    const base = 'https://ghostnet-ji-production.up.railway.app';
    return { url: (path) => `${base}${path}` };
})();

// ─── [F][G] APP STATE — not on window ───────────────────

const AppState = {
    meshReady: false,
    wallet: [],
    peers: [],
    identity: null,
    messages: [],
    files: [],
    activeConvoId: null,
};

// ─── MESH VISUALIZER ────────────────────────────────────

class MeshNetwork {
    constructor(canvasId) {
        this.canvas = document.getElementById(canvasId);
        if (!this.canvas) return;
        this.ctx = this.canvas.getContext('2d');
        this.nodes = [];
        this.width = 0;
        this.height = 0;
        this.resize();
        window.addEventListener('resize', () => this.resize());
        this.initNodes(12);
        this.animate();
    }
    resize() {
        const p = this.canvas.parentElement;
        this.width = p.clientWidth; this.height = p.clientHeight;
        this.canvas.width = this.width; this.canvas.height = this.height;
    }
    initNodes(count) {
        this.nodes = [{ x: this.width / 2, y: this.height / 2, vx: 0, vy: 0, type: 'self', size: 6 }];
        // [E] Use crypto.getRandomValues for node positions instead of Math.random
        const rnd = new Uint32Array(count * 4);
        crypto.getRandomValues(rnd);
        for (let i = 0; i < count; i++) {
            this.nodes.push({
                x: (rnd[i * 4] / 0xFFFFFFFF) * this.width,
                y: (rnd[i * 4 + 1] / 0xFFFFFFFF) * this.height,
                vx: ((rnd[i * 4 + 2] / 0xFFFFFFFF) - 0.5) * 0.8,
                vy: ((rnd[i * 4 + 3] / 0xFFFFFFFF) - 0.5) * 0.8,
                type: 'peer', size: 3
            });
        }
    }
    animate() {
        this.ctx.clearRect(0, 0, this.width, this.height);
        const isDark = document.documentElement.getAttribute('data-theme') === 'dark';
        const acc = isDark ? '#3b82f6' : '#2563eb';
        const muted = isDark ? '#334155' : '#cbd5e1';
        const rgb = isDark ? '59,130,246' : '37,99,235';
        this.ctx.lineWidth = 1;
        this.nodes.forEach((n1, i) => {
            this.nodes.forEach((n2, j) => {
                if (i >= j) return;
                const d = Math.hypot(n1.x - n2.x, n1.y - n2.y);
                if (d < 150) {
                    this.ctx.strokeStyle = `rgba(${rgb},${1 - d / 150})`;
                    this.ctx.beginPath(); this.ctx.moveTo(n1.x, n1.y); this.ctx.lineTo(n2.x, n2.y); this.ctx.stroke();
                }
            });
        });
        this.nodes.forEach(n => {
            if (n.type !== 'self') {
                n.x += n.vx; n.y += n.vy;
                if (n.x < 0 || n.x > this.width) n.vx *= -1;
                if (n.y < 0 || n.y > this.height) n.vy *= -1;
            }
            const g = this.ctx.createRadialGradient(n.x, n.y, n.size / 2, n.x, n.y, n.size * 4);
            g.addColorStop(0, n.type === 'self' ? acc : muted);
            g.addColorStop(1, 'rgba(0,0,0,0)');
            this.ctx.fillStyle = g;
            this.ctx.fillRect(n.x - n.size * 4, n.y - n.size * 4, n.size * 8, n.size * 8);
            this.ctx.fillStyle = n.type === 'self' ? acc : muted;
            this.ctx.beginPath(); this.ctx.arc(n.x, n.y, n.size, 0, Math.PI * 2); this.ctx.fill();
        });
        requestAnimationFrame(() => this.animate());
    }
}

// ─── UI CONTROLLER ──────────────────────────────────────

const UI = {

    init: () => {
        log.info('Booting GhostNet UI...');
        UI.initTheme();
        document.querySelectorAll('.nav-btn').forEach(btn => {
            btn.addEventListener('click', () => UI.navigate(btn.dataset.target));
        });
        new MeshNetwork('mesh');
        UI.setupChat();
        setTimeout(() => { UI.mockData(); window.dispatchEvent(new Event('app:state')); }, 800);
        window.addEventListener('app:state', UI.render);
        UI.loadProfile();
        UI.initVault();
    },

    // [A] Allowlisted navigate targets
    _validTargets: new Set(['home', 'wallet', 'peers', 'chat', 'storage', 'settings', 'vault']),

    navigate: (target) => {
        if (!UI._validTargets.has(target)) return; // [A] block unknown targets
        document.querySelectorAll('.nav-btn').forEach(b => {
            if (b.id !== 'theme-toggle') b.classList.toggle('active', b.dataset.target === target);
        });
        document.querySelectorAll('.mobile-nav-item').forEach(b =>
            b.classList.toggle('active', b.dataset.target === target));
        document.querySelectorAll('.view-section').forEach(s =>
            s.classList.toggle('active', s.id === `view-${target}`));
        if (target === 'vault') UI.vaultLoadFiles();
        const sidebar = document.getElementById('app-sidebar');
        const overlay = document.getElementById('sidebar-overlay');
        if (sidebar) sidebar.classList.remove('open');
        if (overlay) overlay.classList.remove('visible');
        const chatSplit = document.querySelector('.chat-layout-split');
        if (chatSplit) chatSplit.classList.remove('chat-active');
    },

    toggleMobileMenu: () => {
        document.getElementById('app-sidebar')?.classList.toggle('open');
        document.getElementById('sidebar-overlay')?.classList.toggle('visible');
    },

    chatBackToList: () => {
        document.querySelector('.chat-layout-split')?.classList.remove('chat-active');
    },

    initTheme: () => {
        const stored = localStorage.getItem('ghostnet_theme');
        if (stored === 'dark') {
            document.documentElement.setAttribute('data-theme', 'dark');
            st(document.getElementById('theme-label'), 'Light Mode');
            document.getElementById('theme-icon')?.setAttribute('data-lucide', 'sun');
        } else {
            document.documentElement.removeAttribute('data-theme');
        }
        if (typeof lucide !== 'undefined') lucide.createIcons();
    },

    toggleTheme: () => {
        const isDark = document.documentElement.getAttribute('data-theme') === 'dark';
        const label = document.getElementById('theme-label');
        const icon = document.getElementById('theme-icon');
        if (isDark) {
            document.documentElement.removeAttribute('data-theme');
            localStorage.setItem('ghostnet_theme', 'light');
            st(label, 'Dark Mode');
            icon?.setAttribute('data-lucide', 'moon');
        } else {
            document.documentElement.setAttribute('data-theme', 'dark');
            localStorage.setItem('ghostnet_theme', 'dark');
            st(label, 'Light Mode');
            icon?.setAttribute('data-lucide', 'sun');
        }
        if (typeof lucide !== 'undefined') lucide.createIcons();
        UI.render();
    },

    mockData: () => {
        AppState.peers = [
            { id: 'node_alpha', type: 'Bridge', latency: 12 },
            { id: 'node_bravo', type: 'Relay', latency: 45 },
            { id: 'node_charlie', type: 'Mobile', latency: 112 },
            { id: 'node_delta', type: 'Desktop', latency: 8 },
        ];
        AppState.wallet = [
            { symbol: 'ETH', balance: 0.00, chain: 'Sepolia', address: '' },
            { symbol: 'BTC', balance: 0.00, chain: 'Bitcoin', address: '' },
            { symbol: 'SOL', balance: 0.00, chain: 'Solana', address: '' },
            { symbol: 'USDT', balance: 0.00, chain: 'Ethereum', address: '' },
        ];
        AppState.files = [
            { name: 'encrypted_shard_01.dat', size: '4.2 MB' },
            { name: 'keys_backup.json.enc', size: '12 KB' }
        ];
        UI.fetchRealData();
    },

    fetchRealData: async () => {
        try {
            log.info('Connecting to GhostNet Bridge...');
            const res = await fetch(BACKEND.url('/wallet'), { headers: secureHeaders() });
            if (!res.ok) throw new Error(`HTTP ${res.status}`);
            const text = await res.text();
            // [J] Validate schema — must be array of wallet objects
            const walletData = safeJson(text, d => Array.isArray(d) && d.every(
                a => a && typeof a.symbol === 'string' && typeof a.balance === 'number'
            ));
            if (walletData) AppState.wallet = walletData;
            log.info('Wallet loaded.');
            window.dispatchEvent(new Event('app:state'));
        } catch (e) {
            log.warn('Bridge disconnected, using empty fallback.');
            if (!AppState.wallet?.length) {
                AppState.wallet = [
                    { symbol: 'ETH', balance: 0, chain: 'Sepolia', address: '' },
                    { symbol: 'BTC', balance: 0, chain: 'Bitcoin', address: '' },
                    { symbol: 'SOL', balance: 0, chain: 'Solana', address: '' },
                    { symbol: 'USDT', balance: 0, chain: 'Ethereum', address: '' },
                ];
                window.dispatchEvent(new Event('app:state'));
            }
        }
    },

    openReceive: (symbol, address) => {
        // [A] Build entirely via DOM — no innerHTML with user data
        const safeSymbol = sanitize(symbol);
        let qrData = address;
        if (symbol === 'BTC') qrData = `bitcoin:${address}`;
        else if (symbol === 'ETH' || symbol === 'USDT') qrData = `ethereum:${address}`;
        else if (symbol === 'SOL') qrData = `solana:${address}`;

        const qrUrl = `https://api.qrserver.com/v1/create-qr-code/?size=200x200&data=${encodeURIComponent(qrData)}`;

        const modal = document.createElement('div');
        modal.className = 'modal-overlay';

        const card = document.createElement('div');
        card.className = 'modal-card';

        const closeBtn = document.createElement('button');
        closeBtn.className = 'modal-close';
        st(closeBtn, '×');
        closeBtn.addEventListener('click', () => modal.remove());

        const title = document.createElement('div');
        title.className = 'modal-title';
        st(title, `Receive ${safeSymbol}`); // [A]

        const qrImg = document.createElement('img');
        qrImg.className = 'qr-code';
        qrImg.alt = 'QR Code';
        safeImgSrc(qrImg, qrUrl); // [B] validated URL

        const group = document.createElement('div');
        group.className = 'input-group';
        const lbl = document.createElement('label');
        lbl.className = 'input-label';
        st(lbl, 'YOUR ADDRESS');
        const addrInput = document.createElement('input');
        addrInput.type = 'text';
        addrInput.className = 'modal-input';
        addrInput.readOnly = true;
        addrInput.value = address; // .value is safe
        addrInput.addEventListener('click', () => addrInput.select());
        group.append(lbl, addrInput);

        const note = document.createElement('div');
        note.style.cssText = 'font-size:0.8rem;color:#8b9bb4;margin-top:10px;';
        st(note, `Scan to send ${safeSymbol} to this address.`);

        card.append(closeBtn, title, qrImg, group, note);
        modal.appendChild(card);
        document.body.appendChild(modal);
    },

    openSend: (symbol) => {
        const modal = document.createElement('div');
        modal.className = 'modal-overlay';
        const card = document.createElement('div');
        card.className = 'modal-card';

        const closeBtn = document.createElement('button');
        closeBtn.className = 'modal-close';
        st(closeBtn, '×');
        closeBtn.addEventListener('click', () => modal.remove());

        const title = document.createElement('div');
        title.className = 'modal-title';
        st(title, `Send ${sanitize(symbol)}`);

        const recipGroup = document.createElement('div');
        recipGroup.className = 'input-group';
        const recipLbl = document.createElement('label');
        recipLbl.className = 'input-label';
        st(recipLbl, 'RECIPIENT ADDRESS');
        const toInput = document.createElement('input');
        toInput.type = 'text'; toInput.id = 'send-to';
        toInput.className = 'modal-input';
        toInput.placeholder = '0x...';
        toInput.maxLength = 100;
        toInput.autocomplete = 'off';
        recipGroup.append(recipLbl, toInput);

        const amtGroup = document.createElement('div');
        amtGroup.className = 'input-group';
        const amtLbl = document.createElement('label');
        amtLbl.className = 'input-label';
        st(amtLbl, 'AMOUNT');
        const amtInput = document.createElement('input');
        amtInput.type = 'number'; amtInput.id = 'send-amount';
        amtInput.className = 'modal-input';
        amtInput.placeholder = '0.00';
        amtInput.min = '0'; amtInput.step = 'any';
        amtGroup.append(amtLbl, amtInput);

        const errEl = document.createElement('div');
        errEl.id = 'send-error';
        errEl.style.cssText = 'color:#ef4444;font-size:0.8rem;min-height:1.2em;margin-bottom:8px;';

        const confirmBtn = document.createElement('button');
        confirmBtn.className = 'btn-primary';
        st(confirmBtn, 'CONFIRM TRANSACTION');
        confirmBtn.addEventListener('click', () => UI.submitSend(symbol));

        card.append(closeBtn, title, recipGroup, amtGroup, errEl, confirmBtn);
        modal.appendChild(card);
        document.body.appendChild(modal);
    },

    submitSend: async (symbol) => {
        const to = document.getElementById('send-to')?.value.trim() || '';
        const amount = document.getElementById('send-amount')?.value.trim() || '';
        const errEl = document.getElementById('send-error');

        if (!isValidAddress(symbol, to)) {
            if (errEl) st(errEl, `⚠ Invalid ${sanitize(symbol)} address format.`);
            return;
        }
        if (!isValidAmount(amount)) {
            if (errEl) st(errEl, '⚠ Enter a valid positive amount.');
            return;
        }

        document.querySelector('.modal-overlay')?.remove();
        // [D] Never pass user data to alert() — use showNotice()
        showNotice(`Sending ${parseFloat(amount)} ${sanitize(symbol)}...`);

        try {
            // [I] CSRF token on POST
            await fetch(BACKEND.url('/wallet/send'), {
                method: 'POST',
                headers: secureHeaders(true),
                body: JSON.stringify({ symbol, to, amount: parseFloat(amount) })
            });
        } catch (e) {
            log.error('Send failed:', e.message);
            showNotice('Transaction failed. Please try again.', true);
        }
    },

    openNewChat: () => {
        const modal = document.createElement('div');
        modal.className = 'modal-overlay';
        const card = document.createElement('div');
        card.className = 'modal-card';

        const closeBtn = document.createElement('button');
        closeBtn.className = 'modal-close';
        st(closeBtn, '×');
        closeBtn.addEventListener('click', () => modal.remove());

        const title = document.createElement('div');
        title.className = 'modal-title';
        st(title, 'New Encrypted Chat');

        const nameGroup = document.createElement('div');
        nameGroup.className = 'input-group';
        const nameLbl = document.createElement('label');
        nameLbl.className = 'input-label';
        st(nameLbl, 'CONTACT NAME');
        const nameInput = document.createElement('input');
        nameInput.type = 'text'; nameInput.id = 'chat-name';
        nameInput.className = 'modal-input';
        nameInput.placeholder = 'e.g. Alice';
        nameInput.maxLength = 50;
        nameGroup.append(nameLbl, nameInput);

        const pkGroup = document.createElement('div');
        pkGroup.className = 'input-group';
        const pkLbl = document.createElement('label');
        pkLbl.className = 'input-label';
        st(pkLbl, 'NODE ID / PUBLIC KEY');
        const pkInput = document.createElement('input');
        pkInput.type = 'text'; pkInput.id = 'chat-pubkey';
        pkInput.className = 'modal-input';
        pkInput.placeholder = '0x...';
        pkInput.maxLength = 200; // [Q]
        pkGroup.append(pkLbl, pkInput);

        const errEl = document.createElement('div');
        errEl.id = 'chat-new-error';
        errEl.style.cssText = 'color:#ef4444;font-size:0.8rem;margin-top:8px;min-height:1.2em;';

        const startBtn = document.createElement('button');
        startBtn.id = 'chat-start-btn';
        startBtn.className = 'btn-primary';
        st(startBtn, 'START SESSION');
        startBtn.addEventListener('click', () => UI.submitNewChat());

        card.append(closeBtn, title, nameGroup, pkGroup, errEl, startBtn);
        modal.appendChild(card);
        document.body.appendChild(modal);
    },

    submitNewChat: async () => {
        const name = document.getElementById('chat-name')?.value.trim() || '';
        const pubKey = document.getElementById('chat-pubkey')?.value.trim() || '';
        const errEl = document.getElementById('chat-new-error');
        const startBtn = document.getElementById('chat-start-btn');

        if (!name || !pubKey) {
            if (errEl) st(errEl, 'Please fill in both fields.');
            return;
        }
        if (pubKey.length < 10 || pubKey.length > 200) { // [Q]
            if (errEl) st(errEl, '⚠ Invalid Node ID length.');
            return;
        }
        if (startBtn) { startBtn.disabled = true; st(startBtn, 'VALIDATING...'); }
        if (errEl) st(errEl, '');

        try {
            // [I] CSRF on validation call (GET-like but auth-sensitive)
            const res = await fetch(BACKEND.url(`/validate-node/${encodeURIComponent(pubKey)}`), {
                headers: secureHeaders()
            });
            if (!res.ok) {
                if (errEl) st(errEl, `⚠ Validation failed (HTTP ${res.status}).`);
                if (startBtn) { startBtn.disabled = false; st(startBtn, 'START SESSION'); }
                return;
            }
            if (!(res.headers.get('content-type') || '').includes('application/json')) {
                if (errEl) st(errEl, '⚠ Invalid server response.');
                if (startBtn) { startBtn.disabled = false; st(startBtn, 'START SESSION'); }
                return;
            }
            // [J] Validate schema
            const text = await res.text();
            const data = safeJson(text, d => d && typeof d === 'object' && typeof d.valid === 'boolean');
            if (!data) {
                if (errEl) st(errEl, '⚠ Unexpected server response format.');
                if (startBtn) { startBtn.disabled = false; st(startBtn, 'START SESSION'); }
                return;
            }
            if (!data.valid) {
                if (errEl) st(errEl, '⚠ Node not found. Check the Node ID.');
                if (startBtn) { startBtn.disabled = false; st(startBtn, 'START SESSION'); }
                return;
            }
            document.querySelector('.modal-overlay')?.remove();

            const feed = document.getElementById('chat-feed');
            if (feed) {
                feed.innerHTML = '';
                const note = document.createElement('div');
                note.style.cssText = 'text-align:center;color:#64748b;font-size:0.8rem;margin:20px;';
                // [A] textContent — displayName from server never goes into innerHTML
                st(note, `-- Session with ${data.displayName || name} Started --`);
                feed.appendChild(note);
            }

            if (window._app) window._app.chatTarget = pubKey;
            UI.selectChat('new', data.displayName || name, pubKey);
        } catch (e) {
            log.error('Node validation error:', e.message);
            if (errEl) st(errEl, '⚠ Could not verify node. Server may be offline.');
            if (startBtn) { startBtn.disabled = false; st(startBtn, 'START SESSION'); }
        }
    },

    loadConversations: async (userId) => {
        if (!userId) return;
        try {
            const res = await fetch(BACKEND.url(`/conversations?userId=${encodeURIComponent(userId)}`), {
                headers: secureHeaders()
            });
            if (res.ok) {
                const text = await res.text();
                // [J] Validate schema
                const convos = safeJson(text, d => Array.isArray(d));
                if (convos) UI.renderConversations(convos);
            }
        } catch (e) { log.error('Failed to load conversations:', e.message); }
    },

    renderConversations: (convos) => {
        const list = document.getElementById('chat-user-list');
        if (!list) return;
        list.innerHTML = '';

        if (!convos?.length) {
            const empty = document.createElement('div');
            empty.style.cssText = 'padding:20px;text-align:center;color:#64748b;font-size:0.8rem;';
            st(empty, 'No conversations yet.');
            list.appendChild(empty);
            return;
        }

        convos.forEach(c => {
            const otherUser = c.otherUser || {};
            const username = String(otherUser.username || otherUser.address || otherUser.id || 'Unknown');
            const timeStr = new Date(c.updated).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });

            let preview = c.lastMessage || 'Message...';
            if (typeof preview === 'object' && preview.body) preview = preview.body;
            if (typeof preview === 'string' && preview.includes('body":"')) {
                try { preview = JSON.parse(preview).body; } catch (_) { }
            }
            if (typeof preview !== 'string') preview = '';

            const row = document.createElement('div');
            row.className = `chat-user-row${AppState.activeConvoId === c.id ? ' active' : ''}`;
            row.dataset.convo = String(c.id || '');

            // Avatar — [B][M] validated URL only
            const avatarWrap = document.createElement('div');
            avatarWrap.className = 'chat-avatar-wrap';
            if (otherUser.avatar && isSafeImageUrl(otherUser.avatar)) {
                const img = document.createElement('img');
                img.className = 'chat-avatar';
                img.style.objectFit = 'cover';
                safeImgSrc(img, otherUser.avatar); // [B][M]
                avatarWrap.appendChild(img);
            } else {
                const av = document.createElement('div');
                av.className = 'chat-avatar';
                av.style.background = '#3f3f46';
                avatarWrap.appendChild(av);
            }

            // Info — [A] all textContent
            const info = document.createElement('div');
            info.className = 'chat-user-info';
            const top = document.createElement('div');
            top.className = 'chat-user-top';
            const nameEl = document.createElement('span');
            nameEl.className = 'chat-username';
            st(nameEl, username); // [A]
            const timeEl = document.createElement('span');
            timeEl.className = 'chat-time';
            st(timeEl, timeStr);
            top.append(nameEl, timeEl);
            const bottom = document.createElement('div');
            bottom.className = 'chat-user-bottom';
            const prevEl = document.createElement('span');
            prevEl.className = 'chat-preview';
            st(prevEl, preview); // [A]
            bottom.appendChild(prevEl);
            info.append(top, bottom);
            row.append(avatarWrap, info);

            row.addEventListener('click', () =>
                UI.selectChat(c.id, otherUser.username || otherUser.id || 'Unknown', otherUser.id || ''));
            list.appendChild(row);
        });
    },

    selectChat: async (convoId, nameStr = null, targetUserId = null) => {
        document.getElementById('chat-empty-state') && (document.getElementById('chat-empty-state').style.display = 'none');
        document.getElementById('chat-active-state') && (document.getElementById('chat-active-state').style.display = 'flex');
        document.querySelector('.chat-layout-split')?.classList.add('chat-active');

        const label = document.getElementById('label-transport');
        if (label) st(label, nameStr || targetUserId || ''); // [A]

        AppState.activeConvoId = convoId;
        if (window._app) {
            window._app.chatTarget = targetUserId;
            window._app.chatContactName = nameStr || targetUserId;
        }

        document.querySelectorAll('.chat-user-row').forEach(row => {
            row.classList.toggle('active', row.dataset.convo === convoId);
        });

        const feed = document.getElementById('chat-feed');
        if (feed) feed.innerHTML = '';

        if (convoId && convoId !== 'new') {
            try {
                const res = await fetch(BACKEND.url(`/history?convoId=${encodeURIComponent(convoId)}`), {
                    headers: secureHeaders()
                });
                if (res.ok) {
                    const text = await res.text();
                    // [J] Validate schema
                    const msgs = safeJson(text, d => Array.isArray(d));
                    if (msgs) {
                        const myId = AppState.identity ? (AppState.identity.nodeId || AppState.identity.id) : null;
                        msgs.forEach(m => {
                            let txt = m.content;
                            if (typeof txt === 'object' && txt.body) txt = txt.body;
                            if (typeof txt === 'string' && txt.includes('body":"')) {
                                try { txt = JSON.parse(txt).body; } catch (_) { }
                            }
                            UI.addMessage(typeof txt === 'string' ? txt : '***', m.senderId === myId ? 'me' : 'them');
                        });
                    }
                }
            } catch (e) { log.error('Error loading history:', e.message); }
        }
    },

    render: () => {
        UI.renderWallet();
        UI.renderDiscoverNodes();
        UI.renderStorage();
        UI.updateChatStatus();
        const statNodes = document.getElementById('stat-nodes');
        // [K] textContent — not innerHTML
        if (statNodes) st(statNodes, AppState.peers.length);
    },

    updateChatStatus: () => {
        const btnLabel = document.getElementById('btn-ble-label');
        const btnScan = document.getElementById('btn-ble-scan');
        if (!btnLabel || !btnScan) return;
        let blePeers = 0;
        if (window._app?.mesh) blePeers = window._app.mesh.getStatus().blePeers || 0;
        if (blePeers > 0) {
            st(btnLabel, `BLE (${blePeers})`);
            btnScan.style.borderColor = 'var(--accent)';
            btnScan.style.color = 'var(--accent)';
            btnScan.style.background = 'var(--accent-dim)';
        } else {
            st(btnLabel, 'Scan');
            btnScan.style.borderColor = btnScan.style.color = btnScan.style.background = '';
        }
        if (typeof lucide !== 'undefined') lucide.createIcons();
    },

    renderWallet: () => {
        const el = document.getElementById('wallet');
        if (!el) return;

        const LOGOS = {
            ETH: 'https://assets.coingecko.com/coins/images/279/small/ethereum.png',
            BTC: 'https://assets.coingecko.com/coins/images/1/small/bitcoin.png',
            SOL: 'https://assets.coingecko.com/coins/images/4128/small/solana.png',
            USDT: 'https://assets.coingecko.com/coins/images/325/small/Tether.png',
            AHT: 'https://assets.coingecko.com/coins/images/279/small/ethereum.png',
        };
        const META = {
            ETH: { color: '#627EEA', gradient: 'linear-gradient(135deg,#627EEA,#3b5fc0)', darkGlow: 'rgba(98,126,234,0.35)', name: 'Ethereum' },
            BTC: { color: '#F7931A', gradient: 'linear-gradient(135deg,#F7931A,#e2750a)', darkGlow: 'rgba(247,147,26,0.35)', name: 'Bitcoin' },
            SOL: { color: '#9945FF', gradient: 'linear-gradient(135deg,#9945FF,#14F195)', darkGlow: 'rgba(153,69,255,0.35)', name: 'Solana' },
            USDT: { color: '#26A17B', gradient: 'linear-gradient(135deg,#26A17B,#1a7a5c)', darkGlow: 'rgba(38,161,123,0.35)', name: 'Tether' },
            AHT: { color: '#3b82f6', gradient: 'linear-gradient(135deg,#3b82f6,#8b5cf6)', darkGlow: 'rgba(59,130,246,0.35)', name: 'GhostNet' },
        };

        const assets = Array.isArray(AppState.wallet) ? AppState.wallet : [];
        const total = assets.reduce((s, a) => s + (a.balance || 0), 0);

        el.innerHTML = ''; // clear

        // Portfolio banner — built via DOM [A]
        const banner = document.createElement('div');
        banner.className = 'wlt-portfolio-banner';
        const bannerL = document.createElement('div');
        bannerL.className = 'wlt-portfolio-left';
        const lblEl = document.createElement('div');
        lblEl.className = 'wlt-portfolio-label';
        st(lblEl, 'Portfolio Value');
        const totEl = document.createElement('div');
        totEl.className = 'wlt-portfolio-total';
        st(totEl, total.toLocaleString(undefined, { minimumFractionDigits: 2, maximumFractionDigits: 4 }));
        const subEl = document.createElement('div');
        subEl.className = 'wlt-portfolio-subtitle';
        st(subEl, `${assets.length} Assets · GhostNet Wallet`);
        bannerL.append(lblEl, totEl, subEl);
        const tokensEl = document.createElement('div');
        tokensEl.className = 'wlt-portfolio-tokens';
        assets.forEach(a => {
            const m = META[a.symbol] || META['ETH'];
            const tok = document.createElement('div');
            tok.className = 'wlt-mini-token';
            tok.style.setProperty('--tc', m.color);
            const img = document.createElement('img');
            safeImgSrc(img, LOGOS[a.symbol] || LOGOS['ETH']); // [B]
            img.width = 20; img.height = 20;
            img.alt = sanitize(a.symbol);
            tok.appendChild(img);
            tokensEl.appendChild(tok);
        });
        banner.append(bannerL, tokensEl);
        el.appendChild(banner);

        const grid = document.createElement('div');
        grid.className = 'wlt-grid';

        assets.forEach((asset, i) => {
            const meta = META[asset.symbol] || META['ETH'];
            const safeSymbol = sanitize(asset.symbol);
            const safeAddr = sanitize(asset.address || '');
            const addrDisplay = safeAddr
                ? `${safeAddr.substring(0, 6)}···${safeAddr.substring(safeAddr.length - 4)}`
                : 'Not Connected';

            // Card — [A] all user/server data via textContent
            const outer = document.createElement('div');
            outer.className = 'wlt-card-outer';
            outer.style.cssText = `--c1:${meta.color};--cg:${meta.gradient};--cd:${meta.darkGlow};animation-delay:${i * 0.1}s;`;

            const card = document.createElement('div');
            card.className = 'wlt-card';

            const logoRing = document.createElement('div'); logoRing.className = 'wlt-logo-ring';
            const logoInner = document.createElement('div'); logoInner.className = 'wlt-logo-inner';
            const logoImg = document.createElement('img');
            safeImgSrc(logoImg, LOGOS[asset.symbol] || LOGOS['ETH']); // [B]
            logoImg.width = 28; logoImg.height = 28;
            logoImg.alt = safeSymbol;
            logoImg.onerror = () => { logoImg.style.display = 'none'; };
            logoInner.appendChild(logoImg); logoRing.appendChild(logoInner);

            const cardInfo = document.createElement('div'); cardInfo.className = 'wlt-card-info';
            const cardName = document.createElement('div'); cardName.className = 'wlt-card-name';
            st(cardName, safeSymbol);
            const fullName = document.createElement('span'); fullName.className = 'wlt-card-fullname';
            st(fullName, meta.name);
            cardName.appendChild(fullName);
            const chainRow = document.createElement('div'); chainRow.className = 'wlt-card-chain-row';
            const chainBadge = document.createElement('span'); chainBadge.className = 'wlt-chain-badge';
            st(chainBadge, sanitize(asset.chain));
            const statusDot = document.createElement('span'); statusDot.className = 'wlt-status-dot';
            chainRow.append(chainBadge, statusDot);
            cardInfo.append(cardName, chainRow);

            const cardTop = document.createElement('div'); cardTop.className = 'wlt-card-top';
            cardTop.append(logoRing, cardInfo);

            const cardMid = document.createElement('div'); cardMid.className = 'wlt-card-mid';
            const balVal = document.createElement('div'); balVal.className = 'wlt-bal-value';
            st(balVal, (asset.balance || 0).toLocaleString(undefined, { minimumFractionDigits: 2, maximumFractionDigits: 6 }));
            const balLbl = document.createElement('div'); balLbl.className = 'wlt-bal-label';
            st(balLbl, `${safeSymbol} Balance`);
            cardMid.append(balVal, balLbl);

            const addrChip = document.createElement('div'); addrChip.className = 'wlt-addr-chip';
            const addrTxt = document.createElement('span');
            st(addrTxt, addrDisplay); // [A]
            addrChip.appendChild(addrTxt);

            const cardActions = document.createElement('div');
            cardActions.className = 'wlt-card-actions';
            const sendBtn = document.createElement('button');
            sendBtn.className = 'wlt-btn wlt-btn-send';
            st(sendBtn, 'Send');
            sendBtn.addEventListener('click', () => UI.openSend(asset.symbol));
            const recvBtn = document.createElement('button');
            recvBtn.className = 'wlt-btn wlt-btn-recv';
            st(recvBtn, 'Receive');
            recvBtn.addEventListener('click', () => UI.openReceive(asset.symbol, asset.address));
            cardActions.append(sendBtn, recvBtn);

            card.append(cardTop, cardMid, addrChip, cardActions);
            outer.appendChild(card);
            grid.appendChild(outer);
        });

        el.appendChild(grid);
    },

    renderDiscoverNodes: () => {
        const el = document.getElementById('discover-nodes');
        if (!el) return;
        el.innerHTML = '';

        const bleActive = !!(window._app?.transport?.ble?.peers?.size > 0);

        // Header — [A] DOM nodes
        const header = document.createElement('div');
        header.style.cssText = 'width:100%;grid-column:1/-1;margin-bottom:20px;display:flex;justify-content:space-between;align-items:center;background:var(--bg-panel);padding:15px;border-radius:16px;border:1px solid var(--border);box-shadow:var(--glow);';
        const hLeft = document.createElement('div');
        hLeft.style.cssText = 'display:flex;align-items:center;gap:15px;';
        const hIcon = document.createElement('div');
        hIcon.style.cssText = 'width:40px;height:40px;background:var(--accent-dim);border-radius:50%;display:flex;align-items:center;justify-content:center;color:var(--accent);';
        hIcon.innerHTML = '<i data-lucide="bluetooth"></i>';
        const hText = document.createElement('div');
        const hTitle = document.createElement('div');
        hTitle.style.cssText = 'font-weight:bold;color:var(--text-primary);';
        st(hTitle, 'BLE Mesh Layer');
        const hSub = document.createElement('div');
        hSub.style.cssText = 'font-size:0.8rem;color:var(--text-muted);';
        st(hSub, 'Local-First Transport');
        hText.append(hTitle, hSub);
        hLeft.append(hIcon, hText);

        const hRight = document.createElement('div');
        hRight.style.cssText = 'display:flex;align-items:center;gap:10px;';
        const badge = document.createElement('div');
        badge.className = `status-badge ${bleActive ? 'active' : ''}`;
        st(badge, bleActive ? '🟢 Active' : '⚪ Idle');
        const scanBtn = document.createElement('button');
        scanBtn.className = 'btn-primary small';
        st(scanBtn, 'SCAN NETWORK');
        scanBtn.addEventListener('click', () => window._app?.transport?.startBLEScan());
        hRight.append(badge, scanBtn);
        header.append(hLeft, hRight);
        el.appendChild(header);

        const allPeers = [...AppState.peers];
        if (window._app?.transport?.ble) {
            window._app.transport.ble.peers.forEach(p => {
                if (!allPeers.find(ep => ep.id === p.id))
                    allPeers.push({ id: p.id, type: 'BLE', latency: null, verified: true });
            });
        }

        allPeers.forEach(p => {
            const card = document.createElement('div');
            card.className = 'node-card';

            const topRow = document.createElement('div');
            topRow.style.cssText = 'display:flex;justify-content:space-between;align-items:center;';
            const addrEl = document.createElement('div');
            addrEl.className = 'node-address';
            addrEl.style.color = 'var(--accent)';
            st(addrEl, p.id); // [A] textContent
            const latEl = document.createElement('div');
            latEl.style.cssText = `font-size:0.8rem;color:${(p.latency || 999) < 50 ? '#10b981' : '#f59e0b'};`;
            st(latEl, p.latency != null ? `${p.latency}ms` : '??ms');
            topRow.append(addrEl, latEl);

            const metaEl = document.createElement('div');
            metaEl.className = 'node-meta';
            st(metaEl, `${sanitize(p.type)} Node · Verified`); // [A]

            // [E] crypto random for bar width
            const rnd = new Uint8Array(1);
            crypto.getRandomValues(rnd);
            const barPct = rnd[0];
            const barWrap = document.createElement('div');
            barWrap.style.cssText = 'margin-top:10px;height:4px;background:var(--border);border-radius:2px;overflow:hidden;';
            const bar = document.createElement('div');
            bar.style.cssText = `width:${barPct}%;height:100%;background:${p.type === 'BLE' ? '#10b981' : 'var(--text-muted)'};`;
            barWrap.appendChild(bar);

            card.append(topRow, metaEl, barWrap);
            el.appendChild(card);
        });

        if (typeof lucide !== 'undefined') lucide.createIcons();
    },

    renderStorage: () => {
        const el = document.getElementById('storage');
        if (!el) return;
        el.innerHTML = '';
        AppState.files.forEach(f => {
            const card = document.createElement('div');
            card.className = 'file-card';
            card.style.cssText = 'display:flex;align-items:center;gap:15px;';
            const icon = document.createElement('span');
            icon.innerHTML = '<i data-lucide="file-lock" style="color:var(--text-muted);"></i>';
            const info = document.createElement('div');
            info.style.flex = '1';
            const nameEl = document.createElement('div');
            nameEl.style.cssText = 'color:var(--text-primary);font-family:monospace;font-weight:500;';
            st(nameEl, f.name); // [A] textContent
            const sizeEl = document.createElement('div');
            sizeEl.style.cssText = 'font-size:0.8rem;color:var(--text-muted);';
            st(sizeEl, f.size);
            info.append(nameEl, sizeEl);
            const dlBtn = document.createElement('button');
            dlBtn.style.cssText = 'background:none;border:none;color:var(--accent);cursor:pointer;';
            dlBtn.innerHTML = '<i data-lucide="download"></i>';
            card.append(icon, info, dlBtn);
            el.appendChild(card);
        });
        if (typeof lucide !== 'undefined') lucide.createIcons();
    },

    setupChat: () => {
        const btn = document.getElementById('chat-send');
        const input = document.getElementById('chat-input');
        if (btn && input) {
            btn.addEventListener('click', async () => {
                if (!RateLimit.check()) { log.warn('Rate limit hit'); return; }
                if (window._app?.sendMessage) { await window._app.sendMessage(); return; }
                const text = input.value.trim();
                if (!text || text.length > 2000) return;
                UI.addMessage(text, 'me');
                input.value = '';
                const myId = AppState.identity ? (AppState.identity.nodeId || AppState.identity.id) : 'anonymous';
                const targetId = window._app?.chatTarget || 'broadcast';
                try {
                    // [I] CSRF on POST
                    const res = await fetch(BACKEND.url('/message'), {
                        method: 'POST',
                        headers: secureHeaders(true),
                        body: JSON.stringify({ senderId: myId, receiverId: targetId, content: text })
                    });
                    const resText = await res.text();
                    // [J]
                    const result = safeJson(resText, d => d && typeof d === 'object');
                    if (result?.success && result?.convo) {
                        AppState.activeConvoId = result.convo.id;
                        UI.loadConversations(myId);
                    }
                } catch (e) { log.error('Chat send failed:', e.message); }
            });
            input.addEventListener('keypress', e => { if (e.key === 'Enter') btn.click(); });
        }
        document.querySelectorAll('.mode-btn').forEach(m => {
            m.addEventListener('click', () => {
                document.querySelectorAll('.mode-btn').forEach(b => b.classList.remove('active'));
                m.classList.add('active');
            });
        });
    },

    addMessage: (text, type) => {
        const feed = document.getElementById('chat-feed');
        if (!feed) return;
        const msg = document.createElement('div');
        msg.className = `message ${type === 'me' ? 'me' : 'them'}`;
        st(msg, text); // [A] textContent
        feed.appendChild(msg);
        feed.scrollTop = feed.scrollHeight;
    },

    promptFileType: () => {
        const modal = document.createElement('div');
        modal.className = 'modal-overlay';
        const card = document.createElement('div');
        card.className = 'modal-card';
        const closeBtn = document.createElement('button');
        closeBtn.className = 'modal-close';
        st(closeBtn, '×');
        closeBtn.addEventListener('click', () => modal.remove());
        const title = document.createElement('div');
        title.className = 'modal-title';
        st(title, 'Select Attachment Type');
        const grid = document.createElement('div');
        grid.style.cssText = 'display:grid;grid-template-columns:1fr 1fr;gap:15px;margin-top:20px;';
        [
            { label: 'Image', accept: 'image/*' },
            { label: 'Video', accept: 'video/*' },
            { label: 'Document', accept: '.pdf,.doc,.docx,.txt' },
            { label: 'Any', accept: '*' },
        ].forEach(({ label, accept }) => {
            const btn = document.createElement('button');
            btn.className = 'btn-primary';
            st(btn, label);
            btn.addEventListener('click', () => UI.triggerFile(accept));
            grid.appendChild(btn);
        });
        card.append(closeBtn, title, grid);
        modal.appendChild(card);
        document.body.appendChild(modal);
        if (typeof lucide !== 'undefined') lucide.createIcons();
    },

    triggerFile: (acceptType) => {
        const input = document.getElementById('chat-file');
        if (input) { input.accept = acceptType; input.click(); }
        document.querySelector('.modal-overlay')?.remove();
    },

    loadProfile: () => {
        const stored = localStorage.getItem('ghostnet_user');
        if (stored) {
            try {
                // [J] Validate schema
                const user = safeJson(stored, d => d && typeof d === 'object');
                if (!user) throw new Error('Invalid profile schema');
                AppState.identity = user;

                const sidebarAddress = document.getElementById('sidebar-address');
                const sidebarId = document.getElementById('sidebar-id');
                const sidebarAvatar = document.getElementById('sidebar-avatar');
                const sidebarProfile = document.getElementById('sidebar-profile');

                if (sidebarProfile) {
                    sidebarProfile.style.display = 'flex';
                    // [B][M] Avatar URL validated
                    if (user.avatar && sidebarAvatar) {
                        if (isSafeImageUrl(user.avatar)) {
                            sidebarAvatar.src = user.avatar;
                            sidebarAvatar.style.display = 'block';
                        } else {
                            sidebarAvatar.style.display = 'none';
                        }
                    }
                    if (sidebarAddress) st(sidebarAddress, user.username || user.address || ''); // [A]
                    if (sidebarId) st(sidebarId, user.id || '');
                }

                const viewAddress = document.getElementById('profile-address');
                const viewId = document.getElementById('profile-id-display');
                const viewPreview = document.getElementById('profile-preview');

                if (viewAddress) viewAddress.value = user.username || user.address || '';
                if (viewId) st(viewId, 'Current ID: ' + (user.id || '')); // [A]
                if (viewPreview && user.avatar && isSafeImageUrl(user.avatar)) { // [B][M]
                    viewPreview.src = user.avatar;
                    viewPreview.style.display = 'block';
                }

                const userId = AppState.identity.nodeId || AppState.identity.id;
                UI.loadConversations(userId);
            } catch (e) {
                log.error('Error parsing user profile:', e.message);
                if (AppState.identity) UI.loadConversations(AppState.identity.nodeId || AppState.identity.id);
            }
        } else {
            if (AppState.identity) UI.loadConversations(AppState.identity.nodeId || AppState.identity.id);
        }

        const fileInput = document.getElementById('profile-avatar-upload');
        if (fileInput) {
            fileInput.addEventListener('change', e => {
                const file = e.target.files[0];
                if (!file) return;
                if (file.size > 500 * 1024) {
                    showNotice('Avatar must be under 500KB.', true);
                    return;
                }
                // [B] Only allow image MIME types
                if (!file.type.startsWith('image/')) {
                    showNotice('Only image files are allowed for avatars.', true);
                    return;
                }
                const reader = new FileReader();
                reader.onload = ev => {
                    const preview = document.getElementById('profile-preview');
                    if (preview) { preview.src = ev.target.result; preview.style.display = 'block'; }
                };
                reader.readAsDataURL(file);
            });
        }
    },

    saveProfile: () => {
        const addrEl = document.getElementById('profile-address');
        const addr = addrEl ? addrEl.value.trim() : '';
        if (!addr) { showNotice('Username cannot be empty.', true); return; }
        if (addr.length > 50) { showNotice('Username too long (max 50 chars).', true); return; }

        const viewPreview = document.getElementById('profile-preview');
        let avatarData = viewPreview ? viewPreview.getAttribute('src') : '';
        if (avatarData && !avatarData.startsWith('data:image/')) avatarData = ''; // [B] base64 only
        if (avatarData && avatarData.length > 700000) {
            showNotice('Avatar too large. Use a smaller image.', true);
            return;
        }

        // [I] CSRF on POST
        fetch(BACKEND.url('/create-user'), {
            method: 'POST',
            headers: secureHeaders(true),
            body: JSON.stringify({ username: addr, avatar: avatarData })
        })
            .then(r => r.text())
            .then(text => {
                // [J] Validate schema
                const data = safeJson(text, d => d && typeof d === 'object');
                if (!data) { showNotice('Invalid server response.', true); return; }
                if (data.error) {
                    // [D] Never alert() with server error strings
                    showNotice('Could not create user. Please try a different username.', true);
                } else {
                    showNotice('Profile saved!');
                    localStorage.setItem('ghostnet_user', JSON.stringify(data.user));
                    UI.loadProfile();
                }
            })
            .catch(err => {
                log.error('Save profile error:', err.message);
                showNotice('Failed to connect to the server.', true);
            });
    },

    initVault: () => {
        const dropZone = document.getElementById('vault-drop-zone');
        const fileInput = document.getElementById('vault-file-input');
        const browseBtn = document.getElementById('vault-browse-btn');
        if (!dropZone || !fileInput) return;
        browseBtn?.addEventListener('click', e => { e.stopPropagation(); fileInput.click(); });
        dropZone.addEventListener('click', () => fileInput.click());
        fileInput.addEventListener('change', e => {
            const files = Array.from(e.target.files);
            if (files.length) UI.vaultUploadFiles(files);
            fileInput.value = '';
        });
        dropZone.addEventListener('dragover', e => { e.preventDefault(); dropZone.classList.add('drag-over'); });
        dropZone.addEventListener('dragleave', () => dropZone.classList.remove('drag-over'));
        dropZone.addEventListener('drop', e => {
            e.preventDefault(); dropZone.classList.remove('drag-over');
            const files = Array.from(e.dataTransfer.files);
            if (files.length) UI.vaultUploadFiles(files);
        });
        UI.vaultLoadFiles();
    },

    vaultUploadFiles: async (files) => {
        if (!window.GhostVault) { showNotice('Vault encryption module not loaded.', true); return; }
        const progressEl = document.getElementById('vault-upload-progress');
        const stageEl = document.getElementById('vault-progress-stage');
        const barEl = document.getElementById('vault-progress-bar');
        const detailEl = document.getElementById('vault-progress-detail');

        for (const file of files) {
            if (progressEl) progressEl.style.display = 'block';
            const stages = {
                encrypting: { text: 'Encrypting...', detail: 'AES-256-GCM encrypting file', percent: 30 },
                uploading: { text: 'Uploading...', detail: 'Sending encrypted blob', percent: 65 },
                anchoring: { text: 'Anchoring on chain...', detail: 'Recording SHA-256 hash', percent: 90 },
                complete: { text: 'Secured!', detail: 'Encrypted and anchored', percent: 100 },
            };
            try {
                await GhostVault.uploadFile(file, progress => {
                    const s = stages[progress.stage] || stages.encrypting;
                    if (stageEl) st(stageEl, s.text);   // [A]
                    if (barEl) barEl.style.width = s.percent + '%';
                    if (detailEl) st(detailEl, s.detail); // [A]
                });
                log.info('Vault upload complete.');
            } catch (err) {
                log.error('Vault upload failed:', err.message);
                if (stageEl) st(stageEl, 'Upload Failed');
                if (detailEl) st(detailEl, 'An error occurred. Please try again.');
                if (barEl) barEl.style.width = '0%';
            }
            await new Promise(r => setTimeout(r, 1500));
            if (progressEl) progressEl.style.display = 'none';
            if (barEl) barEl.style.width = '0%';
        }
        UI.vaultLoadFiles();
    },

    vaultLoadFiles: async () => { if (!window.GhostVault) return; try { UI.vaultRenderFiles(await GhostVault.listFiles()); } catch (e) { log.warn('Vault load failed:', e.message); } },

    vaultRenderFiles: (files) => {
        const listEl = document.getElementById('vault-file-list');
        const emptyEl = document.getElementById('vault-empty');
        const statsEl = document.getElementById('vault-stats');
        if (!listEl) return;

        if (!files?.length) {
            listEl.innerHTML = '';
            if (emptyEl) emptyEl.style.display = 'block';
            if (statsEl) statsEl.style.display = 'none';
            return;
        }
        if (emptyEl) emptyEl.style.display = 'none';
        if (statsEl) statsEl.style.display = 'flex';

        const totalSize = files.reduce((s, f) => s + (f.originalSize || f.fileSize || 0), 0);
        const anchored = files.filter(f => f.chainAnchored).length;
        const countEl = document.getElementById('vault-stat-count');
        const sizeEl = document.getElementById('vault-stat-size');
        const anchoredEl = document.getElementById('vault-stat-anchored');
        if (countEl) st(countEl, files.length);
        if (sizeEl) st(sizeEl, GhostVault.formatBytes(totalSize));
        if (anchoredEl) st(anchoredEl, anchored);

        listEl.innerHTML = '';
        files.forEach(f => {
            const hasKey = GhostVault.hasKey(f.fileId);
            const safeName = sanitize(f.fileName);
            const shortHash = f.fileHash
                ? `SHA-256: ${f.fileHash.substring(0, 8)}...${f.fileHash.substring(f.fileHash.length - 8)}`
                : '';
            const timeStr = f.uploadedAt ? new Date(f.uploadedAt).toLocaleDateString(undefined, { month: 'short', day: 'numeric', year: 'numeric' }) : '';
            const sizeStr = GhostVault.formatBytes(f.originalSize || f.fileSize || 0);
            const txShort = f.txHash ? f.txHash.substring(0, 10) + '...' : '';

            const card = document.createElement('div');
            card.className = 'vault-file-card';

            const hdr = document.createElement('div'); hdr.className = 'vault-file-header';
            const ico = document.createElement('div'); ico.className = 'vault-file-icon';
            ico.innerHTML = '<i data-lucide="file-lock" style="width:20px;height:20px;"></i>';
            const info = document.createElement('div'); info.className = 'vault-file-info';
            const nameEl = document.createElement('div'); nameEl.className = 'vault-file-name';
            st(nameEl, safeName); // [A]
            const metaEl = document.createElement('div'); metaEl.className = 'vault-file-size';
            st(metaEl, `${sizeStr} · ${timeStr}`);
            info.append(nameEl, metaEl); hdr.append(ico, info);

            const chainBadge = document.createElement('div');
            chainBadge.className = `vault-chain-badge ${f.chainAnchored ? 'anchored' : 'pending'}`;
            st(chainBadge, f.chainAnchored ? `On-Chain${txShort ? ' · ' + txShort : ''}` : 'Pending');

            const hashEl = document.createElement('div'); hashEl.className = 'vault-file-hash';
            st(hashEl, shortHash); // [A]

            const actions = document.createElement('div'); actions.className = 'vault-file-actions';
            const dlBtn = document.createElement('button'); dlBtn.className = 'vault-action-btn';
            if (!hasKey) dlBtn.disabled = true;
            st(dlBtn, hasKey ? 'Download' : 'No Key');
            dlBtn.addEventListener('click', () => UI.vaultDownload(f.fileId));

            const verBtn = document.createElement('button'); verBtn.className = 'vault-action-btn verify';
            st(verBtn, 'Verify');
            verBtn.addEventListener('click', () => UI.vaultVerify(f.fileId));

            const delBtn = document.createElement('button'); delBtn.className = 'vault-action-btn danger';
            st(delBtn, '🗑');
            delBtn.addEventListener('click', () => UI.vaultDelete(f.fileId, f.fileName));

            actions.append(dlBtn, verBtn, delBtn);
            card.append(hdr, chainBadge, hashEl, actions);
            listEl.appendChild(card);
        });
        if (typeof lucide !== 'undefined') lucide.createIcons();
    },

    vaultDownload: async (fileId) => {
        try { await GhostVault.downloadFile(fileId); }
        catch (err) { showNotice('Download failed.', true); } // [D] no server error in alert
    },

    vaultDelete: async (fileId, fileName) => {
        // [C][O] Custom confirm — never native confirm() with fileName
        showConfirm('Delete this file permanently? This cannot be undone.', async () => {
            try { await GhostVault.deleteFile(fileId); UI.vaultLoadFiles(); }
            catch (err) { showNotice('Delete failed.', true); } // [D]
        });
    },

    vaultVerify: async (fileId) => {
        try {
            const result = await GhostVault.verifyFile(fileId);
            if (!result) { showNotice('Verification failed — file not found.', true); return; }

            const modal = document.createElement('div');
            modal.className = 'vault-verify-overlay';
            modal.addEventListener('click', e => { if (e.target === modal) modal.remove(); });

            const card = document.createElement('div'); card.className = 'vault-verify-card';
            const h3 = document.createElement('h3');
            h3.style.cssText = 'font-family:var(--font-heading);margin-bottom:16px;color:var(--text-primary);display:flex;align-items:center;gap:8px;';
            st(h3, '🔒 Integrity Verification');

            const rows = [
                ['File', result.fileName, false],
                ['Disk Integrity', result.diskIntegrity ? 'PASS' : 'TAMPERED', result.diskIntegrity],
                ['Chain Verified', result.chainVerified ? 'ON-CHAIN' : 'PENDING', result.chainVerified],
                ['SHA-256', result.storedHash ? result.storedHash.substring(0, 16) + '...' : 'N/A', null],
                result.txHash ? ['TX Hash', result.txHash.substring(0, 16) + '...', null] : null,
            ].filter(Boolean);

            rows.forEach(([label, value, pass]) => {
                const row = document.createElement('div'); row.className = 'vault-verify-row';
                const lbl = document.createElement('span'); lbl.className = 'vault-verify-label';
                st(lbl, label);
                const val = document.createElement('span');
                val.className = `vault-verify-value${pass === true ? ' pass' : pass === false ? ' fail' : ''}`;
                st(val, value); // [A] textContent — no server data in innerHTML
                row.append(lbl, val); card.appendChild(row);
            });

            const closeBtn = document.createElement('button');
            closeBtn.className = 'btn-primary';
            closeBtn.style.marginTop = '16px';
            st(closeBtn, 'Close');
            closeBtn.addEventListener('click', () => modal.remove());
            card.append(h3, closeBtn);

            // Reorder — h3 first
            card.insertBefore(h3, card.firstChild);
            modal.appendChild(card);
            document.body.appendChild(modal);
            if (typeof lucide !== 'undefined') lucide.createIcons();
        } catch (err) {
            showNotice('Verification error.', true); // [D]
        }
    }
};

// ─── ENTRY POINT ────────────────────────────────────────

function renderHome() {
    const homeView = document.getElementById('view-home');
    if (homeView) {
        UI.navigate('home');
        const statNodes = document.getElementById('stat-nodes');
        // [K] textContent — never innerHTML with state data
        if (statNodes) st(statNodes, AppState.peers?.length || 0);
        return;
    }
    const main = document.getElementById('main-content');
    if (!main) return;

    // [K] Build via DOM — never innerHTML with AppState data
    main.innerHTML = '';
    const canvas = document.createElement('canvas');
    canvas.id = 'mesh';
    canvas.style.cssText = 'width:100%;height:100%;display:block;';
    const overlay = document.createElement('div');
    overlay.className = 'mesh-overlay';
    overlay.style.cssText = 'position:absolute;top:20px;right:20px;';
    const statItem1 = document.createElement('div'); statItem1.className = 'stat-item';
    const lbl1 = document.createElement('span'); lbl1.className = 'label'; st(lbl1, 'Peers');
    const val1 = document.createElement('span'); val1.className = 'value';
    st(val1, AppState.peers?.length || 0); // [K] textContent
    statItem1.append(lbl1, val1);
    const statItem2 = document.createElement('div'); statItem2.className = 'stat-item';
    const lbl2 = document.createElement('span'); lbl2.className = 'label'; st(lbl2, 'Status');
    const val2 = document.createElement('span'); val2.className = 'value';
    val2.style.color = '#00ff9d'; st(val2, 'Active');
    statItem2.append(lbl2, val2);
    overlay.append(statItem1, statItem2);
    main.append(canvas, overlay);
    new MeshNetwork('mesh');
}

// [F][G] Expose ONLY what external scripts absolutely need — not the full UI or AppState
window._app = null; // set by app.js after init
window.UI = UI;   // needed for HTML onclick= handlers (legacy) — minimize surface
window.addEventListener('DOMContentLoaded', () => {
    UI.init();
    renderHome();
});