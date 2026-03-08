/**
 * GhostNet Immersive UI — HARDENED
 *
 * Break fixes (401s in console):
 *  [B1] ALL fetch() calls missing Authorization header — added authHeaders() to every request
 *  [B2] GhostMesh init before token exists — connectMeshWhenReady() called only after token saved
 *
 * XSS fixes:
 *  [X1] renderConversations() injected username/preview/avatar raw into innerHTML
 *  [X2] renderDiscoverNodes() injected peer IDs raw
 *  [X3] renderWallet() injected symbol/chain/address raw
 *  [X4] selectChat() injected data.displayName raw
 *  [X5] openReceive() injected address/symbol into attribute and onclick
 *  [X6] openSend() injected symbol into onclick JS string
 *  [X7] vaultRenderFiles() injected fileName/txHash/fileHash raw
 *  [X8] vaultVerify() injected result fields raw
 *  All fixed via: esc() HTML-escaping helper; DOM API used for onclick handlers
 *
 * HIGH:
 *  [H1] renderConversations() onclick built with unescaped server strings — quote injection
 *       → Row data stored in data-* attributes; single delegated click handler reads them
 *  [H2] submitSend() POSTed to hardcoded http://localhost:3001
 *       → Uses BACKEND_URL constant
 *  [H3] fetchRealData() had no auth header → authHeaders() added
 *  [H4] saveProfile() sent unlimited base64 avatar — no size cap
 *       → MAX_AVATAR_BYTES = 512KB enforced before send
 *  [H5] loadProfile() read localStorage with no schema validation
 *       → validateUserProfile() checks required fields/types before use
 *
 * MEDIUM:
 *  [M1] alert()/confirm() replaced with custom modal dialogs
 *  [M2] MeshNetwork animation loop leaked on navigate — rafId stored; destroy() cancels it
 *
 * LOW:
 *  [L1] Multiple hardcoded Railway URL strings → single BACKEND_URL constant
 *  [L2] Raw server error messages logged/shown → sanitized before display
 */

// ─── Config ───────────────────────────────────────────────────────────────────

const BACKEND_URL = (() => {
    const meta = document.querySelector('meta[name="ghostnet-backend-url"]');
    if (meta && meta.content) return meta.content.replace(/\/$/, '');
    return 'https://ghostnet-ji-production.up.railway.app';
})();

const MAX_AVATAR_BYTES = 512 * 1024;

// ─── Auth header helper [B1] ──────────────────────────────────────────────────

function authHeaders(extra = {}) {
    const token = sessionStorage.getItem('ghostnet_jwt') || localStorage.getItem('ghostnet_jwt');
    const headers = { 'Content-Type': 'application/json', ...extra };
    if (token) headers['Authorization'] = 'Bearer ' + token;
    return headers;
}

// ─── HTML escape [X1-X8] ─────────────────────────────────────────────────────

function esc(str) {
    return String(str ?? '')
        .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;').replace(/'/g, '&#x27;');
}

// ─── Schema validator [H5] ────────────────────────────────────────────────────

function validateUserProfile(obj) {
    if (!obj || typeof obj !== 'object') return null;
    return {
        id: typeof obj.id === 'string' ? obj.id.slice(0, 128) : '',
        nodeId: typeof obj.nodeId === 'string' ? obj.nodeId.slice(0, 128) : '',
        username: typeof obj.username === 'string' ? obj.username.slice(0, 64) : '',
        address: typeof obj.address === 'string' ? obj.address.slice(0, 128) : '',
        avatar: (typeof obj.avatar === 'string' && obj.avatar.startsWith('data:image/')) ? obj.avatar : ''
    };
}

// ─── Custom modal helpers [M1] ────────────────────────────────────────────────

function showAlert(message) {
    return new Promise(resolve => {
        const overlay = document.createElement('div');
        overlay.className = 'modal-overlay';
        overlay.innerHTML = `<div class="modal-card" style="max-width:360px;"><div class="modal-title" style="font-size:1rem;">${esc(message)}</div><button class="btn-primary" style="margin-top:16px;">OK</button></div>`;
        document.body.appendChild(overlay);
        overlay.querySelector('.btn-primary').onclick = () => { overlay.remove(); resolve(); };
    });
}

function showConfirm(message) {
    return new Promise(resolve => {
        const overlay = document.createElement('div');
        overlay.className = 'modal-overlay';
        overlay.innerHTML = `<div class="modal-card" style="max-width:360px;"><div class="modal-title" style="font-size:1rem;">${esc(message)}</div><div style="display:flex;gap:10px;margin-top:16px;"><button class="btn-primary" id="_cy">Confirm</button><button class="btn-primary" id="_cn" style="background:var(--bg-elevated);">Cancel</button></div></div>`;
        document.body.appendChild(overlay);
        overlay.querySelector('#_cy').onclick = () => { overlay.remove(); resolve(true); };
        overlay.querySelector('#_cn').onclick = () => { overlay.remove(); resolve(false); };
    });
}

// ─── Global State ─────────────────────────────────────────────────────────────

window.AppState = {
    meshReady: false,
    wallet: { address: '0x...', balance: 0 },
    peers: [], identity: null, messages: [], files: []
};

// ─── Mesh Visualization ───────────────────────────────────────────────────────

class MeshNetwork {
    constructor(canvasId) {
        this.canvas = document.getElementById(canvasId);
        if (!this.canvas) return;
        this.ctx = this.canvas.getContext('2d');
        this.nodes = []; this.width = 0; this.height = 0;
        this.rafId = null; // [M2]
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
        for (let i = 0; i < count; i++) {
            this.nodes.push({
                x: Math.random() * this.width, y: Math.random() * this.height,
                vx: (Math.random() - 0.5) * 0.8, vy: (Math.random() - 0.5) * 0.8, type: 'peer', size: 3
            });
        }
    }
    animate() {
        this.ctx.clearRect(0, 0, this.width, this.height);
        const isDark = document.documentElement.getAttribute('data-theme') === 'dark';
        const accent = isDark ? '#3b82f6' : '#2563eb';
        const muted = isDark ? '#334155' : '#cbd5e1';
        const rgb = isDark ? '59,130,246' : '37,99,235';
        this.ctx.lineWidth = 1;
        this.nodes.forEach((n1, i) => this.nodes.forEach((n2, j) => {
            if (i >= j) return;
            const d = Math.hypot(n1.x - n2.x, n1.y - n2.y);
            if (d < 150) {
                this.ctx.strokeStyle = `rgba(${rgb},${1 - d / 150})`;
                this.ctx.beginPath(); this.ctx.moveTo(n1.x, n1.y); this.ctx.lineTo(n2.x, n2.y); this.ctx.stroke();
            }
        }));
        this.nodes.forEach(n => {
            if (n.type !== 'self') {
                n.x += n.vx; n.y += n.vy;
                if (n.x < 0 || n.x > this.width) n.vx *= -1;
                if (n.y < 0 || n.y > this.height) n.vy *= -1;
            }
            const g = this.ctx.createRadialGradient(n.x, n.y, n.size / 2, n.x, n.y, n.size * 4);
            g.addColorStop(0, n.type === 'self' ? accent : muted); g.addColorStop(1, 'rgba(0,0,0,0)');
            this.ctx.fillStyle = g;
            this.ctx.fillRect(n.x - n.size * 4, n.y - n.size * 4, n.size * 8, n.size * 8);
            this.ctx.fillStyle = n.type === 'self' ? accent : muted;
            this.ctx.beginPath(); this.ctx.arc(n.x, n.y, n.size, 0, Math.PI * 2); this.ctx.fill();
        });
        this.rafId = requestAnimationFrame(() => this.animate()); // [M2]
    }
    destroy() { if (this.rafId) cancelAnimationFrame(this.rafId); } // [M2]
}

// ─── App Logic ────────────────────────────────────────────────────────────────

const UI = {
    _meshViz: null,

    init: () => {
        UI.initTheme();
        document.querySelectorAll('.nav-btn').forEach(btn => { btn.onclick = () => UI.navigate(btn.dataset.target); });
        UI._meshViz = new MeshNetwork('mesh');
        UI.setupChat();
        setTimeout(() => { UI.mockData(); window.dispatchEvent(new Event('app:state')); }, 800);
        window.addEventListener('app:state', UI.render);
        UI.loadProfile();
        UI.initVault();
    },

    // [B2] Call this from app.js AFTER storing JWT in sessionStorage
    connectMeshWhenReady: () => {
        if (window.app?.mesh) window.app.mesh.connectWebSocket();
    },

    navigate: (target) => {
        document.querySelectorAll('.nav-btn').forEach(b => {
            if (b.id !== 'theme-toggle') b.classList.toggle('active', b.dataset.target === target);
        });
        document.querySelectorAll('.mobile-nav-item').forEach(b => b.classList.toggle('active', b.dataset.target === target));
        document.querySelectorAll('.view-section').forEach(s => s.classList.toggle('active', s.id === `view-${target}`));
        if (target === 'vault') UI.vaultLoadFiles();
        document.getElementById('app-sidebar')?.classList.remove('open');
        document.getElementById('sidebar-overlay')?.classList.remove('visible');
        document.querySelector('.chat-layout-split')?.classList.remove('chat-active');
    },

    toggleMobileMenu: () => {
        document.getElementById('app-sidebar')?.classList.toggle('open');
        document.getElementById('sidebar-overlay')?.classList.toggle('visible');
    },

    chatBackToList: () => { document.querySelector('.chat-layout-split')?.classList.remove('chat-active'); },

    initTheme: () => {
        if (localStorage.getItem('ghostnet_theme') === 'dark') {
            document.documentElement.setAttribute('data-theme', 'dark');
            const lbl = document.getElementById('theme-label'); if (lbl) lbl.innerText = 'Light Mode';
            const ico = document.getElementById('theme-icon'); if (ico) ico.setAttribute('data-lucide', 'sun');
        }
        if (typeof lucide !== 'undefined') lucide.createIcons();
    },

    toggleTheme: () => {
        const isDark = document.documentElement.getAttribute('data-theme') === 'dark';
        const lbl = document.getElementById('theme-label');
        const ico = document.getElementById('theme-icon');
        if (isDark) {
            document.documentElement.removeAttribute('data-theme');
            localStorage.setItem('ghostnet_theme', 'light');
            if (lbl) lbl.innerText = 'Dark Mode'; if (ico) ico.setAttribute('data-lucide', 'moon');
        } else {
            document.documentElement.setAttribute('data-theme', 'dark');
            localStorage.setItem('ghostnet_theme', 'dark');
            if (lbl) lbl.innerText = 'Light Mode'; if (ico) ico.setAttribute('data-lucide', 'sun');
        }
        if (typeof lucide !== 'undefined') lucide.createIcons();
        UI.render();
    },

    mockData: () => {
        AppState.peers = [
            { id: 'node_alpha', type: 'Bridge', latency: 12 }, { id: 'node_bravo', type: 'Relay', latency: 45 },
            { id: 'node_charlie', type: 'Mobile', latency: 112 }, { id: 'node_delta', type: 'Desktop', latency: 8 }
        ];
        AppState.wallet = [
            { symbol: 'ETH', balance: 0, chain: 'Sepolia' }, { symbol: 'BTC', balance: 0, chain: 'Bitcoin' },
            { symbol: 'SOL', balance: 0, chain: 'Solana' }, { symbol: 'USDT', balance: 0, chain: 'Ethereum' }
        ];
        AppState.files = [
            { name: 'encrypted_shard_01.dat', size: '4.2 MB' }, { name: 'keys_backup.json.enc', size: '12 KB' }
        ];
        UI.fetchRealData();
    },

    fetchRealData: async () => {
        try {
            const res = await fetch(`${BACKEND_URL}/wallet`, { headers: authHeaders() }); // [B1][H3]
            if (!res.ok) throw new Error(`HTTP ${res.status}`);
            const data = await res.json();
            if (Array.isArray(data)) AppState.wallet = data;
            window.dispatchEvent(new Event('app:state'));
        } catch (_) {
            if (!AppState.wallet?.length) {
                AppState.wallet = [
                    { symbol: 'ETH', balance: 0, chain: 'Sepolia', address: '0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045' },
                    { symbol: 'BTC', balance: 0, chain: 'Bitcoin', address: 'tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx' },
                    { symbol: 'SOL', balance: 0, chain: 'Solana', address: 'HN7cABqLq46Es1jh92dQQisAq662SmxELLLsHHe4YWrH' },
                    { symbol: 'USDT', balance: 0, chain: 'Ethereum', address: '0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045' }
                ];
                window.dispatchEvent(new Event('app:state'));
            }
        }
    },

    // [X5] openReceive — DOM only, no innerHTML with user data
    openReceive: (symbol, address) => {
        const qrData = symbol === 'BTC' ? `bitcoin:${address}` : symbol === 'SOL' ? `solana:${address}` : `ethereum:${address}`;
        const qrUrl = `https://api.qrserver.com/v1/create-qr-code/?size=200x200&data=${encodeURIComponent(qrData)}`;
        const modal = document.createElement('div');
        modal.className = 'modal-overlay';
        modal.innerHTML = `<div class="modal-card"><button class="modal-close">×</button><div class="modal-title">Receive ${esc(symbol)}</div><img id="_qr" class="qr-code" alt="QR"><div class="input-group"><label class="input-label">YOUR ADDRESS</label><input type="text" id="_qa" class="modal-input" readonly></div></div>`;
        document.body.appendChild(modal);
        modal.querySelector('.modal-close').onclick = () => modal.remove();
        modal.querySelector('#_qr').src = qrUrl;
        const inp = modal.querySelector('#_qa'); inp.value = address; inp.onclick = () => inp.select();
    },

    // [X6] openSend — symbol in closure, never in onclick string
    openSend: (symbol) => {
        const modal = document.createElement('div');
        modal.className = 'modal-overlay';
        modal.innerHTML = `<div class="modal-card"><button class="modal-close">×</button><div class="modal-title">Send ${esc(symbol)}</div><div class="input-group"><label class="input-label">RECIPIENT ADDRESS</label><input type="text" id="send-to" class="modal-input" placeholder="0x..."></div><div class="input-group"><label class="input-label">AMOUNT</label><input type="number" id="send-amount" class="modal-input" placeholder="0.00"></div><button class="btn-primary" id="_sc">CONFIRM TRANSACTION</button></div>`;
        document.body.appendChild(modal);
        modal.querySelector('.modal-close').onclick = () => modal.remove();
        modal.querySelector('#_sc').onclick = () => UI.submitSend(symbol, modal); // [X6] closure
    },

    submitSend: async (symbol, modal) => {
        const to = document.getElementById('send-to')?.value?.trim();
        const amount = document.getElementById('send-amount')?.value?.trim();
        if (!to || !amount) { await showAlert('Please fill all fields'); return; }
        if (modal) modal.remove();
        await showAlert(`Transaction submitted: ${amount} ${symbol}`); // [M1]
        try {
            await fetch(`${BACKEND_URL}/wallet/send`, { // [H2]
                method: 'POST', headers: authHeaders(), // [B1]
                body: JSON.stringify({ symbol, to, amount })
            });
        } catch (_) { }
    },

    openNewChat: () => {
        const modal = document.createElement('div');
        modal.className = 'modal-overlay';
        modal.innerHTML = `<div class="modal-card"><button class="modal-close">×</button><div class="modal-title">New Encrypted Chat</div><div class="input-group"><label class="input-label">CONTACT NAME</label><input type="text" id="chat-name" class="modal-input" placeholder="e.g. Alice"></div><div class="input-group"><label class="input-label">NODE ID / PUBLIC KEY</label><input type="text" id="chat-pubkey" class="modal-input" placeholder="0x..."></div><div id="chat-new-error" style="color:#ef4444;font-size:0.8rem;margin-top:8px;min-height:1.2em;"></div><button class="btn-primary" id="chat-start-btn">START SESSION</button></div>`;
        document.body.appendChild(modal);
        modal.querySelector('.modal-close').onclick = () => modal.remove();
        modal.querySelector('#chat-start-btn').onclick = () => UI.submitNewChat(modal);
    },

    submitNewChat: async (modal) => {
        const name = document.getElementById('chat-name')?.value?.trim();
        const pubKey = document.getElementById('chat-pubkey')?.value?.trim();
        const errEl = document.getElementById('chat-new-error');
        const startBtn = document.getElementById('chat-start-btn');
        if (!name || !pubKey) { if (errEl) errEl.textContent = 'Please fill in both fields.'; return; }
        if (startBtn) { startBtn.disabled = true; startBtn.textContent = 'VALIDATING...'; }
        if (errEl) errEl.textContent = '';
        try {
            const res = await fetch(`${BACKEND_URL}/validate-node/${encodeURIComponent(pubKey)}`, { headers: authHeaders() }); // [B1]
            if (!res.ok) {
                if (errEl) errEl.textContent = `⚠ Validation failed (HTTP ${res.status}). Try again.`;
                if (startBtn) { startBtn.disabled = false; startBtn.textContent = 'START SESSION'; }
                return;
            }
            if (!(res.headers.get('content-type') || '').includes('application/json')) {
                if (errEl) errEl.textContent = '⚠ Server returned invalid response.';
                if (startBtn) { startBtn.disabled = false; startBtn.textContent = 'START SESSION'; }
                return;
            }
            const data = await res.json();
            if (!data.valid) {
                if (errEl) errEl.textContent = '⚠ Node not found. Check the Node ID and try again.';
                if (startBtn) { startBtn.disabled = false; startBtn.textContent = 'START SESSION'; }
                return;
            }
            if (modal) modal.remove();
            const feed = document.getElementById('chat-feed');
            if (feed) {
                const div = document.createElement('div');
                div.style.cssText = 'text-align:center;color:#64748b;font-size:0.8rem;margin:20px;';
                div.textContent = `-- Session with ${data.displayName || name} Started --`; // [X4] textContent
                feed.innerHTML = ''; feed.appendChild(div);
            }
            if (window.app) window.app.chatTarget = pubKey;
            UI.selectChat('new', data.displayName || name, pubKey);
        } catch (_) {
            if (errEl) errEl.textContent = '⚠ Could not verify node. Server may be offline.';
            if (startBtn) { startBtn.disabled = false; startBtn.textContent = 'START SESSION'; }
        }
    },

    loadConversations: async (userId) => {
        if (!userId) return;
        try {
            const res = await fetch(`${BACKEND_URL}/conversations?userId=${encodeURIComponent(userId)}`, { headers: authHeaders() }); // [B1]
            if (res.ok) UI.renderConversations(await res.json());
        } catch (_) { }
    },

    // [X1][H1] — DOM construction, data-* attributes, delegated handlers
    renderConversations: (convos) => {
        const list = document.getElementById('chat-user-list');
        if (!list) return;
        list.innerHTML = '';
        if (!Array.isArray(convos) || !convos.length) {
            list.innerHTML = '<div style="padding:20px;text-align:center;color:#64748b;font-size:0.8rem;">No conversations yet.</div>';
            return;
        }
        convos.forEach(c => {
            const timeStr = new Date(c.updated).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
            const username = c.otherUser ? (c.otherUser.username || c.otherUser.address || c.otherUser.id) : 'Unknown';
            let preview = c.lastMessage || 'Message...';
            if (typeof preview === 'object' && preview.body) preview = preview.body;
            if (typeof preview === 'string' && preview.includes('body":"')) { try { preview = JSON.parse(preview).body; } catch (_) { } }

            const row = document.createElement('div');
            row.className = `chat-user-row${AppState.activeConvoId === c.id ? ' active' : ''}`;
            row.dataset.convo = c.id || ''; // [H1] IDs in data-*, never in onclick strings
            row.dataset.name = username || '';
            row.dataset.targetId = (c.otherUser?.id) || '';

            const avatarWrap = document.createElement('div');
            avatarWrap.className = 'chat-avatar-wrap';
            if (c.otherUser?.avatar) {
                const img = document.createElement('img');
                img.className = 'chat-avatar'; img.style.objectFit = 'cover';
                img.src = c.otherUser.avatar; // .src — not innerHTML [X1]
                avatarWrap.appendChild(img);
            } else {
                const div = document.createElement('div');
                div.className = 'chat-avatar'; div.style.background = '#3f3f46';
                avatarWrap.appendChild(div);
            }

            const info = document.createElement('div');
            info.className = 'chat-user-info';
            info.innerHTML = `<div class="chat-user-top"><span class="chat-username">${esc(username)}</span><span class="chat-time">${esc(timeStr)}</span></div><div class="chat-user-bottom"><span class="chat-preview">${esc(preview)}</span></div>`;

            row.appendChild(avatarWrap); row.appendChild(info);
            row.addEventListener('click', () => UI.selectChat(row.dataset.convo, row.dataset.name, row.dataset.targetId)); // [H1]
            list.appendChild(row);
        });
    },

    selectChat: async (convoId, nameStr = null, targetUserId = null) => {
        document.getElementById('chat-empty-state')?.style.setProperty('display', 'none');
        const as = document.getElementById('chat-active-state'); if (as) as.style.display = 'flex';
        document.querySelector('.chat-layout-split')?.classList.add('chat-active');
        const lbl = document.getElementById('label-transport');
        if (lbl) lbl.textContent = nameStr || targetUserId || ''; // [X4] textContent
        AppState.activeConvoId = convoId;
        if (window.app) { window.app.chatTarget = targetUserId; window.app.chatContactName = nameStr || targetUserId; }
        document.querySelectorAll('.chat-user-row').forEach(r => r.classList.toggle('active', r.dataset.convo === convoId));
        const feed = document.getElementById('chat-feed'); if (feed) feed.innerHTML = '';
        if (convoId && convoId !== 'new') {
            try {
                const res = await fetch(`${BACKEND_URL}/history?convoId=${encodeURIComponent(convoId)}`, { headers: authHeaders() }); // [B1]
                if (res.ok) {
                    const msgs = await res.json();
                    msgs.forEach(m => {
                        const myId = AppState.identity?.nodeId || AppState.identity?.id;
                        let text = m.content;
                        if (typeof text === 'object' && text.body) text = text.body;
                        if (typeof text === 'string' && text.includes('body":"')) { try { text = JSON.parse(text).body; } catch (_) { } }
                        UI.addMessage(text || '***', m.senderId === myId ? 'me' : 'them');
                    });
                }
            } catch (_) { }
        }
    },

    render: () => {
        UI.renderWallet(); UI.renderDiscoverNodes(); UI.renderStorage(); UI.updateChatStatus();
        const sn = document.getElementById('stat-nodes'); if (sn) sn.innerText = AppState.peers.length;
    },

    updateChatStatus: () => {
        const lbl = document.getElementById('btn-ble-label');
        const scan = document.getElementById('btn-ble-scan');
        if (!lbl || !scan) return;
        const blePeers = window.app?.mesh?.getStatus()?.blePeers || 0;
        if (blePeers > 0) {
            lbl.textContent = `BLE (${blePeers})`; scan.style.borderColor = 'var(--accent)';
            scan.style.color = 'var(--accent)'; scan.style.background = 'var(--accent-dim)';
        } else { lbl.textContent = 'Scan'; scan.style.borderColor = scan.style.color = scan.style.background = ''; }
        if (typeof lucide !== 'undefined') lucide.createIcons();
    },

    // [X3] renderWallet — all server values escaped; onclick via DOM
    renderWallet: () => {
        const el = document.getElementById('wallet'); if (!el) return;
        const LOGOS = { ETH: 'https://assets.coingecko.com/coins/images/279/small/ethereum.png', BTC: 'https://assets.coingecko.com/coins/images/1/small/bitcoin.png', SOL: 'https://assets.coingecko.com/coins/images/4128/small/solana.png', USDT: 'https://assets.coingecko.com/coins/images/325/small/Tether.png', AHT: 'https://assets.coingecko.com/coins/images/279/small/ethereum.png' };
        const META = { ETH: { color: '#627EEA', gradient: 'linear-gradient(135deg,#627EEA,#3b5fc0)', darkGlow: 'rgba(98,126,234,0.35)', name: 'Ethereum' }, BTC: { color: '#F7931A', gradient: 'linear-gradient(135deg,#F7931A,#e2750a)', darkGlow: 'rgba(247,147,26,0.35)', name: 'Bitcoin' }, SOL: { color: '#9945FF', gradient: 'linear-gradient(135deg,#9945FF,#14F195)', darkGlow: 'rgba(153,69,255,0.35)', name: 'Solana' }, USDT: { color: '#26A17B', gradient: 'linear-gradient(135deg,#26A17B,#1a7a5c)', darkGlow: 'rgba(38,161,123,0.35)', name: 'Tether' }, AHT: { color: '#3b82f6', gradient: 'linear-gradient(135deg,#3b82f6,#8b5cf6)', darkGlow: 'rgba(59,130,246,0.35)', name: 'GhostNet' } };
        const assets = Array.isArray(AppState.wallet) ? AppState.wallet : (AppState.wallet?.balance ? [{ symbol: 'AHT', balance: AppState.wallet.balance, chain: 'GhostNet' }, { symbol: 'ETH', balance: 0, chain: 'Sepolia' }] : []);
        const total = assets.reduce((s, a) => s + (a.balance || 0), 0);

        let html = `<div class="wlt-portfolio-banner"><div class="wlt-portfolio-left"><div class="wlt-portfolio-label">Portfolio Value</div><div class="wlt-portfolio-total">${total.toLocaleString(undefined, { minimumFractionDigits: 2, maximumFractionDigits: 4 })}</div><div class="wlt-portfolio-subtitle">${assets.length} Assets · GhostNet Wallet</div></div><div class="wlt-portfolio-tokens">${assets.map(a => { const m = META[a.symbol] || META.ETH; return `<div class="wlt-mini-token" style="--tc:${m.color}"><img src="${LOGOS[a.symbol] || LOGOS.ETH}" alt="${esc(a.symbol)}" width="20" height="20"></div>`; }).join('')}</div></div><div class="wlt-grid">`;

        assets.forEach((asset, i) => {
            const sym = esc(asset.symbol || ''); const chain = esc(asset.chain || ''); const addr = esc(asset.address || '');
            const disp = asset.address ? `${asset.address.substring(0, 6)}···${asset.address.slice(-4)}` : 'Not Connected';
            const logo = LOGOS[asset.symbol] || LOGOS.ETH; const meta = META[asset.symbol] || META.ETH;
            html += `<div class="wlt-card-outer" style="--c1:${meta.color};--cg:${meta.gradient};--cd:${meta.darkGlow};animation-delay:${i * 0.1}s;"><div class="wlt-card"><div class="wlt-card-orb"></div><div class="wlt-card-line"></div><div class="wlt-card-top"><div class="wlt-logo-ring"><div class="wlt-logo-inner"><img src="${logo}" alt="${sym}" width="28" height="28" onerror="this.style.display='none'"></div></div><div class="wlt-card-info"><div class="wlt-card-name">${sym}<span class="wlt-card-fullname">${esc(meta.name)}</span></div><div class="wlt-card-chain-row"><span class="wlt-chain-badge">${chain}</span><span class="wlt-status-dot"></span></div></div></div><div class="wlt-card-mid"><div class="wlt-bal-value">${(asset.balance || 0).toLocaleString(undefined, { minimumFractionDigits: 2, maximumFractionDigits: 6 })}</div><div class="wlt-bal-label">${sym} Balance</div></div><div class="wlt-addr-chip" title="${addr}"><svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="9" y="9" width="13" height="13" rx="2"/><path d="M5 15H4a2 2 0 01-2-2V4a2 2 0 012-2h9a2 2 0 012 2v1"/></svg><span>${esc(disp)}</span></div><div class="wlt-card-actions" data-symbol="${sym}" data-address="${addr}"><button class="wlt-btn wlt-btn-send _ws"><svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><line x1="12" y1="19" x2="12" y2="5"/><polyline points="5 12 12 5 19 12"/></svg>Send</button><button class="wlt-btn wlt-btn-recv _wr"><svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><line x1="12" y1="5" x2="12" y2="19"/><polyline points="19 12 12 19 5 12"/></svg>Receive</button></div></div></div>`;
        });
        html += '</div>'; el.innerHTML = html;
        el.querySelectorAll('._ws').forEach(b => { const d = b.closest('.wlt-card-actions'); b.onclick = () => UI.openSend(d.dataset.symbol); }); // [X3]
        el.querySelectorAll('._wr').forEach(b => { const d = b.closest('.wlt-card-actions'); b.onclick = () => UI.openReceive(d.dataset.symbol, d.dataset.address); });
    },

    // [X2] peer IDs escaped
    renderDiscoverNodes: () => {
        const el = document.getElementById('discover-nodes'); if (!el) return;
        const bleActive = !!(window.app?.transport?.ble?.peers?.size > 0);
        let html = `<div style="width:100%;grid-column:1/-1;margin-bottom:20px;display:flex;justify-content:space-between;align-items:center;background:var(--bg-panel);padding:15px;border-radius:16px;border:1px solid var(--border);box-shadow:var(--glow);"><div style="display:flex;align-items:center;gap:15px;"><div style="width:40px;height:40px;background:var(--accent-dim);border-radius:50%;display:flex;align-items:center;justify-content:center;color:var(--accent);"><i data-lucide="bluetooth"></i></div><div><div style="font-weight:bold;color:var(--text-primary);">BLE Mesh Layer</div><div style="font-size:0.8rem;color:var(--text-muted);">Local-First Transport</div></div></div><div style="display:flex;align-items:center;gap:10px;"><div class="status-badge ${bleActive ? 'active' : ''}">${bleActive ? '🟢 Active' : '⚪ Idle'}</div><button class="btn-primary small" id="_blescan">SCAN NETWORK</button></div></div>`;
        const allPeers = [...AppState.peers];
        window.app?.transport?.ble?.peers?.forEach(p => { if (!allPeers.find(e => e.id === p.id)) allPeers.push({ id: p.id, type: 'BLE', latency: Math.floor(Math.random() * 20) + 10 }); });
        allPeers.forEach(p => {
            html += `<div class="node-card"><div style="display:flex;justify-content:space-between;align-items:center;"><div class="node-address" style="color:var(--accent);">${esc(p.id)}</div><div style="font-size:0.8rem;color:${(p.latency || 999) < 50 ? '#10b981' : '#f59e0b'}">${esc(String(p.latency || '??'))}ms</div></div><div class="node-meta">${esc(p.type)} Node • Verified</div>${p.type === 'BLE' ? '<div style="margin-top:5px;font-size:0.75rem;color:#10b981;">via Bluetooth Mesh</div>' : ''}<div style="margin-top:10px;height:4px;background:var(--border);border-radius:2px;overflow:hidden;"><div style="width:${Math.round(Math.random() * 100)}%;height:100%;background:${p.type === 'BLE' ? '#10b981' : 'var(--text-muted)'};"></div></div></div>`;
        });
        el.innerHTML = html;
        el.querySelector('#_blescan')?.addEventListener('click', () => window.app?.transport?.startBLEScan());
        if (typeof lucide !== 'undefined') lucide.createIcons();
    },

    renderStorage: () => {
        const el = document.getElementById('storage'); if (!el) return;
        el.innerHTML = AppState.files.map(f => `<div class="file-card" style="display:flex;align-items:center;gap:15px;"><i data-lucide="file-lock" style="color:var(--text-muted);"></i><div style="flex:1;"><div style="color:var(--text-primary);font-family:monospace;font-weight:500;">${esc(f.name)}</div><div style="font-size:0.8rem;color:var(--text-muted);">${esc(f.size)}</div></div><button style="background:none;border:none;color:var(--accent);cursor:pointer;"><i data-lucide="download"></i></button></div>`).join('');
        if (typeof lucide !== 'undefined') lucide.createIcons();
    },

    setupChat: () => {
        const btn = document.getElementById('chat-send');
        const input = document.getElementById('chat-input');
        if (btn && input) {
            btn.onclick = async () => {
                if (window.app?.sendMessage) { await window.app.sendMessage(); return; }
                const text = input.value.trim(); if (!text) return;
                UI.addMessage(text, 'me'); input.value = '';
                const myId = AppState.identity?.nodeId || AppState.identity?.id || 'anonymous';
                const tid = window.app?.chatTarget || 'broadcast';
                try {
                    const res = await fetch(`${BACKEND_URL}/message`, { method: 'POST', headers: authHeaders(), body: JSON.stringify({ senderId: myId, receiverId: tid, content: text }) }); // [B1]
                    const r = await res.json();
                    if (r.success && r.convo) { AppState.activeConvoId = r.convo.id; UI.loadConversations(myId); }
                } catch (_) { }
            };
            input.onkeypress = e => { if (e.key === 'Enter') btn.click(); };
        }
        document.querySelectorAll('.mode-btn').forEach(m => { m.onclick = () => { document.querySelectorAll('.mode-btn').forEach(b => b.classList.remove('active')); m.classList.add('active'); }; });
    },

    addMessage: (text, type) => {
        const feed = document.getElementById('chat-feed'); if (!feed) return;
        const msg = document.createElement('div');
        msg.className = `message ${type}`;
        msg.textContent = String(text ?? ''); // safe — textContent never innerHTML
        feed.appendChild(msg); feed.scrollTop = feed.scrollHeight;
    },

    promptFileType: () => {
        const modal = document.createElement('div'); modal.className = 'modal-overlay';
        modal.innerHTML = `<div class="modal-card"><button class="modal-close">×</button><div class="modal-title">Select Attachment Type</div><div style="display:grid;grid-template-columns:1fr 1fr;gap:15px;margin-top:20px;"><button class="btn-primary" data-accept="image/*"><i data-lucide="image"></i> Image</button><button class="btn-primary" data-accept="video/*"><i data-lucide="video"></i> Video</button><button class="btn-primary" data-accept=".pdf,.doc,.docx,.txt"><i data-lucide="file-text"></i> Document</button><button class="btn-primary" data-accept="*"><i data-lucide="file"></i> Any</button></div></div>`;
        document.body.appendChild(modal);
        modal.querySelector('.modal-close').onclick = () => modal.remove();
        modal.querySelectorAll('[data-accept]').forEach(b => b.onclick = () => UI.triggerFile(b.dataset.accept, modal));
        if (typeof lucide !== 'undefined') lucide.createIcons();
    },

    triggerFile: (accept, modal) => {
        const inp = document.getElementById('chat-file'); if (inp) { inp.accept = accept; inp.click(); }
        if (modal) modal.remove();
    },

    // [H5] Schema validation on localStorage read
    loadProfile: () => {
        let user = null;
        try { const s = localStorage.getItem('ghostnet_user'); if (s) user = validateUserProfile(JSON.parse(s)); } catch (_) { }
        if (user) {
            AppState.identity = user;
            const sp = document.getElementById('sidebar-profile');
            const sa = document.getElementById('sidebar-avatar');
            const sadr = document.getElementById('sidebar-address');
            const sid = document.getElementById('sidebar-id');
            if (sp) {
                sp.style.display = 'flex';
                if (user.avatar && sa) { sa.src = user.avatar; sa.style.display = 'block'; } else if (sa) sa.style.display = 'none';
                if (sadr) sadr.textContent = user.username || user.address || ''; // textContent [X1]
                if (sid) sid.textContent = user.id || '';
            }
            const va = document.getElementById('profile-address'); if (va) va.value = user.username || user.address || '';
            const vp = document.getElementById('profile-preview');
            if (vp && user.avatar) { vp.src = user.avatar; vp.style.display = 'block'; }
            const vi = document.getElementById('profile-id-display'); if (vi) vi.textContent = 'Current ID: ' + (user.id || '');
            UI.loadConversations(user.nodeId || user.id);
        } else if (AppState.identity) {
            UI.loadConversations(AppState.identity.nodeId || AppState.identity.id);
        }
        const fi = document.getElementById('profile-avatar-upload');
        if (fi) fi.onchange = e => {
            const f = e.target.files[0]; if (!f) return;
            const r = new FileReader();
            r.onload = ev => { const vp = document.getElementById('profile-preview'); if (vp) { vp.src = ev.target.result; vp.style.display = 'block'; } };
            r.readAsDataURL(f);
        };
    },

    saveProfile: async () => {
        const addr = document.getElementById('profile-address')?.value?.trim() || '';
        const vp = document.getElementById('profile-preview');
        let avatar = vp?.getAttribute('src') || '';
        if (!avatar.startsWith('data:image/')) avatar = '';
        if (avatar && avatar.length > MAX_AVATAR_BYTES * 1.4) { // [H4]
            await showAlert('Avatar is too large (max 512 KB). Please use a smaller image.');
            return;
        }
        try {
            const res = await fetch(`${BACKEND_URL}/create-user`, { method: 'POST', headers: authHeaders(), body: JSON.stringify({ username: addr, avatar }) }); // [B1]
            const data = await res.json();
            if (data.error) { await showAlert('Could not save profile. Please try a different username.'); } // [L2]
            else {
                await showAlert('Profile saved!');
                const validated = validateUserProfile(data.user); // [H5]
                if (validated) { localStorage.setItem('ghostnet_user', JSON.stringify(validated)); UI.loadProfile(); }
            }
        } catch (_) { await showAlert('Failed to connect to the server.'); }
    },

    // ══════════════════════════════════════════════════
    //  FILE VAULT UI
    // ══════════════════════════════════════════════════

    initVault: () => {
        const dz = document.getElementById('vault-drop-zone');
        const fi = document.getElementById('vault-file-input');
        if (!dz || !fi) return;
        document.getElementById('vault-browse-btn')?.addEventListener('click', e => { e.stopPropagation(); fi.click(); });
        dz.addEventListener('click', () => fi.click());
        fi.addEventListener('change', e => { const f = Array.from(e.target.files); if (f.length) UI.vaultUploadFiles(f); fi.value = ''; });
        dz.addEventListener('dragover', e => { e.preventDefault(); dz.classList.add('drag-over'); });
        dz.addEventListener('dragleave', () => dz.classList.remove('drag-over'));
        dz.addEventListener('drop', e => { e.preventDefault(); dz.classList.remove('drag-over'); const f = Array.from(e.dataTransfer.files); if (f.length) UI.vaultUploadFiles(f); });
        UI.vaultLoadFiles();
    },

    vaultUploadFiles: async (files) => {
        if (!window.GhostVault) { await showAlert('Vault encryption module not loaded.'); return; }
        const pe = document.getElementById('vault-upload-progress'), se = document.getElementById('vault-progress-stage'),
            be = document.getElementById('vault-progress-bar'), de = document.getElementById('vault-progress-detail'), ie = document.getElementById('vault-progress-icon');
        const stages = { encrypting: { text: 'Encrypting...', p: 30, icon: 'shield' }, uploading: { text: 'Uploading...', p: 65, icon: 'upload-cloud' }, anchoring: { text: 'Anchoring...', p: 90, icon: 'link' }, complete: { text: 'Secured!', p: 100, icon: 'check-circle' } };
        for (const file of files) {
            if (pe) pe.style.display = 'block';
            try {
                await GhostVault.uploadFile(file, prog => {
                    const s = stages[prog.stage] || stages.encrypting;
                    if (se) se.textContent = s.text; if (be) be.style.width = s.p + '%'; if (de) de.textContent = `${s.text} "${file.name}"`;
                    if (ie) { ie.innerHTML = `<i data-lucide="${s.icon}" style="width:32px;height:32px;"></i>`; if (typeof lucide !== 'undefined') lucide.createIcons(); }
                });
            } catch (_) { if (se) se.textContent = 'Upload Failed'; if (de) de.textContent = 'An error occurred.'; if (be) be.style.width = '0%'; }
            await new Promise(r => setTimeout(r, 1500));
            if (pe) pe.style.display = 'none'; if (be) be.style.width = '0%';
        }
        UI.vaultLoadFiles();
    },

    vaultLoadFiles: async () => {
        if (!window.GhostVault) return;
        try { UI.vaultRenderFiles(await GhostVault.listFiles()); } catch (_) { }
    },

    // [X7] All server values escaped; onclick via delegated DOM handlers
    vaultRenderFiles: (files) => {
        const le = document.getElementById('vault-file-list'), ee = document.getElementById('vault-empty'), se = document.getElementById('vault-stats');
        if (!le) return;
        if (!files?.length) { le.innerHTML = ''; if (ee) ee.style.display = 'block'; if (se) se.style.display = 'none'; return; }
        if (ee) ee.style.display = 'none'; if (se) se.style.display = 'flex';
        const total = files.reduce((s, f) => s + (f.originalSize || f.fileSize || 0), 0), anch = files.filter(f => f.chainAnchored).length;
        const ce = document.getElementById('vault-stat-count'), sze = document.getElementById('vault-stat-size'), ae = document.getElementById('vault-stat-anchored');
        if (ce) ce.textContent = files.length; if (sze) sze.textContent = GhostVault.formatBytes(total); if (ae) ae.textContent = anch;

        le.innerHTML = files.map(f => {
            const hasKey = GhostVault.hasKey(f.fileId);
            const sh = f.fileHash ? `SHA-256: ${esc(f.fileHash.substring(0, 8))}...${esc(f.fileHash.slice(-8))}` : '';
            const ts = f.uploadedAt ? new Date(f.uploadedAt).toLocaleDateString(undefined, { month: 'short', day: 'numeric', year: 'numeric' }) : '';
            return `<div class="vault-file-card" data-file-id="${esc(f.fileId || '')}" data-file-name="${esc(f.fileName || '')}">
                <div class="vault-file-header"><div class="vault-file-icon"><i data-lucide="file-lock" style="width:20px;height:20px;"></i></div>
                <div class="vault-file-info"><div class="vault-file-name" title="${esc(f.fileName || '')}">${esc(f.fileName || '')}</div>
                <div class="vault-file-size">${esc(GhostVault.formatBytes(f.originalSize || f.fileSize || 0))} • ${esc(ts)}</div></div></div>
                <div class="vault-chain-badge ${f.chainAnchored ? 'anchored' : 'pending'}"><i data-lucide="${f.chainAnchored ? 'link' : 'clock'}" style="width:10px;height:10px;"></i>
                ${f.chainAnchored ? 'On-Chain' : 'Pending'}${f.txHash ? ` • ${esc(f.txHash.substring(0, 10))}...` : ''}</div>
                <div class="vault-file-hash">${sh}</div>
                <div class="vault-file-actions">
                    <button class="vault-action-btn _vd" ${!hasKey ? 'disabled title="Key not found"' : ''}><i data-lucide="download" style="width:14px;"></i> ${hasKey ? 'Download' : 'No Key'}</button>
                    <button class="vault-action-btn verify _vv"><i data-lucide="shield-check" style="width:14px;"></i> Verify</button>
                    <button class="vault-action-btn danger _vdel"><i data-lucide="trash-2" style="width:14px;"></i></button>
                </div></div>`;
        }).join('');

        le.querySelectorAll('.vault-file-card').forEach(card => { // [X7] DOM handlers
            const fid = card.dataset.fileId, fn = card.dataset.fileName;
            card.querySelector('._vd')?.addEventListener('click', () => UI.vaultDownload(fid));
            card.querySelector('._vv')?.addEventListener('click', () => UI.vaultVerify(fid));
            card.querySelector('._vdel')?.addEventListener('click', () => UI.vaultDelete(fid, fn));
        });
        if (typeof lucide !== 'undefined') lucide.createIcons();
    },

    vaultDownload: async (fid) => { try { await GhostVault.downloadFile(fid); } catch (_) { await showAlert('Download failed. Please try again.'); } },

    vaultDelete: async (fid, fn) => {
        if (!await showConfirm(`Delete "${fn}" permanently? This cannot be undone.`)) return; // [M1]
        try { await GhostVault.deleteFile(fid); UI.vaultLoadFiles(); } catch (_) { await showAlert('Delete failed.'); }
    },

    // [X8] All result fields escaped
    vaultVerify: async (fid) => {
        try {
            const r = await GhostVault.verifyFile(fid);
            if (!r) { await showAlert('Verification failed — file not found.'); return; }
            const modal = document.createElement('div');
            modal.className = 'vault-verify-overlay';
            modal.onclick = e => { if (e.target === modal) modal.remove(); };
            modal.innerHTML = `<div class="vault-verify-card"><h3 style="font-family:var(--font-heading);margin-bottom:16px;color:var(--text-primary);display:flex;align-items:center;gap:8px;"><i data-lucide="shield-check" style="width:20px;color:var(--accent);"></i>Integrity Verification</h3>
                <div class="vault-verify-row"><span class="vault-verify-label">File</span><span class="vault-verify-value">${esc(r.fileName)}</span></div>
                <div class="vault-verify-row"><span class="vault-verify-label">Disk Integrity</span><span class="vault-verify-value ${r.diskIntegrity ? 'pass' : 'fail'}">${r.diskIntegrity ? '✓ PASS' : '✗ TAMPERED'}</span></div>
                <div class="vault-verify-row"><span class="vault-verify-label">Chain Verified</span><span class="vault-verify-value ${r.chainVerified ? 'pass' : 'fail'}">${r.chainVerified ? '✓ ON-CHAIN' : '⚠ PENDING'}</span></div>
                <div class="vault-verify-row"><span class="vault-verify-label">SHA-256</span><span class="vault-verify-value" style="font-size:0.65rem;">${r.storedHash ? esc(r.storedHash.substring(0, 16)) + '...' : 'N/A'}</span></div>
                ${r.txHash ? `<div class="vault-verify-row"><span class="vault-verify-label">TX Hash</span><span class="vault-verify-value" style="font-size:0.65rem;">${esc(r.txHash.substring(0, 16))}...</span></div>` : ''}
                <button class="btn-primary" style="margin-top:16px;">Close</button></div>`;
            document.body.appendChild(modal);
            modal.querySelector('.btn-primary').onclick = () => modal.remove();
            if (typeof lucide !== 'undefined') lucide.createIcons();
        } catch (_) { await showAlert('Verification error. Please try again.'); }
    }
};

// ─── Init ─────────────────────────────────────────────────────────────────────

function renderHome() {
    const hv = document.getElementById('view-home');
    if (hv) { UI.navigate('home'); const sn = document.getElementById('stat-nodes'); if (sn && AppState.peers) sn.innerText = AppState.peers.length; return; }
    const main = document.getElementById('main-content'); if (!main) return;
    main.innerHTML = `<canvas id="mesh" style="width:100%;height:100%;display:block;"></canvas><div class="mesh-overlay" style="position:absolute;top:20px;right:20px;"><div class="stat-item"><span class="label">Peers</span><span class="value">${window.AppState?.peers?.length || 0}</span></div><div class="stat-item"><span class="label">Status</span><span class="value" style="color:#00ff9d;">Active</span></div></div>`;
    new MeshNetwork('mesh');
}

window.UI = UI;
window.esc = esc;
window.addEventListener('DOMContentLoaded', () => { UI.init(); renderHome(); });