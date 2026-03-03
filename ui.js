/**
 * GhostNet Immersive UI
 * Single-file logic for Visualization, State, and Interaction.
 */

// --- GLOBAL STATE ---
window.AppState = {
    meshReady: false,
    wallet: { address: '0x...', balance: 0 },
    peers: [],
    identity: null,
    messages: [],
    files: []
};

// --- MESH VISUALIZATION (CANVAS) ---
class MeshNetwork {
    constructor(canvasId) {
        this.canvas = document.getElementById(canvasId);
        if (!this.canvas) return;
        this.ctx = this.canvas.getContext('2d');
        this.nodes = [];
        this.width = 0;
        this.height = 0;
        this.resize();

        // Listeners
        window.addEventListener('resize', () => this.resize());
        this.initNodes(12);
        this.animate();
    }

    resize() {
        const parent = this.canvas.parentElement;
        this.width = parent.clientWidth;
        this.height = parent.clientHeight;
        this.canvas.width = this.width;
        this.canvas.height = this.height;
    }

    initNodes(count) {
        this.nodes = [];
        // Add Self
        this.nodes.push({
            x: this.width / 2, y: this.height / 2,
            vx: 0, vy: 0,
            type: 'self', size: 6
        });

        // Add Random Peers
        for (let i = 0; i < count; i++) {
            this.nodes.push({
                x: Math.random() * this.width,
                y: Math.random() * this.height,
                vx: (Math.random() - 0.5) * 0.8,
                vy: (Math.random() - 0.5) * 0.8,
                type: 'peer', size: 3
            });
        }
    }

    animate() {
        this.ctx.clearRect(0, 0, this.width, this.height);

        const computed = getComputedStyle(document.documentElement);
        // Using accent as base color, stripping the hash or rgb if needed, but simple fallback works:
        const isDark = document.documentElement.getAttribute('data-theme') === 'dark';
        const accentCol = isDark ? '#3b82f6' : '#2563eb';
        const mutedCol = isDark ? '#334155' : '#cbd5e1';
        // Stroke RGB components for the network lines (blue)
        const rgbStr = isDark ? '59, 130, 246' : '37, 99, 235';

        // Draw Connections
        this.ctx.lineWidth = 1;
        this.nodes.forEach((n1, i) => {
            this.nodes.forEach((n2, j) => {
                if (i >= j) return;
                const dist = Math.hypot(n1.x - n2.x, n1.y - n2.y);
                if (dist < 150) {
                    this.ctx.strokeStyle = `rgba(${rgbStr}, ${1 - dist / 150})`;
                    this.ctx.beginPath();
                    this.ctx.moveTo(n1.x, n1.y);
                    this.ctx.lineTo(n2.x, n2.y);
                    this.ctx.stroke();
                }
            });
        });

        // Update & Draw Nodes
        this.nodes.forEach(n => {
            if (n.type !== 'self') {
                n.x += n.vx;
                n.y += n.vy;

                // Bounce
                if (n.x < 0 || n.x > this.width) n.vx *= -1;
                if (n.y < 0 || n.y > this.height) n.vy *= -1;
            }

            // Glow
            const glow = this.ctx.createRadialGradient(n.x, n.y, n.size / 2, n.x, n.y, n.size * 4);
            glow.addColorStop(0, n.type === 'self' ? accentCol : mutedCol);
            glow.addColorStop(1, 'rgba(0,0,0,0)');

            this.ctx.fillStyle = glow;
            this.ctx.fillRect(n.x - n.size * 4, n.y - n.size * 4, n.size * 8, n.size * 8);

            this.ctx.fillStyle = n.type === 'self' ? accentCol : mutedCol;
            this.ctx.beginPath();
            this.ctx.arc(n.x, n.y, n.size, 0, Math.PI * 2);
            this.ctx.fill();
        });

        requestAnimationFrame(() => this.animate());
    }
}

// --- APP LOGIC ---

const UI = {
    init: () => {
        console.log("SYSTEM: Booting GhostNet UI...");

        // 0. Setup Theme
        UI.initTheme();

        // 1. Setup Nav
        document.querySelectorAll('.nav-btn').forEach(btn => {
            btn.onclick = () => UI.navigate(btn.dataset.target);
        });

        // 2. Start Visualizer
        new MeshNetwork('mesh');

        // 3. Setup Chat
        UI.setupChat();

        // 4. Mock Initial Data (for visual validation)
        setTimeout(() => {
            UI.mockData();
            // Emit Initial State
            window.dispatchEvent(new Event("app:state"));
        }, 800);

        // 5. State Listener
        window.addEventListener("app:state", UI.render);

        // 6. Load Profile
        UI.loadProfile();

        // 7. Init Vault
        UI.initVault();
    },

    navigate: (target) => {
        // Sidebar buttons
        document.querySelectorAll('.nav-btn').forEach(b => {
            if (b.id !== 'theme-toggle') {
                b.classList.toggle('active', b.dataset.target === target);
            }
        });

        // Mobile bottom nav buttons
        document.querySelectorAll('.mobile-nav-item').forEach(b => {
            b.classList.toggle('active', b.dataset.target === target);
        });

        // Sections
        document.querySelectorAll('.view-section').forEach(s =>
            s.classList.toggle('active', s.id === `view-${target}`));

        // Auto-load vault files when navigating to vault
        if (target === 'vault') UI.vaultLoadFiles();

        // Close mobile sidebar if open
        const sidebar = document.getElementById('app-sidebar');
        const overlay = document.getElementById('sidebar-overlay');
        if (sidebar) sidebar.classList.remove('open');
        if (overlay) overlay.classList.remove('visible');

        // Reset chat mobile state (show list by default when entering chat)
        const chatSplit = document.querySelector('.chat-layout-split');
        if (chatSplit) chatSplit.classList.remove('chat-active');
    },

    toggleMobileMenu: () => {
        const sidebar = document.getElementById('app-sidebar');
        const overlay = document.getElementById('sidebar-overlay');
        if (sidebar) sidebar.classList.toggle('open');
        if (overlay) overlay.classList.toggle('visible');
    },

    chatBackToList: () => {
        const chatSplit = document.querySelector('.chat-layout-split');
        if (chatSplit) chatSplit.classList.remove('chat-active');
    },

    initTheme: () => {
        const stored = localStorage.getItem('ghostnet_theme');
        if (stored === 'dark') {
            document.documentElement.setAttribute('data-theme', 'dark');
            const label = document.getElementById('theme-label');
            const icon = document.getElementById('theme-icon');
            if (label) label.innerText = 'Light Mode';
            if (icon) icon.setAttribute('data-lucide', 'sun');
        } else {
            document.documentElement.removeAttribute('data-theme');
        }
        if (typeof lucide !== 'undefined') lucide.createIcons();
    },

    toggleTheme: () => {
        const doc = document.documentElement;
        const current = doc.getAttribute('data-theme');
        const isDark = current === 'dark';

        const label = document.getElementById('theme-label');
        const icon = document.getElementById('theme-icon');

        if (isDark) {
            doc.removeAttribute('data-theme');
            localStorage.setItem('ghostnet_theme', 'light');
            if (label) label.innerText = 'Dark Mode';
            if (icon) icon.setAttribute('data-lucide', 'moon');
        } else {
            doc.setAttribute('data-theme', 'dark');
            localStorage.setItem('ghostnet_theme', 'dark');
            if (label) label.innerText = 'Light Mode';
            if (icon) icon.setAttribute('data-lucide', 'sun');
        }

        if (typeof lucide !== 'undefined') lucide.createIcons();

        // Re-render UI pieces that might have raw js state bindings on mode swaps
        UI.render();
    },

    mockData: () => {
        // Default Mock Data (Fallback)
        AppState.peers = [
            { id: 'node_alpha', type: 'Bridge', latency: 12 },
            { id: 'node_bravo', type: 'Relay', latency: 45 },
            { id: 'node_charlie', type: 'Mobile', latency: 112 },
            { id: 'node_delta', type: 'Desktop', latency: 8 },
        ];
        AppState.wallet = [
            { symbol: "ETH", balance: 0.00, chain: "Sepolia" }, // Will update from backend
            { symbol: "BTC", balance: 0.00, chain: "Bitcoin" }, // Will update from backend
            { symbol: "SOL", balance: 0.00, chain: "Solana" },   // Will update from backend
            { symbol: "USDT", balance: 0.00, chain: "Ethereum" }  // Will update from backend
        ];
        AppState.files = [
            { name: 'encrypted_shard_01.dat', size: '4.2 MB' },
            { name: 'keys_backup.json.enc', size: '12 KB' }
        ];

        // Attempt to fetch real data
        UI.fetchRealData();
    },

    fetchRealData: async () => {
        try {
            console.log("🔗 Connecting to GhostNet Bridge...");

            const res = await fetch(`${import.meta.env.VITE_BRIDGE_URL}/wallet`);

            if (!res.ok) throw new Error("Bridge Error");

            const walletData = await res.json();

            console.log("✅ Bridge Data Received:", walletData);

            if (Array.isArray(walletData)) {
                AppState.wallet = walletData;
            }

            console.log("Wallet hydrated:", AppState.wallet);

            // Re-render
            window.dispatchEvent(new Event("app:state"));

        } catch (e) {
            console.warn("⚠️ Bridge Disconnected (Using Fallback Data):", e);

            // Safety: Fallback if fetch fails
            if (!AppState.wallet || AppState.wallet.length === 0) {
                AppState.wallet = [
                    { symbol: "ETH", balance: 0.0, chain: "Sepolia", address: "0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045" },
                    { symbol: "BTC", balance: 0.0, chain: "Bitcoin", address: "tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx" },
                    { symbol: "SOL", balance: 0.0, chain: "Solana", address: "HN7cABqLq46Es1jh92dQQisAq662SmxELLLsHHe4YWrH" },
                    { symbol: "USDT", balance: 0.0, chain: "Ethereum", address: "0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045" }
                ];
                console.log("Wallet hydrated (FALLBACK)::", AppState.wallet);
                window.dispatchEvent(new Event("app:state"));
            }
        }
    },

    openReceive: (symbol, address) => {
        // Construct URI Scheme for Wallets
        let qrData = address;
        if (symbol === 'BTC') qrData = `bitcoin:${address}`;
        else if (symbol === 'ETH' || symbol === 'USDT') qrData = `ethereum:${address}`; // USDT typically on ETH chain here
        else if (symbol === 'SOL') qrData = `solana:${address}`;

        const qrUrl = `https://api.qrserver.com/v1/create-qr-code/?size=200x200&data=${encodeURIComponent(qrData)}`;

        const modal = document.createElement('div');
        modal.className = "modal-overlay";
        modal.innerHTML = `
            <div class="modal-card">
                <button class="modal-close" onclick="this.closest('.modal-overlay').remove()">×</button>
                <div class="modal-title">Receive ${symbol}</div>
                <img src="${qrUrl}" class="qr-code">
                <div class="input-group">
                    <label class="input-label">YOUR ADDRESS</label>
                    <input type="text" class="modal-input" value="${address}" readonly onclick="this.select()">
                </div>
                <div style="font-size:0.8rem; color:#8b9bb4; margin-top:10px;">
                    Scan to send ${symbol} to this address.
                </div>
            </div>
        `;
        document.body.appendChild(modal);
    },

    openSend: (symbol) => {
        const modal = document.createElement('div');
        modal.className = "modal-overlay";
        modal.innerHTML = `
            <div class="modal-card">
                <button class="modal-close" onclick="this.closest('.modal-overlay').remove()">×</button>
                <div class="modal-title">Send ${symbol}</div>
                
                <div class="input-group">
                    <label class="input-label">RECIPIENT ADDRESS</label>
                    <input type="text" id="send-to" class="modal-input" placeholder="0x...">
                </div>
                
                <div class="input-group">
                     <label class="input-label">AMOUNT</label>
                    <input type="number" id="send-amount" class="modal-input" placeholder="0.00">
                </div>

                <button class="btn-primary" onclick="UI.submitSend('${symbol}')">CONFIRM TRANSACTION</button>
            </div>
        `;
        document.body.appendChild(modal);
    },

    submitSend: async (symbol) => {
        const to = document.getElementById('send-to').value;
        const amount = document.getElementById('send-amount').value;

        if (!to || !amount) return alert("Please fill all fields");

        // Close Modal
        document.querySelector('.modal-overlay').remove();

        // Optimistic UI
        alert(`Transaction Broadcasted!\nSending ${amount} ${symbol} to ${to}`);

        try {
            await fetch('http://localhost:3001/wallet/send', {
                method: 'POST',
                body: JSON.stringify({ symbol, to, amount })
            });
        } catch (e) { console.error(e); }
    },

    openNewChat: () => {
        const modal = document.createElement('div');
        modal.className = "modal-overlay";
        modal.innerHTML = `
            <div class="modal-card">
                <button class="modal-close" onclick="this.closest('.modal-overlay').remove()">×</button>
                <div class="modal-title">New Encrypted Chat</div>
                
                <div class="input-group">
                    <label class="input-label">CONTACT NAME</label>
                    <input type="text" id="chat-name" class="modal-input" placeholder="e.g. Alice">
                </div>
                
                <div class="input-group">
                    <label class="input-label">NODE ID / PUBLIC KEY</label>
                    <input type="text" id="chat-pubkey" class="modal-input" placeholder="0x...">
                </div>

                <button class="btn-primary" onclick="UI.submitNewChat()">START SESSION</button>
            </div>
        `;
        document.body.appendChild(modal);
    },

    submitNewChat: () => {
        const name = document.getElementById('chat-name').value;
        const pubKey = document.getElementById('chat-pubkey').value;

        if (!name || !pubKey) return alert("Please fill details");

        document.querySelector('.modal-overlay').remove();

        // Clear feed for new chat effect
        const feed = document.getElementById('chat-feed');
        if (feed) {
            feed.innerHTML = `<div style="text-align:center;color:#64748b;font-size:0.8rem;margin:20px;">-- Session with ${name} Started --</div>`;
        }

        // Setup app state target
        if (window.app) {
            window.app.chatTarget = pubKey;
        }

        UI.selectChat('new', name, pubKey);
    },

    loadConversations: async (userId) => {
        try {
            const res = await fetch(`https://ghostnet-ji-production.up.railway.app/conversations?userId=${userId}`);
            if (res.ok) {
                const convos = await res.json();
                UI.renderConversations(convos);
            }
        } catch (e) {
            console.error("Failed to load conversations:", e);
        }
    },

    renderConversations: (convos) => {
        const list = document.getElementById('chat-user-list');
        if (!list) return;

        list.innerHTML = '';

        if (convos.length === 0) {
            list.innerHTML = `<div style="padding:20px; text-align:center; color:#64748b; font-size:0.8rem;">No conversations yet.</div>`;
            return;
        }

        let html = '';
        convos.forEach(c => {
            const timeStr = new Date(c.updated).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
            const avatar = c.otherUser && c.otherUser.avatar
                ? `<img src="${c.otherUser.avatar}" class="chat-avatar" style="object-fit:cover;">`
                : `<div class="chat-avatar" style="background: #3f3f46;"></div>`;

            const username = c.otherUser ? (c.otherUser.username || c.otherUser.address || c.otherUser.id) : 'Unknown';
            let preview = c.lastMessage || 'Message...';
            if (typeof preview === 'object' && preview.body) preview = preview.body;
            if (typeof preview === 'string' && preview.includes('body":"')) {
                try { preview = JSON.parse(preview).body; } catch (e) { }
            }

            const activeClass = (AppState.activeConvoId === c.id) ? 'active' : '';

            html += `
                <div class="chat-user-row ${activeClass}" onclick="UI.selectChat('${c.id}', '${username}', '${c.otherUser ? c.otherUser.id : ''}')" data-convo="${c.id}">
                    <div class="chat-avatar-wrap">
                        ${avatar}
                    </div>
                    <div class="chat-user-info">
                        <div class="chat-user-top">
                            <span class="chat-username">${username}</span>
                            <span class="chat-time">${timeStr}</span>
                        </div>
                        <div class="chat-user-bottom">
                            <span class="chat-preview">${preview}</span>
                        </div>
                    </div>
                </div>
            `;
        });
        list.innerHTML = html;
    },

    selectChat: async (convoId, nameStr = null, targetUserId = null) => {
        // Toggle UI Panels
        const emptyState = document.getElementById('chat-empty-state');
        const activeState = document.getElementById('chat-active-state');
        if (emptyState) emptyState.style.display = 'none';
        if (activeState) activeState.style.display = 'flex';

        // Mobile: switch to chat view
        const chatSplit = document.querySelector('.chat-layout-split');
        if (chatSplit) chatSplit.classList.add('chat-active');

        // Setup Active Header visually
        const label = document.getElementById('label-transport');
        if (label) {
            label.innerText = nameStr ? nameStr : targetUserId;
        }

        // Store active targets state globally
        AppState.activeConvoId = convoId;
        if (window.app) {
            window.app.chatTarget = targetUserId;
            window.app.chatContactName = nameStr || targetUserId;
        }

        // Visual selection
        document.querySelectorAll('.chat-user-row').forEach(row => {
            row.classList.remove('active');
            if (row.dataset.convo === convoId) row.classList.add('active');
        });

        const feed = document.getElementById('chat-feed');
        if (feed) feed.innerHTML = ''; // clear current feed

        // Load History
        if (convoId && convoId !== 'new') {
            try {
                const res = await fetch(`/history?convoId=${convoId}`);
                if (res.ok) {
                    const msgs = await res.json();
                    msgs.forEach(m => {
                        const myId = AppState.identity ? AppState.identity.id : null;
                        const type = (m.senderId === myId) ? 'me' : 'them';

                        let text = m.content;
                        if (typeof text === 'object' && text.body) text = text.body;
                        if (typeof text === 'string' && text.includes('body":"')) {
                            try { text = JSON.parse(text).body; } catch (e) { }
                        }
                        UI.addMessage(text || '***', type);
                    });
                }
            } catch (e) { console.error("Error loading history", e) }
        }
    },

    render: () => {
        UI.renderWallet();
        UI.renderDiscoverNodes();
        UI.renderStorage();
        UI.updateChatStatus(); // New Method

        // Update Stats
        const statNodes = document.getElementById('stat-nodes');
        if (statNodes) statNodes.innerText = AppState.peers.length;
    },

    updateChatStatus: () => {
        const btnLabel = document.getElementById('btn-ble-label');
        const btnScan = document.getElementById('btn-ble-scan');
        if (!btnLabel || !btnScan) return;

        let blePeers = 0;
        let totalPeers = 0;

        if (window.app && window.app.mesh) {
            const status = window.app.mesh.getStatus();
            blePeers = status.blePeers;
            totalPeers = status.totalPeers;
        }

        // Update scan button text
        if (blePeers > 0) {
            btnLabel.textContent = `BLE (${blePeers})`;
            btnScan.style.borderColor = 'var(--accent)';
            btnScan.style.color = 'var(--accent)';
            btnScan.style.background = 'var(--accent-dim)';
        } else {
            btnLabel.textContent = 'Scan';
            btnScan.style.borderColor = '';
            btnScan.style.color = '';
            btnScan.style.background = '';
        }

        if (typeof lucide !== 'undefined') lucide.createIcons();
    },

    // --- RENDERERS ---

    renderWallet: () => {
        const el = document.getElementById('wallet');
        if (!el) return;

        const CRYPTO_LOGOS = {
            'ETH': 'https://assets.coingecko.com/coins/images/279/small/ethereum.png',
            'BTC': 'https://assets.coingecko.com/coins/images/1/small/bitcoin.png',
            'SOL': 'https://assets.coingecko.com/coins/images/4128/small/solana.png',
            'USDT': 'https://assets.coingecko.com/coins/images/325/small/Tether.png',
            'AHT': 'https://assets.coingecko.com/coins/images/279/small/ethereum.png'
        };

        const CRYPTO_META = {
            'ETH': { color: '#627EEA', gradient: 'linear-gradient(135deg, #627EEA, #3b5fc0)', darkGlow: 'rgba(98,126,234,0.35)', name: 'Ethereum' },
            'BTC': { color: '#F7931A', gradient: 'linear-gradient(135deg, #F7931A, #e2750a)', darkGlow: 'rgba(247,147,26,0.35)', name: 'Bitcoin' },
            'SOL': { color: '#9945FF', gradient: 'linear-gradient(135deg, #9945FF, #14F195)', darkGlow: 'rgba(153,69,255,0.35)', name: 'Solana' },
            'USDT': { color: '#26A17B', gradient: 'linear-gradient(135deg, #26A17B, #1a7a5c)', darkGlow: 'rgba(38,161,123,0.35)', name: 'Tether' },
            'AHT': { color: '#3b82f6', gradient: 'linear-gradient(135deg, #3b82f6, #8b5cf6)', darkGlow: 'rgba(59,130,246,0.35)', name: 'GhostNet' }
        };

        let walletAssets = [];
        if (Array.isArray(AppState.wallet)) {
            walletAssets = AppState.wallet;
        } else if (AppState.wallet && AppState.wallet.balance) {
            walletAssets = [
                { symbol: "AHT", balance: AppState.wallet.balance, chain: "GhostNet" },
                { symbol: "ETH", balance: 0.0, chain: "Sepolia" }
            ];
        }

        const totalBalance = walletAssets.reduce((sum, a) => sum + (a.balance || 0), 0);

        // Portfolio Overview Banner
        let html = `
            <div class="wlt-portfolio-banner">
                <div class="wlt-portfolio-left">
                    <div class="wlt-portfolio-label">Portfolio Value</div>
                    <div class="wlt-portfolio-total">${totalBalance.toLocaleString(undefined, { minimumFractionDigits: 2, maximumFractionDigits: 4 })}</div>
                    <div class="wlt-portfolio-subtitle">${walletAssets.length} Assets · GhostNet Wallet</div>
                </div>
                <div class="wlt-portfolio-tokens">
                    ${walletAssets.map(a => {
            const m = CRYPTO_META[a.symbol] || CRYPTO_META['ETH'];
            return `<div class="wlt-mini-token" style="--tc:${m.color}">
                            <img src="${CRYPTO_LOGOS[a.symbol] || CRYPTO_LOGOS['ETH']}" alt="${a.symbol}" width="20" height="20">
                        </div>`;
        }).join('')}
                </div>
            </div>
            <div class="wlt-grid">
        `;

        walletAssets.forEach((asset, i) => {
            const addrDisplay = asset.address ? `${asset.address.substring(0, 6)}···${asset.address.substring(asset.address.length - 4)}` : "Not Connected";
            const logo = CRYPTO_LOGOS[asset.symbol] || CRYPTO_LOGOS['ETH'];
            const meta = CRYPTO_META[asset.symbol] || CRYPTO_META['ETH'];
            const delay = i * 0.1;

            html += `
              <div class="wlt-card-outer" style="--c1:${meta.color}; --cg:${meta.gradient}; --cd:${meta.darkGlow}; animation-delay:${delay}s;">
                <div class="wlt-card">
                    <!-- Decorative elements -->
                    <div class="wlt-card-orb"></div>
                    <div class="wlt-card-line"></div>

                    <!-- Top: Logo + Info -->
                    <div class="wlt-card-top">
                        <div class="wlt-logo-ring">
                            <div class="wlt-logo-inner">
                                <img src="${logo}" alt="${asset.symbol}" width="28" height="28" onerror="this.style.display='none'">
                            </div>
                        </div>
                        <div class="wlt-card-info">
                            <div class="wlt-card-name">${asset.symbol}<span class="wlt-card-fullname">${meta.name}</span></div>
                            <div class="wlt-card-chain-row">
                                <span class="wlt-chain-badge">${asset.chain}</span>
                                <span class="wlt-status-dot"></span>
                            </div>
                        </div>
                    </div>

                    <!-- Middle: Balance -->
                    <div class="wlt-card-mid">
                        <div class="wlt-bal-value">${asset.balance.toLocaleString(undefined, { minimumFractionDigits: 2, maximumFractionDigits: 6 })}</div>
                        <div class="wlt-bal-label">${asset.symbol} Balance</div>
                    </div>

                    <!-- Address chip -->
                    <div class="wlt-addr-chip" title="${asset.address || ''}">
                        <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="9" y="9" width="13" height="13" rx="2"/><path d="M5 15H4a2 2 0 01-2-2V4a2 2 0 012-2h9a2 2 0 012 2v1"/></svg>
                        <span>${addrDisplay}</span>
                    </div>

                    <!-- Bottom: Actions -->
                    <div class="wlt-card-actions">
                         <button class="wlt-btn wlt-btn-send" onclick="UI.openSend('${asset.symbol}')">
                            <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><line x1="12" y1="19" x2="12" y2="5"/><polyline points="5 12 12 5 19 12"/></svg>
                            Send
                         </button>
                         <button class="wlt-btn wlt-btn-recv" onclick="UI.openReceive('${asset.symbol}', '${asset.address || ""}')">
                            <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><line x1="12" y1="5" x2="12" y2="19"/><polyline points="19 12 12 19 5 12"/></svg>
                            Receive
                         </button>
                    </div>
                </div>
              </div>
            `;
        });

        html += `</div>`;
        el.innerHTML = html;
    },

    renderDiscoverNodes: () => {
        const el = document.getElementById('discover-nodes');
        if (!el) return;

        // --- BLE STATUS HEADER ---
        let bleActive = false;
        if (window.app && window.app.transport && window.app.transport.ble) {
            bleActive = app.transport.ble.peers.size > 0;
        }

        let html = `
            <div style="width:100%; grid-column: 1 / -1; margin-bottom: 20px; display:flex; justify-content:space-between; align-items:center; background:var(--bg-panel); padding:15px; border-radius:16px; border:1px solid var(--border); box-shadow:var(--glow);">
                <div style="display:flex; align-items:center; gap:15px;">
                    <div style="width:40px; height:40px; background:var(--accent-dim); border-radius:50%; display:flex; align-items:center; justify-content:center; color:var(--accent);">
                        <i data-lucide="bluetooth"></i>
                    </div>
                    <div>
                        <div style="font-weight:bold; color:var(--text-primary);">BLE Mesh Layer</div>
                        <div style="font-size:0.8rem; color:var(--text-muted);">Local-First Transport</div>
                    </div>
                </div>
                
                <div style="display:flex; align-items:center; gap:10px;">
                     <div class="status-badge ${bleActive ? 'active' : ''}">
                        ${bleActive ? '🟢 Active' : '⚪ Idle'}
                    </div>
                    <button class="btn-primary small" onclick="window.app.transport.startBLEScan()">
                        SCAN NETWORK
                    </button>
                </div>
            </div>
        `;

        // --- MERGE PEERS ---
        // Combine AppState.peers (Simulated/Mock) with Real BLE Peers
        let allPeers = [...AppState.peers];

        // Add BLE Peers if available
        if (window.app && window.app.transport && window.app.transport.ble) {
            window.app.transport.ble.peers.forEach(p => {
                // Check if already exists to avoid duplicates
                if (!allPeers.find(ep => ep.id === p.id)) {
                    allPeers.push({
                        id: p.id,
                        type: 'BLE',
                        latency: Math.floor(Math.random() * 20) + 10, // Mock latency for BLE
                        verified: true
                    });
                }
            });
        }

        html += allPeers.map(p => `
            <div class="node-card">
                <div style="display:flex; justify-content:space-between; align-items:center;">
                    <div class="node-address" style="color:var(--accent);">${p.id}</div>
                    <div style="font-size:0.8rem; color:${p.latency < 50 ? '#10b981' : '#f59e0b'}">${p.latency || '??'}ms</div>
                </div>
                <div class="node-meta">${p.type} Node • Verified</div>
                ${p.type === 'BLE' ? '<div style="margin-top:5px; font-size:0.75rem; color:#10b981;">via Bluetooth Mesh</div>' : ''}
                <div style="margin-top:10px; height:4px; background:var(--border); border-radius:2px; overflow:hidden;">
                    <div style="width: ${Math.random() * 100}%; height:100%; background:${p.type === 'BLE' ? '#10b981' : 'var(--text-muted)'};"></div>
                </div>
            </div>
        `).join('');

        el.innerHTML = html;
        if (typeof lucide !== 'undefined') lucide.createIcons();
    },

    renderStorage: () => {
        const el = document.getElementById('storage');
        if (!el) return;

        el.innerHTML = AppState.files.map(f => `
            <div class="file-card" style="display:flex; align-items:center; gap:15px;">
                <i data-lucide="file-lock" style="color:var(--text-muted);"></i>
                <div style="flex:1;">
                    <div style="color:var(--text-primary); font-family:monospace; font-weight:500;">${f.name}</div>
                    <div style="font-size:0.8rem; color:var(--text-muted);">${f.size}</div>
                </div>
                <button style="background:none; border:none; color:var(--accent); cursor:pointer;"><i data-lucide="download"></i></button>
            </div>
        `).join('');
        if (typeof lucide !== 'undefined') lucide.createIcons();
    },

    // --- INTERACTION ---
    setupChat: () => {
        const btn = document.getElementById('chat-send');
        const input = document.getElementById('chat-input');
        const modes = document.querySelectorAll('.mode-btn');

        if (btn && input) {
            btn.onclick = async () => {
                // Delegate to app.js sendMessage if available (it handles HTTP persistence)
                if (window.app && window.app.sendMessage) {
                    await window.app.sendMessage();
                    return;
                }

                // Fallback: directly persist via HTTP if app.sendMessage not wired yet
                const text = input.value.trim();
                if (!text) return;
                UI.addMessage(text, 'me');
                input.value = '';

                // Direct HTTP persistence fallback
                const myId = (window.AppState && window.AppState.identity) ? window.AppState.identity.id : 'anonymous';
                const targetId = (window.app && window.app.chatTarget) || 'broadcast';
                try {
                    const res = await fetch('/message', {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify({
                            senderId: myId,
                            receiverId: targetId,
                            content: { body: text, from: myId, to: targetId, ts: Date.now(), type: 'MSG' }
                        })
                    });
                    const result = await res.json();
                    if (result.success && result.convo) {
                        AppState.activeConvoId = result.convo.id;
                        UI.loadConversations(myId);
                    }
                } catch (e) {
                    console.error("Direct HTTP fallback failed:", e);
                }
            };

            input.onkeypress = (e) => {
                if (e.key === 'Enter') btn.click();
            };
        }

        modes.forEach(m => {
            m.onclick = () => {
                modes.forEach(b => b.classList.remove('active'));
                m.classList.add('active');
            }
        });
    },

    // Start UI Logic
    addMessage: (text, type) => {
        const feed = document.getElementById('chat-feed');
        if (!feed) return;

        const msg = document.createElement('div');
        msg.className = `message ${type}`;
        msg.innerText = text;
        feed.appendChild(msg);
        feed.scrollTop = feed.scrollHeight;
    },

    promptFileType: () => {
        const modal = document.createElement('div');
        modal.className = "modal-overlay";
        modal.innerHTML = `
            <div class="modal-card">
                <button class="modal-close" onclick="this.closest('.modal-overlay').remove()">×</button>
                <div class="modal-title">Select Attachment Type</div>
                
                <div style="display:grid; grid-template-columns:1fr 1fr; gap:15px; margin-top:20px;">
                    <button class="btn-primary" onclick="UI.triggerFile('image/*')">
                        <i data-lucide="image"></i> Image
                    </button>
                    <button class="btn-primary" onclick="UI.triggerFile('video/*')">
                        <i data-lucide="video"></i> Video
                    </button>
                    <button class="btn-primary" onclick="UI.triggerFile('.pdf,.doc,.docx,.txt')">
                        <i data-lucide="file-text"></i> Document
                    </button>
                    <button class="btn-primary" onclick="UI.triggerFile('*')">
                        <i data-lucide="file"></i> Any
                    </button>
                </div>
            </div>
        `;
        document.body.appendChild(modal);
        if (typeof lucide !== 'undefined') lucide.createIcons();
    },

    triggerFile: (acceptType) => {
        const input = document.getElementById('chat-file');
        if (input) {
            input.accept = acceptType;
            input.click();
        }
        document.querySelector('.modal-overlay').remove();
    },

    loadProfile: () => {
        const stored = localStorage.getItem('ghostnet_user');
        if (stored) {
            try {
                const user = JSON.parse(stored);
                // Keep identity in global state
                AppState.identity = user;

                // Update Sidebar
                const sidebarProfile = document.getElementById('sidebar-profile');
                const sidebarAvatar = document.getElementById('sidebar-avatar');
                const sidebarAddress = document.getElementById('sidebar-address');
                const sidebarId = document.getElementById('sidebar-id');

                if (sidebarProfile) {
                    sidebarProfile.style.display = 'flex';
                    if (user.avatar) {
                        sidebarAvatar.src = user.avatar;
                        sidebarAvatar.style.display = 'block';
                    } else {
                        sidebarAvatar.style.display = 'none';
                    }
                    sidebarAddress.innerText = user.username || user.address || '';
                    sidebarId.innerText = user.id || '';
                }

                // Update Profile View
                const viewAddress = document.getElementById('profile-address');
                const viewPreview = document.getElementById('profile-preview');
                const viewId = document.getElementById('profile-id-display');

                if (viewAddress) viewAddress.value = user.username || user.address || '';
                if (viewId) viewId.innerText = 'Current ID: ' + (user.id || '');
                if (viewPreview && user.avatar) {
                    viewPreview.src = user.avatar;
                    viewPreview.style.display = 'block';
                }

                // Load conversations for this user
                UI.loadConversations(user.id);
            } catch (e) {
                console.error("Error parsing user profile", e);
                if (AppState && AppState.identity && AppState.identity.id) {
                    UI.loadConversations(AppState.identity.id);
                }
            }
        } else {
            // No custom profile saved, but we still have a stable AppState identity from app.js
            if (AppState && AppState.identity && AppState.identity.id) {
                UI.loadConversations(AppState.identity.id);
            }
        }

        // Setup file upload preview
        const fileInput = document.getElementById('profile-avatar-upload');
        if (fileInput) {
            fileInput.onchange = (e) => {
                const file = e.target.files[0];
                if (file) {
                    const reader = new FileReader();
                    reader.onload = (event) => {
                        const viewPreview = document.getElementById('profile-preview');
                        if (viewPreview) {
                            viewPreview.src = event.target.result;
                            viewPreview.style.display = 'block';
                        }
                    };
                    reader.readAsDataURL(file);
                }
            };
        }
    },

    saveProfile: () => {
        const addr = document.getElementById('profile-address').value;
        const viewPreview = document.getElementById('profile-preview');
        let avatarData = viewPreview ? viewPreview.getAttribute('src') : '';
        if (avatarData && !avatarData.startsWith('data:')) {
            avatarData = '';
        }

        fetch("/create-user", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({
                username: addr,
                avatar: avatarData
            })
        })
            .then(res => res.json())
            .then(data => {
                if (data.error) {
                    alert(data.error + "\\nSuggestions:\\n" + (data.suggestions ? data.suggestions.join("\\n") : ""));
                } else {
                    alert("User created!");
                    localStorage.setItem("ghostnet_user", JSON.stringify(data.user));
                    UI.loadProfile();
                }
            })
            .catch(err => {
                console.error("Save profile error:", err);
                alert("Failed to connect to the server.");
            });
    },

    // ═══════════════════════════════════════════════════
    //  FILE VAULT UI
    // ═══════════════════════════════════════════════════

    initVault: () => {
        const dropZone = document.getElementById('vault-drop-zone');
        const fileInput = document.getElementById('vault-file-input');
        const browseBtn = document.getElementById('vault-browse-btn');

        if (!dropZone || !fileInput) return;

        // Browse button
        browseBtn?.addEventListener('click', (e) => {
            e.stopPropagation();
            fileInput.click();
        });

        // Drop zone click
        dropZone.addEventListener('click', () => fileInput.click());

        // File input change
        fileInput.addEventListener('change', (e) => {
            const files = Array.from(e.target.files);
            if (files.length > 0) UI.vaultUploadFiles(files);
            fileInput.value = ''; // Reset
        });

        // Drag & Drop
        dropZone.addEventListener('dragover', (e) => {
            e.preventDefault();
            dropZone.classList.add('drag-over');
        });

        dropZone.addEventListener('dragleave', () => {
            dropZone.classList.remove('drag-over');
        });

        dropZone.addEventListener('drop', (e) => {
            e.preventDefault();
            dropZone.classList.remove('drag-over');
            const files = Array.from(e.dataTransfer.files);
            if (files.length > 0) UI.vaultUploadFiles(files);
        });

        // Load existing files
        UI.vaultLoadFiles();
    },

    vaultUploadFiles: async (files) => {
        if (!window.GhostVault) {
            alert('Vault encryption module not loaded.');
            return;
        }

        const progressEl = document.getElementById('vault-upload-progress');
        const stageEl = document.getElementById('vault-progress-stage');
        const barEl = document.getElementById('vault-progress-bar');
        const detailEl = document.getElementById('vault-progress-detail');
        const iconEl = document.getElementById('vault-progress-icon');

        for (const file of files) {
            // Show progress
            if (progressEl) progressEl.style.display = 'block';

            const stages = {
                encrypting: { text: '🔐 Encrypting...', detail: `AES-256-GCM encrypting "${file.name}"`, icon: 'shield', percent: 30 },
                uploading: { text: '📤 Uploading...', detail: `Sending encrypted blob to vault`, icon: 'upload-cloud', percent: 65 },
                anchoring: { text: '⛓️ Anchoring on chain...', detail: `Recording SHA-256 hash on blockchain`, icon: 'link', percent: 90 },
                complete: { text: '✅ Secured!', detail: `"${file.name}" encrypted & anchored`, icon: 'check-circle', percent: 100 }
            };

            try {
                const result = await GhostVault.uploadFile(file, (progress) => {
                    const stage = stages[progress.stage] || stages.encrypting;
                    if (stageEl) stageEl.textContent = stage.text;
                    if (barEl) barEl.style.width = stage.percent + '%';
                    if (detailEl) detailEl.textContent = stage.detail;
                    if (iconEl) {
                        iconEl.innerHTML = `<i data-lucide="${stage.icon}" style="width:32px; height:32px;"></i>`;
                        if (typeof lucide !== 'undefined') lucide.createIcons();
                    }
                });

                console.log('✅ Vault upload complete:', result);
            } catch (err) {
                console.error('❌ Vault upload failed:', err);
                if (stageEl) stageEl.textContent = '❌ Upload Failed';
                if (detailEl) detailEl.textContent = err.message;
                if (barEl) barEl.style.width = '0%';
            }

            // Hide progress after delay
            await new Promise(r => setTimeout(r, 1500));
            if (progressEl) progressEl.style.display = 'none';
            if (barEl) barEl.style.width = '0%';
        }

        // Refresh file list
        UI.vaultLoadFiles();
    },

    vaultLoadFiles: async () => {
        if (!window.GhostVault) return;

        try {
            const files = await GhostVault.listFiles();
            UI.vaultRenderFiles(files);
        } catch (err) {
            console.warn('Vault load failed:', err);
        }
    },

    vaultRenderFiles: (files) => {
        const listEl = document.getElementById('vault-file-list');
        const emptyEl = document.getElementById('vault-empty');
        const statsEl = document.getElementById('vault-stats');

        if (!listEl) return;

        if (!files || files.length === 0) {
            listEl.innerHTML = '';
            if (emptyEl) emptyEl.style.display = 'block';
            if (statsEl) statsEl.style.display = 'none';
            return;
        }

        if (emptyEl) emptyEl.style.display = 'none';
        if (statsEl) statsEl.style.display = 'flex';

        // Update stats
        const countEl = document.getElementById('vault-stat-count');
        const sizeEl = document.getElementById('vault-stat-size');
        const anchoredEl = document.getElementById('vault-stat-anchored');
        const totalSize = files.reduce((s, f) => s + (f.originalSize || f.fileSize || 0), 0);
        const anchored = files.filter(f => f.chainAnchored).length;

        if (countEl) countEl.textContent = files.length;
        if (sizeEl) sizeEl.textContent = GhostVault.formatBytes(totalSize);
        if (anchoredEl) anchoredEl.textContent = anchored;

        // Render file cards
        listEl.innerHTML = files.map(f => {
            const hasKey = GhostVault.hasKey(f.fileId);
            const shortHash = f.fileHash ? `SHA-256: ${f.fileHash.substring(0, 8)}...${f.fileHash.substring(f.fileHash.length - 8)}` : '';
            const timeStr = f.uploadedAt ? new Date(f.uploadedAt).toLocaleDateString(undefined, { month: 'short', day: 'numeric', year: 'numeric' }) : '';
            const sizeStr = GhostVault.formatBytes(f.originalSize || f.fileSize || 0);

            return `
                <div class="vault-file-card" data-file-id="${f.fileId}">
                    <div class="vault-file-header">
                        <div class="vault-file-icon">
                            <i data-lucide="file-lock" style="width:20px; height:20px;"></i>
                        </div>
                        <div class="vault-file-info">
                            <div class="vault-file-name" title="${f.fileName}">${f.fileName}</div>
                            <div class="vault-file-size">${sizeStr} • ${timeStr}</div>
                        </div>
                    </div>
                    <div class="vault-chain-badge ${f.chainAnchored ? 'anchored' : 'pending'}">
                        <i data-lucide="${f.chainAnchored ? 'link' : 'clock'}" style="width:10px; height:10px;"></i>
                        ${f.chainAnchored ? 'On-Chain' : 'Pending'}
                        ${f.txHash ? ` • ${f.txHash.substring(0, 10)}...` : ''}
                    </div>
                    <div class="vault-file-hash">${shortHash}</div>
                    <div class="vault-file-actions">
                        <button class="vault-action-btn" onclick="UI.vaultDownload('${f.fileId}')" ${!hasKey ? 'disabled title="Key not found on this device"' : ''}>
                            <i data-lucide="download" style="width:14px;"></i> ${hasKey ? 'Download' : 'No Key'}
                        </button>
                        <button class="vault-action-btn verify" onclick="UI.vaultVerify('${f.fileId}')">
                            <i data-lucide="shield-check" style="width:14px;"></i> Verify
                        </button>
                        <button class="vault-action-btn danger" onclick="UI.vaultDelete('${f.fileId}', '${f.fileName.replace(/'/g, "\\'")}')">
                            <i data-lucide="trash-2" style="width:14px;"></i>
                        </button>
                    </div>
                </div>
            `;
        }).join('');

        if (typeof lucide !== 'undefined') lucide.createIcons();
    },

    vaultDownload: async (fileId) => {
        try {
            await GhostVault.downloadFile(fileId);
        } catch (err) {
            alert('Download failed: ' + err.message);
        }
    },

    vaultDelete: async (fileId, fileName) => {
        if (!confirm(`Delete "${fileName}" permanently?\n\nThis will remove the file from the vault. The blockchain record will be marked as deleted.`)) return;

        try {
            await GhostVault.deleteFile(fileId);
            console.log('🗑️ File deleted:', fileId);
            UI.vaultLoadFiles();
        } catch (err) {
            alert('Delete failed: ' + err.message);
        }
    },

    vaultVerify: async (fileId) => {
        try {
            const result = await GhostVault.verifyFile(fileId);
            if (!result) {
                alert('Verification failed — file not found.');
                return;
            }

            // Show verify modal
            const modal = document.createElement('div');
            modal.className = 'vault-verify-overlay';
            modal.onclick = (e) => { if (e.target === modal) modal.remove(); };
            modal.innerHTML = `
                <div class="vault-verify-card">
                    <h3 style="font-family:var(--font-heading); margin-bottom:16px; color:var(--text-primary); display:flex; align-items:center; gap:8px;">
                        <i data-lucide="shield-check" style="width:20px; color:var(--accent);"></i>
                        Integrity Verification
                    </h3>
                    <div class="vault-verify-row">
                        <span class="vault-verify-label">File</span>
                        <span class="vault-verify-value">${result.fileName}</span>
                    </div>
                    <div class="vault-verify-row">
                        <span class="vault-verify-label">Disk Integrity</span>
                        <span class="vault-verify-value ${result.diskIntegrity ? 'pass' : 'fail'}">
                            ${result.diskIntegrity ? '✅ PASS' : '❌ TAMPERED'}
                        </span>
                    </div>
                    <div class="vault-verify-row">
                        <span class="vault-verify-label">Chain Verified</span>
                        <span class="vault-verify-value ${result.chainVerified ? 'pass' : 'fail'}">
                            ${result.chainVerified ? '✅ ON-CHAIN' : '⏳ PENDING'}
                        </span>
                    </div>
                    <div class="vault-verify-row">
                        <span class="vault-verify-label">SHA-256 Hash</span>
                        <span class="vault-verify-value" style="font-size:0.65rem;">${result.storedHash ? result.storedHash.substring(0, 16) + '...' : 'N/A'}</span>
                    </div>
                    ${result.txHash ? `
                    <div class="vault-verify-row">
                        <span class="vault-verify-label">TX Hash</span>
                        <span class="vault-verify-value" style="font-size:0.65rem;">${result.txHash.substring(0, 16)}...</span>
                    </div>` : ''}
                    <button class="btn-primary" onclick="this.closest('.vault-verify-overlay').remove()" style="margin-top:16px;">Close</button>
                </div>
            `;
            document.body.appendChild(modal);
            if (typeof lucide !== 'undefined') lucide.createIcons();
        } catch (err) {
            alert('Verification error: ' + err.message);
        }
    }
};

// --- RENDER HOME & INIT ---
function renderHome() {
    // If our fancy UI structure exists, just ensure it's active
    const homeView = document.getElementById('view-home');
    if (homeView) {
        UI.navigate('home');
        // Ensure stats are updated
        const statNodes = document.getElementById('stat-nodes');
        if (statNodes && AppState.peers) statNodes.innerText = AppState.peers.length;
        return;
    }

    // Fallback: If minimal mode (no views), inject minimal HTML
    const main = document.getElementById("main-content");
    if (!main) return;

    main.innerHTML = `
        <canvas id="mesh" style="width:100%;height:100%;display:block;"></canvas>
        <div class="mesh-overlay" style="position:absolute;top:20px;right:20px;">
          <div class="stat-item"><span class="label">Peers</span> <span class="value">${window.AppState?.peers?.length || 0}</span></div>
          <div class="stat-item"><span class="label">Status</span> <span class="value" style="color:#00ff9d;">Active</span></div>
        </div>
    `;
    startMesh();
}

function startMesh() {
    new MeshNetwork('mesh');
}

// User requested initialization pattern
window.UI = UI; // Expose to global scope for onclick handlers
window.addEventListener("DOMContentLoaded", () => {
    UI.init();
    renderHome();
});
