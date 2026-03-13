/**
 * GhostNet Core v3.1 (Ahost Net Integration)
 * Full Feature Restore: Wallet, Messaging, Storage, Visualization
 */

// --- 0. CRYPTO PRIMITIVES ---
const GhostSecurity = {
    algo: { name: "AES-GCM", length: 256 },
    genKey: async () => window.crypto.subtle.generateKey(GhostSecurity.algo, true, ["encrypt", "decrypt"]),
    encrypt: async (data, key) => {
        const iv = window.crypto.getRandomValues(new Uint8Array(12));
        const enc = await window.crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, new TextEncoder().encode(data));
        return { iv, data: enc };
    },
    encryptBuffer: async (buffer, key) => {
        const iv = window.crypto.getRandomValues(new Uint8Array(12));
        const enc = await window.crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, buffer);
        return { iv, data: enc };
    },
    importKey: async (raw) => window.crypto.subtle.importKey("raw", raw, GhostSecurity.algo, true, ["encrypt", "decrypt"]),
};

// --- 1. MANAGERS & LOGIC ---

// Wallet Logic
// Memory-only mnemonic — never persisted to storage.
let _sessionMnemonic = null;
function setSessionMnemonic(mnemonic) {
    _sessionMnemonic = mnemonic;
}
function getSessionMnemonic() {
    return _sessionMnemonic;
}
window.addEventListener('beforeunload', () => { _sessionMnemonic = null; });

async function initWallet() {
    let mnemonic = getSessionMnemonic();
    if (!mnemonic) {
        if (typeof ethers === 'undefined') return "0x0000...";
        const randomWallet = ethers.Wallet.createRandom();
        mnemonic = randomWallet.mnemonic.phrase;
        setSessionMnemonic(mnemonic);
    }
    const wallet = ethers.Wallet.fromMnemonic(mnemonic);
    localStorage.setItem("ahost_address", wallet.address);
    // Update UI
    const el = document.getElementById("wallet-address");
    if (el) el.innerText = wallet.address.substring(0, 6) + "..." + wallet.address.substring(38);
    const badge = document.getElementById("my-node-id");
    if (badge) badge.innerText = "Node: " + wallet.address.substring(2, 8).toUpperCase();
    return wallet.address;
}

window.openReceive = async function () {
    // Show modal or alert with QR
    const addr = localStorage.getItem("ahost_address") || await initWallet();
    const overlay = document.getElementById('modal-overlay');

    // Reuse existing modal structure for Receive
    if (overlay) {
        overlay.classList.remove('hidden');
        const modal = overlay.querySelector('.modal');
        modal.innerHTML = `
            <h3>Receive AHT / ETH</h3>
            <div style="display:flex;justify-content:center;margin:20px 0;">
                <canvas id="qr-canvas"></canvas>
            </div>
            <p style="font-family:monospace;word-break:break-all;text-align:center;color:var(--text-secondary);">${addr}</p>
            <div class="modal-actions">
                <button class="btn-primary" onclick="app.closeModal()">Done</button>
            </div>
        `;
        // Generate QR
        if (typeof QRCode !== 'undefined') {
            QRCode.toCanvas(document.getElementById('qr-canvas'), addr, { margin: 2, scale: 4, color: { dark: '#000000', light: '#ffffff' } });
        }
    }
};

// Messaging Logic (Matrix/Signal Sim) - REPLACED WITH GHOSTCHAT INTEGRATION
const ContactManager = {
    contacts: [
        { id: 'u1', name: 'Alice (Relay)', online: true, pub: 'pub_alice' },
        { id: 'u2', name: 'Bob (Bridge)', online: false, pub: 'pub_bob' },
        { id: 'u3', name: 'Cipher_Node_9', online: true, pub: 'pub_cipher' }
    ],
    activeContact: null,
    currentMode: 'PERSIST', // Default

    init: () => {
        // Load contacts from storage if available
        const stored = localStorage.getItem("ghost_contacts");
        if (stored) {
            ContactManager.contacts = JSON.parse(stored);
        }

        ContactManager.renderList();
        ContactManager.setupModeToggles();

        // Init Ghost Chat Layer
        const myIdentity = { pub: "pub_me", priv: "priv_me" };

        // Mock Transport Sender (logs to console for demo)
        const mockSender = (payloadStr) => {
            console.log("[Network] Outgoing Ciphertext Packet:", payloadStr.length + " bytes");
            // Simulate Loopback active network
            setTimeout(() => {
                // In a real app, this goes to the peer.
                // Here we just loop it back to "receive" it as if it were an echo or response.
                // app.ghostChat.receive(payloadStr);
            }, 100);
        };

        app.ghostChat = new GhostChat(myIdentity, mockSender);

        // Render Persisted Messages
        app.ghostChat.messages.forEach(msg => {
            const type = msg.from === myIdentity.pub ? 'me' : 'them';
            ContactManager.renderMessage(msg, type);
        });

        // Handle Incoming Decrypted Messages
        app.ghostChat.onMessage = (msg) => {
            ContactManager.renderMessage(msg, 'them');
        };

        app.ghostChat.onDelete = (msgId) => {
            const el = document.getElementById(`msg-${msgId}`);
            if (el) {
                el.style.opacity = '0';
                setTimeout(() => el.remove(), 500);
            }
        };
    },

    // ... rest of code

    setupModeToggles: () => {
        document.querySelectorAll('.mode-btn').forEach(btn => {
            btn.onclick = () => {
                // Update UI
                document.querySelectorAll('.mode-btn').forEach(b => b.classList.remove('active'));
                btn.classList.add('active');

                // Update State
                ContactManager.currentMode = btn.dataset.mode;
                console.log("Chat Mode Switched:", ContactManager.currentMode);
            };
        });
    },

    addContact: (name, pubKey) => {
        const newContact = {
            id: 'u_' + Date.now(),
            name: name,
            online: true, // assume online for now
            pub: pubKey
        };
        ContactManager.contacts.push(newContact);
        localStorage.setItem("ghost_contacts", JSON.stringify(ContactManager.contacts));
        ContactManager.renderList(); // If we had a sidebar list
        ContactManager.selectContact(newContact);
    },

    renderList: () => {
        // (Sidebar logic if implemented would go here)
    },

    selectContact: (c) => {
        ContactManager.activeContact = c;
        document.getElementById('chat-target-label').innerText = c.name + (c.pub ? ` (${c.pub.substring(0, 6)}...)` : "");

        const history = document.getElementById('chat-history');
        if (history) {
            history.innerHTML = `
                <div class="sys-msg" style="text-align:center;color:#52525b;font-size:0.8rem;margin:10px 0;">
                    -- End-to-End Encrypted Session [${c.name}] --
                </div>`;

            // Re-render relevant messages from cache
            app.ghostChat.messages.forEach(msg => {
                if (msg.to === c.pub || msg.from === c.pub) {
                    const type = msg.from === "pub_me" ? 'me' : 'them';
                    ContactManager.renderMessage(msg, type);
                }
            });
        }
    },

    activeSend: async () => {
        const input = document.getElementById('chat-input');
        if (!input || !input.value) return;

        const text = input.value;
        const targetPub = ContactManager.activeContact ? ContactManager.activeContact.pub : "broadcast";
        const mode = ContactManager.currentMode;

        // Send via GhostChat Layer
        // TTL is 30s for Ephemeral
        const sentMsg = await app.ghostChat.sendMessage(text, targetPub, mode, mode === 'EPHEMERAL' ? 30 : 0);

        // Render Locally
        ContactManager.renderMessage(sentMsg, 'me');

        input.value = '';
    },

    renderMessage: (msg, type) => { // type = 'me' | 'them'
        const area = document.getElementById('chat-history');
        const el = document.createElement('div');
        el.id = `msg-${msg.id}`;
        el.className = `message ${type}`;

        // Base Style
        let style = "max-width:80%; margin:4px 0; padding:8px 12px; border-radius:12px; font-size:0.9rem; word-break:break-word;";
        if (type === 'me') style += " align-self:flex-end; background:#8b5cf6; color:white; border-bottom-right-radius:2px;";
        else style += " align-self:flex-start; background:rgba(255,255,255,0.1); color:#e4e4e7; border-bottom-left-radius:2px;";

        let iconHtml = "";
        if (msg.mode === 'EPHEMERAL') {
            el.classList.add('msg-ephemeral');
            iconHtml = `<span style="font-size:0.75rem; opacity:0.7; margin-left:6px;">🔥 30s</span>`;
        } else if (msg.mode === 'DELETE' && type === 'me') {
            // Add Delete Button for sender
            // We'll overlay it or append it
            iconHtml = `<span onclick="app.ghostChat.sendDeleteRequest('${msg.id}', '${msg.to}')" style="cursor:pointer; margin-left:8px; opacity:0.6;" title="Delete for everyone">🗑️</span>`;
        }

        el.style.cssText = style;
        el.innerHTML = `
            <div>${msg.body}${iconHtml}</div>
            <div style="font-size:0.65rem; opacity:0.5; margin-top:4px; text-align:right;">
                ${new Date(msg.ts).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}
            </div>
        `;

        area.appendChild(el);
        area.scrollTop = area.scrollHeight;
    }
};

// Storage Logic (GhostFS)
const GhostFS = {
    formatBytes: (bytes) => {
        if (bytes === 0) return '0 B';
        const k = 1024; const sizes = ['B', 'KB', 'MB', 'GB'];
        const i = Math.floor(Math.log(bytes) / Math.log(k));
        return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
    },

    upload: async (file) => {
        // Chunk & Encrypt Sim
        const chunks = Math.ceil(file.size / (64 * 1024));
        const key = await GhostSecurity.genKey();
        return { name: file.name, size: file.size, chunks };
    }
};

// Peer Manager
const PeerManager = {
    init: () => {
        // Fake Peers
        const tbody = document.getElementById('peer-table-body');
        if (tbody) {
            tbody.innerHTML = `
                <tr><td><span class="mono">node_8A21</span></td><td>WebRTC</td><td>24ms</td><td>98%</td><td style="color:#10b981">Active</td><td><button class="btn-tiny">Ping</button></td></tr>
                <tr><td><span class="mono">node_9B77</span></td><td>BLE</td><td>45ms</td><td>92%</td><td style="color:#10b981">Active</td><td><button class="btn-tiny">Ping</button></td></tr>
                <tr><td><span class="mono">node_C3X1</span></td><td>Relay</td><td>112ms</td><td>85%</td><td style="color:#f59e0b">Slow</td><td><button class="btn-tiny">Ping</button></td></tr>
            `;
        }
    }
};

// --- APP CONTROLLER ---
const app = {
    currency: 'AHT',
    balance: 1450.50,

    init: async () => {
        await initWallet();
        ContactManager.init();
        PeerManager.init();

        app.setupNavigation();
        app.updateBalanceDisplay();

        // Init Storage Handler
        app.storage = {
            handleUpload: async (input) => {
                const file = input.files[0];
                if (!file) return;
                const meta = await GhostFS.upload(file);

                const list = document.getElementById('storage-file-list');
                const card = document.createElement('div');
                card.className = "glass-card";
                card.style.cssText = "padding:16px;text-align:center;";
                card.innerHTML = `
                    <i data-lucide="file-lock" style="width:32px;height:32px;color:#a1a1aa;margin-bottom:8px;"></i>
                    <div style="font-weight:600;font-size:0.9rem;">${meta.name}</div>
                    <div style="font-size:0.8rem;color:#71717a;">${GhostFS.formatBytes(meta.size)}</div>
                    <button class="btn-glass small" style="margin-top:10px;width:100%">Share Key</button>
                `;
                list.prepend(card);
                lucide.createIcons();
            }
        };

        app.wallet = {
            request: window.openReceive,
            openSendModal: () => {
                const ov = document.getElementById('modal-overlay');
                ov.classList.remove('hidden');
                const m = ov.querySelector('.modal');
                // Restore Send UI
                m.innerHTML = `
                    <h3>Send AHT</h3>
                    <div class="input-group"><label>Recipient</label><input type="text" placeholder="0x..."></div>
                    <div class="input-group"><label>Amount</label><input type="number" placeholder="0.00"></div>
                    <div class="modal-actions">
                        <button class="btn-subtle" onclick="app.closeModal()">Cancel</button>
                        <button class="btn-primary" onclick="app.closeModal()">Sign & Send</button>
                    </div>
                `;
            },
            confirmSend: () => app.closeModal()
        };

        // --- NEW CHAT MODAL HANDLERS ---
        app.openNewChatModal = () => {
            const m = document.getElementById('newChatModal');
            if (m) m.classList.remove('hidden');
        };
        app.closeNewChatModal = () => {
            const m = document.getElementById('newChatModal');
            if (m) m.classList.add('hidden');
        };
        app.confirmNewChat = () => {
            const pub = document.getElementById('newChatPub').value;
            const name = document.getElementById('newChatName').value || 'Unknown Peer';
            if (!pub) { alert("Public Key Required"); return; }

            ContactManager.addContact(name, pub);
            app.closeNewChatModal();
        };

        app.messaging = { send: ContactManager.activeSend };
        app.closeModal = () => document.getElementById('modal-overlay').classList.add('hidden');

        // Init Visualizer
        const vizCanvas = document.createElement('canvas');
        const vizContainer = document.getElementById('network-viz');
        if (vizContainer) {
            vizContainer.innerHTML = '';
            vizContainer.appendChild(vizCanvas);
            new MeshVisualizer(vizCanvas).start();
        }

        lucide.createIcons();
    },

    setupNavigation: () => {
        document.querySelectorAll('.nav-btn').forEach(btn => {
            btn.onclick = () => {
                const target = btn.dataset.target;
                if (target) app.navigate(target);
            }
        });
    },

    navigate: (targetId) => {
        document.querySelectorAll('.nav-btn').forEach(b => b.classList.toggle('active', b.dataset.target === targetId));
        document.querySelectorAll('.tab-view').forEach(v => v.classList.toggle('active', v.id === targetId));
        document.querySelectorAll('.tab-view').forEach(v => v.classList.toggle('hidden', v.id !== targetId));

        const titles = {
            'dash-home': 'Overview',
            'dash-wallet': 'Wallet & Assets',
            'dash-nodes': 'Network Swarm',
            'dash-messages': 'Encrypted Comms',
            'dash-storage': 'Ghost Storage',
            'dash-settings': 'System Config'
        };
        document.getElementById('page-title').innerText = titles[targetId] || 'Dashboard';
    },

    updateBalanceDisplay: () => {
        ['overview-balance', 'wallet-balance'].forEach(id => {
            const el = document.getElementById(id);
            if (el) el.innerText = app.balance.toLocaleString();
        });
    }
};

// --- VISUALIZER ---
class MeshVisualizer {
    constructor(canvas) {
        this.canvas = canvas;
        this.ctx = canvas.getContext('2d');
        this.nodes = [];
        this.width = 0; this.height = 0;
        const ro = new ResizeObserver(() => this.resize());
        ro.observe(canvas.parentElement);
        this.resize();
        this.nodes.push({ x: 0, y: 0, type: 'self' });
        for (let i = 0; i < 6; i++) this.addRandom();
    }
    resize() {
        const p = this.canvas.parentElement.getBoundingClientRect();
        this.canvas.width = p.width; this.canvas.height = p.height;
        this.width = p.width; this.height = p.height;
        if (this.nodes[0]) { this.nodes[0].x = this.width / 2; this.nodes[0].y = this.height / 2; }
    }
    addRandom() {
        const a = Math.random() * Math.PI * 2;
        const d = 50 + Math.random() * 100;
        this.nodes.push({
            x: this.width / 2 + Math.cos(a) * d, y: this.height / 2 + Math.sin(a) * d,
            vx: (Math.random() - 0.5) * 0.5, vy: (Math.random() - 0.5) * 0.5, type: 'peer'
        });
    }
    start() { this.animate(); }
    animate() { this.update(); this.draw(); requestAnimationFrame(() => this.animate()); }
    update() {
        this.nodes.forEach(n => {
            if (n.type === 'self') return;
            n.x += n.vx; n.y += n.vy;
            const dx = n.x - this.width / 2; const dy = n.y - this.height / 2;
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
                this.ctx.beginPath(); this.ctx.moveTo(n1.x, n1.y); this.ctx.lineTo(n2.x, n2.y); this.ctx.stroke();
            });
        });
        this.nodes.forEach(n => {
            this.ctx.fillStyle = n.type === 'self' ? '#f59e0b' : '#52525b';
            this.ctx.beginPath(); this.ctx.arc(n.x, n.y, 4, 0, Math.PI * 2); this.ctx.fill();
        });
    }
}

// Setup Navigation
window.enterMesh = () => {
    const modal = document.getElementById('intro-modal');
    if (modal) {
        modal.style.opacity = '0';
        setTimeout(() => modal.remove(), 500);
    }
};

window.onload = app.init;
