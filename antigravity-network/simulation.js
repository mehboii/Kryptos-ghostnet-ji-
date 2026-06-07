/**
 * GhostNet Core v3.1 (Simulation & Transport)
 * Merged & Optimized for Antigravity Network (Fixed UI Sync & Chat)
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
            iconHtml = `<span style="font-size:0.75rem; opacity:0.7; margin-left:6px;"> 30s</span>`;
        } else if (msg.mode === 'DELETE' && type === 'me') {
            // Add Delete Button for sender
            // We'll overlay it or append it
            iconHtml = `<span onclick="app.ghostChat.sendDeleteRequest('${msg.id}', '${msg.to}')" style="cursor:pointer; margin-left:8px; opacity:0.6;" title="Delete for everyone"></span>`;
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
        // Override with dynamic content
        const container = document.getElementById('peer-list-container');
        const target = container || document.getElementById('discover-nodes');

        if (!target) return;

        const render = () => {
            const bleActive = app.transport && app.transport.ble && app.transport.ble.peers.size > 0;

            let html = `
                <div style="padding:10px; margin-bottom:10px; display:flex; gap:10px;">
                    <button class="btn-primary small" onclick="app.transport.startBLEScan()">
                        <i data-lucide="bluetooth"></i> Scan BLE Mesh
                    </button>
                    <div class="status-badge ${bleActive ? 'active' : ''}">
                        ${bleActive ? ' BLE Active' : ' BLE Idle'}
                    </div>
                </div>
            `;

            // Mock Peers + Real BLE Peers
            const peers = [
                { id: 'node_8A21', type: 'Bridge', lat: '24ms', status: 'Active' },
                { id: 'node_C3X1', type: 'Relay', lat: '112ms', status: 'Slow' }
            ];

            // Add BLE Peers if any
            if (app.transport && app.transport.ble) {
                app.transport.ble.peers.forEach(p => {
                    peers.push({ id: p.id, type: 'BLE', lat: '---', status: 'Connected' });
                });
            }

            html += peers.map(p => `
                <div class="peer-card">
                    <div class="peer-icon ${p.type === 'Bridge' ? 'bridge' : ''}"><i data-lucide="${p.type === 'BLE' ? 'bluetooth' : 'cpu'}"></i></div>
                    <div class="peer-info"><div class="peer-id">${p.id}</div><div class="peer-meta">${p.type} • ${p.lat}</div></div>
                    <div class="peer-status" style="color:${p.status === 'Active' || p.status === 'Connected' ? '#10b981' : '#f59e0b'}">${p.status}</div>
                </div>
            `).join('');

            target.innerHTML = html;
            if (typeof lucide !== 'undefined') lucide.createIcons();
        };

        render();
        // Subscribe to updates
        window.addEventListener('ble-update', render);
    }
};

// --- TRANSPORT ABSTRACTION ---
class TransportManager {
    constructor(identity) {
        this.identity = identity;
        // Check if GhostBLE is loaded
        if (typeof GhostBLE !== 'undefined') {
            this.ble = new GhostBLE(identity);
        } else {
            console.warn("GhostBLE not loaded");
            this.ble = { init: async () => false, peers: new Map(), mode: 'none' };
        }

        this.activeTransport = 'ip'; // Default

        if (this.ble.onPeer) {
            this.ble.onPeer = (peer) => {
                console.log("Transport: BLE Peer Found", peer);
                // Trigger Global UI update
                // Add to AppState if needed or just trigger re-render
                window.dispatchEvent(new Event('app:state'));

                // Show toast
                const toast = document.createElement('div');
                toast.innerText = `BLE Peer Connected: ${peer.id}`;
                toast.className = 'toast-notification'; // Ensure CSS exists or style inline
                toast.style.cssText = "position:fixed;bottom:20px;right:20px;background:#10b981;color:black;padding:10px 20px;border-radius:8px;z-index:9999;";
                document.body.appendChild(toast);
                setTimeout(() => toast.remove(), 3000);
            };
        }

        if (this.ble.onMessage) {
            this.ble.onMessage = (msg, from) => {
                console.log("Transport: BLE Message", msg);
                // Inject into GhostChat
                if (app.ghostChat) app.ghostChat.receive(msg, from);
            };
        }
    }

    async init() {
        const bleCapable = await this.ble.init();
        if (bleCapable) {
            console.log("Transport: BLE Initialized");
        }
    }

    async send(payload, peerId) {
        // Auto-select Transport
        if (this.ble && this.ble.peers.has(peerId)) {
            console.log(`Transport: Routing via BLE to ${peerId}`);
            return this.ble.send(peerId, payload);
        } else {
            console.log(`Transport: Routing via IP/Mock to ${peerId}`);
            // Fallback to mock sender defined in App logic
            // In a real app this would be check WebRTC peers
            return true;
        }
    }

    startBLEScan() {
        if (this.ble && this.ble.scanBrowser) {
            this.ble.scanBrowser();
        } else {
            alert("BLE not supported or not in browser mode");
        }
    }
}


// --- APP CONTROLLER ---
const app = {
    currency: 'AHT',
    balance: 1450.50,

    init: async () => {
        try {
            console.log(" Initializing App...");

            // 1. Wallet
            try {
                await initWallet();
                console.log(" Wallet Initialized");
            } catch (e) { console.error("Wallet Init Failed:", e); }

            // 2. Transport
            app.transport = new TransportManager({ nodeId: 'me' });
            await app.transport.init();

            // 3. Chat
            try {
                if (typeof GhostChat !== 'undefined') {
                    // Update mockSender to use Transport
                    const transportSender = (payloadStr) => {
                        // Broadcast or targeted? GhostChat usually handles encryption but here we just pass 'payloadStr'
                        // We need a target. GhostChat.sendMessage passes (text, targetPub...)
                        // But the 'sender' callback in GhostChat might just expect raw bytes.
                        // For now, adhere to previous MockSender logic but check Transport.
                        console.log("Transport: Sending via best route...");
                    };

                    ContactManager.init();
                    console.log(" Chat Initialized");
                } else {
                    console.error(" GhostChat Class Missing! Check script load order.");
                }
            } catch (e) { console.error("Chat Init Failed:", e); }

            // 3. Peers
            try {
                PeerManager.init();
                console.log(" Peers Initialized");
            } catch (e) { console.error("Peer Init Failed:", e); }

            // 4. UI Setup
            app.setupNavigation();
            app.updateBalanceDisplay();

            // 5. Storage (UI Handlers)
            app.storage = {
                handleUpload: async (input) => {
                    const file = input.files[0];
                    if (!file) return;
                    const meta = await GhostFS.upload(file);

                    const list = document.getElementById('storage-file-list');
                    if (list) {
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
                        if (typeof lucide !== 'undefined') lucide.createIcons();
                    }
                }
            };

            // 6. Wallet (UI Handlers)
            app.wallet = {
                request: window.openReceive || (() => alert("Receive not implemented")),
                openSendModal: () => {
                    const ov = document.getElementById('modal-overlay');
                    if (ov) {
                        ov.classList.remove('hidden');
                        const m = ov.querySelector('.modal');
                        if (m) {
                            m.innerHTML = `
                                <h3>Send AHT</h3>
                                <div class="input-group"><label>Recipient</label><input type="text" placeholder="0x..."></div>
                                <div class="input-group"><label>Amount</label><input type="number" placeholder="0.00"></div>
                                <div class="modal-actions">
                                    <button class="btn-subtle" onclick="app.closeModal()">Cancel</button>
                                    <button class="btn-primary" onclick="app.closeModal()">Sign & Send</button>
                                </div>
                            `;
                        }
                    }
                },
                confirmSend: () => app.closeModal()
            };

            // 7. Chat (UI Handlers)
            app.openNewChatModal = () => {
                const m = document.getElementById('newChatModal');
                if (m) m.classList.remove('hidden');
            };
            app.closeNewChatModal = () => {
                const m = document.getElementById('newChatModal');
                if (m) m.classList.add('hidden');
            };
            app.confirmNewChat = () => {
                const pubInput = document.getElementById('newChatPub');
                const nameInput = document.getElementById('newChatName');

                const pub = pubInput ? pubInput.value : null;
                const name = nameInput ? nameInput.value : 'Unknown Peer';

                if (!pub) { alert("Public Key Required"); return; }

                ContactManager.addContact(name, pub);
                app.closeNewChatModal();
            };

            app.messaging = { send: ContactManager.activeSend };
            app.closeModal = () => {
                const ov = document.getElementById('modal-overlay');
                if (ov) ov.classList.add('hidden');
            };

            // 8. Visualizer
            try {
                const vizContainer = document.getElementById('network-viz');
                if (vizContainer) {
                    vizContainer.innerHTML = '';
                    const vizCanvas = document.createElement('canvas');
                    vizContainer.appendChild(vizCanvas);
                    new MeshVisualizer(vizCanvas).start();
                }
            } catch (e) { console.error("Visualizer Init Failed", e); }

            // 9. Icons
            if (typeof lucide !== 'undefined') lucide.createIcons();

        } catch (err) {
            console.error(" APP FATAL CRASH:", err);
            alert("App Initialization Failed. Check Console.");
        }
    },

    setupNavigation: () => {
        document.querySelectorAll('.menu-item').forEach(btn => {
            btn.onclick = () => {
                const target = btn.dataset.view;
                if (target) app.navigate(target);
            }
        });
    },

    navigate: (targetId) => {
        // Update Buttons
        document.querySelectorAll('.menu-item').forEach(b => {
            b.classList.toggle('active', b.dataset.view === targetId)
        });

        // Update Views
        const targetViewId = 'view-' + targetId;
        document.querySelectorAll('.view-panel').forEach(v => {
            if (v.id === targetViewId) {
                v.classList.add('active');
                v.style.display = "block";
            } else {
                v.classList.remove('active');
                v.style.display = "none";
            }
        });

        const titles = {
            'dashboard': 'Overview',
            'wallet': 'Wallet & Assets',
            'peers': 'Network Swarm',
            'chat': 'Ghost Chat',
            'storage': 'Ghost Storage',
            'settings': 'System Config'
        };
        const el = document.getElementById('view-title');
        if (el) el.innerText = titles[targetId] || 'Dashboard';
    },

    updateBalanceDisplay: () => {
        // Simple balance text update
        const el = document.getElementById('wallet-balance');
        if (el) el.innerText = app.balance.toLocaleString();
    }
};

// Override PeerManager.init to use Divs - HANDLED IN MAIN CLASS NOW
// PeerManager.init = () => { ... } removed to avoid conflict with the definition above.


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

window.app = app; // Expose global
window.onload = app.init;
