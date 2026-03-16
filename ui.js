/**
 * GhostNet Immersive UI
 * Single-file logic for Visualization, State, and Interaction.
 */

/**
 * GhostCode diagnostic (why it can stick on "Loading..."):
 * - `index.html` renders the badge with literal "Loading..." (`#ghostcode-badge`).
 * - The app stores a node JWT in `sessionStorage.ghostnet_token` via `POST /auth/node`.
 * - The UI calls `GET /user/shortcode` expecting a GhostCode back.
 * - Node JWTs originally did not map to an email-auth user, so the server could return 404.
 * - Identity/token availability can lag initial render (race), so one fetch attempt is not enough.
 *
 * Fix: a bounded watcher that retries while auth settles, then shows "Not connected" + Retry.
 */

// --- GLOBAL STATE ---
window.AppState = {
    meshReady: false,
    wallet: { address: '0x...', balance: 0 },
    peers: [],
    identity: null,
    messages: [],
    files: [],
    ghostCode: null
};

// --- CONSTANTS ---
const BACKEND_URL = 'https://ghostnet-ji-production.up.railway.app';

// ── AUTH TOKEN HELPERS ─────────────────────────────────────────────────────
// Guard flag: once clearSession fires, block all further calls in this page load
let _authRedirectFired = false;

/**
 * Read the JWT token. Returns the raw token string or '' if none.
 * Checks BOTH storages because index.html writes to sessionStorage
 * while the long-lived "remember me" path may write to localStorage.
 */
function _readToken() {
    return sessionStorage.getItem('ghostnet_token')
        || localStorage.getItem('ghostnet_token')
        || localStorage.getItem('ghostnet_jwt')
        || '';
}

/**
 * Quick boolean check — does a valid-looking token exist?
 */
function hasAuthToken() {
    return !!_readToken();
}

/**
 * Build { Authorization, Content-Type } headers if a token exists.
 * If no token is present, returns {} — callers MUST check first
 * with hasAuthToken() or check `!headers.Authorization`.
 *
 * IMPORTANT: This function NEVER calls clearSession or redirects.
 * Redirecting on missing token is done explicitly by callers.
 */
const getAuthHeaders = () => {
    const token = _readToken();
    if (!token) return {};
    return {
        'Authorization': `Bearer ${token}`,
        'Content-Type': 'application/json'
    };
};

/**
 * Legacy wrapper for compatibility.
 */
function authHeaders() {
    return getAuthHeaders();
}

/**
 * Poll for the auth token to exist (handles race conditions during re-login).
 */
async function _waitForToken(maxWait = 5000) {
    const start = Date.now();
    while (Date.now() - start < maxWait) {
        // Check both storages for maximum resilience
        const token = sessionStorage.getItem('ghostnet_token') || localStorage.getItem('ghostnet_token') || '';
        if (token) return token;
        await new Promise(r => setTimeout(r, 200));
    }
    return null;
}

/**
 * Show a toast notification for a given duration.
 */
function showToast(message, durationMs = 2000) {
    const el = document.getElementById('ghostnet-toast');
    if (!el) return;
    el.textContent = message;
    el.style.opacity = '1';
    el.style.transform = 'translateX(-50%) translateY(0)';
    el.style.pointerEvents = 'auto';
    setTimeout(() => {
        el.style.opacity = '0';
        el.style.transform = 'translateX(-50%) translateY(20px)';
        el.style.pointerEvents = 'none';
    }, durationMs);
}

// ─── GhostCode Display (robust loading state) ────────────────────────────────
const GHOSTCODE_BADGE_ID = 'ghostcode-badge';
const GHOSTCODE_MAX_WAIT_MS = 8000;

function _getGhostcodeBadgeEl() {
    return document.getElementById(GHOSTCODE_BADGE_ID);
}

function _setGhostCodeBadgeText(text) {
    const el = _getGhostcodeBadgeEl();
    if (!el) return;
    el.textContent = text;
}

function _ensureGhostCodeRetryButton() {
    const section = document.getElementById('ghostcode-section');
    if (!section) return null;
    let btn = document.getElementById('ghostcode-retry-btn');
    if (btn) return btn;

    btn = document.createElement('button');
    btn.id = 'ghostcode-retry-btn';
    btn.type = 'button';
    btn.textContent = 'Retry';
    btn.style.cssText = 'margin-top:10px;background:rgba(0,240,255,0.08);border:1px solid rgba(0,240,255,0.25);color:#00f0ff;border-radius:10px;padding:6px 10px;cursor:pointer;font-weight:700;font-size:0.75rem;display:none;';
    btn.addEventListener('click', () => {
        btn.style.display = 'none';
        if (window.UI && typeof window.UI.startGhostCodeWatcher === 'function') {
            window.UI.startGhostCodeWatcher(true);
        }
    });
    section.appendChild(btn);
    return btn;
}

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

        // 0a. Load Identity from Storage FIRST
        if (window.AppState) {
            let stored = null;
            if (window.GhostIdentity) {
                stored = GhostIdentity.getStoredIdentity();
            } else {
                // Fallback if GhostIdentity not yet loaded
                const nodeId = localStorage.getItem('ghostnet_node_id');
                if (nodeId) {
                    stored = {
                        nodeId,
                        displayName: localStorage.getItem('ghostnet_display_name'),
                        address: localStorage.getItem('ghostnet_address'),
                        publicKey: localStorage.getItem('ghostnet_pubkey')
                    };
                }
            }

            if (stored && stored.nodeId && stored.nodeId !== 'null') {
                AppState.identity = {
                    nodeId: stored.nodeId,
                    displayName: stored.displayName || 'Guest',
                    address: stored.address || '0x...',
                    publicKey: stored.publicKey || ''
                };
                console.log("[UI] Identity pre-loaded from storage:", AppState.identity.nodeId);
            }
        }

        // 0b. Setup Theme
        UI.initTheme();

        // 1. Setup Nav
        document.querySelectorAll('.nav-btn').forEach(btn => {
            btn.onclick = () => UI.navigate(btn.dataset.target);
        });

        // 2. Start Visualizer
        new MeshNetwork('mesh');

        // 3. Setup Chat
        UI.setupChat();

        // 4. Hook Logout (if exists)
        document.querySelectorAll('.auth-logout-btn, #logout-btn, [data-action="logout"]').forEach(btn => {
            btn.addEventListener('click', () => {
                UI.clearSession();
            });
        });

        // 5. Add Ghost Card buttons dynamically
        setTimeout(() => {
            const viewProfile = document.getElementById('view-profile');
            if (viewProfile) {
                const pContainer = viewProfile.querySelector('.profile-container') || viewProfile;
                const gcBtn = document.createElement('button');
                gcBtn.className = 'btn-primary ghostcard-btn';
                gcBtn.style.marginTop = '12px';
                gcBtn.innerText = 'My Ghost Card';
                gcBtn.onclick = () => { if(UI.generateGhostCard) UI.generateGhostCard(); };
                pContainer.appendChild(gcBtn);
            }

            const newChatBtn = document.querySelector('.chat-new-btn');
            if (newChatBtn && newChatBtn.parentNode) {
                // Add Scan button
                const scanBtn = document.createElement('button');
                scanBtn.className = 'chat-new-btn';
                scanBtn.title = 'Scan a Ghost Card';
                scanBtn.innerHTML = '<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M3 7V5a2 2 0 0 1 2-2h2"/><path d="M17 3h2a2 2 0 0 1 2 2v2"/><path d="M21 17v2a2 2 0 0 1-2 2h-2"/><path d="M7 21H5a2 2 0 0 1-2-2v-2"/><circle cx="12" cy="12" r="3"/><line x1="12" y1="9" x2="12" y2="9.01"/><line x1="12" y1="15" x2="12" y2="15.01"/><line x1="9" y1="12" x2="9.01" y2="12"/><line x1="15" y1="12" x2="15.01" y2="12"/></svg>';
                scanBtn.style.marginRight = '8px';
                scanBtn.style.flexShrink = '0';
                scanBtn.style.display = 'flex';
                scanBtn.style.alignItems = 'center';
                scanBtn.style.justifyContent = 'center';
                scanBtn.style.color = '#a855f7'; // Purple-tinted icon
                scanBtn.style.borderColor = 'rgba(168,85,247,0.3)';
                scanBtn.style.background = 'rgba(168,85,247,0.1)';
                scanBtn.onclick = () => { if(UI.startQRScanner) UI.startQRScanner(); };
                newChatBtn.parentNode.insertBefore(scanBtn, newChatBtn);

                // Existing QR button
                const qrBtn = document.createElement('button');
                qrBtn.className = 'chat-new-btn';
                qrBtn.title = 'Ghost Card';
                qrBtn.innerHTML = '⊞';
                qrBtn.style.fontSize = '18px';
                qrBtn.style.marginRight = '8px';
                qrBtn.style.flexShrink = '0';
                qrBtn.style.display = 'flex';
                qrBtn.style.alignItems = 'center';
                qrBtn.style.justifyContent = 'center';
                qrBtn.onclick = () => { if(UI.generateGhostCard) UI.generateGhostCard(); };
                newChatBtn.parentNode.insertBefore(qrBtn, newChatBtn);
            }
        }, 1500);

        // 6. Mock Initial Data (for visual validation)
        setTimeout(() => {
            if (hasAuthToken()) {
                UI.mockData();
            }
            // Emit Initial State
            window.dispatchEvent(new Event("app:state"));
        }, 800);

        // 7. State Listener
        window.addEventListener("app:state", UI.render);

        // 6. Load Profile — only if we have a session
        if (hasAuthToken()) {
            UI.loadProfile();
        }

        // 7. Init Vault
        UI.initVault();

        // 8. Init GhostCode search
        UI.initChatSearch();

        // 9. GhostCode watcher — only if authenticated
        if (hasAuthToken()) {
            UI.startGhostCodeWatcher(false);
        }

        // Re-run after identity updates (unlock/login flow)
        window.addEventListener('identity:updated', () => {
            // Reset auth guard so new session can work
            _authRedirectFired = false;

            if (hasAuthToken()) {
                UI.startGhostCodeWatcher(true);
                UI.fetchRealData();
                UI.loadProfile();
            }

            // Re-initialize vault for newly authenticated user
            if (window.GhostVault) {
                window.GhostVault.init().then(() => {
                    UI.vaultLoadFiles();
                    console.log('[UI] Vault re-loaded for authenticated user');
                }).catch(err => {
                    console.warn('[UI] Vault init on login failed:', err.message);
                });
            }
        });

        // 9. Anti-screenshot and privacy measures
        document.addEventListener('contextmenu', e => {
            if (e.target.tagName === 'IMG' || e.target.closest('#chat-feed')) {
                e.preventDefault();
            }
        });
        document.addEventListener('dragstart', e => {
            if (e.target.tagName === 'IMG') e.preventDefault();
        });
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

        // Screenshot protection init/destroy
        if (target === 'chat' && AppState.identity) {
            UI.initScreenshotProtection();
        } else {
            if (UI.destroyScreenshotProtection) {
                UI.destroyScreenshotProtection();
            }
        }

        // [Feature 4] Node Monitor Polling
        if (target === 'nodes-monitor') {
            if (UI._relayTimer) clearInterval(UI._relayTimer);
            UI._relayTimer = setInterval(UI.updateRelayMonitor, 2000);
            UI.updateRelayMonitor();
        } else {
            if (UI._relayTimer) clearInterval(UI._relayTimer);
            UI._relayTimer = null;
        }
    },

    clearSession: (isDestroy = false) => {
        // --- ONE-TIME GUARD: never fire more than once per page load ---
        if (_authRedirectFired || window._isClearingSession) {
            console.log('[UI] clearSession blocked — already fired this page load.');
            return;
        }
        window._isClearingSession = true;
        _authRedirectFired = true;  // permanent flag for this page load

        console.log(`[UI] Initiating unified session clear (destroy=${isDestroy})...`);
        
        // Preserve current theme
        const theme = document.documentElement.getAttribute('data-theme') || 'dark';
        
        // Clear screenshot protection
        if (UI.destroyScreenshotProtection) {
            UI.destroyScreenshotProtection();
        }

        // 1. Selective Storage Cleanup
        // ONLY remove session/token keys — NEVER touch identity or seed phrase
        // NOTE: 'ghostnet_node_id' is IDENTITY data (used by getStoredIdentity),
        //       NOT a session key. Removing it breaks nodeId on next login.
        const sessionKeys = [
            'ghostnet_token',
            'ghostnet_jwt',
            'ghostnet_vault_unlocked',
            'ghostnet_session_key',
            'ghostnet_last_convo'
        ];

        sessionKeys.forEach(k => {
            localStorage.removeItem(k);
            sessionStorage.removeItem(k);
        });

        if (isDestroy) {
            console.log('[UI] Full identity destruction requested...');
            const identityKeys = [
                'ghostnet_identity',
                'ghostnet_identity_vault',
                'ghostnet_vault_index',
                'ghostnet_seed_words',
                'ghostnet_ble_devices'
            ];
            identityKeys.forEach(k => localStorage.removeItem(k));
            
            // Also wipe all avatars
            for (let i = 0; i < localStorage.length; i++) {
                const key = localStorage.key(i);
                if (key && key.startsWith('ghostnet_avatar_')) {
                    localStorage.removeItem(key);
                    i--;
                }
            }
        }

        // Restore theme preference
        if (!isDestroy) {
            localStorage.setItem('ghostnet_theme', theme);
        }
        
        // 2. Vault Cleanup
        if (window.GhostVault && typeof window.GhostVault.clearVaultState === 'function') {
            window.GhostVault.clearVaultState();
        }
        if (typeof UI.vaultRenderFiles === 'function') {
            UI.vaultRenderFiles([]);
        }

        // 3. Clear In-Memory State
        if (window.AppState) {
            window.AppState.identity = null;
            window.AppState.messages = [];
            window.AppState.files = [];
            window.AppState.ghostCode = null;
            window.AppState.peers = [];
        }
        if (window.app) {
            window.app.identity = null;
            window.app.chat = null;
            window.app.chatTarget = null;
        }

        // 4. Restore Scroll Style
        document.body.style.overflow = 'auto';
        document.documentElement.style.overflow = 'auto';
        
        // 5. Remove all Modals and Overlays
        const blockers = [
            'ghostcard-modal', 
            'screenshot-overlay', 
            'sidebar-overlay', 
            'vault-upload-progress',
            'chat-file-overlay',
            'qr-scanner-modal'
        ];
        blockers.forEach(id => {
            const el = document.getElementById(id);
            if (el) el.remove();
        });
        
        document.querySelectorAll('.vault-verify-overlay').forEach(el => el.remove());

        if (isDestroy) {
            console.log('[UI] Identity destroyed. Reloading...');
            window.location.reload();
            return;
        }

        // 6. Navigation
        const loginUrl = new URL(window.location.href);
        loginUrl.hash = 'profile'; 
        window.history.replaceState(null, '', loginUrl.href);
        
        UI.navigate('profile');
        
        if (window.IdentityUI && typeof window.IdentityUI.showScreen === 'function') {
            window.IdentityUI.init(); 
        }

        const sidebarProfile = document.getElementById('sidebar-profile');
        if (sidebarProfile) sidebarProfile.style.display = 'none';
        
        console.log('[UI] Session fully cleared. Redirected to identity screen.');
        showToast('Safety Logout Complete');
        
        // Release the recursion guard (NOT the page-load guard)
        setTimeout(() => { window._isClearingSession = false; }, 1000);
    },

    initScreenshotProtection: () => {
        // CSS layer
        const chatContainer = document.querySelector('.chat-layout-split');
        if (chatContainer) {
            chatContainer.style.userSelect = 'none';
            chatContainer.style.webkitUserSelect = 'none';
            chatContainer.style.webkitTouchCallout = 'none';
        }

        // Blur/focus layer
        const blurHandler = () => {
            if (document.getElementById('screenshot-overlay')) return;
            const overlay = document.createElement('div');
            overlay.id = 'screenshot-overlay';
            overlay.style.position = 'fixed';
            overlay.style.top = '0';
            overlay.style.left = '0';
            overlay.style.width = '100vw';
            overlay.style.height = '100vh';
            overlay.style.zIndex = '99999';
            overlay.style.background = '#000';
            overlay.style.opacity = '1';
            document.body.appendChild(overlay);
        };

        const focusHandler = () => {
            const overlay = document.getElementById('screenshot-overlay');
            if (overlay) overlay.remove();
        };

        // Keyboard layer
        const keydownHandler = (e) => {
            if (e.key === 'PrintScreen' || e.keyCode === 44) {
                if (navigator.clipboard && navigator.clipboard.writeText) {
                    navigator.clipboard.writeText('');
                }
                // Custom toast warning
                const toast = document.createElement('div');
                toast.textContent = 'Screenshots are protected in GhostNet';
                toast.style.position = 'fixed';
                toast.style.bottom = '20px';
                toast.style.left = '50%';
                toast.style.transform = 'translateX(-50%)';
                toast.style.background = '#ef4444';
                toast.style.color = '#fff';
                toast.style.padding = '10px 20px';
                toast.style.borderRadius = '8px';
                toast.style.zIndex = '100000';
                document.body.appendChild(toast);
                setTimeout(() => toast.remove(), 3000);
            }
        };

        // Visibility layer
        const visibilityHandler = () => {
            const bubbles = document.querySelectorAll('.message');
            if (document.hidden) {
                bubbles.forEach(b => {
                    b.dataset.originalText = b.innerText;
                    b.innerText = '🔒 Protected';
                });
            } else {
                bubbles.forEach(b => {
                    if (b.dataset.originalText !== undefined) {
                        b.innerText = b.dataset.originalText;
                        delete b.dataset.originalText;
                    }
                });
            }
        };

        // Attach listeners if not already attached
        if (!window._screenshotHandlers) {
            window._screenshotHandlers = { blurHandler, focusHandler, keydownHandler, visibilityHandler };
            window.addEventListener('blur', blurHandler);
            window.addEventListener('focus', focusHandler);
            document.addEventListener('keydown', keydownHandler);
            document.addEventListener('visibilitychange', visibilityHandler);
        }

        // Add small status badge
        const headerInfo = document.querySelector('.chat-header-info');
        if (headerInfo && !document.getElementById('ss-protected-badge')) {
            const badge = document.createElement('span');
            badge.id = 'ss-protected-badge';
            badge.className = 'e2e-badge';
            badge.textContent = '📵 SS Protected';
            headerInfo.appendChild(badge);
        }
    },

    destroyScreenshotProtection: () => {
        if (window._screenshotHandlers) {
            window.removeEventListener('blur', window._screenshotHandlers.blurHandler);
            window.removeEventListener('focus', window._screenshotHandlers.focusHandler);
            document.removeEventListener('keydown', window._screenshotHandlers.keydownHandler);
            document.removeEventListener('visibilitychange', window._screenshotHandlers.visibilityHandler);
            delete window._screenshotHandlers;
        }

        const overlay = document.getElementById('screenshot-overlay');
        if (overlay) overlay.remove();

        const badge = document.getElementById('ss-protected-badge');
        if (badge) badge.remove();
        
        const chatContainer = document.querySelector('.chat-layout-split');
        if (chatContainer) {
            chatContainer.style.userSelect = '';
            chatContainer.style.webkitUserSelect = '';
            chatContainer.style.webkitTouchCallout = '';
        }
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
        // Skip entirely when not authenticated
        if (!hasAuthToken()) return;
        try {
            console.log("🔗 Connecting to GhostNet Bridge...");

            const headers = getAuthHeaders();
            if (!headers.Authorization) return; // Silent stop if not authed

            const res = await fetch('https://ghostnet-ji-production.up.railway.app/wallet', {
                headers
            });

            if (!res.ok) throw new Error("Bridge Error");

            const walletData = await res.json();

            console.log(" Bridge Data Received:", walletData);

            if (Array.isArray(walletData)) {
                AppState.wallet = walletData;
            }


            console.log("Wallet hydrated:", AppState.wallet);

            // Re-render
            window.dispatchEvent(new Event("app:state"));

        } catch (e) {
            console.warn(" Bridge Disconnected (Using Fallback Data):", e);

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
            const headers = getAuthHeaders();
            if (!headers.Authorization) return;

            await fetch('http://localhost:3001/wallet/send', {
                method: 'POST',
                headers,
                body: JSON.stringify({ symbol, to, amount })
            });
        } catch (e) { console.error(e); }
    },

    openNewChat: () => {
        const modal = document.createElement('div');
        modal.className = "modal-overlay";

        const card = document.createElement('div');
        card.className = 'modal-card';

        // Close button
        const closeBtn = document.createElement('button');
        closeBtn.className = 'modal-close';
        closeBtn.textContent = '×';
        closeBtn.addEventListener('click', () => modal.remove());
        card.appendChild(closeBtn);

        // Title
        const title = document.createElement('div');
        title.className = 'modal-title';
        title.textContent = 'New Encrypted Chat';
        card.appendChild(title);

        // Contact name group
        const nameGroup = document.createElement('div');
        nameGroup.className = 'input-group';
        const nameLabel = document.createElement('label');
        nameLabel.className = 'input-label';
        nameLabel.textContent = 'CONTACT NAME';
        const nameInput = document.createElement('input');
        nameInput.type = 'text';
        nameInput.id = 'chat-name';
        nameInput.className = 'modal-input';
        nameInput.placeholder = 'e.g. Alice';
        nameGroup.appendChild(nameLabel);
        nameGroup.appendChild(nameInput);
        card.appendChild(nameGroup);

        // Node ID / GhostCode group
        const keyGroup = document.createElement('div');
        keyGroup.className = 'input-group';
        const keyLabel = document.createElement('label');
        keyLabel.className = 'input-label';
        keyLabel.textContent = 'NODE ID / PUBLIC KEY';
        const keyInputWrap = document.createElement('div');
        keyInputWrap.style.cssText = 'position:relative;display:flex;align-items:center;gap:8px;';
        const keyInput = document.createElement('input');
        keyInput.type = 'text';
        keyInput.id = 'chat-pubkey';
        keyInput.className = 'modal-input';
        keyInput.placeholder = '0x... or GN-XXXX';
        keyInput.style.cssText = 'flex:1;padding-right:36px;';
        const keySpinner = document.createElement('div');
        keySpinner.id = 'ghostcode-resolve-spinner';
        keySpinner.style.cssText = 'display:none;position:absolute;right:10px;width:16px;height:16px;border:2px solid rgba(0,240,255,0.3);border-top-color:#00f0ff;border-radius:50%;animation:spin 0.6s linear infinite;';
        // QR scanner button
        const qrBtn = document.createElement('button');
        qrBtn.className = 'btn-primary';
        qrBtn.style.cssText = 'padding:0 12px;width:auto;border-radius:12px;font-size:16px;';
        qrBtn.title = 'Scan QR';
        qrBtn.textContent = '⊞';
        qrBtn.addEventListener('click', () => { if (UI.startQRScanner) UI.startQRScanner(); });
        keyInputWrap.appendChild(keyInput);
        keyInputWrap.appendChild(keySpinner);
        keyInputWrap.appendChild(qrBtn);
        keyGroup.appendChild(keyLabel);
        keyGroup.appendChild(keyInputWrap);
        card.appendChild(keyGroup);

        // Inline resolve feedback
        const resolveFeedback = document.createElement('div');
        resolveFeedback.id = 'ghostcode-resolve-feedback';
        resolveFeedback.style.cssText = 'font-size:0.8rem;margin-top:6px;min-height:1.2em;';
        card.appendChild(resolveFeedback);

        // Error area 
        const errEl = document.createElement('div');
        errEl.id = 'chat-new-error';
        errEl.style.cssText = 'color:#ef4444;font-size:0.8rem;margin-top:8px;min-height:1.2em;';
        card.appendChild(errEl);

        // Start button
        const startBtn = document.createElement('button');
        startBtn.className = 'btn-primary';
        startBtn.id = 'chat-start-btn';
        startBtn.textContent = 'START SESSION';
        startBtn.addEventListener('click', () => UI.submitNewChat());
        card.appendChild(startBtn);

        modal.appendChild(card);
        document.body.appendChild(modal);

        // --- GhostCode auto-resolve ---
        const GHOSTCODE_PATTERN = /^GN-[A-Z0-9]{4,6}$/i;
        let resolveTimeout = null;

        keyInput.addEventListener('input', () => {
            const val = keyInput.value.trim();
            // Clear previous feedback
            resolveFeedback.textContent = '';
            resolveFeedback.style.color = '';

            // If it looks like a GhostCode, set up resolve
            if (val.match(/^GN-/i)) {
                clearTimeout(resolveTimeout);
                resolveTimeout = setTimeout(() => {
                    if (GHOSTCODE_PATTERN.test(val)) {
                        UI.resolveGhostCode(val.toUpperCase(), keyInput, nameInput, resolveFeedback, keySpinner);
                    }
                }, 600);
            }
        });

        keyInput.addEventListener('keydown', (e) => {
            if (e.key === 'Enter' || e.key === 'Tab') {
                const val = keyInput.value.trim();
                if (GHOSTCODE_PATTERN.test(val)) {
                    e.preventDefault();
                    clearTimeout(resolveTimeout);
                    UI.resolveGhostCode(val.toUpperCase(), keyInput, nameInput, resolveFeedback, keySpinner);
                }
            }
        });
    },

    /**
     * Resolve a GhostCode via the public /resolve endpoint.
     */
    resolveGhostCode: async (code, keyInput, nameInput, feedbackEl, spinnerEl) => {
        // Show spinner
        if (spinnerEl) spinnerEl.style.display = 'block';
        if (feedbackEl) {
            feedbackEl.textContent = '';
            feedbackEl.style.color = '';
        }

        try {
            const res = await fetch(`${BACKEND_URL}/resolve/${encodeURIComponent(code)}`);

            if (spinnerEl) spinnerEl.style.display = 'none';

            if (res.status === 429) {
                if (feedbackEl) {
                    feedbackEl.textContent = 'Too many attempts — wait a moment';
                    feedbackEl.style.color = '#f59e0b';
                }
                return;
            }

            if (res.status === 404) {
                if (feedbackEl) {
                    feedbackEl.textContent = 'GhostCode not found — check and try again';
                    feedbackEl.style.color = '#ef4444';
                }
                return;
            }

            if (!res.ok) {
                if (feedbackEl) {
                    feedbackEl.textContent = 'Lookup failed — try again';
                    feedbackEl.style.color = '#ef4444';
                }
                return;
            }

            const data = await res.json();

            // Auto-fill nodeId
            if (data.nodeId) {
                keyInput.value = data.nodeId;
                keyInput.readOnly = true;
                keyInput.style.opacity = '0.8';

                // Add edit/clear button
                const editBtn = document.createElement('button');
                editBtn.textContent = '✕';
                editBtn.title = 'Clear and re-enter manually';
                editBtn.style.cssText = 'position:absolute;right:10px;background:none;border:none;color:#ef4444;cursor:pointer;font-size:1rem;padding:4px;';
                editBtn.addEventListener('click', () => {
                    keyInput.value = '';
                    keyInput.readOnly = false;
                    keyInput.style.opacity = '1';
                    editBtn.remove();
                    if (feedbackEl) feedbackEl.textContent = '';
                });
                keyInput.parentElement.appendChild(editBtn);
                // Remove spinner to make room for edit button
                if (spinnerEl) spinnerEl.style.display = 'none';
            }

            // Auto-fill name if empty
            if (data.displayName && !nameInput.value.trim()) {
                nameInput.value = data.displayName;
            }

            // Show success feedback
            if (feedbackEl) {
                feedbackEl.style.color = '#10b981';
                feedbackEl.textContent = '✓ Found: ' + (data.displayName || code);
            }

        } catch (e) {
            if (spinnerEl) spinnerEl.style.display = 'none';
            if (feedbackEl) {
                feedbackEl.textContent = 'Could not reach server — try again';
                feedbackEl.style.color = '#ef4444';
            }
        }
    },

    submitNewChat: async () => {
        const name = document.getElementById('chat-name').value;
        const pubKey = document.getElementById('chat-pubkey').value;
        const errEl = document.getElementById('chat-new-error');
        const startBtn = document.getElementById('chat-start-btn');

        if (!name || !pubKey) {
            if (errEl) errEl.textContent = 'Please fill in both fields.';
            return;
        }

        // Show loading state
        if (startBtn) {
            startBtn.disabled = true;
            startBtn.textContent = 'VALIDATING...';
        }
        if (errEl) errEl.textContent = '';

        // Silent backend validation
        const BACKEND_URL = 'https://ghostnet-ji-production.up.railway.app';
        try {
            const validateUrl = `${BACKEND_URL}/validate-node/${encodeURIComponent(pubKey)}`;
            console.log(' Validating node:', validateUrl);
            const res = await fetch(validateUrl, {
                headers: getAuthHeaders()
            });

            if (!res.ok) {
                console.error('Validation HTTP error:', res.status, res.statusText);
                if (errEl) errEl.textContent = `⚠ Validation failed (HTTP ${res.status}). Try again.`;
                if (startBtn) {
                    startBtn.disabled = false;
                    startBtn.textContent = 'START SESSION';
                }
                return;
            }

            const contentType = res.headers.get('content-type') || '';
            if (!contentType.includes('application/json')) {
                console.error('Validation returned non-JSON:', contentType);
                if (errEl) errEl.textContent = '⚠ Server returned invalid response. Please try again.';
                if (startBtn) {
                    startBtn.disabled = false;
                    startBtn.textContent = 'START SESSION';
                }
                return;
            }

            const data = await res.json();

            if (!data.valid) {
                if (errEl) errEl.textContent = '⚠ Node not found. Check the Node ID and try again.';
                if (startBtn) {
                    startBtn.disabled = false;
                    startBtn.textContent = 'START SESSION';
                }
                return;
            }

            // Node is valid — connect seamlessly
            document.querySelector('.modal-overlay').remove();

            // Clear feed for new chat effect
            const feed = document.getElementById('chat-feed');
            if (feed) {
                feed.innerHTML = `<div style="text-align:center;color:#64748b;font-size:0.8rem;margin:20px;">-- Session with ${data.displayName || name} Started --</div>`;
            }

            // Setup app state target
            if (window.app) {
                window.app.chatTarget = pubKey;
            }

            UI.selectChat('new', data.displayName || name, pubKey);

        } catch (e) {
            console.error('Node validation error:', e);
            if (errEl) errEl.textContent = '⚠ Could not verify node. Server may be offline.';
            if (startBtn) {
                startBtn.disabled = false;
                startBtn.textContent = 'START SESSION';
            }
        }
    },

    loadConversations: async (userId) => {
        try {
            // [FIX] Robust Polling: Wait for the token to actually exist (up to 5s)
            // to prevent 401s during the re-login race condition.
            const token = await _waitForToken();

            if (!token) {
                console.error('[UI] Aborting conversations fetch: Auth token never arrived after 5s.');
                return;
            }

            const res = await fetch(`${BACKEND_URL}/conversations?userId=${userId}`, {
                headers: {
                    'Authorization': `Bearer ${token}`,
                    'Content-Type': 'application/json'
                }
            });
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

        list.replaceChildren();

        if (convos.length === 0) {
            const emptyState = document.createElement('div');
            emptyState.style.padding = '20px';
            emptyState.style.textAlign = 'center';
            emptyState.style.color = '#64748b';
            emptyState.style.fontSize = '0.8rem';
            emptyState.textContent = 'No conversations yet.';
            list.appendChild(emptyState);
            return;
        }

        convos.forEach(c => {
            const timeStr = new Date(c.updated).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });

            const username = c.otherUser ? (c.otherUser.username || c.otherUser.address || c.otherUser.id) : 'Unknown';
            let preview = c.lastMessage || 'Message...';
            if (typeof preview === 'object' && preview.body) preview = preview.body;
            if (typeof preview === 'string' && preview.includes('body":"')) {
                try { preview = JSON.parse(preview).body; } catch (e) { }
            }

            const row = document.createElement('div');
            row.className = `chat-user-row ${(AppState.activeConvoId === c.id) ? 'active' : ''}`;
            row.dataset.convo = c.id;
            row.onclick = () => UI.selectChat(c.id, username, c.otherUser ? c.otherUser.id : '');

            const avatarWrap = document.createElement('div');
            avatarWrap.className = 'chat-avatar-wrap';
            avatarWrap.appendChild(UI.renderAvatar(c.otherUser, 40));

            const userInfo = document.createElement('div');
            userInfo.className = 'chat-user-info';

            const userTop = document.createElement('div');
            userTop.className = 'chat-user-top';

            const usernameSpan = document.createElement('span');
            usernameSpan.className = 'chat-username';
            usernameSpan.textContent = username;

            const timeSpan = document.createElement('span');
            timeSpan.className = 'chat-time';
            timeSpan.textContent = timeStr;

            userTop.appendChild(usernameSpan);
            userTop.appendChild(timeSpan);

            const userBottom = document.createElement('div');
            userBottom.className = 'chat-user-bottom';

            const previewSpan = document.createElement('span');
            previewSpan.className = 'chat-preview';
            previewSpan.textContent = preview;

            userBottom.appendChild(previewSpan);

            userInfo.appendChild(userTop);
            userInfo.appendChild(userBottom);

            row.appendChild(avatarWrap);
            row.appendChild(userInfo);

            list.appendChild(row);
        });
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

        // Setup Header Avatar
        const activeRow = document.querySelector(`.chat-user-row[data-convo="${convoId}"]`);
        const headerAvatar = document.getElementById('active-chat-avatar');
        if (headerAvatar) {
            let avatarData = null;
            if (activeRow) {
                const img = activeRow.querySelector('img');
                if (img) avatarData = img.src;
            }
            const activeUser = {
                displayName: nameStr || targetUserId,
                username: nameStr || targetUserId,
                avatar: avatarData
            };

            headerAvatar.style.background = 'transparent';
            headerAvatar.style.width = 'auto';
            headerAvatar.style.height = 'auto';
            headerAvatar.style.border = 'none';
            headerAvatar.replaceChildren(UI.renderAvatar(activeUser, 44));
        }

        const feed = document.getElementById('chat-feed');
        if (feed) feed.innerHTML = ''; // clear current feed

        // Load History
        if (convoId && convoId !== 'new') {
            try {
                const res = await fetch(`https://ghostnet-ji-production.up.railway.app/history?convoId=${convoId}`, {
                    headers: getAuthHeaders()
                });
                if (res.ok) {
                    const msgs = await res.json();
                    msgs.forEach(m => {
                        const myNodeId = AppState.identity ? (AppState.identity.nodeId || AppState.identity.id) : null;
                        const type = (m.senderId === myNodeId) ? 'me' : 'them';

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

        UI.updateRelayMonitor(); // [Feature 4]
    },

    updateRelayMonitor: () => {
        if (!window.app || !window.app.mesh) return;
        const stats = window.app.mesh.getRelayStats();
        
        const packetsEl = document.getElementById('relay-stat-packets');
        const bytesEl = document.getElementById('relay-stat-bytes');
        const uptimeEl = document.getElementById('relay-stat-uptime');

        if (packetsEl) packetsEl.textContent = stats.packets.toLocaleString();
        if (bytesEl) {
            let size = stats.bytes;
            let unit = 'B';
            if (size > 1024) { size /= 1024; unit = 'KB'; }
            if (size > 1024) { size /= 1024; unit = 'MB'; }
            bytesEl.textContent = `${size.toFixed(1)} ${unit}`;
        }
        if (uptimeEl) {
            let s = stats.uptime;
            let m = Math.floor(s / 60);
            let h = Math.floor(m / 60);
            s %= 60; m %= 60;
            uptimeEl.textContent = `${h > 0 ? h + 'h ' : ''}${m > 0 ? m + 'm ' : ''}${s}s`;
        }
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
                const myId = (window.AppState && window.AppState.identity) ? (window.AppState.identity.nodeId || window.AppState.identity.id) : 'anonymous';
                const targetId = (window.app && window.app.chatTarget) || 'broadcast';
                try {
                    const res = await fetch('https://ghostnet-ji-production.up.railway.app/message', {
                        method: 'POST',
                        headers: getAuthHeaders(),
                        body: JSON.stringify({
                            senderId: myId,
                            receiverId: targetId,
                            content: text
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

    stringToColor: (str) => {
        if (!str) return 'hsl(220, 55%, 40%)';
        let hash = 0;
        for (let i = 0; i < str.length; i++) {
            hash = str.charCodeAt(i) + ((hash << 5) - hash);
        }
        const hue = Math.abs(hash % 360);
        return `hsl(${hue}, 55%, 40%)`;
    },

    _renderAvatarText: (container, user) => {
        const nameStr = (user && (user.displayName || user.username)) ? (user.displayName || user.username) : '?';
        const initial = nameStr.charAt(0).toUpperCase();

        container.style.background = UI.stringToColor(nameStr);
        container.style.color = '#ffffff';
        container.style.fontSize = `${parseInt(container.style.width) * 0.45}px`;
        container.style.fontWeight = 'bold';
        container.style.userSelect = 'none';

        const txt = document.createElement('span');
        txt.textContent = initial;
        container.appendChild(txt);
    },

    renderAvatar: (user, size = 40) => {
        const container = document.createElement('div');
        container.className = 'chat-avatar-rendered';
        container.style.width = `${size}px`;
        container.style.height = `${size}px`;
        container.style.borderRadius = '50%';
        container.style.overflow = 'hidden';
        container.style.background = '#2a2f45';
        container.style.display = 'flex';
        container.style.alignItems = 'center';
        container.style.justifyContent = 'center';
        container.style.flexShrink = '0';

        if (user && user.avatar && /^data:image\/(png|jpeg|webp|gif);base64,/.test(user.avatar)) {
            const img = document.createElement('img');
            img.src = user.avatar;
            img.style.width = '100%';
            img.style.height = '100%';
            img.style.objectFit = 'cover';
            img.style.cursor = 'pointer';

            img.onclick = (e) => {
                e.stopPropagation();
                if (window.UI) UI.viewLargeAvatar(img.src);
            };

            img.onerror = () => {
                img.remove();
                UI._renderAvatarText(container, user);
            };

            container.appendChild(img);
        } else {
            UI._renderAvatarText(container, user);
        }

        return container;
    },

    viewLargeAvatar: (src) => {
        const modal = document.createElement('div');
        modal.className = "modal-overlay";
        modal.style.zIndex = "99999";
        modal.innerHTML = `
            <div class="modal-card" style="padding:10px; background: transparent; border: none; text-align:center; max-width:95vw; max-height:95vh;">
                <button class="modal-close" style="position:absolute; right:15px; top:15px; z-index:100; background:rgba(0,0,0,0.6); padding:5px 12px; border-radius:50%; font-size:1.5rem; border:1px solid #444;" onclick="this.closest('.modal-overlay').remove()">×</button>
                <img src="${src}" style="max-width:100%; max-height:85vh; border-radius:12px; object-fit:contain; box-shadow: 0 10px 40px rgba(0,0,0,0.8); pointer-events:none;">
            </div>
        `;
        document.body.appendChild(modal);
    },

    addMessage: (text, type) => {
        const feed = document.getElementById('chat-feed');
        if (!feed) return;

        const msg = document.createElement('div');
        msg.className = `message ${type}`;

        let fileId, mimeType, encKeyStr, fileName;
        if (typeof text === 'string' && text.startsWith('[FILE:') && text.endsWith(']')) {
            const parts = text.slice(6, -1).split(':');
            if (parts.length >= 4) {
                fileId = parts[0];
                mimeType = parts[1];
                encKeyStr = parts[2] || '';
                fileName = parts.slice(3).join(':');
            } else if (parts.length === 3) {
                fileId = parts[0];
                mimeType = parts[1];
                encKeyStr = '';
                fileName = parts[2];
            }
        }

        if (fileId) {
            msg.innerHTML = `
                <div style="display:flex; flex-direction:column; gap:8px; background:rgba(0,0,0,0.1); padding:8px; border-radius:8px;">
                    <div style="font-weight:bold; font-size:0.9em; word-break:break-all;">📎 ${fileName.replace(/</g, '&lt;')}</div>
                    <button class="btn-primary" style="padding:6px 12px; font-size:0.85em; cursor:pointer;" onclick="this.textContent='Decrypting...'; window.GhostVault.downloadFile('${fileId}', '${encKeyStr}').then(() => this.textContent='Decrypted & Downloaded!').catch(() => { showToast('Download failed'); this.textContent='Download Failed'; })">
                        Secure Download
                    </button>
                </div>
            `;
        } else {
            msg.innerText = text;
        }

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

    promptVaultKeyRecovery: async (serverKeyData) => {
        return new Promise((resolve) => {
            const modal = document.createElement('div');
            modal.className = "modal-overlay";
            const action = serverKeyData ? 'Recover Vault Key' : 'Create Vault Key';
            const subtitle = serverKeyData
                ? 'Your file vault key was found on the network. Enter your PIN to decrypt and restore it.'
                : 'Your file vault key is missing. Enter your PIN to generate a new one. <br><span style="color:#ef4444;font-size:0.8rem;">Warning: Previous files will not be decryptable.</span>';
            modal.innerHTML = `
                <div class="modal-card">
                    <div class="modal-title">${action}</div>
                    <div style="font-size:0.9rem; color:var(--text-muted); margin-bottom:15px;">${subtitle}</div>
                    <input type="password" id="vault-pin-input" class="wlt-input" placeholder="Enter 6-digit PIN" maxlength="6" style="text-align:center; letter-spacing:4px; font-size:1.2rem;">
                    <div id="vault-pin-error" style="color:#ef4444; font-size:0.8rem; height:20px; text-align:center; margin-top:10px;"></div>
                    <div style="display:flex; gap:10px; margin-top:15px;">
                        <button class="btn-primary" style="background:var(--border);" onclick="this.closest('.modal-overlay').remove(); window._vaultKeyResolver(null)">Cancel</button>
                        <button class="btn-primary" id="vault-pin-submit">Confirm</button>
                    </div>
                </div>
            `;
            document.body.appendChild(modal);

            window._vaultKeyResolver = resolve;

            document.getElementById('vault-pin-submit').onclick = async () => {
                const pin = document.getElementById('vault-pin-input').value;
                if (pin.length < 6) {
                    document.getElementById('vault-pin-error').textContent = 'Enter full 6-digit PIN';
                    return;
                }
                document.getElementById('vault-pin-error').textContent = 'Processing...';
                document.getElementById('vault-pin-submit').disabled = true;

                try {
                    let finalKey = null;
                    if (serverKeyData) {
                        finalKey = await window.GhostVault._recoverVaultKey(pin, serverKeyData);
                    } else {
                        finalKey = await window.GhostVault._generateVaultKey(pin);
                    }
                    modal.remove();
                    resolve(finalKey);
                } catch (e) {
                    document.getElementById('vault-pin-error').textContent = e.message || 'Incorrect PIN';
                    document.getElementById('vault-pin-submit').disabled = false;
                }
            };
        });
    },

    loadProfile: async () => {
        // Skip server fetch when not authenticated — use cached data only
        if (hasAuthToken()) {
            try {
                const res = await fetch(`${BACKEND_URL}/user/profile`, { headers: authHeaders() });
                if (res.ok) {
                    const user = await res.json();
                    localStorage.setItem('ghostnet_profile_cache', JSON.stringify(user));
                    localStorage.setItem('ghostnet_user', JSON.stringify(user));
                }
            } catch { }
        }

        const stored = localStorage.getItem('ghostnet_profile_cache') || localStorage.getItem('ghostnet_user');
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
                    sidebarAddress.innerText = user.displayName || user.username || user.address || '';
                    sidebarId.innerText = user.id || '';
                }

                // Update Profile View
                const viewAddress = document.getElementById('profile-address');
                const viewPreview = document.getElementById('profile-preview');
                const viewId = document.getElementById('profile-id-display');

                if (viewAddress) viewAddress.value = user.displayName || user.username || user.address || '';
                if (viewId) viewId.innerText = 'Current ID: ' + (user.id || '');
                if (viewPreview && user.avatar) {
                    viewPreview.src = user.avatar;
                    viewPreview.style.display = 'block';
                }

        // Load conversations for this user
                const userId = (AppState && AppState.identity) ? (AppState.identity.nodeId || AppState.identity.id) : user.id;
                UI.loadConversations(userId);

                // Fetch and display GhostCode
                UI.fetchGhostCode();
            } catch (e) {
                console.error("Error parsing user profile", e);
                if (AppState && AppState.identity) {
                    UI.loadConversations(AppState.identity.nodeId || AppState.identity.id);
                }
            }
        } else {
            // No custom profile saved, but we still have a stable AppState identity from app.js
            if (AppState && AppState.identity) {
                UI.loadConversations(AppState.identity.nodeId || AppState.identity.id);
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

    saveProfile: async () => {
        const addr = document.getElementById('profile-address').value;
        const viewPreview = document.getElementById('profile-preview');
        let avatarData = viewPreview ? viewPreview.getAttribute('src') : '';
        if (avatarData && !avatarData.startsWith('data:')) {
            avatarData = '';
        }

        try {
            const res = await fetch(`${BACKEND_URL}/user/profile`, {
                method: "PATCH",
                headers: authHeaders(),
                body: JSON.stringify({
                    displayName: addr,
                    avatar: avatarData
                })
            });
            const data = await res.json();
            if (data.error) {
                alert(data.error + "\\nSuggestions:\\n" + (data.suggestions ? data.suggestions.join("\\n") : ""));
            } else {
                alert("Profile saved!");
                localStorage.setItem("ghostnet_user", JSON.stringify(data.user || data));
                UI.loadProfile();
            }
        } catch (err) {
            console.error("Save profile error:", err);
            alert("Failed to connect to the server.");
        }
    },

    // ═══════════════════════════════════════════════════
    //  FILE VAULT UI
    // ═══════════════════════════════════════════════════

    initVault: () => {
        const dropZone = document.getElementById('vault-drop-zone');
        const fileInput = document.getElementById('vault-file-input');
        const browseBtn = document.getElementById('vault-browse-btn');

        if (!dropZone || !fileInput) return;

        // Vault depends on Web Crypto (secure context) and the GhostVault module script.
        // Never use native alert(); show an inline warning + disable interactions.
        const ensureVaultBanner = (message) => {
            const host = document.getElementById('view-vault') || dropZone.closest('.view-section') || dropZone.parentElement;
            if (!host) return null;
            let banner = document.getElementById('vault-crypto-banner');
            if (banner) {
                banner.textContent = message;
                return banner;
            }
            banner = document.createElement('div');
            banner.id = 'vault-crypto-banner';
            banner.textContent = message;
            banner.style.cssText = [
                'margin:0 0 12px 0',
                'padding:10px 12px',
                'border-radius:12px',
                'border:1px solid rgba(245,158,11,0.35)',
                'background:rgba(245,158,11,0.10)',
                'color:var(--text-primary)',
                'font-size:0.82rem',
                'line-height:1.4',
            ].join(';');
            const dzParent = dropZone.parentElement;
            if (dzParent) dzParent.insertBefore(banner, dropZone);
            else host.prepend(banner);
            return banner;
        };

        const setVaultEnabled = (enabled) => {
            const opacity = enabled ? '1' : '0.55';
            dropZone.style.opacity = opacity;
            dropZone.style.pointerEvents = enabled ? 'auto' : 'none';
            if (browseBtn) {
                browseBtn.disabled = !enabled;
                browseBtn.style.opacity = opacity;
                browseBtn.style.pointerEvents = enabled ? 'auto' : 'none';
            }
            const lockBtn = document.getElementById('vault-lock-btn');
            if (lockBtn) {
                lockBtn.disabled = !enabled;
                lockBtn.style.opacity = enabled ? '1' : opacity;
            }
        };

        const webCryptoOk = !!(window.crypto && window.crypto.subtle);
        if (!webCryptoOk) {
            ensureVaultBanner(`🔒 Vault requires a secure context (HTTPS or localhost). Current: ${location.protocol}`);
            showToast('Vault encryption unavailable — HTTPS required');
            setVaultEnabled(false);
            return;
        }
        if (!window.GhostVault) {
            ensureVaultBanner('🔒 Vault encryption module failed to load. Refresh the page, or ensure `ghostnet-file-vault.js` is reachable.');
            showToast('Vault encryption unavailable — module not loaded');
            setVaultEnabled(false);
            return;
        }
        setVaultEnabled(true);

        // Wire "Lock Vault" button to clear session state.
        const lockBtn = document.getElementById('vault-lock-btn');
        if (lockBtn && !lockBtn._wired) {
            lockBtn._wired = true;
            lockBtn.addEventListener('click', () => {
                if (window.GhostVault && typeof window.GhostVault.lockVault === 'function') {
                    window.GhostVault.lockVault();
                    showToast('Vault locked for this session');
                }
            });
        }

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
            showToast('Vault encryption module not loaded');
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
                encrypting: { text: ' Encrypting...', detail: `AES-256-GCM encrypting "${file.name}"`, icon: 'shield', percent: 30 },
                uploading: { text: 'Uploading...', detail: `Sending encrypted blob to vault`, icon: 'upload-cloud', percent: 65 },
                anchoring: { text: ' Anchoring on chain...', detail: `Recording SHA-256 hash on blockchain`, icon: 'link', percent: 90 },
                complete: { text: ' Secured!', detail: `"${file.name}" encrypted & anchored`, icon: 'check-circle', percent: 100 }
            };

            try {
                const result = await GhostVault.uploadFile(file, (progress) => {
                    const stage = stages[progress.stage] || stages.encrypting;
                    if (stageEl) stageEl.textContent = stage.text;
                    if (barEl) barEl.style.width = stage.percent + '%';
                    if (detailEl) detailEl.textContent = stage.detail;
                    if (iconEl) {
                        iconEl.textContent = '';
                        const icon = document.createElement('i');
                        icon.setAttribute('data-lucide', stage.icon);
                        icon.style.width = '32px';
                        icon.style.height = '32px';
                        iconEl.appendChild(icon);
                        if (typeof lucide !== 'undefined') lucide.createIcons();
                    }
                });

                console.log(' Vault upload complete:', result);
            } catch (err) {
                console.error(' Vault upload failed:', err);
                if (stageEl) stageEl.textContent = ' Upload Failed';
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

        const clearEl = (el) => {
            while (el.firstChild) el.removeChild(el.firstChild);
        };

        if (!files || files.length === 0) {
            clearEl(listEl);
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

        // "On-chain" is not fully implemented yet; show actually stored files instead.
        // Treat any successfully listed file as stored, and treat chainAnchored as "confirmed".
        const storedCount = files.length;
        const confirmedCount = files.filter(f => f.chainAnchored).length;

        if (countEl) countEl.textContent = String(files.length);
        if (sizeEl) sizeEl.textContent = GhostVault.formatBytes(totalSize);
        if (anchoredEl) {
            const label = confirmedCount > 0 ? `${confirmedCount} confirmed` : `${storedCount} stored`;
            anchoredEl.textContent = label;
        }

        // Render file cards (DOM API only; no innerHTML)
        clearEl(listEl);
        for (const f of files) {
            const card = document.createElement('div');
            card.className = 'vault-file-card';
            card.dataset.fileId = f.fileId;

            const header = document.createElement('div');
            header.className = 'vault-file-header';

            const iconWrap = document.createElement('div');
            iconWrap.className = 'vault-file-icon';
            const icon = document.createElement('i');
            icon.setAttribute('data-lucide', 'file-lock');
            icon.style.width = '20px';
            icon.style.height = '20px';
            iconWrap.appendChild(icon);

            const info = document.createElement('div');
            info.className = 'vault-file-info';

            const name = document.createElement('div');
            name.className = 'vault-file-name';
            name.title = f.fileName || '';
            name.textContent = f.fileName || 'encrypted_file';

            const timeStr = f.uploadedAt
                ? new Date(f.uploadedAt).toLocaleDateString(undefined, { month: 'short', day: 'numeric', year: 'numeric' })
                : '';
            const sizeStr = GhostVault.formatBytes(f.originalSize || f.fileSize || 0);
            const meta = document.createElement('div');
            meta.className = 'vault-file-size';
            meta.textContent = timeStr ? `${sizeStr} • ${timeStr}` : sizeStr;

            info.appendChild(name);
            info.appendChild(meta);

            header.appendChild(iconWrap);
            header.appendChild(info);
            card.appendChild(header);

            const badge = document.createElement('div');
            // Status mapping:
            // - If chainAnchored is true → Confirmed
            // - Otherwise → Stored (upload succeeded but not anchored on-chain)
            let status = 'Stored';
            let statusClass = 'stored';
            if (f.chainAnchored) {
                status = 'Confirmed';
                statusClass = 'confirmed';
            }
            badge.className = `vault-chain-badge ${statusClass}`;
            const badgeIcon = document.createElement('i');
            if (status === 'Pending') {
                badgeIcon.setAttribute('data-lucide', 'clock');
            } else if (status === 'Failed') {
                badgeIcon.setAttribute('data-lucide', 'x-circle');
            } else if (status === 'Confirmed') {
                badgeIcon.setAttribute('data-lucide', 'link');
            } else {
                // Stored
                badgeIcon.setAttribute('data-lucide', 'shield-check');
            }
            badgeIcon.style.width = '10px';
            badgeIcon.style.height = '10px';
            badge.appendChild(badgeIcon);

            const badgeText = document.createElement('span');
            const txShort = f.txHash ? ` • ${String(f.txHash).substring(0, 10)}...` : '';
            badgeText.textContent = `${status}${txShort}`;
            badge.appendChild(badgeText);
            card.appendChild(badge);

            const hash = document.createElement('div');
            hash.className = 'vault-file-hash';
            hash.textContent = f.fileHash
                ? `SHA-256: ${String(f.fileHash).substring(0, 8)}...${String(f.fileHash).substring(String(f.fileHash).length - 8)}`
                : '';
            card.appendChild(hash);

            const actions = document.createElement('div');
            actions.className = 'vault-file-actions';

            const downloadBtn = document.createElement('button');
            downloadBtn.className = 'vault-action-btn';
            const downloadIcon = document.createElement('i');
            downloadIcon.setAttribute('data-lucide', 'download');
            downloadIcon.style.width = '14px';
            downloadBtn.appendChild(downloadIcon);
            const hasKey = GhostVault.hasKey(f.fileId);
            downloadBtn.appendChild(document.createTextNode(' ' + (hasKey ? 'Download' : 'No Key')));
            downloadBtn.disabled = !hasKey;
            if (!hasKey) downloadBtn.title = 'Key not found on this device';
            downloadBtn.addEventListener('click', () => UI.vaultDownload(f.fileId));

            const verifyBtn = document.createElement('button');
            verifyBtn.className = 'vault-action-btn verify';
            const verifyIcon = document.createElement('i');
            verifyIcon.setAttribute('data-lucide', 'shield-check');
            verifyIcon.style.width = '14px';
            verifyBtn.appendChild(verifyIcon);
            verifyBtn.appendChild(document.createTextNode(' Verify'));
            verifyBtn.addEventListener('click', () => UI.vaultVerify(f.fileId));

            const delBtn = document.createElement('button');
            delBtn.className = 'vault-action-btn danger';
            const delIcon = document.createElement('i');
            delIcon.setAttribute('data-lucide', 'trash-2');
            delIcon.style.width = '14px';
            delBtn.appendChild(delIcon);
            delBtn.addEventListener('click', () => UI.vaultDelete(f.fileId, f.fileName || 'file'));

            actions.appendChild(downloadBtn);
            actions.appendChild(verifyBtn);
            actions.appendChild(delBtn);
            card.appendChild(actions);

            listEl.appendChild(card);
        }

        if (typeof lucide !== 'undefined') lucide.createIcons();
    },

    vaultDownload: async (fileId) => {
        try {
            await GhostVault.downloadFile(fileId);
        } catch (err) {
            showToast('Download failed');
        }
    },

    vaultDelete: async (fileId, fileName) => {
        if (!confirm(`Delete "${fileName}" permanently?\n\nThis will remove the file from the vault. The blockchain record will be marked as deleted.`)) return;

        try {
            await GhostVault.deleteFile(fileId);
            console.log(' File deleted:', fileId);
            UI.vaultLoadFiles();
        } catch (err) {
            showToast('Delete failed');
        }
    },

    vaultVerify: async (fileId) => {
        try {
            const result = await GhostVault.verifyFile(fileId);
            if (!result) {
                showToast('Verification failed');
                return;
            }

            // Show verify modal
            const modal = document.createElement('div');
            modal.className = 'vault-verify-overlay';
            modal.onclick = (e) => { if (e.target === modal) modal.remove(); };
            const cardEl = document.createElement('div');
            cardEl.className = 'vault-verify-card';

            const h3 = document.createElement('h3');
            h3.style.cssText = "font-family:var(--font-heading); margin-bottom:16px; color:var(--text-primary); display:flex; align-items:center; gap:8px;";
            h3.textContent = 'Integrity Verification';
            cardEl.appendChild(h3);

            const rows = [
                { label: 'File', value: result.fileName, cls: '' },
                { label: 'Disk Integrity', value: result.diskIntegrity ? '✓ PASS' : '✕ TAMPERED', cls: result.diskIntegrity ? 'pass' : 'fail' },
                { label: 'Chain Verified', value: result.chainVerified ? '✓ ON-CHAIN' : '⏳ PENDING', cls: result.chainVerified ? 'pass' : 'fail' },
                { label: 'SHA-256 Hash', value: result.storedHash ? result.storedHash.substring(0, 16) + '...' : 'N/A', cls: '', style: 'font-size:0.65rem;' },
            ];
            if (result.txHash) {
                rows.push({ label: 'TX Hash', value: result.txHash.substring(0, 16) + '...', cls: '', style: 'font-size:0.65rem;' });
            }

            rows.forEach(r => {
                const row = document.createElement('div');
                row.className = 'vault-verify-row';
                const lbl = document.createElement('span');
                lbl.className = 'vault-verify-label';
                lbl.textContent = r.label;
                const val = document.createElement('span');
                val.className = 'vault-verify-value' + (r.cls ? ' ' + r.cls : '');
                if (r.style) val.style.cssText = r.style;
                val.textContent = r.value;
                row.appendChild(lbl);
                row.appendChild(val);
                cardEl.appendChild(row);
            });

            const closeBtn = document.createElement('button');
            closeBtn.className = 'btn-primary';
            closeBtn.textContent = 'Close';
            closeBtn.style.marginTop = '16px';
            closeBtn.addEventListener('click', () => modal.remove());
            cardEl.appendChild(closeBtn);

            modal.appendChild(cardEl);
            document.body.appendChild(modal);
            if (typeof lucide !== 'undefined') lucide.createIcons();
        } catch (err) {
            showToast('Verification error');
        }
    },


    // ═══════════════════════════════════════════════════
    //  GHOSTCODE UI FUNCTIONS
    // ═══════════════════════════════════════════════════

    /**
     * Fetch the current user's GhostCode from the server and display it.
     */
    fetchGhostCode: async () => {
        // Skip when not authenticated to avoid 401 errors
        if (!hasAuthToken()) return;
        try {
            const nodeId = AppState.identity ? (AppState.identity.nodeId || AppState.identity.id) : null;
            const displayName = AppState.identity ? (AppState.identity.displayName || AppState.identity.username) : null;
            let url = `${BACKEND_URL}/user/shortcode`;
            const params = [];
            if (nodeId) params.push(`nodeId=${encodeURIComponent(nodeId)}`);
            if (displayName) params.push(`displayName=${encodeURIComponent(displayName)}`);
            if (params.length > 0) url += '?' + params.join('&');

            const res = await fetch(url, { headers: authHeaders() });
            if (!res.ok) {
                console.warn('GhostCode fetch failed:', res.status);
                _setGhostCodeBadgeText(res.status === 401 ? 'SIGN IN' : 'ERROR');
                return;
            }
            const data = await res.json();
            if (data.shortCode) {
                AppState.ghostCode = data.shortCode.toUpperCase();
                UI.updateGhostCodeBadge(AppState.ghostCode);
            }
        } catch (e) {
            console.warn('GhostCode fetch error:', e);
            _setGhostCodeBadgeText('OFFLINE');
        }
    },

    /**
     * Watcher to ensure the GhostCode badge resolves.
     * - Retries while auth token / identity may still be settling.
     * - After 8s with no code, shows "Not connected" + a Retry button.
     */
    startGhostCodeWatcher: (force = false) => {
        const badge = _getGhostcodeBadgeEl();
        if (!badge) return;

        const existing = (AppState && AppState.ghostCode) ? String(AppState.ghostCode) : '';
        if (!force && existing && /^GN-/.test(existing)) {
            _setGhostCodeBadgeText(existing);
            return;
        }

        const start = Date.now();
        _setGhostCodeBadgeText('Loading...');

        const tick = async () => {
            const current = (AppState && AppState.ghostCode) ? String(AppState.ghostCode) : '';
            if (current && /^GN-/.test(current)) {
                _setGhostCodeBadgeText(current);
                const retryBtn = document.getElementById('ghostcode-retry-btn');
                if (retryBtn) retryBtn.style.display = 'none';
                return;
            }

            const liveToken =
                sessionStorage.getItem('ghostnet_token') ||
                localStorage.getItem('ghostnet_jwt') ||
                localStorage.getItem('ghostnet_token') ||
                '';

            if (liveToken) {
                await UI.fetchGhostCode();
            }

            const after = (AppState && AppState.ghostCode) ? String(AppState.ghostCode) : '';
            if (after && /^GN-/.test(after)) {
                _setGhostCodeBadgeText(after);
                const retryBtn = document.getElementById('ghostcode-retry-btn');
                if (retryBtn) retryBtn.style.display = 'none';
                return;
            }

            if (Date.now() - start >= GHOSTCODE_MAX_WAIT_MS) {
                _setGhostCodeBadgeText('Not connected');
                const btn = _ensureGhostCodeRetryButton();
                if (btn) btn.style.display = 'inline-flex';
                return;
            }

            setTimeout(tick, 1000);
        };

        setTimeout(tick, 150);
    },

    /**
     * Update the GhostCode badge element in the profile dashboard.
     */
    updateGhostCodeBadge: (code) => {
        _setGhostCodeBadgeText(String(code).toUpperCase());
    },

    /**
     * Copy the current user's GhostCode to clipboard.
     */
    copyGhostCode: () => {
        const code = AppState.ghostCode ? String(AppState.ghostCode) : '';
        if (!code || code === 'Loading...' || code === 'Not connected') {
            showToast('GhostCode not ready yet');
            return;
        }
        try {
            navigator.clipboard.writeText(code);
            showToast('GhostCode copied!');
        } catch (e) {
            console.error('Copy failed:', e);
        }
    },

    /**
     * Share GhostCode via Web Share API, or fallback to copy.
     */
    shareGhostCode: () => {
        const code = AppState.ghostCode ? String(AppState.ghostCode) : '';
        if (!code || code === 'Loading...' || code === 'Not connected') {
            showToast('GhostCode not ready yet');
            return;
        }
        if (navigator.share) {
            navigator.share({
                text: 'Find me on GhostNet: ' + code,
                title: 'GhostNet'
            }).catch(() => {});
        } else {
            try {
                navigator.clipboard.writeText(code);
                showToast('GhostCode copied — share it anywhere');
            } catch (e) {
                console.error('Share fallback failed:', e);
            }
        }
    },

    /**
     * Initialize GhostCode search in the chat sidebar search bar.
     */
    initChatSearch: () => {
        const searchInput = document.getElementById('chat-search-input');
        const resultContainer = document.getElementById('ghostcode-search-result');
        if (!searchInput || !resultContainer) return;

        let searchTimeout = null;

        searchInput.addEventListener('input', () => {
            const val = searchInput.value.trim();
            clearTimeout(searchTimeout);

            // If input matches GN- prefix, search for GhostCode
            if (val.match(/^GN-/i)) {
                searchTimeout = setTimeout(async () => {
                    const code = val.toUpperCase();
                    if (!/^GN-[A-Z0-9]{4,6}$/i.test(code)) {
                        resultContainer.style.display = 'none';
                        return;
                    }

                    try {
                        const res = await fetch(`${BACKEND_URL}/resolve/${encodeURIComponent(code)}`, {
                            headers: getAuthHeaders()
                        });
                        if (res.ok) {
                            const data = await res.json();
                            // Build result row using DOM API
                            resultContainer.textContent = '';
                            resultContainer.style.display = 'block';
                            resultContainer.style.cssText = 'display:block;padding:10px 12px;margin:0 8px 8px 8px;background:var(--bg-panel);border-left:3px solid #00f0ff;border-radius:8px;cursor:pointer;';
                            
                            const rowWrap = document.createElement('div');
                            rowWrap.style.cssText = 'display:flex;align-items:center;justify-content:space-between;';
                            
                            const textWrap = document.createElement('div');
                            const nameSpan = document.createElement('span');
                            nameSpan.style.cssText = 'font-weight:700;color:var(--text-primary);';
                            nameSpan.textContent = 'Add ' + (data.displayName || 'User');
                            const codeSpan = document.createElement('span');
                            codeSpan.style.cssText = 'color:#00f0ff;font-family:monospace;font-size:0.8rem;margin-left:8px;';
                            codeSpan.textContent = '(' + data.shortCode + ')';
                            textWrap.appendChild(nameSpan);
                            textWrap.appendChild(codeSpan);
                            
                            const addBtn = document.createElement('button');
                            addBtn.textContent = '+';
                            addBtn.style.cssText = 'background:#00f0ff;color:#0d1117;border:none;border-radius:50%;width:28px;height:28px;font-size:1.2rem;font-weight:bold;cursor:pointer;display:flex;align-items:center;justify-content:center;';
                            addBtn.addEventListener('click', (e) => {
                                e.stopPropagation();
                                // Open new chat pre-filled
                                UI.openNewChat();
                                setTimeout(() => {
                                    const nameEl = document.getElementById('chat-name');
                                    const keyEl = document.getElementById('chat-pubkey');
                                    if (nameEl && data.displayName) nameEl.value = data.displayName;
                                    if (keyEl && data.nodeId) {
                                        keyEl.value = data.nodeId;
                                        keyEl.readOnly = true;
                                        keyEl.style.opacity = '0.8';
                                    }
                                    const feedback = document.getElementById('ghostcode-resolve-feedback');
                                    if (feedback) {
                                        feedback.style.color = '#10b981';
                                        feedback.textContent = '✓ Found: ' + (data.displayName || code);
                                    }
                                }, 100);
                                searchInput.value = '';
                                resultContainer.style.display = 'none';
                            });

                            rowWrap.appendChild(textWrap);
                            rowWrap.appendChild(addBtn);
                            resultContainer.appendChild(rowWrap);
                        } else if (res.status === 404) {
                            resultContainer.textContent = '';
                            resultContainer.style.display = 'block';
                            resultContainer.style.cssText = 'display:block;padding:10px 12px;margin:0 8px 8px 8px;color:var(--text-muted);font-size:0.8rem;text-align:center;';
                            resultContainer.textContent = 'No GhostNet user found with that code';
                        } else {
                            resultContainer.style.display = 'none';
                        }
                    } catch (err) {
                        resultContainer.textContent = '';
                        resultContainer.style.display = 'block';
                        resultContainer.style.cssText = 'display:block;padding:10px 12px;margin:0 8px 8px 8px;color:var(--text-muted);font-size:0.8rem;text-align:center;';
                        resultContainer.textContent = 'Could not reach server';
                    }
                }, 500);
            } else {
                resultContainer.style.display = 'none';
                // TODO: Local conversation search can happen here
            }
        });
    },

    // GHOST CARDS - Generate Ghost Card
    generateGhostCard: async () => {
        if (!AppState || !AppState.identity || !AppState.identity.nodeId) {
            const toast = document.createElement('div');
            toast.textContent = 'Connect to GhostNet first to generate your card';
            toast.style.cssText = 'position:fixed;bottom:20px;left:50%;transform:translateX(-50%);background:#ef4444;color:#fff;padding:10px 20px;border-radius:8px;z-index:100000;';
            document.body.appendChild(toast);
            setTimeout(() => toast.remove(), 3000);
            return;
        }

        if (document.getElementById('ghostcard-modal')) {
            document.getElementById('ghostcard-modal').focus();
            return;
        }

        if (!document.getElementById('ghost-card-styles')) {
            const style = document.createElement('style');
            style.id = 'ghost-card-styles';
            style.textContent = `
@keyframes ghostCardEntrance {
  0%   { transform: perspective(1000px) rotateX(25deg) rotateY(-15deg) scale(0.6); opacity: 0; }
  60%  { transform: perspective(1000px) rotateX(-5deg) rotateY(3deg) scale(1.03); opacity: 1; }
  80%  { transform: perspective(1000px) rotateX(2deg) rotateY(-1deg) scale(0.99); }
  100% { transform: perspective(1000px) rotateX(0deg) rotateY(0deg) scale(1); }
}
@keyframes ghostCardExit {
  0%   { transform: perspective(1000px) rotateX(0deg) rotateY(0deg) scale(1); opacity: 1; }
  100% { transform: perspective(1000px) rotateX(15deg) rotateY(10deg) scale(0.5); opacity: 0; }
}
@keyframes floatCard {
  0%, 100% { transform: perspective(1000px) rotateX(2deg) rotateY(2deg) translateY(0px); }
  50%       { transform: perspective(1000px) rotateX(-2deg) rotateY(-2deg) translateY(-8px); }
}
@keyframes fadeSlideUp {
  0% { opacity: 0; transform: translateY(20px); }
  100% { opacity: 1; transform: translateY(0); }
}
@keyframes shimmer {
  0% { transform: translateX(-100%) skewX(-15deg); }
  100% { transform: translateX(200%) skewX(-15deg); }
}`;
            document.head.appendChild(style);
        }

        const nodeId = AppState.identity.nodeId;
        const rawDisplayName = AppState.identity.displayName || 'Ghost User';
        const displayName = String(rawDisplayName).slice(0, 32);

        const buildCard = (qrCanvasOrFallbackStr) => {
            const c = document.createElement('canvas');
            c.width = 400;
            c.height = 240;
            const ctx = c.getContext('2d');
            
            if (!ctx) {
                const fallbackDiv = document.createElement('div');
                fallbackDiv.id = 'ghostcard-modal';
                fallbackDiv.style.cssText = 'position:fixed;top:0;left:0;width:100vw;height:100vh;background:rgba(0,0,0,0.9);z-index:99999;display:flex;align-items:center;justify-content:center;flex-direction:column;';
                const card = document.createElement('div');
                card.style.cssText = 'background:#0a0f1e;border:2px solid #00f0ff;border-radius:20px;padding:30px;text-align:center;max-width:90%;color:#fff;';
                const nameEl = document.createElement('h2');
                nameEl.textContent = displayName;
                card.appendChild(nameEl);
                const idEl = document.createElement('p');
                idEl.textContent = nodeId;
                idEl.style.cssText = 'word-break:break-all;font-family:monospace;color:#00f0ff;margin:20px 0;';
                card.appendChild(idEl);
                const copyBtn = document.createElement('button');
                copyBtn.textContent = 'Copy ID';
                copyBtn.className = 'btn-primary';
                copyBtn.onclick = () => { if (navigator.clipboard) navigator.clipboard.writeText(nodeId); };
                card.appendChild(copyBtn);
                const closeBtn = document.createElement('button');
                closeBtn.textContent = 'Close';
                closeBtn.style.cssText = 'margin-top:20px;padding:10px 20px;background:none;border:1px solid #fff;color:#fff;border-radius:12px;cursor:pointer;';
                closeBtn.onclick = () => fallbackDiv.remove();
                card.appendChild(closeBtn);
                fallbackDiv.appendChild(card);
                document.body.appendChild(fallbackDiv);
                return;
            }

            // Fill Background
            ctx.fillStyle = '#0a0f1e';
            ctx.fillRect(0, 0, 400, 240);
            
            const bgGrd = ctx.createLinearGradient(0,0,400,0);
            bgGrd.addColorStop(0, '#0d1117');
            bgGrd.addColorStop(1, '#0a1628');
            ctx.fillStyle = bgGrd;
            ctx.fillRect(0, 0, 400, 240);

            // Hex grid
            ctx.strokeStyle = 'rgba(0,240,255,0.06)';
            ctx.lineWidth = 0.5;
            ctx.beginPath();
            for (let x = 0; x <= 400; x += 20) {
                for (let y = 0; y <= 240; y += 34.64) {
                    ctx.moveTo(x + 10, y); ctx.lineTo(x + 20, y + 17.32); ctx.lineTo(x + 10, y + 34.64);
                    ctx.lineTo(x - 10, y + 34.64); ctx.lineTo(x - 20, y + 17.32); ctx.lineTo(x - 10, y);
                }
            }
            ctx.stroke();

            // Glow 
            const grd = ctx.createRadialGradient(200, 120, 0, 200, 120, 150);
            grd.addColorStop(0, 'rgba(0,240,255,0.08)');
            grd.addColorStop(1, 'rgba(0,0,0,0)');
            ctx.fillStyle = grd;
            ctx.fillRect(0, 0, 400, 240);

            // Border
            ctx.strokeStyle = '#00f0ff';
            ctx.lineWidth = 1.5;
            ctx.globalAlpha = 0.6;
            ctx.beginPath();
            ctx.roundRect(8, 8, 384, 224, 16);
            ctx.stroke();
            ctx.globalAlpha = 1.0;

            // Divider vertical
            ctx.strokeStyle = 'rgba(0,240,255,0.15)';
            ctx.lineWidth = 1;
            ctx.beginPath();
            ctx.moveTo(160, 24);
            ctx.lineTo(160, 216);
            ctx.stroke();

            // Left Side: User Info
            ctx.fillStyle = '#1e293b';
            ctx.beginPath();
            ctx.arc(80, 74, 26, 0, Math.PI * 2);
            ctx.fill();
            ctx.strokeStyle = '#00f0ff';
            ctx.lineWidth = 1.5;
            ctx.stroke();

            ctx.fillStyle = '#00f0ff';
            ctx.font = 'bold 20px Arial';
            ctx.textAlign = 'center';
            ctx.textBaseline = 'middle';
            ctx.fillText(displayName.charAt(0).toUpperCase(), 80, 74);

            ctx.fillStyle = '#ffffff';
            ctx.font = 'bold 18px Arial';
            ctx.textBaseline = 'alphabetic';
            ctx.fillText(displayName.length > 12 ? displayName.slice(0, 10) + '..' : displayName, 80, 134);

            ctx.fillStyle = '#00f0ff';
            ctx.font = '11px monospace';
            const formattedNodeId = nodeId.slice(0, 6) + '..' + nodeId.slice(-4);
            ctx.fillText(formattedNodeId, 80, 158);

            ctx.fillStyle = 'rgba(255,255,255,0.4)';
            ctx.font = '10px Arial';
            ctx.fillText('GhostNet', 80, 190);

            // Right Side: QR Code
            ctx.fillStyle = '#ffffff';
            ctx.beginPath();
            ctx.roundRect(190, 30, 172, 172, 8);
            ctx.fill();

            if (typeof qrCanvasOrFallbackStr === 'object') {
                ctx.drawImage(qrCanvasOrFallbackStr, 196, 36, 160, 160);
            } else {
                ctx.fillStyle = '#0a0f1e';
                ctx.font = '10px monospace';
                ctx.fillText('QR fail', 276, 116);
            }

            ctx.fillStyle = 'rgba(255,255,255,0.6)';
            ctx.font = '10px Arial';
            ctx.fillText('Scan to connect', 276, 220);

            // Set up Modal with 3D animation
            const modal = document.createElement('div');
            modal.id = 'ghostcard-modal';
            modal.style.cssText = 'position:fixed;top:0;left:0;width:100vw;height:100vh;background:rgba(0,0,0,0.85);backdrop-filter:blur(12px);z-index:99999;display:flex;align-items:center;justify-content:center;flex-direction:column;perspective:1000px;';

            const cardWrapper = document.createElement('div');
            cardWrapper.style.cssText = 'position:relative; transform-style:preserve-3d; will-change:transform; animation: ghostCardEntrance 0.6s cubic-bezier(0.34, 1.56, 0.64, 1) forwards; overflow:hidden; border-radius:16px;';
            
            c.style.cssText = 'width:400px;max-width:90vw;height:auto;border-radius:16px;display:block;box-shadow: 0 25px 60px rgba(0,240,255,0.25), 0 0 120px rgba(0,240,255,0.08);';

            const shimmer = document.createElement('div');
            shimmer.style.cssText = 'position:absolute;top:0;left:0;width:100%;height:100%;background:linear-gradient(90deg, rgba(255,255,255,0) 0%, rgba(255,255,255,0.08) 50%, rgba(255,255,255,0) 100%);pointer-events:none;border-radius:16px;opacity:0;overflow:hidden;';

            cardWrapper.appendChild(c);
            cardWrapper.appendChild(shimmer);
            modal.appendChild(cardWrapper);

            // Parallax interactions
            const mouseMoveParallax = (e) => {
                const rect = cardWrapper.getBoundingClientRect();
                const x = e.clientX - rect.left - rect.width/2;
                const y = e.clientY - rect.top - rect.height/2;
                const rotateX = -(y / (rect.height/2)) * 12;
                const rotateY = (x / (rect.width/2)) * 12;
                cardWrapper.style.transform = `rotateX(${rotateX}deg) rotateY(${rotateY}deg)`;
            };
            const deviceParallax = (e) => {
                if (!e.gamma || !e.beta) return;
                const gamma = Math.max(-30, Math.min(30, e.gamma)); 
                const beta = Math.max(-30, Math.min(30, e.beta - 45));
                cardWrapper.style.transform = `rotateX(${-(beta/30)*12}deg) rotateY(${(gamma/30)*12}deg)`;
            };

            cardWrapper.addEventListener('animationend', (ev) => {
                if (ev.animationName === 'ghostCardEntrance') {
                    cardWrapper.style.animation = 'floatCard 4s ease-in-out infinite';
                    shimmer.style.animation = 'shimmer 4s ease-in-out infinite';
                    shimmer.style.opacity = '1';
                    
                    if (window.DeviceOrientationEvent && 'ontouchstart' in window) {
                        window.addEventListener('deviceorientation', deviceParallax);
                    } else {
                        cardWrapper.addEventListener('mousemove', mouseMoveParallax);
                        cardWrapper.addEventListener('mouseleave', () => {
                            cardWrapper.style.transition = 'transform 0.5s ease-out';
                            cardWrapper.style.transform = 'rotateX(0deg) rotateY(0deg)';
                        });
                        cardWrapper.addEventListener('mouseenter', () => {
                            cardWrapper.style.transition = 'none';
                        });
                    }
                }
            });

            // Action Buttons
            const btnContainer = document.createElement('div');
            btnContainer.style.cssText = 'display:flex;gap:12px;margin-top:40px;opacity:0;animation: fadeSlideUp 0.4s 0.3s ease both;';

            const saveBtn = document.createElement('button');
            saveBtn.textContent = 'Save Card';
            saveBtn.style.cssText = 'background:#00f0ff;color:#0a0f1e;border:none;border-radius:24px;padding:12px 24px;font-weight:bold;cursor:pointer;';
            saveBtn.onclick = () => {
                c.toBlob(blob => {
                    const objUrl = URL.createObjectURL(blob);
                    const a = document.createElement('a');
                    const safeName = String(displayName).replace(/[^a-zA-Z0-9]/g, '_');
                    a.download = `ghostcard-${safeName}.png`;
                    a.href = objUrl;
                    a.click();
                    URL.revokeObjectURL(objUrl);
                }, 'image/png');
            };

            const shareBtn = document.createElement('button');
            shareBtn.textContent = 'Share';
            shareBtn.style.cssText = 'background:transparent;color:#fff;border:1px solid #00f0ff;border-radius:24px;padding:12px 24px;font-weight:bold;cursor:pointer;';
            shareBtn.onclick = () => {
                if (navigator.canShare) {
                    c.toBlob(blob => {
                        const safeName = String(displayName).replace(/[^a-zA-Z0-9]/g, '_');
                        const file = new File([blob], `ghostcard-${safeName}.png`, { type: 'image/png' });
                        if (navigator.canShare({ files: [file] })) navigator.share({ files: [file] });
                    });
                } else if (navigator.clipboard) {
                    navigator.clipboard.writeText(nodeId);
                    alert("Node ID copied to share.");
                }
            };

            const closeBtn = document.createElement('button');
            closeBtn.textContent = '✕ Close';
            closeBtn.style.cssText = 'background:#1e293b;color:#94a3b8;border:none;border-radius:24px;padding:12px 24px;font-weight:bold;cursor:pointer;';

            const triggerClose = () => {
                // Remove listeners to avoid leaks
                cardWrapper.removeEventListener('mousemove', mouseMoveParallax);
                if (window.DeviceOrientationEvent && 'ontouchstart' in window) {
                    window.removeEventListener('deviceorientation', deviceParallax);
                }
                
                // Stop floats and start exit
                cardWrapper.style.animation = 'ghostCardExit 0.3s ease forwards';
                shimmer.style.animation = 'none';
                shimmer.style.opacity = '0';
                btnContainer.style.opacity = '0';
                
                setTimeout(() => modal.remove(), 300);
            };

            closeBtn.onclick = triggerClose;
            
            // Close on backdrop click (not inner elements)
            modal.addEventListener('click', (e) => {
                if (e.target === modal) triggerClose();
            });

            btnContainer.appendChild(saveBtn);
            btnContainer.appendChild(shareBtn);
            btnContainer.appendChild(closeBtn);
            modal.appendChild(btnContainer);
            document.body.appendChild(modal);
        };

        if (typeof QRCode === 'undefined' && typeof window.QRCode === 'undefined') {
            buildCard('fallback');
            return;
        }

        drawQRAndBuild();

        function drawQRAndBuild() {
            try {
                const tempDiv = document.createElement('div');
                const expTS = Date.now() + (7 * 24 * 60 * 60 * 1000);
                const qrData = JSON.stringify({"v":1,"app":"ghostnet","nodeId":nodeId,"name":displayName,"exp":expTS});
                new QRCode(tempDiv, {
                    text: qrData,
                    width: 180,
                    height: 180,
                    correctLevel: QRCode.CorrectLevel.M
                });
                
                setTimeout(() => {
                    const tempCanvas = tempDiv.querySelector('canvas');
                    if (tempCanvas) {
                        buildCard(tempCanvas);
                    } else {
                        const tempImg = tempDiv.querySelector('img');
                        if (tempImg && tempImg.src) {
                            const dynImg = new Image();
                            dynImg.src = tempImg.src;
                            dynImg.onload = () => buildCard(dynImg);
                        } else {
                            buildCard('fallback');
                        }
                    }
                }, 50);
            } catch (e) {
                console.error('QR code generation failed', e);
                buildCard('fallback');
            }
        }
    },

    // GHOST CARDS - QR Scanner
    startQRScanner: () => {
        const modal = document.createElement('div');
        modal.id = 'qr-scanner-modal';
        modal.style.cssText = 'position:fixed;top:0;left:0;width:100vw;height:100vh;background:#000;z-index:99999;display:flex;align-items:center;justify-content:center;flex-direction:column;';
        
        const video = document.createElement('video');
        video.muted = true;
        video.playsInline = true;
        video.autoplay = true;
        video.style.cssText = 'position:absolute;top:0;left:0;width:100%;height:100%;object-fit:cover;';
        
        const canvas = document.createElement('canvas');
        canvas.style.cssText = 'position:absolute;top:0;left:0;width:100vw;height:100vh;pointer-events:none;';
        
        const infoDiv = document.createElement('div');
        infoDiv.textContent = 'Point at a Ghost Card QR code';
        infoDiv.style.cssText = 'position:absolute;bottom:100px;color:#fff;font-family:Arial;font-size:16px;text-align:center;width:100%;z-index:100000;text-shadow:0 2px 4px rgba(0,0,0,0.8);';

        const errorDiv = document.createElement('div');
        errorDiv.style.cssText = 'position:absolute;bottom:130px;color:#ef4444;font-family:Arial;font-size:14px;text-align:center;width:100%;z-index:100000;';

        const closeBtn = document.createElement('button');
        closeBtn.textContent = 'Cancel';
        closeBtn.style.cssText = 'position:absolute;bottom:40px;padding:12px 24px;border-radius:12px;background:rgba(255,255,255,0.1);color:#fff;border:1px solid rgba(255,255,255,0.2);cursor:pointer;z-index:100000;';

        modal.appendChild(video);
        modal.appendChild(canvas);
        modal.appendChild(infoDiv);
        modal.appendChild(errorDiv);
        modal.appendChild(closeBtn);
        document.body.appendChild(modal);

        let stream;
        let rafId;

        const cleanup = () => {
            if (rafId) cancelAnimationFrame(rafId);
            if (stream) stream.getTracks().forEach(t => t.stop());
            video.srcObject = null;
            modal.remove();
            window.removeEventListener('resize', resizeCanvas);
        };

        closeBtn.onclick = cleanup;

        const ctx = canvas.getContext('2d');
        let offscreenCanvas = document.createElement('canvas');
        let offscreenCtx = offscreenCanvas.getContext('2d', { willReadFrequently: true });

        const resizeCanvas = () => {
            canvas.width = window.innerWidth;
            canvas.height = window.innerHeight;
            offscreenCanvas.width = video.videoWidth;
            offscreenCanvas.height = video.videoHeight;
        };
        window.addEventListener('resize', resizeCanvas);

        const initCamera = async (facingMode = 'environment') => {
            try {
                stream = await navigator.mediaDevices.getUserMedia({ video: { facingMode: { ideal: facingMode }, width: { ideal: 1280 }, height: { ideal: 720 } } });
                video.srcObject = stream;
                video.onloadedmetadata = () => {
                    video.play();
                    resizeCanvas();
                    requestAnimationFrame(scanFrame);
                };
            } catch (err) {
                if (facingMode === 'environment') {
                    initCamera('user');
                } else {
                    cleanup();
                    const errToast = document.createElement('div');
                    if (err.name === 'NotAllowedError') {
                        errToast.textContent = 'Camera permission denied — you can still enter a Node ID manually';
                    } else {
                        errToast.textContent = 'Camera not available — enter Node ID manually';
                    }
                    errToast.style.cssText = 'position:fixed;bottom:20px;left:50%;transform:translateX(-50%);background:#ef4444;color:#fff;padding:10px 20px;border-radius:8px;z-index:100000;';
                    document.body.appendChild(errToast);
                    setTimeout(() => errToast.remove(), 4000);
                }
            }
        };

        let bracketOffset = 0;
        let bracketDir = 1;

        const scanFrame = () => {
            if (video.readyState === video.HAVE_ENOUGH_DATA) {
                bracketOffset += bracketDir * 0.5;
                if (bracketOffset > 10 || bracketOffset < 0) bracketDir *= -1;

                ctx.clearRect(0,0, canvas.width, canvas.height);
                ctx.fillStyle = 'rgba(0,0,0,0.6)';
                ctx.fillRect(0,0, canvas.width, canvas.height);

                const size = 250;
                const cx = canvas.width/2;
                const cy = canvas.height/2;

                ctx.globalCompositeOperation = 'destination-out';
                ctx.fillRect(cx - size/2, cy - size/2, size, size);
                ctx.globalCompositeOperation = 'source-over';

                ctx.strokeStyle = '#00f0ff';
                ctx.lineWidth = 4;
                const bs = size/2 + bracketOffset;
                const bl = 20;
                
                ctx.beginPath();
                ctx.moveTo(cx - bs + bl, cy - bs); ctx.lineTo(cx - bs, cy - bs); ctx.lineTo(cx - bs, cy - bs + bl);
                ctx.moveTo(cx + bs - bl, cy - bs); ctx.lineTo(cx + bs, cy - bs); ctx.lineTo(cx + bs, cy - bs + bl);
                ctx.moveTo(cx - bs + bl, cy + bs); ctx.lineTo(cx - bs, cy + bs); ctx.lineTo(cx - bs, cy + bs - bl);
                ctx.moveTo(cx + bs - bl, cy + bs); ctx.lineTo(cx + bs, cy + bs); ctx.lineTo(cx + bs, cy + bs - bl);
                ctx.stroke();

                if (window.jsQR) {
                    offscreenCtx.drawImage(video, 0, 0, offscreenCanvas.width, offscreenCanvas.height);
                    const imageData = offscreenCtx.getImageData(0, 0, offscreenCanvas.width, offscreenCanvas.height);
                    const code = jsQR(imageData.data, imageData.width, imageData.height, { inversionAttempts: 'dontInvert' });

                    if (code) {
                        try {
                            const data = JSON.parse(code.data);
                            if (data.v && data.app === 'ghostnet' && /^0x[a-fA-F0-9]{8,64}$/.test(data.nodeId)) {
                                handleSuccess(data);
                                return;
                            } else {
                                throw new Error('Invalid JSON format');
                            }
                        } catch (e) {
                            if (/^0x[a-fA-F0-9]{8,64}$/.test(code.data)) {
                                handleSuccess({ nodeId: code.data });
                                return;
                            } else {
                                errorDiv.textContent = 'Invalid QR — this doesn\'t look like a Ghost Card';
                            }
                        }
                    } else {
                        errorDiv.textContent = '';
                    }
                }
            }
            rafId = requestAnimationFrame(scanFrame);
        };

        const handleSuccess = (data) => {
            if (data.exp && Date.now() > data.exp) {
                const toast = document.createElement('div');
                toast.textContent = 'This Ghost Card has expired — ask them to generate a new one';
                toast.style.cssText = 'position:fixed;bottom:80px;left:50%;transform:translateX(-50%);background:#f59e0b;color:#fff;padding:10px 20px;border-radius:8px;z-index:100000;';
                document.body.appendChild(toast);
                setTimeout(() => toast.remove(), 4000);
                cleanup();
                return;
            }

            const toast = document.createElement('div');
            toast.textContent = '✓ Ghost Card scanned — tap Add to connect';
            toast.style.cssText = 'position:fixed;bottom:80px;left:50%;transform:translateX(-50%);background:#10b981;color:#fff;padding:10px 20px;border-radius:8px;z-index:100000;';
            document.body.appendChild(toast);
            setTimeout(() => toast.remove(), 3000);

            cleanup();

            const pkInput = document.getElementById('chat-pubkey');
            if (pkInput) {
                pkInput.value = data.nodeId;
                const nameInput = document.getElementById('chat-name');
                if (nameInput && data.name) nameInput.value = data.name;
            } else {
                // New chat modal not open — open it first then fill scanned data
                UI.openNewChat();
                setTimeout(() => {
                    const pk = document.getElementById('chat-pubkey');
                    const nm = document.getElementById('chat-name');
                    if (pk) pk.value = data.nodeId;
                    if (nm && data.name) nm.value = data.name;
                }, 100);
            }
        };

        if (typeof jsQR === 'undefined' && typeof window.jsQR === 'undefined') {
            cleanup();
            const pkInput = document.getElementById('chat-pubkey');
            if (pkInput) {
                pkInput.style.transition = 'box-shadow 0.3s ease-out';
                pkInput.style.boxShadow = '0 0 12px #00f0ff';
                pkInput.focus();
                
                const hint = document.createElement('div');
                hint.textContent = 'Paste a Node ID or ask for their Ghost Card';
                hint.style.cssText = 'color:#00f0ff;font-size:12px;margin-top:4px;';
                pkInput.parentNode.parentNode.appendChild(hint);

                setTimeout(() => {
                    if (pkInput) pkInput.style.boxShadow = '';
                }, 3000);
            }
            return;
        }

        initCamera();
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
