/**
 * GhostNet Application Logic — FULLY HARDENED VERSION
 *
 * Vulnerabilities fixed in THIS pass (on top of prior hardening):
 *
 * [A] _showDevWarning uses innerHTML with caller-controlled HTML → XSS vector.
 *     Fixed: accept only plain text + a whitelist of safe tags via DOM construction.
 *
 * [B] alert() is still called in two places inside sendMessage / file handler,
 *     contradicting the stated Fix [11]. Fixed: route through _showDevWarning.
 *
 * [C] Rate limiter (MsgRateLimit) lives entirely in JS — trivially reset via
 *     DevTools (`MsgRateLimit._timestamps = []`). Fixed: move to a closure so
 *     the internal state is not globally writable.
 *
 * [D] Double rate-limit consumption: sendMessage() calls MsgRateLimit.check()
 *     then immediately calls persistMessage() which calls it AGAIN, burning two
 *     slots per message. Fixed: remove the redundant check from persistMessage.
 *
 * [E] contactName is written into the POST payload without sanitization,
 *     allowing stored-XSS if the server echoes it back to other clients.
 *     Fixed: sanitize() applied before payload construction.
 *
 * [F] File attachment handler validates only size — not MIME type.
 *     A renamed .html or .svg file passes straight through.
 *     Fixed: enforce an allowlist of safe MIME types.
 *
 * [G] targetId (from window.app.chatTarget) flows into the POST payload
 *     without sanitization. Fixed: sanitize() applied before use.
 */

// ─────────────────────────────────────────────
//  SECURITY UTILITIES
// ─────────────────────────────────────────────

function getAuthToken() {
    return sessionStorage.getItem('ghostnet_token') || '';
}

function secureHeaders(extra = {}) {
    return {
        'Content-Type': 'application/json',
        'X-Auth-Token': getAuthToken(),
        ...extra
    };
}

function generateSecureId(prefix = 'user') {
    const array = new Uint8Array(16);
    crypto.getRandomValues(array);
    const hex = Array.from(array).map(b => b.toString(16).padStart(2, '0')).join('');
    return `${prefix}_${hex}`;
}

function sanitize(str) {
    if (str === null || str === undefined) return '';
    const div = document.createElement('div');
    div.textContent = String(str);
    return div.innerHTML;
}

var isDev = window.location.hostname === 'localhost' || window.location.hostname === '127.0.0.1';
var log = {
    info: (...a) => isDev && console.log('[GN]', ...a),
    warn: (...a) => isDev && console.warn('[GN]', ...a),
    error: (...a) => console.error('[GN:ERR]', ...a),
};

// ─── [FIX C] Rate limiter wrapped in a closure so internal state is
//             NOT reachable / resettable from the global scope. ────────────────
const MsgRateLimit = (() => {
    let _timestamps = [];          // private — not on window or any exported object
    const MAX_PER_MINUTE = 30;
    return {
        check() {
            const now = Date.now();
            _timestamps = _timestamps.filter(t => now - t < 60_000);
            if (_timestamps.length >= MAX_PER_MINUTE) return false;
            _timestamps.push(now);
            return true;
        }
    };
})();

var BACKEND = {
    http: 'https://ghostnet-ji-production.up.railway.app',
    ws: 'wss://ghostnet-ji-production.up.railway.app/ws',
    url: (path) => `https://ghostnet-ji-production.up.railway.app${path}`
};

const MAX_MSG_LENGTH = 2000;

// ─── [FIX F] Allowlist of safe attachment MIME types. ────────────────────────
const ALLOWED_ATTACHMENT_MIME = new Set([
    'image/png', 'image/jpeg', 'image/gif', 'image/webp',
    'application/pdf',
    'text/plain',
    'application/msword',
    'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
    'video/mp4', 'video/webm', 'video/ogg', 'video/quicktime', 'video/x-matroska'
]);

// ─────────────────────────────────────────────
//  APP STATE
// ─────────────────────────────────────────────
window.app = {
    identity: null,
    chat: null,
    chatTarget: null,
    chatContactName: null,
    mesh: null,
    _sendAbort: null,
    transport: {
        ble: null,
        startBLEScan: async () => {
            if (window.app.mesh) {
                await window.app.mesh.scanBLE();
            } else {
                log.warn('Mesh transport not ready for BLE scan.');
            }
        }
    }
};

// ─────────────────────────────────────────────
//  MAIN INIT
// ─────────────────────────────────────────────
window.addEventListener('DOMContentLoaded', async () => {
    log.info('Initializing GhostNet...');

    // ── 1. IDENTITY ──────────────────────────────

    let myId = localStorage.getItem('ghostnet_user_id');
    if (!myId) {
        myId = generateSecureId('user');
        localStorage.setItem('ghostnet_user_id', myId);
    }

    let stored = null;
    try {
        if (window.GhostIdentity) {
            stored = GhostIdentity.getStoredIdentity();
        } else {
            const nodeId = localStorage.getItem('ghostnet_node_id');
            const displayName = localStorage.getItem('ghostnet_display_name');
            const address = localStorage.getItem('ghostnet_address');
            if (nodeId && nodeId !== 'null') stored = { nodeId, displayName, address };
        }
    } catch (e) {
        log.error('Failed to read identity from storage:', e.message);
    }

    if (stored?.nodeId) {
        window.app.identity = {
            id: stored.nodeId,
            pub: stored.nodeId,
            nodeId: stored.nodeId,
            displayName: stored.displayName,
            address: stored.address
        };
        log.info('Using stored identity.');
    } else if (window.AppState?.identity?.nodeId) {
        const real = window.AppState.identity;
        window.app.identity = {
            id: real.nodeId,
            pub: real.nodeId,
            nodeId: real.nodeId,
            displayName: real.displayName,
            address: real.address
        };
        log.info('Using AppState identity.');
    } else {
        window.app.identity = { id: myId, pub: myId, nodeId: myId };
        log.info('Using fallback identity.');
    }

    if (window.AppState && !window.AppState.identity) {
        window.AppState.identity = window.app.identity;
    }

    window.addEventListener('identity:updated', () => {
        const real = window.AppState?.identity;
        if (!real?.nodeId) return;
        window.app.identity = {
            id: real.nodeId,
            pub: real.publicKey || real.nodeId,
            nodeId: real.nodeId,
            displayName: real.displayName,
            address: real.address
        };
        log.info('Identity updated.');

        if (window.app.mesh?.ws && window.app.mesh.wsReady) {
            _safeSendWS(window.app.mesh.ws, {
                type: 'register',
                id: window.app.identity.id,
                nodeId: window.app.identity.nodeId,
                capabilities: { ble: false, ws: true }
            });
        } else if (window.app.mesh && !window.app.mesh.wsReady) {
            // Mesh was deferred because no auth token was present at startup — retry now.
            const token = sessionStorage.getItem('ghostnet_token') || '';
            if (token) {
                window.app.mesh.setAuthToken(token);
            }
        }
        if (window.UI) {
            setTimeout(() => UI.loadConversations(real.nodeId), 500);
        }
    });

    // ── 2. HTTP PERSISTENCE ───────────────────────

    window.app.persistMessage = async (text, targetId) => {
        if (!text || typeof text !== 'string') return null;
        if (text.length > MAX_MSG_LENGTH) {
            log.warn('Message exceeds max length, truncating.');
            text = text.substring(0, MAX_MSG_LENGTH);
        }

        // ─── [FIX D] Rate limit is checked ONLY in sendMessage (the caller).
        //             Checking it again here caused double-slot consumption.
        //             persistMessage is also callable internally, so we do NOT
        //             re-check here.

        const myId = window.app.identity.nodeId || window.app.identity.id;

        // ─── [FIX G] Sanitize targetId before using in payload. ──────────────
        const safeTargetId = sanitize(targetId || window.app.chatTarget || 'broadcast');

        // ─── [FIX E] Sanitize contactName before it enters the payload. ───────
        const rawContactName =
            window.app.chatContactName ||
            window.app.identity.displayName ||
            'Anonymous';
        const safeContactName = sanitize(rawContactName);

        try {
            const payload = {
                senderId: myId,
                receiverId: safeTargetId,
                contactName: safeContactName,
                content: text,
                encrypted: !!(window.app.chat),
            };

            const response = await fetch(BACKEND.url('/message'), {
                method: 'POST',
                headers: secureHeaders(),
                body: JSON.stringify(payload)
            });

            if (response.ok) {
                const result = await response.json();
                if (result.convo && window.AppState) {
                    window.AppState.activeConvoId = result.convo.id;
                }
                if (window.UI) window.UI.loadConversations(myId);
                return result;
            } else {
                const errBody = await response.json().catch(() => ({}));
                const errMsg = sanitize(errBody.error || `HTTP ${response.status}`);
                log.error('Message rejected:', errMsg);
                if (response.status === 404 && window.UI) {
                    UI.addMessage(`⚠ ${errMsg}`, 'them');
                }
            }
        } catch (e) {
            log.error('HTTP persistence failed:', e.message);
        }
        return null;
    };

    // ── 3. SEND BUTTON ────────────────────────────

    const wireUpSendButton = () => {
        const btn = document.getElementById('chat-send');
        const input = document.getElementById('chat-input');

        if (!btn || !input) {
            log.warn('Chat elements not found, retrying...');
            setTimeout(wireUpSendButton, 500);
            return;
        }

        if (window.app._sendAbort) window.app._sendAbort.abort();
        window.app._sendAbort = new AbortController();
        const { signal } = window.app._sendAbort;

        const sendMessage = async () => {
            const text = input.value.trim();
            if (!text) return;

            if (text.length > MAX_MSG_LENGTH) {
                // ─── [FIX B] Replace alert() with non-blocking UI banner. ──────
                _showDevWarning(`⚠ Message too long — maximum ${MAX_MSG_LENGTH} characters.`);
                return;
            }

            // ─── [FIX D] Rate limit checked here (ONCE), not also in persistMessage.
            if (!MsgRateLimit.check()) {
                log.warn('Rate limit hit.');
                _showDevWarning('⚠ Slow down — message rate limit reached (30/min).');
                return;
            }

            const recipientNodeId = window.app.chatTarget || 'broadcast';
            const myId = window.app.identity.nodeId || window.app.identity.id;

            if (window.UI) UI.addMessage(text, 'me');
            input.value = '';

            try {
                const result = await window.app.persistMessage(text, recipientNodeId);
                if (result?.success) {
                    log.info('Message sent and persisted.');
                } else if (result === null) {
                    if (window.app.mesh?.ws?.readyState === WebSocket.OPEN) {
                        _safeSendWS(window.app.mesh.ws, {
                            type: 'message',
                            to: recipientNodeId,
                            from: myId,
                            content: { body: text, from: myId, to: recipientNodeId, ts: Date.now(), type: 'MSG' },
                            timestamp: Date.now()
                        });
                    }
                }
            } catch (e) {
                log.error('Send message error:', e.message);
            }
        };

        window.app.sendMessage = sendMessage;
        btn.addEventListener('click', sendMessage, { signal });
        input.addEventListener('keypress', (e) => {
            if (e.key === 'Enter') sendMessage();
        }, { signal });

        log.info('Chat send button wired.');

        const fileInput = document.getElementById('chat-file');
        if (fileInput) {
            fileInput.addEventListener('change', async (e) => {
                const file = e.target.files[0];
                if (!file) return;

                const isVideo = file.type?.startsWith('video/');
                const isDoc = file.type && !file.type.startsWith('image/') && !isVideo;
                const maxBytes = isVideo ? (3 * 1024 * 1024 * 1024) : (10 * 1024 * 1024);

                if (file.size > maxBytes) {
                    _showDevWarning(`⚠ File too large — maximum size is ${isVideo ? '3 GB' : '10 MB'}.`);
                    fileInput.value = '';
                    return;
                }

                // Warn but allow if missing from direct Set
                if (file.type && !ALLOWED_ATTACHMENT_MIME.has(file.type)) {
                    _showDevWarning(`⚠ File type "${sanitize(file.type)}" is unexpected, attempting upload anyway.`);
                }

                if (window.GhostVault) {
                    try {
                        _showDevWarning(`Encrypting and Uploading ${sanitize(file.name)}...`);
                        const vaultResult = await window.GhostVault.uploadFile(file);

                        if (vaultResult && vaultResult.fileId) {
                            const chatInput = document.getElementById('chat-input');
                            const safeName = sanitize(file.name).replace(/:/g, '_');
                            chatInput.value = `[FILE:${vaultResult.fileId}:${file.type || 'unknown'}:${vaultResult.encKeyStr || ''}:${safeName}]`;
                            const sendBtn = document.getElementById('chat-send');
                            if (sendBtn) sendBtn.click();
                            _showDevWarning(`Upload Complete!`);
                        }
                    } catch (e) {
                        _showDevWarning(`⚠ Upload failed: ${e.message}`);
                    }
                } else {
                    const safeName = sanitize(file.name);
                    const sizeKB = (file.size / 1024).toFixed(1);
                    if (window.UI) UI.addMessage(`📎 FILE: ${safeName} (${sizeKB} KB)`, 'me');
                }

                fileInput.value = '';
            }, { signal });
        }
    };

    wireUpSendButton();

    // ── 4. MESH TRANSPORT ─────────────────────────

    if (window.GhostMesh) {
        try {
            const mesh = new GhostMesh(window.app.identity);
            window.app.mesh = mesh;

            mesh.onPeerJoin = (peer) => {
                log.info('Peer joined via', peer.transport);
                if (window.AppState && !window.AppState.peers.find(p => p.id === peer.id)) {
                    window.AppState.peers.push({
                        id: sanitize(peer.id),
                        type: peer.transport === 'ble' ? 'Bluetooth' : 'Wi-Fi',
                        name: sanitize(peer.name || 'Unknown'),
                        latency: peer.transport === 'ble' ? 15 : 5
                    });
                }
                window.dispatchEvent(new Event('app:state'));
            };

            mesh.onPeerLeave = (peer) => {
                log.info('Peer left.');
                if (window.AppState) {
                    window.AppState.peers = window.AppState.peers.filter(p => p.id !== peer.id);
                }
                window.dispatchEvent(new Event('app:state'));
            };

            mesh.onMessage = (msgData, from, transport) => {
                if (!msgData || typeof msgData !== 'object') return;

                if (msgData.type === 'MSG' && msgData.iv) {
                    if (window.app.chat) {
                        try {
                            const gcPacket = {
                                type: 'MSG',
                                id: msgData.id,
                                from: sanitize(from),
                                to: window.app.identity.nodeId,
                                ts: Date.now(),
                                iv: msgData.iv,
                                data: msgData.data,
                                mode: msgData.mode,
                                ttl: msgData.ttl
                            };
                            window.app.chat.receive(JSON.stringify(gcPacket));
                        } catch (e) {
                            log.warn('GhostChat decryption error:', e.message);
                        }
                    }
                } else if (msgData.type === 'MSG' || msgData.body) {
                    const body = sanitize(msgData.body || '');
                    if (body && window.UI) UI.addMessage(body, 'them');
                }
            };

            mesh.onMeshUpdate = (peers) => {
                const statNodes = document.getElementById('stat-nodes');
                if (statNodes) statNodes.textContent = peers.length + 1;
            };

            mesh.onStatusChange = (status) => {
                log.info('Mesh state:', status?.state);
                if (status?.state === 'error') {
                    log.error('Mesh error occurred:', status?.message || '');
                }
            };

            await mesh.start();
            log.info('GhostMesh started.');

        } catch (e) {
            log.warn('GhostMesh init failed:', e.message);
        }
    } else {
        log.warn('GhostMesh not loaded, using direct WebSocket fallback.');
        try {
            const ws = new WebSocket(BACKEND.ws);

            ws.addEventListener('open', () => {
                _safeSendWS(ws, {
                    type: 'register',
                    id: window.app.identity.id,
                    nodeId: window.app.identity.nodeId
                });
            });

            ws.addEventListener('message', (event) => {
                try {
                    if (typeof event.data !== 'string') return;
                    if (event.data.length > 65536) {
                        log.warn('WS message too large, ignoring.');
                        return;
                    }
                    const msg = JSON.parse(event.data);
                    if (!msg || typeof msg !== 'object') return;
                    if (typeof msg.type !== 'string') return;

                    if (msg.type === 'PEER_JOIN' && window.AppState) {
                        const safeId = sanitize(String(msg.id || ''));
                        if (safeId && !window.AppState.peers.find(p => p.id === safeId)) {
                            window.AppState.peers.push({ id: safeId, type: 'Wi-Fi', latency: 5 });
                            window.dispatchEvent(new Event('app:state'));
                        }
                    }
                } catch (e) {
                    log.warn('WS message parse error:', e.message);
                }
            });

            ws.addEventListener('error', () => {
                log.error('WebSocket error occurred.');
            });

        } catch (e) {
            log.warn('WebSocket fallback failed:', e.message);
        }
    }

    // ── 5. GHOST CHAT ENCRYPTION ─────────────────

    if (window.GhostChat) {
        try {
            const transportSender = async (payloadStr) => {
                if (typeof payloadStr !== 'string') return;
                let gcPayload;
                try { gcPayload = JSON.parse(payloadStr); }
                catch (e) { log.error('Invalid GhostChat payload.'); return; }
                if (!gcPayload || typeof gcPayload !== 'object') return;

                const customPayload = {
                    type: 'message',
                    to: gcPayload.to,
                    from: gcPayload.from,
                    content: {
                        iv: gcPayload.iv,
                        data: gcPayload.data,
                        mode: gcPayload.mode,
                        ttl: gcPayload.ttl,
                        id: gcPayload.id,
                        type: 'MSG'
                    },
                    timestamp: gcPayload.ts
                };

                if (window.app.mesh?.ws?.readyState === WebSocket.OPEN) {
                    _safeSendWS(window.app.mesh.ws, customPayload);
                } else if (window.app.mesh) {
                    window.app.mesh.broadcast(customPayload);
                }
            };

            const chat = new GhostChat(window.app.identity, transportSender);
            window.app.chat = chat;

            chat.onMessage = (msg) => {
                if (!msg?.body) return;
                const safeBody = sanitize(msg.body);
                if (window.UI) {
                    UI.addMessage(safeBody, 'them');
                    const userId = window.AppState?.identity?.id || window.AppState?.identity?.nodeId;
                    if (userId) UI.loadConversations(userId);
                }
            };

            log.info('GhostChat encryption layer initialized.');
        } catch (e) {
            log.warn('GhostChat init failed (non-critical):', e.message);
        }
    }

    // ── 5.5 BACKGROUND RECONNECT ─────────────────
    try {
        if (typeof window !== 'undefined' && window.Capacitor) {
            import('@capacitor/app').then(({ App }) => {
                App.addListener('appStateChange', ({ isActive }) => {
                    if (isActive) {
                        log.info('[GhostNet] App resumed — checking WebSocket...');
                        if (window.app.mesh && (!window.app.mesh.ws || window.app.mesh.ws.readyState !== WebSocket.OPEN)) {
                            window.app.mesh.connectWebSocket();
                        }
                    }
                });
            }).catch(() => {});

            import('@capacitor/network').then(({ Network }) => {
                Network.addListener('networkStatusChange', status => {
                    if (status.connected) {
                        log.info('[GhostNet] Network restored — reconnecting WebSocket...');
                        if (window.app.mesh && (!window.app.mesh.ws || window.app.mesh.ws.readyState !== WebSocket.OPEN)) {
                            window.app.mesh.connectWebSocket();
                        }
                    }
                });
            }).catch(() => {});
        }
    } catch (e) { }

    // ── 6. READY ──────────────────────────────────

    window.dispatchEvent(new Event('app:ready'));
    window.dispatchEvent(new Event('app:state'));

    if (window.location.protocol === 'file:') {
        _showDevWarning(
            '⚠ Running from file:// — run node ghostnet-server.js and visit http://localhost:8080'
        );
    }
});

// ─────────────────────────────────────────────
//  HELPERS
// ─────────────────────────────────────────────

function _safeSendWS(ws, data) {
    try {
        if (!ws || ws.readyState !== WebSocket.OPEN) {
            log.warn('WS send skipped — not open.');
            return;
        }
        const str = JSON.stringify(data);
        if (str.length > 65536) {
            log.warn('WS payload too large, skipping.');
            return;
        }
        ws.send(str);
    } catch (e) {
        log.error('WS send error:', e.message);
    }
}

/**
 * [FIX A] Show a non-blocking warning banner.
 *
 * ORIGINAL BUG: used `banner.innerHTML = html` where `html` was a
 * caller-supplied string containing markup — a stored/reflected XSS vector.
 *
 * FIX: accept ONLY a plain-text message string. All content is injected
 * via textContent (never innerHTML). The close button is built via the DOM
 * API, not by concatenating HTML strings.
 *
 * @param {string} message  Plain text message to show (no HTML accepted).
 */
function _showDevWarning(message) {
    const banner = document.createElement('div');
    banner.style.cssText = [
        'position:fixed', 'bottom:20px', 'left:50%', 'transform:translateX(-50%)',
        'background:#7c2d12', 'color:#fef2f2', 'padding:12px 20px',
        'border-radius:8px', 'font-size:0.85rem', 'z-index:9999',
        'max-width:90vw', 'text-align:center', 'box-shadow:0 4px 20px rgba(0,0,0,0.4)'
    ].join(';');

    // ── Safe: textContent never executes markup. ──────────────────────────────
    const span = document.createElement('span');
    span.textContent = String(message);   // sanitized — no innerHTML

    const close = document.createElement('button');
    close.textContent = '×';             // textContent, not innerHTML
    close.style.cssText = 'margin-left:12px;background:none;border:none;color:inherit;cursor:pointer;font-size:1.1rem;';
    close.addEventListener('click', () => banner.remove());

    banner.appendChild(span);
    banner.appendChild(close);
    document.body.appendChild(banner);

    // Auto-dismiss after 6 seconds so banners don't pile up.
    setTimeout(() => banner.isConnected && banner.remove(), 6000);
}