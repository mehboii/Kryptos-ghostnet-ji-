
/**
 * GhostNet Application Logic
 * Integrates Identity, GhostMesh Transport, and Chat.
 *
 * SECURITY FIXES:
 * [FIX 08] Use crypto.randomUUID() instead of Math.random() for IDs
 * [FIX 18] Persist identity keys in IndexedDB across sessions
 * [FIX 19] No hardcoded production URLs — derive from current host
 */

window.app = {
    identity: null,
    chat: null,
    chatTarget: null,
    chatContactName: null,
    mesh: null,
    authToken: null,
    transport: {
        ble: null,
        startBLEScan: async () => {
            if (window.app.mesh) {
                await window.app.mesh.scanBLE();
            } else {
                alert("Mesh transport not ready. Please wait for initialization.");
            }
        }
    }
};

// ─── IndexedDB Identity Persistence ─────────────────────────────────────────
// [FIX 18] Store CryptoKey pairs in IndexedDB so identity survives page reloads.
// IndexedDB can store non-extractable CryptoKey objects natively.

const IDENTITY_DB_NAME = 'ghostnet_identity';
const IDENTITY_STORE = 'keys';

function openIdentityDB() {
    return new Promise((resolve, reject) => {
        const req = indexedDB.open(IDENTITY_DB_NAME, 1);
        req.onupgradeneeded = () => {
            req.result.createObjectStore(IDENTITY_STORE, { keyPath: 'id' });
        };
        req.onsuccess = () => resolve(req.result);
        req.onerror = () => reject(req.error);
    });
}

async function loadStoredIdentity() {
    try {
        const db = await openIdentityDB();
        return new Promise((resolve, reject) => {
            const tx = db.transaction(IDENTITY_STORE, 'readonly');
            const store = tx.objectStore(IDENTITY_STORE);
            const req = store.get('primary');
            req.onsuccess = () => resolve(req.result || null);
            req.onerror = () => reject(req.error);
        });
    } catch {
        return null;
    }
}

async function saveIdentity(identity) {
    try {
        const db = await openIdentityDB();
        const tx = db.transaction(IDENTITY_STORE, 'readwrite');
        const store = tx.objectStore(IDENTITY_STORE);
        store.put({ id: 'primary', ...identity });
        return new Promise((resolve, reject) => {
            tx.oncomplete = resolve;
            tx.onerror = () => reject(tx.error);
        });
    } catch (e) {
        console.warn("Failed to persist identity to IndexedDB:", e.message);
    }
}

// ─── Auth Token Helper ──────────────────────────────────────────────────────
function getAuthHeaders() {
    const token = window.app.authToken || localStorage.getItem('ghostnet_token') || '';
    return {
        'Authorization': `Bearer ${token}`,
        'Content-Type': 'application/json',
        'X-GhostNet-Client': '1',
    };
}

// Initialize App on Load
window.addEventListener('DOMContentLoaded', async () => {
    console.log("System: Initializing GhostNet...");

    // Load auth token
    window.app.authToken = localStorage.getItem('ghostnet_token') || '';

    // --- 1. IDENTITY ---
    // [FIX 18] Try to load persisted identity from IndexedDB first
    let identity = null;
    const stored = await loadStoredIdentity();

    if (stored && stored.publicKey && stored.nodeId) {
        identity = stored;
        console.log("Identity loaded from IndexedDB");
    } else if (window.GhostIdentity) {
        identity = await window.GhostIdentity.generateIdentity();
        await saveIdentity(identity);
        console.log("New identity generated and persisted");
    }

    if (identity) {
        window.app.identity = identity;
    } else {
        // [FIX 08] Fallback ID uses crypto.randomUUID instead of Math.random
        const fallbackId = "user_" + (crypto.randomUUID ? crypto.randomUUID() : Date.now().toString(36));
        window.app.identity = { id: fallbackId, pub: fallbackId, nodeId: fallbackId };
        console.warn("GhostIdentity module missing, using fallback identity");
    }

    // Ensure a stable user ID is persisted in localStorage for HTTP API usage
    let myId = localStorage.getItem('ghostnet_user_id');
    if (!myId) {
        myId = window.app.identity.nodeId || window.app.identity.id;
        localStorage.setItem('ghostnet_user_id', myId);
    }
    window.app.identity.id = myId;
    window.app.identity.nodeId = myId;

    if (window.AppState) {
        window.AppState.identity = window.app.identity;
    }

    console.log("Identity:", myId.slice(0, 12) + "…");

    // --- 2. HTTP PERSISTENCE ---
    window.app.persistMessage = async (text, targetId) => {
        const myId = window.app.identity.id;
        targetId = targetId || window.app.chatTarget || 'broadcast';

        try {
            const response = await fetch('/message', {
                method: 'POST',
                headers: getAuthHeaders(),
                body: JSON.stringify({
                    receiverId: targetId,
                    contactName: window.app.chatContactName || targetId,
                    content: { body: text, from: myId, to: targetId, ts: Date.now(), type: 'MSG' }
                })
            });

            if (response.ok) {
                const result = await response.json();
                if (result.convo && window.AppState) {
                    window.AppState.activeConvoId = result.convo.id;
                }
                if (window.UI) {
                    window.UI.loadConversations(myId);
                }
                return result;
            }
        } catch (e) {
            console.error("HTTP Persistence failed");
        }
        return null;
    };

    // --- 3. WIRE UP SEND BUTTON ---
    const wireUpSendButton = () => {
        const btn = document.getElementById('chat-send');
        const input = document.getElementById('chat-input');
        if (!btn || !input) {
            setTimeout(wireUpSendButton, 500);
            return;
        }

        const sendMessage = async () => {
            const text = input.value.trim();
            if (!text) return;

            if (window.UI) UI.addMessage(text, 'me');
            input.value = '';

            await window.app.persistMessage(text, window.app.chatTarget);

            if (window.app.mesh) {
                try {
                    window.app.mesh.broadcast({
                        body: text,
                        from: window.app.identity.id,
                        to: window.app.chatTarget || 'broadcast',
                        type: 'MSG'
                    });
                } catch (e) {
                    console.warn("Mesh broadcast failed");
                }
            }

            if (window.app.chat && window.app.chat.sendToNetwork) {
                try {
                    await window.app.chat.sendToNetwork(JSON.stringify({
                        body: text,
                        from: window.app.identity.id,
                        to: window.app.chatTarget || 'broadcast'
                    }));
                } catch (e) {
                    console.warn("GhostChat send failed");
                }
            }
        };

        window.app.sendMessage = sendMessage;

        const newBtn = btn.cloneNode(true);
        btn.parentNode.replaceChild(newBtn, btn);

        const newInput = input.cloneNode(true);
        input.parentNode.replaceChild(newInput, input);

        newBtn.onclick = sendMessage;
        newInput.onkeypress = (e) => {
            if (e.key === 'Enter') sendMessage();
        };

        console.log("Chat SEND button wired to HTTP + Mesh");

        const fileInput = document.getElementById('chat-file');
        if (fileInput) {
            fileInput.onchange = async (e) => {
                const file = e.target.files[0];
                if (!file) return;
                UI.addMessage(`FILE: ${file.name} (${(file.size / 1024).toFixed(1)} KB)`, 'me');
                fileInput.value = '';
            };
        }
    };

    wireUpSendButton();

    // --- 4. INITIALIZE MESH TRANSPORT ---
    if (window.GhostMesh) {
        try {
            const mesh = new GhostMesh(window.app.identity);
            window.app.mesh = mesh;

            mesh.onPeerJoin = (peer) => {
                console.log(`Peer joined: ${(peer.name || '').slice(0, 12)} via ${peer.transport}`);

                if (window.AppState && !window.AppState.peers.find(p => p.id === peer.id)) {
                    window.AppState.peers.push({
                        id: peer.id,
                        type: peer.transport === 'ble' ? 'Bluetooth' : 'Wi-Fi',
                        name: peer.name,
                        latency: peer.transport === 'ble' ? 15 : 5
                    });
                }
                window.dispatchEvent(new Event("app:state"));
            };

            mesh.onPeerLeave = (peer) => {
                if (window.AppState) {
                    window.AppState.peers = window.AppState.peers.filter(p => p.id !== peer.id);
                }
                window.dispatchEvent(new Event("app:state"));
            };

            mesh.onMessage = (msgData, from, transport) => {
                if (msgData && (msgData.type === 'MSG' || msgData.body)) {
                    if (window.UI) {
                        UI.addMessage(msgData.body || JSON.stringify(msgData), 'them');
                    }
                }
            };

            mesh.onMeshUpdate = (peers) => {
                const statNodes = document.getElementById('stat-nodes');
                if (statNodes) statNodes.innerText = peers.length + 1;
            };

            mesh.onStatusChange = (status) => {
                if (status.state === 'error') {
                    console.warn('Mesh error:', status.message);
                }
            };

            await mesh.start();
            console.log("GhostMesh started. Status:", mesh.getStatus());

        } catch (e) {
            console.warn("GhostMesh init failed");
        }
    } else {
        // [FIX 19] Derive WS URL from current host — no hardcoded production URL
        console.warn("GhostMesh not loaded, using direct WebSocket fallback");
        try {
            const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
            const token = window.app.authToken || '';
            const wsUrl = `${protocol}//${window.location.host}/ws?token=${encodeURIComponent(token)}`;
            const ws = new WebSocket(wsUrl);
            ws.onopen = () => {
                ws.send(JSON.stringify({ type: 'MESH_HELLO', capabilities: {} }));
            };
            ws.onmessage = (event) => {
                try {
                    const msg = JSON.parse(event.data);
                    if (msg.type === 'PEER_JOIN') {
                        if (window.AppState) {
                            window.AppState.peers.push({ id: msg.id, type: 'Wi-Fi', latency: 5 });
                            window.dispatchEvent(new Event("app:state"));
                        }
                    }
                } catch (e) { }
            };
        } catch (e) {
            console.warn("WebSocket fallback failed");
        }
    }

    // --- 5. OPTIONAL: GhostChat encryption layer ---
    if (window.GhostChat) {
        try {
            const transportSender = async (payloadStr) => {
                if (window.app.mesh) {
                    window.app.mesh.broadcast(JSON.parse(payloadStr));
                }
            };
            const chat = new GhostChat(window.app.identity, transportSender);
            window.app.chat = chat;
            chat.onMessage = (msg) => {
                if (window.UI) UI.addMessage(msg.body, "them");
            };
            console.log("GhostChat encryption layer initialized");
        } catch (e) {
            console.warn("GhostChat init failed (non-critical)");
        }
    }

    // --- 6. SIGNAL READY ---
    window.dispatchEvent(new Event("app:ready"));
    window.dispatchEvent(new Event("app:state"));

    if (window.location.protocol === 'file:') {
        alert("WARNING: You are running from a file:// path.\n\nPlease run 'node ghostnet-server.js' and visit http://localhost:8080");
    }
});
