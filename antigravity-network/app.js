
/**
 * GhostNet Application Logic
 * Integrates Identity, GhostMesh Transport, and Chat.
 * 
 * Architecture:
 * - GhostMesh handles ALL transport (WebSocket auto-connect + BLE scan)
 * - HTTP persistence always works independently
 * - BLE and GhostChat are optional enhancements
 */

window.app = {
    identity: null,
    chat: null,
    chatTarget: null,
    chatContactName: null,
    mesh: null,
    transport: {
        ble: null,
        // Legacy compatibility: startBLEScan delegates to mesh
        startBLEScan: async () => {
            if (window.app.mesh) {
                await window.app.mesh.scanBLE();
            } else {
                alert("Mesh transport not ready. Please wait for initialization.");
            }
        }
    }
};

// [DAST-09] IndexedDB-backed non-extractable storage key
async function _getOrCreateStorageKey() {
    return new Promise((resolve, reject) => {
        const req = indexedDB.open('ghostnet_keys', 1);
        req.onupgradeneeded = (e) => {
            e.target.result.createObjectStore('keys');
        };
        req.onerror = () => reject(req.error);
        req.onsuccess = async () => {
            const db = req.result;
            const tx = db.transaction('keys', 'readonly');
            const store = tx.objectStore('keys');
            const getReq = store.get('storage_key');
            getReq.onsuccess = async () => {
                if (getReq.result) {
                    resolve(getReq.result);
                } else {
                    const key = await crypto.subtle.generateKey(
                        { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']
                    );
                    const wtx = db.transaction('keys', 'readwrite');
                    wtx.objectStore('keys').put(key, 'storage_key');
                    wtx.oncomplete = () => resolve(key);
                    wtx.onerror = () => reject(wtx.error);
                }
            };
            getReq.onerror = () => reject(getReq.error);
        };
    });
}

// Initialize App on Load
window.addEventListener('DOMContentLoaded', async () => {
    console.log(" System: Initializing GhostNet...");

    // --- 1. IDENTITY ---
    let myId = localStorage.getItem('ghostnet_user_id');
    if (!myId) {
        myId = "user_" + crypto.randomUUID();
        localStorage.setItem('ghostnet_user_id', myId);
    }

    // [RT-BREAK-12] Persist identity keypair in IndexedDB across page loads
    if (window.GhostIdentity) {
        let storedIdentity = null;
        try {
            storedIdentity = await new Promise((resolve, reject) => {
                const req = indexedDB.open('ghostnet_keys', 1);
                req.onerror = () => reject(req.error);
                req.onsuccess = () => {
                    const db = req.result;
                    const tx = db.transaction('keys', 'readonly');
                    const store = tx.objectStore('keys');
                    const getReq = store.get('identity');
                    getReq.onsuccess = () => resolve(getReq.result || null);
                    getReq.onerror = () => reject(getReq.error);
                };
            });
        } catch {}

        if (storedIdentity && storedIdentity.privateKey && storedIdentity.publicKey) {
            window.app.identity = storedIdentity;
        } else {
            window.app.identity = await window.GhostIdentity.generateIdentity();
            try {
                await new Promise((resolve, reject) => {
                    const req = indexedDB.open('ghostnet_keys', 1);
                    req.onerror = () => reject(req.error);
                    req.onsuccess = () => {
                        const db = req.result;
                        const tx = db.transaction('keys', 'readwrite');
                        tx.objectStore('keys').put(window.app.identity, 'identity');
                        tx.oncomplete = () => resolve();
                        tx.onerror = () => reject(tx.error);
                    };
                });
            } catch {}
        }
        window.app.identity.id = myId;
        window.app.identity.pub = myId;
        window.app.identity.nodeId = myId;
    } else {
        window.app.identity = { id: myId, pub: myId, nodeId: myId };
        console.warn(" GhostIdentity module missing, using fallback identity");
    }

    // Set identity in global state
    if (window.AppState) {
        window.AppState.identity = window.app.identity;
    }

    console.log(" Identity:", myId);

    // --- 2. HTTP PERSISTENCE (always works) ---
    // [RT-12] Storage key held in closure — not on window.app — so XSS cannot access it
    const _storageKey = await _getOrCreateStorageKey();

    // [RT-BREAK-11] Never fall back to plaintext — throw on encryption failure
    const _encryptForStorage = async (text) => {
        const iv = crypto.getRandomValues(new Uint8Array(12));
        const cipherBuf = await crypto.subtle.encrypt(
            { name: 'AES-GCM', iv }, _storageKey, new TextEncoder().encode(text)
        );
        return JSON.stringify({
            enc: true,
            iv: Array.from(iv),
            data: Array.from(new Uint8Array(cipherBuf))
        });
    };

    window.app.persistMessage = async (text, targetId) => {
        const myId = window.app.identity.id;
        targetId = targetId || window.app.chatTarget || 'broadcast';

        const encryptedContent = await _encryptForStorage(text);

        try {
            // [DAST-F13] Auth via HttpOnly cookie — sent automatically by browser
            const response = await fetch('/message', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({
                    senderId: myId,
                    receiverId: targetId,
                    contactName: window.app.chatContactName || targetId,
                    content: encryptedContent
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
        } catch (e) { }
        return null;
    };

    // --- 3. WIRE UP SEND BUTTON ---
    const wireUpSendButton = () => {
        const btn = document.getElementById('chat-send');
        const input = document.getElementById('chat-input');
        if (!btn || !input) {
            console.warn("Chat send button or input not found. Retrying...");
            setTimeout(wireUpSendButton, 500);
            return;
        }

        const sendMessage = async () => {
            const text = input.value.trim();
            if (!text) return;

            if (window.UI) UI.addMessage(text, 'me');
            input.value = '';

            await window.app.persistMessage(text, window.app.chatTarget);

            if (window.app.chat && window.app.chat.sendMessage) {
                try {
                    await window.app.chat.sendMessage(
                        text,
                        window.app.chatTarget || 'broadcast',
                        'PERSIST'
                    );
                } catch (e) {
                    console.warn("GhostChat encrypted send failed, falling back to mesh:", e);
                    if (window.app.mesh) {
                        window.app.mesh.broadcast({
                            from: window.app.identity.id,
                            to: window.app.chatTarget || 'broadcast',
                            type: 'MSG'
                        });
                    }
                }
            } else if (window.app.mesh) {
                window.app.mesh.broadcast({
                    from: window.app.identity.id,
                    to: window.app.chatTarget || 'broadcast',
                    type: 'MSG'
                });
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

        console.log(" Chat SEND button wired to HTTP + Mesh");

        // File Attachment Logic
        const fileInput = document.getElementById('chat-file');
        if (fileInput) {
            fileInput.onchange = async (e) => {
                const file = e.target.files[0];
                if (!file) return;
                console.log(" File Selected:", file.name);
                UI.addMessage(` FILE: ${file.name} (${(file.size / 1024).toFixed(1)} KB)`, 'me');
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

            // --- Mesh event handlers ---

            mesh.onPeerJoin = (peer) => {
                console.log(` Peer joined: ${peer.name} via ${peer.transport}`);

                // Add to AppState peers
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
                console.log(` Peer left: ${peer.name || peer.id}`);

                if (window.AppState) {
                    window.AppState.peers = window.AppState.peers.filter(p => p.id !== peer.id);
                }
                window.dispatchEvent(new Event("app:state"));
            };

            mesh.onMessage = (msgData, from, transport) => {
                console.log(` Mesh message from ${from} via ${transport}:`, msgData);

                // Display in chat if it's a MSG type
                if (msgData && (msgData.type === 'MSG' || msgData.body)) {
                    if (window.UI) {
                        UI.addMessage(msgData.body || JSON.stringify(msgData), 'them');
                    }
                }
            };

            mesh.onMeshUpdate = (peers) => {
                // Update the UI stat counter
                const statNodes = document.getElementById('stat-nodes');
                if (statNodes) statNodes.innerText = peers.length + 1; // +1 for self
            };

            mesh.onStatusChange = (status) => {
                console.log(' Mesh status:', status);

                if (status.state === 'error') {
                    console.warn('Mesh error:', status.message);
                }
            };

            // Start the mesh (WebSocket auto-connects, BLE auto-reconnects known devices)
            await mesh.start();
            console.log(" GhostMesh started. Status:", mesh.getStatus());

        } catch (e) {
            console.warn("GhostMesh init failed:", e);
        }
    } else {
        // Fallback: Direct WebSocket if GhostMesh not loaded
        console.warn(" GhostMesh not loaded, using direct WebSocket fallback");
        try {
            const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
            // [DAST-F13] Cookie-based auth — cookie sent automatically with upgrade request
            const wsUrl = (window.GHOSTNET_CONFIG && window.GHOSTNET_CONFIG.wsUrl)
                || `${protocol}//${window.location.host}/ws`;
            const ws = new WebSocket(wsUrl);
            ws.onopen = () => {
                ws.send(JSON.stringify({ type: 'HELLO', id: myId }));
            };
            ws.onmessage = (event) => {
                try {
                    const raw = event.data;
                    if (typeof raw !== 'string' || raw.length > 65536) return;
                    const msg = JSON.parse(raw);
                    if (!msg || typeof msg !== 'object' || typeof msg.type !== 'string') return;
                    const allowedTypes = new Set(['PEER_JOIN', 'PEER_LEAVE', 'MESH_PEERS', 'welcome', 'HEARTBEAT']);
                    if (!allowedTypes.has(msg.type)) return;
                    if (msg.type === 'PEER_JOIN') {
                        if (typeof msg.id !== 'string' || msg.id.length > 128) return;
                        if (window.AppState) {
                            window.AppState.peers.push({ id: String(msg.id), type: 'Wi-Fi', latency: 5 });
                            window.dispatchEvent(new Event("app:state"));
                        }
                    }
                } catch (e) { }
            };
        } catch (e) {
            console.warn("WebSocket fallback failed:", e);
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
            console.log(" GhostChat encryption layer initialized");
        } catch (e) {
            console.warn("GhostChat init failed (non-critical):", e);
        }
    }

    // --- 6. SIGNAL READY ---
    window.dispatchEvent(new Event("app:ready"));
    window.dispatchEvent(new Event("app:state"));

    if (window.location.protocol === 'file:') {
        alert(" WARNING: You are running from a file:// path.\n\nPlease run 'node ghostnet-server.js' and visit http://localhost:8080");
    }
});
