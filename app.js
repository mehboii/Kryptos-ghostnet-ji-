
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

// Initialize App on Load
window.addEventListener('DOMContentLoaded', async () => {
    console.log(" System: Initializing GhostNet...");

    // --- 1. IDENTITY ---
    // Generate a fallback ID for initial boot (before PIN unlock)
    let myId = localStorage.getItem('ghostnet_user_id');
    if (!myId) {
        myId = "user_" + Date.now() + "_" + Math.floor(Math.random() * 1000);
        localStorage.setItem('ghostnet_user_id', myId);
    }

    // Use real crypto identity if already available (e.g. stored in localStorage)
    let stored = null;
    try {
        if (localStorage.getItem('ghostnet_enc_pk')) {
            stored = {
                nodeId: localStorage.getItem('ghostnet_node_id'),
                publicKey: localStorage.getItem('ghostnet_pubkey'),
                displayName: localStorage.getItem('ghostnet_display_name'),
                address: localStorage.getItem('ghostnet_address')
            };
        }
    } catch (e) { }
    if (stored && stored.nodeId) {
        window.app.identity = {
            id: stored.nodeId,
            pub: stored.nodeId,
            nodeId: stored.nodeId,
            displayName: stored.displayName,
            address: stored.address
        };
        console.log(" Using crypto identity from storage:", stored.nodeId.substring(0, 15) + '...');
    } else if (window.AppState && window.AppState.identity && window.AppState.identity.nodeId) {
        const real = window.AppState.identity;
        window.app.identity = {
            id: real.nodeId,
            pub: real.nodeId,
            nodeId: real.nodeId,
            displayName: real.displayName,
            address: real.address
        };
        console.log(" Using crypto identity from state:", real.nodeId.substring(0, 15) + '...');
    } else {
        // Fallback identity for before PIN unlock
        window.app.identity = { id: myId, pub: myId, nodeId: myId };
        console.log(" Using fallback identity:", myId);
    }

    // Set identity in global state
    if (window.AppState && !window.AppState.identity) {
        window.AppState.identity = window.app.identity;
    }

    // Listen for identity updates (when user unlocks PIN after page load)
    window.addEventListener('identity:updated', () => {
        if (window.AppState && window.AppState.identity && window.AppState.identity.nodeId) {
            const real = window.AppState.identity;
            window.app.identity = {
                id: real.nodeId,
                pub: real.publicKey || real.nodeId,
                nodeId: real.nodeId,
                displayName: real.displayName,
                address: real.address
            };
            console.log(" Identity updated to:", real.nodeId.substring(0, 15) + '...');

            // Re-register with mesh if connected
            if (window.app.mesh && window.app.mesh.ws && window.app.mesh.wsReady) {
                window.app.mesh.identity = window.app.identity;
                window.app.mesh.ws.send(JSON.stringify({
                    type: 'register',
                    id: window.app.identity.id,
                    nodeId: window.app.identity.nodeId,
                    capabilities: { ble: false, ws: true }
                }));
                console.log(" Re-registered with mesh as:", real.nodeId.substring(0, 15) + '...');
            }

            // Load conversation history with the real identity
            if (window.UI) {
                setTimeout(() => UI.loadConversations(real.nodeId), 500);
            }
        }
    });

    // --- 2. HTTP PERSISTENCE (always works) ---
    window.app.persistMessage = async (text, targetId) => {
        const myId = window.app.identity.nodeId || window.app.identity.id;
        targetId = targetId || window.app.chatTarget || 'broadcast';

        try {
            const response = await fetch('https://ghostnet-ji-production.up.railway.app/message', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    senderId: myId,
                    receiverId: targetId,
                    contactName: window.app.chatContactName || (window.app.identity.displayName) || myId.substring(0, 10),
                    content: text  // Send plain text — server stores as-is
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
            } else {
                const errBody = await response.json().catch(() => ({}));
                const errMsg = errBody.error || `HTTP ${response.status}`;
                console.error(` Message rejected:`, errMsg);

                // Show specific error to user
                if (response.status === 404) {
                    if (window.UI) UI.addMessage(`⚠️ ${errMsg}`, 'them');
                }
            }
        } catch (e) {
            console.error("HTTP Persistence failed:", e);
        }
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

            const recipientNodeId = window.app.chatTarget || 'broadcast';
            const myId = window.app.identity.nodeId || window.app.identity.id;

            // Immediately show in UI
            if (window.UI) UI.addMessage(text, 'me');
            input.value = '';

            // PRIMARY: Always persist via HTTP POST /message
            // This is the single source of truth for message storage + delivery
            // The server handles: DB save, WS real-time delivery, offline queuing
            try {
                const result = await window.app.persistMessage(text, recipientNodeId);
                if (result && result.success) {
                    console.log(' Message sent and persisted:', result.message?.id);
                } else if (result === null) {
                    console.warn(' Message persistence returned null (server may be down)');
                    // Still try WS fallback for real-time delivery
                    if (window.app.mesh && window.app.mesh.ws && window.app.mesh.ws.readyState === 1) {
                        window.app.mesh.ws.send(JSON.stringify({
                            type: 'message',
                            to: recipientNodeId,
                            from: myId,
                            content: { body: text, from: myId, to: recipientNodeId, ts: Date.now(), type: 'MSG' },
                            timestamp: Date.now()
                        }));
                    }
                }
            } catch (e) {
                console.error(' Send message error:', e);
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

        console.log(" Chat SEND button wired to HTTP persistence");

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

                // Decrypt via GhostChat if it contains crypto payload
                if (msgData && msgData.type === 'MSG' && msgData.iv) {
                    if (window.app.chat) {
                        try {
                            // Reconstruct the expected GhostChat structure to feed the decryptor
                            const gcPacket = {
                                type: "MSG",
                                id: msgData.id,
                                from: from,
                                to: window.app.identity.nodeId,
                                ts: Date.now(),
                                iv: msgData.iv,
                                data: msgData.data,
                                mode: msgData.mode,
                                ttl: msgData.ttl
                            };
                            window.app.chat.receive(JSON.stringify(gcPacket));
                        } catch (e) { console.warn("GhostChat Decryption error:", e); }
                    }
                }
                // Display in chat if it's plaintext fallback
                else if (msgData && (msgData.type === 'MSG' || msgData.body)) {
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
            const wsUrl = `wss://ghostnet-ji-production.up.railway.app/ws`;
            const ws = new WebSocket(wsUrl);
            ws.onopen = () => {
                ws.send(JSON.stringify({ type: 'register', id: window.app.identity.id, nodeId: window.app.identity.nodeId }));
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
            console.warn("WebSocket fallback failed:", e);
        }
    }

    // --- 5. OPTIONAL: GhostChat encryption layer ---
    if (window.GhostChat) {
        try {
            const transportSender = async (payloadStr) => {
                const gcPayload = JSON.parse(payloadStr);

                // Format it exactly as required by the backend routing
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

                if (window.app.mesh && window.app.mesh.ws && window.app.mesh.ws.readyState === 1) {
                    window.app.mesh.ws.send(JSON.stringify(customPayload));
                } else if (window.app.mesh) {
                    window.app.mesh.broadcast(customPayload);
                }
            };
            const chat = new GhostChat(window.app.identity, transportSender);
            window.app.chat = chat;
            chat.onMessage = (msg) => {
                if (window.UI) {
                    UI.addMessage(msg.body, "them");
                    if (window.AppState && window.AppState.identity) {
                        UI.loadConversations(window.AppState.identity.id || window.AppState.identity.nodeId);
                    }
                }
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
