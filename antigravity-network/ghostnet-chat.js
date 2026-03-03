/**
 * GhostNet Chat
 * Universal Module
 */

(function (root, factory) {
    if (typeof module === 'object' && module.exports) {
        module.exports = factory();
    } else {
        root.GhostChat = factory();
    }
}(typeof self !== 'undefined' ? self : this, function () {

    class GhostChat {
        constructor(myIdentity, transportSender) {
            this.myIdentity = myIdentity; // { pub: "...", priv: "..." }
            this.sendToNetwork = transportSender; // Function: (payload) => void
            this.sessions = new Map(); // PeerPubKey -> SharedSecret
            this.messages = new Map(); // MsgID -> MessageObject
            this.onMessage = (msg) => { }; // Callback

            // Load Persisted Messages on Start
            this._loadPersistedMessages();
        }

        _loadPersistedMessages() {
            try {
                const stored = localStorage.getItem("ghost_chat_history");
                if (stored) {
                    const parsed = JSON.parse(stored);
                    parsed.forEach(msg => {
                        this.messages.set(msg.id, msg);
                        // We might want to notify UI to render these on load
                        // But onMessage is usually set AFTER constructor.
                        // So we'll rely on script.js to ask for them or trigger a reload event.
                    });
                }
            } catch (e) {
                console.error("Failed to load chat history", e);
            }
        }

        _persist() {
            // Save only PERSIST mode messages
            const toSave = Array.from(this.messages.values()).filter(m => m.mode === 'PERSIST' || m.mode === 'DELETE');
            localStorage.setItem("ghost_chat_history", JSON.stringify(toSave));
        }

        // --- Session Management ---
        async getSessionKey(peerPubKey) {
            if (this.sessions.has(peerPubKey)) return this.sessions.get(peerPubKey);

            // Simple ECDH for Session Key (Simulated for this demo using Node/Web Crypto overlap)
            // In real double-ratchet, this would be complex. 
            // Here we derive a stable shared secret from the two generic Identity Keys.
            // For the sake of the demo, we'll assume a shared-secret derivation function exists or mock it securely.
            // A simple way: SHA256(Sort(MyPub, PeerPub)) since we don't have real ECDH keys passed in yet.
            // BETTER: Use window.crypto.subtle if available.

            const secret = await this._deriveSharedSecret(peerPubKey);
            this.sessions.set(peerPubKey, secret);
            return secret;
        }

        async _deriveSharedSecret(peerPubKey) {
            const encoder = new TextEncoder();
            const keys = [this.myIdentity.pub, peerPubKey].sort().join(":");
            const hash = await crypto.subtle.digest("SHA-256", encoder.encode(keys));
            return hash; // ArrayBuffer
        }

        // --- Sending Messages ---
        async sendMessage(body, toPubKey, mode = "PERSIST", ttl = 0) {
            const msgId = crypto.randomUUID();
            const ts = Date.now();
            const sessionKey = await this.getSessionKey(toPubKey);

            // Encrypt Body
            const iv = crypto.getRandomValues(new Uint8Array(12));
            const encodedBody = new TextEncoder().encode(body);
            const key = await crypto.subtle.importKey("raw", sessionKey, "AES-GCM", false, ["encrypt"]);
            const ciphertext = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, encodedBody);

            // Construct Payload
            const payload = {
                id: msgId,
                type: "MSG",
                from: this.myIdentity.pub,
                to: toPubKey,
                ts: ts,
                mode: mode,
                ttl: ttl,
                body: body, // Added to allow simple historical storage 
                iv: Array.from(iv), // Send as array for JSON serialization
                data: Array.from(new Uint8Array(ciphertext))
            };

            // Send via GhostNet
            this.sendToNetwork(JSON.stringify(payload));

            // Store locally (if not ephemeral outgoing?)
            const msgObj = { ...payload, body, status: "sent" };
            if (mode !== 'EPHEMERAL') {
                this.messages.set(msgId, msgObj);
                this._persist();
            }
            return msgObj;
        }

        async sendDeleteRequest(targetMsgId, toPubKey) {
            const payload = {
                id: crypto.randomUUID(),
                type: "DELETE",
                targetId: targetMsgId,
                from: this.myIdentity.pub,
                to: toPubKey,
                ts: Date.now()
            };
            this.sendToNetwork(JSON.stringify(payload));
        }

        // --- Receiving Messages ---
        async receive(rawJson) {
            try {
                const packet = JSON.parse(rawJson);

                // 1. Check if for me
                if (packet.to !== this.myIdentity.pub && packet.to !== "broadcast") return;

                // 2. Handle types
                if (packet.type === "DELETE") {
                    this.handleDelete(packet);
                    return;
                }

                if (packet.type === "MSG") {
                    await this.handleMessage(packet);
                }

            } catch (e) {
                console.error("Chat Receive Error:", e);
            }
        }

        async handleMessage(packet) {
            // Decrypt
            const sessionKey = await this.getSessionKey(packet.from);
            const key = await crypto.subtle.importKey("raw", sessionKey, "AES-GCM", false, ["decrypt"]);

            try {
                const decryptedBuffer = await crypto.subtle.decrypt(
                    { name: "AES-GCM", iv: new Uint8Array(packet.iv) },
                    key,
                    new Uint8Array(packet.data)
                );

                const body = new TextDecoder().decode(decryptedBuffer);
                const msgObj = { ...packet, body };

                // Handle Modes
                if (packet.mode === "EPHEMERAL") {
                    msgObj.ephemeral = true;
                    // Auto-delete logic handled by UI or simple timeout here
                    setTimeout(() => {
                        this.onDelete(packet.id);
                    }, (packet.ttl || 30) * 1000);
                } else {
                    // PERSIST or DELETE mode -> Save
                    this.messages.set(packet.id, msgObj);
                    this._persist();
                }

                this.onMessage(msgObj);

            } catch (e) {
                console.error("Decryption Failed:", e);
            }
        }

        handleDelete(packet) {
            // Verify sender (simplified: assume transport authenticated or check signature)
            if (this.messages.has(packet.targetId)) {
                const target = this.messages.get(packet.targetId);
                // Allow sender OR self to delete? Usually sender.
                if (target.from === packet.from || packet.from === this.myIdentity.pub) {
                    this.messages.delete(packet.targetId);
                    this._persist(); // Update storage
                    if (this.onDelete) this.onDelete(packet.targetId);
                }
            }
        }
    }

    return GhostChat;
}));
