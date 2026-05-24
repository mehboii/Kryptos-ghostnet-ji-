/**
 * GhostNet WebRTC — E2E Encrypted Voice/Video
 * Universal Module
 *
 * SECURITY FIX:
 * [FIX 13] Implement actual AES-GCM frame encryption via Insertable Streams.
 *          Previously, encryptStream() was a passthrough that did nothing.
 *          Now, a shared AES-GCM-256 key is derived per call and used to
 *          encrypt each encoded frame before it leaves the local peer.
 */

(function (root, factory) {
    if (typeof module === 'object' && module.exports) {
        module.exports = factory();
    } else {
        root.GhostWebRTC = factory();
    }
}(typeof self !== 'undefined' ? self : this, function () {

    if (typeof window === 'undefined') {
        return class GhostWebRTC_NodeStub {
            constructor() { console.log("WebRTC not supported in Node environment"); }
        }
    }

    // [FIX 13] Frame header: 12-byte IV prepended to each encrypted frame.
    // The receiver reads the IV from the first 12 bytes, then decrypts the rest.
    const IV_LENGTH = 12;

    class GhostWebRTC {
        constructor(signaling) {
            this.signaling = signaling;
            this.activeCalls = new Map();
            this.localStream = null;

            // [FIX 13] Per-call encryption keys
            this._callKeys = new Map();

            this.rtcConfig = {
                iceServers: [{ urls: "stun:stun.l.google.com:19302" }],
                encodedInsertableStreams: true
            };

            if (this.signaling) {
                this.signaling.onSignal = (msg, from) => this.handleSignal(msg, from);
            }
        }

        async getLocalStream(video = false, audio = true) {
            if (!this.localStream) {
                this.localStream = await navigator.mediaDevices.getUserMedia({ video, audio });
            }
            return this.localStream;
        }

        // [FIX 13] Generate a per-call AES-GCM-256 key
        async _generateCallKey(callId) {
            const key = await crypto.subtle.generateKey(
                { name: 'AES-GCM', length: 256 },
                true,
                ['encrypt', 'decrypt']
            );
            this._callKeys.set(callId, key);
            return key;
        }

        // [FIX 13] Exchange the call key with the remote peer via signaling
        // In production, this should use the ECDH shared secret from the
        // peer's public key. For now, we export and send via the signaling channel.
        async _exportCallKey(callId) {
            const key = this._callKeys.get(callId);
            if (!key) return null;
            const raw = await crypto.subtle.exportKey('raw', key);
            return Array.from(new Uint8Array(raw)).map(b => b.toString(16).padStart(2, '0')).join('');
        }

        async _importCallKey(callId, keyHex) {
            const bytes = new Uint8Array(keyHex.match(/.{2}/g).map(b => parseInt(b, 16)));
            const key = await crypto.subtle.importKey(
                'raw',
                bytes,
                { name: 'AES-GCM', length: 256 },
                false,
                ['encrypt', 'decrypt']
            );
            this._callKeys.set(callId, key);
            return key;
        }

        async createCall(targetPeerId) {
            const pc = new RTCPeerConnection(this.rtcConfig);
            const callId = crypto.randomUUID();
            this.activeCalls.set(targetPeerId, pc);

            // [FIX 13] Generate encryption key for this call
            await this._generateCallKey(callId);
            const keyHex = await this._exportCallKey(callId);

            const stream = await this.getLocalStream();
            stream.getTracks().forEach(track => {
                const sender = pc.addTrack(track, stream);
                // [FIX 13] Apply real encryption to outgoing frames
                this._encryptSenderStream(sender, callId);
            });

            // [FIX 13] Decrypt incoming frames
            pc.ontrack = (event) => {
                this._decryptReceiverStream(event.receiver, callId);
                const remoteStream = event.streams[0];
                const video = document.createElement('video');
                video.srcObject = remoteStream;
                video.autoplay = true;
                video.id = `remote-${targetPeerId}`;
                document.body.appendChild(video);
            };

            pc.onicecandidate = (event) => {
                if (event.candidate) {
                    this.signaling.sendMessage(targetPeerId, {
                        type: "candidate",
                        candidate: event.candidate,
                        callId
                    });
                }
            };

            const offer = await pc.createOffer();
            await pc.setLocalDescription(offer);

            await this.signaling.sendMessage(targetPeerId, {
                type: "offer",
                sdp: offer,
                callId,
                encryptionKey: keyHex,
            });

            return { callId, pc };
        }

        async acceptCall(fromPeerId, offerData) {
            const pc = new RTCPeerConnection(this.rtcConfig);
            this.activeCalls.set(fromPeerId, pc);

            const callId = offerData.callId;

            // [FIX 13] Import the caller's encryption key
            if (offerData.encryptionKey) {
                await this._importCallKey(callId, offerData.encryptionKey);
            }

            pc.ontrack = (event) => {
                // [FIX 13] Decrypt incoming frames
                this._decryptReceiverStream(event.receiver, callId);

                const remoteStream = event.streams[0];
                const video = document.createElement('video');
                video.srcObject = remoteStream;
                video.autoplay = true;
                video.id = `remote-${fromPeerId}`;
                document.body.appendChild(video);
            };

            const stream = await this.getLocalStream();
            stream.getTracks().forEach(track => {
                const sender = pc.addTrack(track, stream);
                // [FIX 13] Encrypt outgoing frames
                this._encryptSenderStream(sender, callId);
            });

            await pc.setRemoteDescription(new RTCSessionDescription(offerData.sdp));

            const answer = await pc.createAnswer();
            await pc.setLocalDescription(answer);

            this.signaling.sendMessage(fromPeerId, {
                type: "answer",
                sdp: answer,
                callId
            });

            return pc;
        }

        // [FIX 13] Actual AES-GCM encryption of outgoing encoded frames
        _encryptSenderStream(sender, callId) {
            if (!sender.createEncodedStreams) return;
            const streams = sender.createEncodedStreams();
            const self = this;

            const transformer = new TransformStream({
                async transform(chunk, controller) {
                    const key = self._callKeys.get(callId);
                    if (!key) {
                        controller.enqueue(chunk);
                        return;
                    }

                    try {
                        const iv = crypto.getRandomValues(new Uint8Array(IV_LENGTH));
                        const frameData = new Uint8Array(chunk.data);

                        const encrypted = await crypto.subtle.encrypt(
                            { name: 'AES-GCM', iv },
                            key,
                            frameData
                        );

                        // Prepend IV to encrypted data
                        const combined = new Uint8Array(IV_LENGTH + encrypted.byteLength);
                        combined.set(iv, 0);
                        combined.set(new Uint8Array(encrypted), IV_LENGTH);

                        chunk.data = combined.buffer;
                        controller.enqueue(chunk);
                    } catch {
                        // On encryption failure, drop the frame rather than send plaintext
                    }
                }
            });

            streams.readable.pipeThrough(transformer).pipeTo(streams.writable);
        }

        // [FIX 13] Actual AES-GCM decryption of incoming encoded frames
        _decryptReceiverStream(receiver, callId) {
            if (!receiver.createEncodedStreams) return;
            const streams = receiver.createEncodedStreams();
            const self = this;

            const transformer = new TransformStream({
                async transform(chunk, controller) {
                    const key = self._callKeys.get(callId);
                    if (!key) {
                        controller.enqueue(chunk);
                        return;
                    }

                    try {
                        const data = new Uint8Array(chunk.data);
                        if (data.length < IV_LENGTH + 16) {
                            // Too short to be a valid AES-GCM frame (IV + tag minimum)
                            return;
                        }

                        const iv = data.slice(0, IV_LENGTH);
                        const ciphertext = data.slice(IV_LENGTH);

                        const decrypted = await crypto.subtle.decrypt(
                            { name: 'AES-GCM', iv },
                            key,
                            ciphertext
                        );

                        chunk.data = decrypted;
                        controller.enqueue(chunk);
                    } catch {
                        // Decryption failed — frame tampered or wrong key; drop it
                    }
                }
            });

            streams.readable.pipeThrough(transformer).pipeTo(streams.writable);
        }

        async handleSignal(msg, from) {
            let pc = this.activeCalls.get(from);
            if (msg.type === "offer") {
                await this.acceptCall(from, msg);
            }
            else if (msg.type === "answer" && pc) {
                await pc.setRemoteDescription(new RTCSessionDescription(msg.sdp));
            }
            else if (msg.type === "candidate" && pc) {
                await pc.addIceCandidate(new RTCIceCandidate(msg.candidate));
            }
        }

        // Clean up call keys when a call ends
        endCall(peerId) {
            const pc = this.activeCalls.get(peerId);
            if (pc) {
                pc.close();
                this.activeCalls.delete(peerId);
            }
            // Find and delete associated call key
            for (const [callId] of this._callKeys) {
                if (!this.activeCalls.size) {
                    this._callKeys.delete(callId);
                }
            }
        }
    }

    return GhostWebRTC;
}));
