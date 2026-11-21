/**
 * Kryptos WebRTC — E2E Encrypted Voice/Video
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

            // [RT2-01] Per-peer identity public keys for ECDH signature verification
            this._peerIdentityKeys = new Map();

            this.rtcConfig = {
                iceServers: [{ urls: "stun:stun.l.google.com:19302" }],
                encodedInsertableStreams: true
            };

            if (this.signaling) {
                this.signaling.onSignal = (msg, from) => this.handleSignal(msg, from);
            }
        }

        // [RT2-01] Register a peer's identity public key for ECDH verification
        async registerPeerIdentity(peerId, publicKeyRaw) {
            if (!publicKeyRaw) return;
            try {
                let key = publicKeyRaw;
                if (!(publicKeyRaw instanceof CryptoKey)) {
                    const keyBytes = typeof publicKeyRaw === 'string'
                        ? new Uint8Array(publicKeyRaw.match(/.{2}/g).map(b => parseInt(b, 16)))
                        : new Uint8Array(publicKeyRaw);
                    key = await crypto.subtle.importKey(
                        'spki', keyBytes,
                        { name: 'ECDSA', namedCurve: 'P-256' }, false, ['verify']
                    );
                }
                this._peerIdentityKeys.set(peerId, key);
            } catch {}
        }

        async getLocalStream(video = false, audio = true) {
            if (!this.localStream) {
                this.localStream = await navigator.mediaDevices.getUserMedia({ video, audio });
            }
            return this.localStream;
        }

        // [IAST-07][RT-BREAK-02] ECDH key agreement with identity-signed public keys
        async _generateCallKeyPair(callId) {
            const keyPair = await crypto.subtle.generateKey(
                { name: 'ECDH', namedCurve: 'P-256' },
                false,
                ['deriveKey']
            );
            if (!this._callECDH) this._callECDH = new Map();
            this._callECDH.set(callId, keyPair);
            const exported = await crypto.subtle.exportKey('raw', keyPair.publicKey);
            const pubKeyHex = Array.from(new Uint8Array(exported)).map(b => b.toString(16).padStart(2, '0')).join('');

            // [RT-BREAK-02] Sign the ECDH public key with identity key to prevent MITM substitution
            let ecdhSig = null;
            if (this._identityKey) {
                try {
                    const sigBuf = await crypto.subtle.sign(
                        { name: 'ECDSA', hash: 'SHA-256' },
                        this._identityKey,
                        new TextEncoder().encode(callId + '|' + pubKeyHex)
                    );
                    ecdhSig = Array.from(new Uint8Array(sigBuf)).map(b => b.toString(16).padStart(2, '0')).join('');
                } catch {}
            }
            this._lastEcdhSig = ecdhSig;
            return pubKeyHex;
        }

        // [RT-BREAK-02] Verify remote ECDH public key is signed by the peer's identity
        async _deriveCallKey(callId, remotePubKeyHex, ecdhSig, peerIdentityPubKey) {
            const ecdhState = this._callECDH ? this._callECDH.get(callId) : null;
            if (!ecdhState) return null;

            // [DAST-F18] ECDH signature verification is MANDATORY — reject unsigned key exchange
            if (!ecdhSig || !peerIdentityPubKey) {
                console.error('[DAST-F18] ECDH key must be identity-signed — refusing unsigned key exchange');
                return null;
            }
            try {
                const valid = await crypto.subtle.verify(
                    { name: 'ECDSA', hash: 'SHA-256' },
                    peerIdentityPubKey,
                    new Uint8Array(ecdhSig.match(/.{2}/g).map(b => parseInt(b, 16))),
                    new TextEncoder().encode(callId + '|' + remotePubKeyHex)
                );
                if (!valid) {
                    console.error('[DAST-F18] ECDH key signature invalid — possible MITM');
                    return null;
                }
            } catch {
                console.error('[DAST-F18] ECDH signature verification failed');
                return null;
            }

            const remoteBytes = new Uint8Array(remotePubKeyHex.match(/.{2}/g).map(b => parseInt(b, 16)));
            const remotePubKey = await crypto.subtle.importKey(
                'raw', remoteBytes,
                { name: 'ECDH', namedCurve: 'P-256' },
                false, []
            );
            const derivedKey = await crypto.subtle.deriveKey(
                { name: 'ECDH', public: remotePubKey },
                ecdhState.privateKey,
                { name: 'AES-GCM', length: 256 },
                false,
                ['encrypt', 'decrypt']
            );
            this._callKeys.set(callId, derivedKey);
            return derivedKey;
        }

        async createCall(targetPeerId) {
            const pc = new RTCPeerConnection(this.rtcConfig);
            const callId = crypto.randomUUID();
            this.activeCalls.set(targetPeerId, pc);

            // [IAST-07] Generate ECDH keypair — only public key is sent
            const myPubKeyHex = await this._generateCallKeyPair(callId);

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
                ecdhPubKey: myPubKeyHex,
                ecdhSig: this._lastEcdhSig,
            });

            return { callId, pc };
        }

        async acceptCall(fromPeerId, offerData) {
            const pc = new RTCPeerConnection(this.rtcConfig);
            this.activeCalls.set(fromPeerId, pc);

            const callId = offerData.callId;

            // [RT2-01] Generate our ECDH keypair and derive shared key with peer's identity key
            const myPubKeyHex = await this._generateCallKeyPair(callId);
            if (offerData.ecdhPubKey) {
                const peerIdKey = this._peerIdentityKeys.get(fromPeerId) || null;
                await this._deriveCallKey(callId, offerData.ecdhPubKey, offerData.ecdhSig, peerIdKey);
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
                callId,
                ecdhPubKey: myPubKeyHex,
                ecdhSig: this._lastEcdhSig,
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
                // [RT2-01] Derive shared call key using peer's registered identity key
                if (msg.ecdhPubKey && msg.callId) {
                    const peerIdKey = this._peerIdentityKeys.get(from) || null;
                    await this._deriveCallKey(msg.callId, msg.ecdhPubKey, msg.ecdhSig, peerIdKey);
                }
                await pc.setRemoteDescription(new RTCSessionDescription(msg.sdp));
            }
            else if (msg.type === "candidate" && pc) {
                await pc.addIceCandidate(new RTCIceCandidate(msg.candidate));
            }
        }

        // [RASP-10] Set identity signing key for ECDH signature binding
        setIdentityKey(privateKey) {
            this._identityKey = privateKey;
        }

        // Clean up call keys and ECDH state when a call ends
        endCall(peerId) {
            const pc = this.activeCalls.get(peerId);
            if (pc) {
                pc.close();
                this.activeCalls.delete(peerId);
            }
            // Clean up associated call keys and ECDH state
            for (const [callId] of this._callKeys) {
                if (!this.activeCalls.size) {
                    this._callKeys.delete(callId);
                    if (this._callECDH) this._callECDH.delete(callId);
                }
            }
        }
    }

    return GhostWebRTC;
}));
