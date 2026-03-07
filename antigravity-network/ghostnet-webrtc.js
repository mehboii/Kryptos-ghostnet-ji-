/**
 * GhostNet WebRTC
 * Universal Module
 */

(function (root, factory) {
    if (typeof module === 'object' && module.exports) {
        module.exports = factory();
    } else {
        root.GhostWebRTC = factory();
    }
}(typeof self !== 'undefined' ? self : this, function () {

    // Node.js placeholder (WebRTC not native in Node)
    if (typeof window === 'undefined') {
        return class GhostWebRTC_NodeStub {
            constructor() { console.log("WebRTC not supported in Node environment"); }
        }
    }

    class GhostWebRTC {
        constructor(signaling) {
            this.signaling = signaling;
            this.activeCalls = new Map();
            this.localStream = null;
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

        async createCall(targetPeerId) {
            const pc = new RTCPeerConnection(this.rtcConfig);
            const callId = crypto.randomUUID();
            this.activeCalls.set(targetPeerId, pc);

            const stream = await this.getLocalStream();
            stream.getTracks().forEach(track => {
                const sender = pc.addTrack(track, stream);
                this.encryptStream(sender);
            });

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
                callId
            });

            return { callId, pc };
        }

        async acceptCall(fromPeerId, offerData) {
            const pc = new RTCPeerConnection(this.rtcConfig);
            this.activeCalls.set(fromPeerId, pc);

            pc.ontrack = (event) => {
                const remoteStream = event.streams[0];
                const video = document.createElement('video');
                video.srcObject = remoteStream;
                video.autoplay = true;
                video.id = `remote-${fromPeerId}`;
                document.body.appendChild(video);
            };

            const stream = await this.getLocalStream();
            stream.getTracks().forEach(track => pc.addTrack(track, stream));

            await pc.setRemoteDescription(new RTCSessionDescription(offerData.sdp));

            const answer = await pc.createAnswer();
            await pc.setLocalDescription(answer);

            this.signaling.sendMessage(fromPeerId, {
                type: "answer",
                sdp: answer,
                callId: offerData.callId
            });

            return pc;
        }

        encryptStream(sender) {
            if (!sender.createEncodedStreams) return;
            const streams = sender.createEncodedStreams();
            const transformer = new TransformStream({
                async transform(chunk, controller) {
                    controller.enqueue(chunk);
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
    }

    return GhostWebRTC;
}));
