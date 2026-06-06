# GhostNet 1:1 Encrypted Voice Calls (Phase 1)

Identity-authenticated 1:1 audio calls between two GhostTag identities, built
**entirely on existing GhostNet infrastructure** — no new server, no new socket.

| Concern | Reused component |
| --- | --- |
| Signaling transport | `GhostMesh` (`ghostnet-mesh.js`) — `sendToPeer()` / `onMessage` |
| ICE servers | `GhostNATManager` (`ghostnet-nat.js`) — STUN consensus + TURN relay |
| Identity | GhostTag key (**secp256k1**, the same key used for node auth) |
| Media | WebRTC `RTCPeerConnection` (browser + Expo WebView) |

## Files

| File | Role |
| --- | --- |
| `ghostnet-call-signaling.js` | Typed message schema + fail-closed validators (`call.offer/answer/ice/hangup`). Pure. |
| `ghostnet-call-fingerprint.js` | DTLS fingerprint extraction + identity-bound sign/verify (DI core, live secp256k1 impl). Pure. |
| `ghostnet-call.js` | `GhostCall` — state machine, mesh signaling, media, Opus/DTX shaping. |
| `tests/call-signaling.test.js` | Schema unit tests. |
| `tests/call-fingerprint.test.js` | Fingerprint sign/verify tests (tamper = fail closed). |

All three modules are classic UMD scripts: loaded via `<script>` in `index.html`
(after `ghostnet-nat.js`, before `app.js`) in the browser, and importable under
Node for tests.

## Call flow

```
Caller (A)                         mesh (E2EE, identity-auth)            Callee (B)
──────────                         ─────────────────────────            ──────────
startCall(@bob)
  resolveTag(@bob) → {routeId, pubKey_B}
  getUserMedia(audio)
  createOffer → munge Opus(DTX,bitrate) → setLocalDescription
  extract DTLS fingerprint → sign with A's key
  ── call.offer {sdp, fp:sign_A(fp)} ─────────────────────────────────▶ _onOffer
                                                                          resolve A's pubKey (independent)
                                                                          verifyProof(fp, pubKey_A)  ← BEFORE applying SDP
                                                                          ✗ mismatch → hangup(fingerprint)
                                                                          ✓ → emit 'incoming' → ring
                                                                        acceptCall()
                                                                          setRemoteDescription(offer)
                                                                          getUserMedia(audio)
                                                                          createAnswer → munge Opus → setLocalDescription
                                                                          extract fingerprint → sign with B's key
  _onAnswer ◀──────────────────── call.answer {sdp, fp:sign_B(fp)} ──────
  verifyProof(fp, pubKey_B)  ← BEFORE applying SDP
  ✗ mismatch → endCall (error)
  ✓ → setRemoteDescription(answer)
  ◀───────────── call.ice (trickle, both directions) ─────────────▶
  ICE connected → emit 'connected' (state: active)
  ── call.hangup {reason} ── (either side) ──▶  emit 'ended'
```

## Privacy by mathematics — identity-bound DTLS fingerprint

WebRTC already encrypts media with DTLS-SRTP; the DTLS handshake is authenticated
by the certificate **fingerprint** carried in the SDP. The only attack surface is
SDP *delivery* — a malicious relay could swap an SDP+fingerprint to MITM the media
keys. We close that:

1. The sender extracts its local DTLS fingerprint from `localDescription`.
2. It signs a canonical, length-prefixed message binding
   `domain | kind | callId | from | to | fingerprint` with its **GhostTag identity
   key**, and includes the signature in the signed signaling message.
3. The receiver **independently resolves** the peer's identity key (from the
   GhostTag — *not* from the proof) and verifies, **before** `setRemoteDescription`:
   - the proof's fingerprint equals the fingerprint in the SDP, and
   - the signature verifies against the resolved identity key.

Any mismatch **fails closed**: the call is aborted with a `fingerprint` hangup and
an `error` event. The signaling relay can read/route messages but cannot forge a
fingerprint binding, so it cannot insert itself into the media path.

> The live signer/verifier is **secp256k1** (the app's GhostTag key, via `ethers`
> personal-sign + address recovery — interoperable across ethers v5/v6). The crypto
> is dependency-injected, so an Ed25519 implementation can be dropped in behind the
> same `signer` / `verifier` interface without touching call logic.

## State machine

```
        startCall / incoming offer
 idle ───────────────────────────▶ ringing
                                      │ accept (callee) / answer recv (caller)
                                      ▼
                                  connecting ──ICE connected──▶ active
   ▲                                  │                           │
   └──────────── ended ◀──────────────┴───── hangup / timeout / error / endCall ─┘
```

- **Ring timeout:** an unanswered call auto-hangs-up (`timeout`) after
  `ringTimeoutMs` (default 30s).
- **Hangup** is honored from either side; `endCall()` notifies the peer and tears
  down media + the peer connection.

## API

```js
const call = new GhostCall({
  mesh,                       // GhostMesh instance
  nat,                        // GhostNATManager (optional; for iceServers)
  identity: {                 // local GhostTag identity
    id: myRouteId,            // GhostTag/nodeId peers route to
    publicKey,                // secp256k1 public key
    privateKey,               // secp256k1 private key (used to sign fingerprints)
  },
  // optional injections:
  resolveGhostTag,            // async (tag) => { routeId, publicKey }
  resolveIdentityKey,         // async (peerId, msg) => publicKey | null (verify incoming)
  getIceServers,              // async () => RTCIceServer[]
  ringTimeoutMs, maxAverageBitrate,
});

call.on('incoming',  ({ callId, from }) => { /* show accept/reject UI */ });
call.on('ringing',   ({ callId, peer }) => { /* outgoing ringing */ });
call.on('connected', ({ remoteStream }) => { /* attach to <audio> */ });
call.on('ended',     ({ reason }) => { /* reason: normal|rejected|busy|timeout|cancelled|fingerprint|error */ });
call.on('error',     ({ code, message }) => { /* code: resolve|fingerprint|mic-permission|webrtc|transport|peer-unresolved */ });

await call.startCall('@bob');   // place a call
await call.acceptCall();        // accept the ringing call
call.rejectCall();              // decline
call.endCall();                 // hang up
```

Defaults (`resolveGhostTag` / `resolveIdentityKey`) use `window.GhostTag`. For
**incoming** calls the identity key is resolved independently and the call is
rejected if it can't be resolved (fail closed) — inject a stronger node-registry
lookup via `resolveIdentityKey` in production.

## Media

- **Codec:** Opus (WebRTC default for audio).
- **DTX:** enabled (`usedtx=1`) — silence suppression to save mobile data.
- **Bitrate:** capped via SDP `maxaveragebitrate` and `RTCRtpSender.setParameters`
  (`maxBitrate`), default **24 kbps** average — tune via `maxAverageBitrate`.
- In-band FEC (`useinbandfec=1`) is enabled for loss resilience.

## TURN relay (Cloudflare Realtime)

TURN is the **relay fallback** for when direct P2P (host/STUN/hole-punching)
fails — not a replacement. Credentials are **minted server-side** so the
Cloudflare API token never touches the client.

- **Server:** `POST /turn/credentials` (auth required) calls Cloudflare's
  Realtime TURN API with `CLOUDFLARE_TURN_KEY_ID` + `CLOUDFLARE_TURN_API_TOKEN`
  (env only) and returns `{ iceServers, ttl }` — a short-lived (1h) username +
  credential. The token/key ID are never sent to the client or logged.
- **Client:** `ghostnet-call-ice.js` →
  `GhostCallIce.createCloudflareIceProvider({ stunServers })` returns a
  `getIceServers()` that fetches **fresh creds per call** (at PC creation, on both
  `startCall` and `acceptCall`), keeps your STUN/hole-punching servers first, and
  appends the TURN entry (udp + tcp + tls).
- **Fail closed:** if the credential fetch fails, `getIceServers()` throws,
  `GhostCall` emits `error` with `code: 'ice'` and **aborts** — a call never starts
  with no relay.

Wire it via the existing `getIceServers` hook (no call-logic change):

```js
const call = new GhostCall({
  mesh, identity,
  getIceServers: GhostCallIce.createCloudflareIceProvider({
    stunServers, // your NAT STUN consensus (defaults to public STUN)
  }),
});
```

Env (see `.env.example`):

```
CLOUDFLARE_TURN_KEY_ID=...
CLOUDFLARE_TURN_API_TOKEN=...
```

## ⚠️ Follow-up: microphone permission in the Expo WebView

`RTCPeerConnection` works inside the Android System WebView, **but `getUserMedia`
(mic) needs native permission plumbing that is NOT implemented in Phase 1**:

- **Android:** add `RECORD_AUDIO` to the manifest and handle
  `WebChromeClient.onPermissionRequest` to grant `RESOURCE_AUDIO_CAPTURE` to the
  WebView (the Expo wrapper passes WebView permission requests through).
- **iOS:** add `NSMicrophoneUsageDescription` to `Info.plist`.

Until that is wired, `getUserMedia` throws and `GhostCall` surfaces a clear
`error` with `code: 'mic-permission'` (it does **not** fail silently). Wiring the
native side is the next task.

## Extension points (intentionally NOT built in Phase 1)

- **Group calls / SFU** — `GhostCall` manages a single 1:1 session by design. A
  multi-party layer would hold a map of peer connections + a media router.
- **Insertable streams** (per-frame E2EE on top of DTLS) — omitted; the security
  guarantee here is the identity-bound DTLS fingerprint.
- **Native `react-native-webrtc`** — inject `RTCPeerConnection` / `getUserMedia`
  via the constructor to swap the media engine without changing call logic.

## Tests

```bash
node --test tests/call-signaling.test.js tests/call-fingerprint.test.js
```

Covers the signaling schema (accept valid / reject malformed, fail closed) and
fingerprint sign/verify — every tamper case (swapped fingerprint, wrong key,
malformed signature, kind/replay mismatch) must verify to `false`.
