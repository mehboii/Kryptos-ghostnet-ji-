# Proximity Connect (offline BLE) — GhostNet

Two nearby phones discover each other over Bluetooth LE with **no server**, mutually
authenticate with their GhostNet identity keys, and derive an encrypted session.
Discovery is **mutual and concurrent** — each phone advertises *and* scans at the
same time — and works cross‑platform (iOS ↔ Android).

> Requires a **dev/EAS build** (custom native code). It does **not** run in Expo Go
> or in a desktop browser.

---

## Why this needed native code (and what was broken before)

The GhostNet mobile app is a thin Expo **WebView shell** ([App.js](App.js) loads
`offline-web/index.html`); the UI/logic lives in the web bundle built from the
`antigravity/` root JS files. The previous BLE code could never work in that
runtime:

- `proximity-connect.js` imported `@capacitor-community/bluetooth-le` — a **Capacitor**
  plugin. This is not a Capacitor app, so the import threw and discovery silently
  failed. It also only ever **scanned** (never advertised), so two phones could
  never see each other.
- `ghostnet-mesh.js` BLE used the **Web Bluetooth API** (`navigator.bluetooth`),
  which does **not exist** inside `react-native-webview`.

So BLE now runs **natively in React Native** and is bridged into the WebView.

```
WebView (web bundle)                          React Native (native)
─────────────────────                         ─────────────────────────────
proximity-connect.js  ──window.GhostNetBLE──▶  App.js bridge ──▶ ProximityBLE
 (state machine,        (RPC over postMessage)                     │
  identity auth,        ◀── injectJavaScript ──                    ├─ central:  react-native-ble-plx
  session crypto)            (events/acks)                         └─ peripheral: ghostnet-ble-peripheral
ghostnet-mesh.js                                                       (advertise + GATT server, native)
 (neighbor registry)
```

## Pieces

| File | Role |
|---|---|
| [src/ble/uuids.js](src/ble/uuids.js) | Rendezvous Service UUID + characteristic UUIDs (single source of truth, matches the web mesh) |
| [src/ble/pseudonym.js](src/ble/pseudonym.js) | Rotating ephemeral pseudonym (HMAC, 15‑min window) — reference impl |
| [src/ble/ProximityBLE.js](src/ble/ProximityBLE.js) | Native transport: ble‑plx central (scan/connect/MTU/GATT client) + peripheral module, concurrent |
| [src/ble/bridgeShim.js](src/ble/bridgeShim.js) | `window.GhostNetBLE` injected into the WebView |
| [App.js](App.js) | WebView ↔ native RPC bridge, permission handling |
| [modules/ghostnet-ble-peripheral/](modules/ghostnet-ble-peripheral/) | Local Expo module: **advertise + GATT server** (Android Kotlin, iOS Swift) — the half ble‑plx can't do |
| [plugins/withGhostnetBle.js](plugins/withGhostnetBle.js) | Config plugin: Android perms (`neverForLocation`) + iOS plist + background modes |
| `../proximity-connect.js` | State machine, mutual identity auth, session — **rewired** to the native bridge |
| `../ghostnet-mesh.js` | `registerProximityPeer()` added so an authenticated peer becomes a mesh neighbor |

## The flow / state machine

```
IDLE → ADVERTISING+SCANNING → PEER_FOUND → CONNECTING → AUTHENTICATING → SESSION_READY → MESH_REGISTERED
                                  ↑________________ (errors/timeouts return to scanning) _________________|
```

1. **Beacon + scan concurrently.** Advertise the rendezvous Service UUID + a rotating
   pseudonym (Android service data; iOS strips it — by design); scan for the same
   UUID, dedupe, sort by RSSI, expose a live nearby list.
2. **Connect** (central) on tap; negotiate MTU up (~185 iOS / 247 Android).
3. **Authenticate — mutual.** Ephemeral **ECDH (P‑256)** → shared key, then a
   challenge–response where **each side signs a fresh random nonce with its
   long‑term GhostNet identity key (secp256k1/ethers)** and verifies the peer's
   signature against the peer's identity public key. The signed transcript is
   **bound to both ephemeral public keys**, so a MITM that swaps its own ECDH keys
   cannot forge a victim's signature. Fail closed on any mismatch/timeout.
4. **Session.** HKDF → **AES‑256‑GCM**; all further data encrypted. A 6‑digit
   verification code (from the shared secret) is shown for optional human compare.
5. **Mesh.** The authenticated peer is registered with `GhostMesh` as a BLE neighbor
   (`registerProximityPeer`), carrying an encrypted `send()` closure.

## Security / privacy properties

- **Rotating pseudonym** `HMAC(pseudonymSecret, floor(now/15min))[0..4)` — unlinkable
  across windows, not reversible to the identity. The secret is derived from the
  identity private key (or a random per‑session value if locked). **No stable
  identifier (GhostTag, public key, node id) is ever advertised.**
- **Identity is revealed only after** the mutual authenticated handshake.
- **MITM/impersonation** is rejected by the nonce signature bound to the ECDH
  ephemerals (verified in tests T3).
- Uses existing primitives (ethers secp256k1, Web Crypto P‑256 ECDH, AES‑256‑GCM).
  No keys/secrets are logged.

---

## Build & run

```bash
cd ghostnet-expo
npm install                      # adds react-native-ble-plx + buffer
npm run build:offline-web        # inline the web bundle (proximity-connect.js etc.)
npx expo prebuild --clean        # regenerates android/ + ios/ with BLE config plugin
# Home dir is a git repo → EAS needs EAS_NO_VCS=1 (already in eas.json env)
eas build --profile development --platform android
eas build --profile development --platform ios
```

> The committed `android/` predates this feature — **regenerate it** with
> `expo prebuild --clean` so the BLE permissions/manifest from the config plugin
> are applied. There is no `ios/` yet; prebuild creates it.

Run the logic tests (no device needed):

```bash
node tests/proximity-connect.test.mjs   # 9 checks: fragmentation, ECDH, AES-GCM, MITM rejection
```

## Two‑device test (definition of done)

1. Install the dev build on **two physical phones** (ideally one iOS, one Android),
   sign into GhostNet on each (unlock identity — signing needs the private key).
2. Open Proximity Connect on **both**. Within a few seconds **A appears in B's
   nearby list and B appears in A's**, simultaneously.
3. Tap a peer on one phone → it connects, runs the Ed25519‑style (here secp256k1)
   challenge–response, and reaches **SESSION_READY**; the 6‑digit codes match.
4. Send a message → it round‑trips encrypted over the session.
5. The peer appears in the mesh neighbor list (`window.app.mesh.getPeers()`).
6. Wait >15 min (or watch logs) → the advertised pseudonym value rotates.
7. Negative paths degrade gracefully (no crash): deny the Bluetooth permission;
   turn Bluetooth off; run on a device whose radio can't advertise
   (`isPeripheralSupported()===false` → **scan‑only**, with a surfaced notice).

### Device‑support caveats
- **Android advertising** requires `isMultipleAdvertisementSupported()` — some older
  radios return false; that device becomes scan‑only and can still *connect to*
  advertisers, but cannot *be discovered*. For mutual discovery the **other** phone
  must be advertise‑capable.
- **iOS** advertises only the Service UUID (CoreBluetooth strips service data and the
  local name, especially in background). The rotating pseudonym is therefore a no‑op
  on iOS advertisements — fine, since identity is exchanged only post‑GATT.
- **Background** both‑roles BLE (esp. iOS↔iOS) is OS‑throttled. This targets
  **foreground**. Android may add a foreground service later for persistence.

---

## Assumptions made & APIs expected‑but‑not‑found

These are the deviations from the original task wording, forced by what actually
exists in the repo:

1. **No Ed25519 / X25519 anywhere.** The spec asked for them, but the real GhostNet
   identity is **secp256k1** (ethers wallet, `crypto-identity.js`); `src/security/`
   has a *separate, unused* **P‑256** ECDSA util; the proximity handshake uses
   **P‑256 ECDH**. **Decision (confirmed with maintainer):** the identity proof signs
   with the actual secp256k1 identity; ephemeral key agreement stays P‑256 ECDH.
   If true Ed25519 identity is desired, that's a separate identity‑system change.
2. **WebView architecture, not native‑RN UI.** The app is a WebView shell, so BLE is
   native + bridged into the existing web UI (confirmed approach), rather than a new
   native screen. `window.GhostNetBLE` is the bridge contract.
3. **No GATT‑server / advertiser library exists for RN that fits** → wrote the local
   Expo module `ghostnet-ble-peripheral`. `react-native-ble-advertiser` was **not**
   added because the module already needs native code for the GATT server, so it does
   advertising too (one fewer dependency).
4. **`GhostMesh` had no public "add peer" method** — peers were only added internally
   by the (dead) Web‑Bluetooth path. Added `registerProximityPeer()` as the minimal
   surface the bridge needs.
5. **BLE fragmentation was missing.** Handshake frames exceed a single BLE
   notification (MTU‑3); added chunk/reassembly to the DATA channel (tested T1).
6. **`src/security/tofu.js` (native TOFU registry) is not wired to the web layer.**
   It's RN‑side P‑256 and the web identity is secp256k1, so trust‑on‑first‑use here
   is delegated to `GhostMesh`. Bridging native TOFU is possible future work.

## Cannot be verified in this environment
EAS builds and the **two‑physical‑phone** checks above require real hardware and a
build pipeline. The native Kotlin/Swift in `ghostnet-ble-peripheral` is written to
the Expo Modules API but has **not been compiled on‑device here** — compile it in the
first dev build and watch `onError`/`onStateChange` events. The pure‑JS security
logic *is* verified by `tests/proximity-connect.test.mjs`.
