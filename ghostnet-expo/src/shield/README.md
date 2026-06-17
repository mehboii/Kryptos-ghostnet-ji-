# Ghost Shield

A cumulative privacy controller for GhostNet. One state machine, four cloaking
tiers, each a strict superset of the one below:

```
OFF ⊂ STEALTH ⊂ GHOST ⊂ PHANTOM ⊂ FULL_GHOST
```

`FULL_GHOST` is `PHANTOM` with every knob pinned to maximum and cover traffic
always-on — the preset `panic()` jumps to.

## Why this design

Ghost Shield touches BLE, DNS, the mesh transport, timers, and storage. Rather
than reach into those directly, every platform effect goes through a small
**adapter interface** (`types.ts` → `ShieldPorts`). The host app injects real
implementations; tests inject in-memory fakes (`testing.ts`). That is what makes
two things possible at once:

1. **Honest capability reporting.** We probe the adapter to learn what the device
   can actually do, and each module reports `{ requested, active, degraded, reason }`.
2. **Off-device unit testing.** All timing, jitter, rotation, and rollback logic
   runs deterministically under a fake clock and seeded RNG.

```ts
import { ShieldManager, ShieldTier } from './shield';

const shield = new ShieldManager(ports);   // ports = your platform wiring
await shield.restore();                     // re-apply last tier on launch
await shield.setTier(ShieldTier.GHOST);
shield.on('degraded', ({ reports }) => showPartialCloakBanner(reports));
// global panic gesture:
await shield.panic();                       // → FULL_GHOST
```

See [`example.ts`](./example.ts) for a full wiring walkthrough.

## Tier → behavior

| Tier         | Adds on top of the tier below                                                                 |
|--------------|------------------------------------------------------------------------------------------------|
| `OFF`        | nothing                                                                                        |
| `STEALTH`    | silence GhostNet's own BLE advertising + discovery beacon; force DoH (fail-closed); watch on-device observation (CoResidentGuard) |
| `GHOST`      | length-pad mesh frames to `{256,512,1024,4096}`; 20–250 ms send jitter; adaptive cover traffic |
| `PHANTOM`    | 2–4 decoy peers; rotate advertised node id every 30–90 s; force min mesh hop count             |
| `FULL_GHOST` | cover traffic always-on; rotation aggressive (10–20 s); decoys maxed                            |

The mapping lives in exactly one place — [`config.ts`](./config.ts)
(`resolveConfig` / `modulesForTier`) — so the cumulative guarantee can't drift.

## The honesty matrix — real vs platform-gated

> **This is a mobile app on unprivileged iOS / non-rooted Android.** It cannot
> change the hardware WiFi/BLE MAC and cannot suppress the OS radio's own probe
> requests. Everything below operates on GhostNet's **overlay** identity — the
> advertisement/node id an observer correlates on — never the hardware. Anything
> a platform can't deliver is run as its achievable subset and reported with
> `degraded: true` + a reason code; nothing silently no-ops and claims success.

| Behavior | What it really does | iOS | Android | Degrades to |
|---|---|---|---|---|
| **BleCloak** — stop advertising | Stops GhostNet's *own* BLE advertising | ⚠️ Partial — background advertising is OS-controlled and CoreBluetooth strips service data; foreground stop works | ✅ Real when the BLE peripheral module is present | Stops the app-level discovery beacon only; `ble_advertising_control_unsupported` |
| **BleCloak** — probe suppression | Stops GhostNet's *own* discovery beaconing | ✅ Real | ✅ Real | — |
| ~~Hardware MAC rotation~~ | **Not attempted.** Unprivileged apps cannot change the radio MAC. "Rotation" here = overlay node id (see NodeIdRotator). | ❌ Impossible | ❌ Impossible | n/a — never claimed |
| **MacRandomizer** | Flips the OS MAC-randomization **policy** to NON-PERSISTENT on the Wi-Fi networks **GhostNet itself suggests** (fresh randomized MAC per rejoin). A policy flip on *our* networks — **not** app-driven MAC rotation, and it cannot touch the user's home/office/café Wi-Fi. | ❌ No app API — OS-managed Private Wi-Fi Address (`unavailable`) | ✅ Real on **Android 12+** via `WifiNetworkSuggestion.setMacRandomizationSetting`; ⚠️ Android < 31 registers with OS-default randomization only | `mac_randomization_unavailable_no_suggestion_api` (iOS/web); `mac_randomization_requires_android_12` (API < 31) |
| ~~OS WiFi probe suppression~~ | **Not attempted.** The OS radio's probe requests are outside app control. | ❌ Impossible | ❌ Impossible | n/a — never claimed |
| **DnsGuard** — DoH | Routes DNS through an app-controlled DoH resolver, **fail-closed** | ⚠️ App-scoped only (system resolver for other apps is untouched) | ⚠️ App-scoped only | If unreachable: blocks plaintext, `doh_unreachable_failclosed`. If unsupported: `doh_unsupported_on_platform` |
| **TrafficShaper** — padding | Pads ciphertext to fixed buckets (outer envelope; E2EE untouched) | ✅ Real | ✅ Real | — (pure overlay) |
| **TrafficShaper** — jitter | Order-preserving random send delay | ✅ Real | ✅ Real | — |
| **TrafficShaper** — cover traffic | Indistinguishable dummy frames, ramped in/out | ✅ Real | ✅ Real | — |
| **MeshRouting** — min hops | Forces a minimum *mesh overlay* hop count (not the IP path) | ⚠️ Mesh-only | ⚠️ Mesh-only | `mesh_hop_control_unsupported` if the mesh build lacks hop control |
| **DecoyEngine** | Injects plausible, unlinkable fake peer announcements (no payload, never the real id) | ✅ Real | ✅ Real | — |
| **NodeIdRotator** | Rotates the advertised **overlay** node id with session-safe handoff; re-randomizes advertising interval + payload length per rotation | ⚠️ Overlay id only — **not** the MAC; interval/length fixed by CoreBluetooth | ⚠️ Overlay id only — **not** the MAC; interval/length vary via advertise modes | `node_id_rotation_unsupported`; or `ble_advertising_params_fixed_platform` (iOS) |
| **DnsGuard** — ECH/SNI | Detects ECH availability; flags that TLS SNI still leaks the destination host without it | ⚠️ Surfaced, not fixed | ⚠️ Surfaced, not fixed | `sni_leak_no_ech` when DoH works but ECH is unavailable |
| **CoResidentGuard** | Detects screen capture / accessibility scraping; clears clipboard after sensitive copy | ⚠️ `UIScreen.isCaptured` (no a11y enumeration) | ⚠️ MediaProjection + AccessibilityManager | `screen_capture_active` / `accessibility_service_active` / `ondevice_detection_unsupported` |

Legend: ✅ real · ⚠️ real but scoped/partial (and reported honestly) · ❌ impossible on the platform (never attempted).

For the full threat model and red-team regression checklist see
[`../../docs/THREAT_MODEL.md`](../../docs/THREAT_MODEL.md) and
[`../../docs/REDTEAM_CHECKLIST.md`](../../docs/REDTEAM_CHECKLIST.md).

## Guarantees the code enforces

- **Atomic transitions.** A tier change enables the modules it needs and disables
  the rest. If any module's `enable()` *throws* (a hard failure), the whole
  transition rolls back to the last stable tier and emits `degraded` with
  `rolledBack: true`. A module reporting `degraded` (achievable subset) is a
  success, not a rollback.
- **E2EE integrity.** Padding wraps the already-encrypted ciphertext in a
  length-prefixed outer envelope; `unpadFrame` is the exact inverse of
  `padFrame`. The Shield never sees plaintext.
- **Message ordering.** Jitter delays a frame by a random amount but clamps each
  scheduled time to be ≥ the previous one, so a later frame can never overtake an
  earlier one.
- **Session-safe rotation.** On each node-id rotation, peers receive an
  authenticated old→new handoff over the existing encrypted channel *before* the
  old id is retired (after an 8 s grace window), so no active session drops.
- **No-leak.** No telemetry/logs record the real node id, peer ids, or a tier
  *history*. Logging is opt-in, local-only, and redacts identifier-shaped values.
  The persisted tier is a single overwritten key, not an append-only timeline.
- **No on/off signature.** Cover traffic ramps in and out over several steps
  rather than toggling hard, so enabling/disabling Shield is not itself a
  distinct, observable traffic event. (`panic()` intentionally trades this
  smoothness for immediacy.)
- **Statistically-modeled cover/decoys.** The decoy/cover algorithm is assumed
  PUBLIC. Cover and decoy traffic draw their inter-arrival and size from a shared
  model of the *observed real* traffic (`traffic-model.ts`) — never a fixed
  cadence — so a single-threshold classifier on timing or size is ≈ chance.
- **On-device honesty.** CoResidentGuard's detectors are best-effort on an
  unprivileged app; where a platform offers no detection it reports
  `ondevice_detection_unsupported` rather than implying safety. It defends
  against *observation* (capture/scrape/clipboard), not a rooted device.

## Layout

```
src/shield/
  types.ts          enums, config, reports, ShieldModule + adapter ports
  config.ts         single-source tier → behavior + module mapping
  capabilities.ts   runtime platform probe + reason codes
  logger.ts         opt-in, local-only, redacting logger
  ShieldManager.ts  the state machine (transitions, rollback, panic, persist, events)
  traffic-model.ts  observed inter-arrival + size distribution (shared by shaper/decoy)
  modules/          BleCloak · DnsGuard · TrafficShaper · MeshRouting · DecoyEngine · NodeIdRotator · CoResidentGuard · MacRandomizer
  testing.ts        in-memory fakes (fake clock, seeded RNG, fake adapters)
  example.ts        runnable wiring walkthrough
  index.ts          public barrel
  __tests__/        Vitest suites
```

## Develop

```bash
# typecheck (scoped to the module)
npx tsc -p src/shield/tsconfig.json --noEmit
# unit tests
npx vitest run --config vitest.shield.config.ts
```

> Deployment is manual — Ghost Shield ships no deploy step of its own.
