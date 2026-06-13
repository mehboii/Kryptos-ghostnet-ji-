# GhostNet / Ghost Shield — Threat Model

**Audience:** practitioners deciding whether to rely on Ghost Shield, and the
engineers maintaining it. **Tone:** underclaim, never overclaim. The people who
use this are journalists and activists; telling them they are hidden when they
are not is the actual harm. Every row below says plainly what we do *not* defend.

**Scope of this document:** the privacy properties of **Ghost Shield**, the
cumulative cloaking controller in `src/shield/` (tiers `OFF → STEALTH → GHOST →
PHANTOM`, with the `FULL_GHOST` preset). It does not cover the GhostNet
end-to-end crypto itself, which is assumed sound and is reviewed separately.

## The one thing to internalize

Ghost Shield runs in an **unprivileged app sandbox** on iOS / non-rooted Android.
From there it controls GhostNet's **overlay**: the application-level identifiers,
frames, and advertisements an observer correlates on. It has **no access to the
layers beneath it** — it cannot change the hardware WiFi/BLE MAC, cannot silence
the OS radio's own probe requests, cannot see or rewrite the IP path, and cannot
police other apps or the OS on the device.

So the honest mental model is: **Ghost Shield raises the cost of *overlay* and
*network-content* correlation. It does nothing against an adversary operating at
the physical radio layer next to you, or one who already controls the device or
the network's metadata.**

- **"Node ID rotation"** = rotating the overlay identifier GhostNet advertises.
  It is **not** MAC randomization. A sniffer that correlates on the hardware MAC
  is unaffected.
- **"Probe / beacon suppression"** = stopping GhostNet's *own* BLE
  advertising/discovery. It is **not** suppression of the OS radio's 802.11 probe
  requests, which we cannot touch.
- **"DoH"** = GhostNet's DNS goes over HTTPS. It does **not** hide the TLS SNI of
  the connections that follow (unless ECH is available — see below), and it does
  not change DNS for other apps.

## Honesty matrix

| # | Threat | In scope? | Ghost Shield mitigation | Residual risk | Platform-gated? |
|---|--------|-----------|-------------------------|---------------|-----------------|
| 1 | **Passive on-path content interception** (Wi-Fi/ISP/relay reads message bytes) | ✅ Yes | **DEFENDED.** E2EE (outside Shield) + TrafficShaper length-padding to fixed buckets `{256,512,1024,4096}`, so content and true length are not on the wire. | Bucket *class* is observable (small vs large); volume over time is observable unless cover traffic is on. | No — pure overlay, works on both OSes. |
| 2 | **Casual overlay correlation on the node ID** (observer links sessions by the advertised GhostNet id) | ✅ Yes | **DEFENDED (overlay only).** NodeIdRotator rotates the advertised overlay id (30–90 s; 10–20 s at FULL_GHOST) with session-safe handoff, and randomizes advertising interval + payload length so we don't fingerprint as "the GhostNet app." | An adversary correlating on a **lower layer** (MAC, radio fingerprint) is unaffected — see #3. | Partial — interval/length randomization needs Android advertise-mode control; iOS cannot set it (degrades, reported). |
| 3 | **Co-located physical-layer BLE/Wi-Fi sniffer** (attacker with a radio in the room) | ⚠️ Acknowledged, **not defended** | **NONE.** We cannot change the hardware MAC or suppress OS-level probe requests from an unprivileged app. Overlay rotation does not help against MAC/PHY correlation. | **Full physical-layer linkability.** A co-located sniffer can track the device regardless of Ghost Shield. | Yes — hard OS/hardware limit on both platforms. |
| 4 | **Traffic correlation by a global passive adversary** (sees timing/volume across the whole path) | ⚠️ Partial | **PARTIAL.** TrafficShaper adds per-frame jitter and **statistically-modeled** cover traffic (Poisson-distributed, not a fixed metronome), always-on at FULL_GHOST, ramped in/out so the *transition* isn't a signature. | A true global passive adversary with long observation can still perform end-to-end timing/volume correlation. Cover raises cost; it is not a guarantee. | No — overlay, both OSes. But only meaningful at GHOST+ (cover) / FULL_GHOST (always-on). |
| 5 | **Relay / TURN metadata observation** (the relay sees who talks to whom, and when) | ⚠️ Acknowledged, **not defended** | **NONE (trust assumption).** Voice/relayed paths transit a TURN/relay. That relay observes source/destination IPs and timing. Ghost Shield does not onion-route. | The relay operator (or anyone observing it) learns metadata: your IP, peer/relay IP, timing, volume. **Treat the relay as semi-trusted.** | No — architectural. Documented, not mitigated. |
| 6 | **Co-resident malicious app on the same device** (non-rooted) | ⚠️ Partial | **PARTIAL.** CoResidentGuard detects active screen capture / MediaProjection and accessibility-service usage, clears the clipboard after sensitive copy, and keeps sensitive data out of notifications; on detection it emits `degraded` and can warn / auto-raise tier. | A non-rooted co-resident app cannot read our memory, but screen-capture/accessibility detection is best-effort and racy; a *rooted* device or OS-level compromise defeats it entirely. | Yes — detection coverage differs by OS (iOS `isCaptured` vs Android MediaProjection/AccessibilityManager). |
| 7 | **Behavioral / intersection deanonymization over time** (who is online when, set intersection across sessions) | ⚠️ Partial | **PARTIAL (FULL_GHOST).** Always-on cover traffic + aggressive id rotation + maxed decoys at FULL_GHOST flatten the online/active signal that intersection attacks feed on. | At lower tiers, presence and activity timing leak. Even at FULL_GHOST, long-horizon intersection with auxiliary data is not fully defeated. | No — overlay; effective only at FULL_GHOST. |

**Legend:** ✅ defended · ⚠️ partial or acknowledged-undefended.

## Per-threat notes

### 1 — Content interception (DEFENDED)
Padding is an outer, length-prefixed envelope around the already-encrypted
ciphertext; it never touches plaintext and is exactly reversible. An observer
learns only the bucket a frame fell into. **Caveat:** without cover traffic
(GHOST+), the *number and timing* of real frames still leak.

### 2 — Overlay node-ID correlation (DEFENDED, overlay only)
Rotation carries active sessions across the change via an authenticated old→new
handoff before the old id is retired, so connectivity is preserved. As of the
hardening pass, each rotation **also** re-randomizes the BLE advertising interval
(within OS-default ranges) and the advertised payload length, so the *cadence
and shape* of our advertisement don't become the fingerprint that rotation was
meant to remove. **This is overlay only — see #3.**

### 3 — Co-located physical sniffer (NOT DEFENDED)
This is the most important honesty statement in this document. An unprivileged
app **cannot** randomize the hardware MAC or stop the OS from emitting 802.11
probe requests. A person with a BLE/Wi-Fi sniffer in the same room can correlate
your device at the physical layer no matter what tier you select. Ghost Shield
does not claim otherwise, and the UI must not imply otherwise.

### 4 — Global passive traffic correlation (PARTIAL)
Cover traffic is drawn from a statistical model (Poisson inter-arrivals seeded
from the observed real-traffic distribution), not a fixed interval — a fixed
rate would itself be a fingerprint. It is always-on at FULL_GHOST and ramps in
and out on tier changes so that *turning Shield on/off* is not a step-change an
observer can timestamp. This raises the cost of correlation; it is not immunity.

### 5 — Relay/TURN metadata (NOT DEFENDED — trust assumption)
GhostNet relays some traffic (e.g. voice) through a TURN server. That relay, and
anyone who can observe it, sees connection metadata (IPs, timing, volume) even
though content is encrypted. We do **not** onion-route or mix. Users who must
hide *that they are communicating at all* from a network observer need Tor/a
mixnet in addition to GhostNet. Documented as a trust assumption, not solved.

### 6 — Co-resident app (PARTIAL — see CoResidentGuard)
On a non-rooted device, other apps cannot read GhostNet's memory or key material.
The realistic on-device risks are **observation**: screen recording, an abusive
accessibility service scraping the screen, clipboard snooping, and sensitive data
leaking into notification text. CoResidentGuard addresses these best-effort and
reports honestly when detection is unsupported. A rooted/compromised device or a
malicious OS is out of scope and undefendable from the sandbox.

### 7 — Intersection/behavioral attacks (PARTIAL — FULL_GHOST)
Presence and activity timing are the raw material for intersection attacks.
FULL_GHOST's always-on cover and aggressive rotation blur this; lower tiers do
not. We do not claim resistance to a determined long-horizon correlation with
external data.

## Non-goals (explicitly out of scope)
- Hardware MAC randomization or OS probe-request suppression (impossible unprivileged).
- Anonymity against the relay/TURN operator (no onion routing / mixing).
- Defense on a rooted or OS-compromised device.
- Defeating a co-located physical-layer radio sniffer.
- Hiding *that GhostNet is installed/running* from a co-resident app or the OS.

## Operational guidance for high-risk users
- For "hide that I am communicating at all" from a network/relay observer: use
  GhostNet **over** Tor or a trusted VPN; Ghost Shield alone does not provide this.
- Assume a co-located adversary with radio hardware can track the device; physical
  separation/airplane-mode is the only mitigation, and it is outside the app.
- FULL_GHOST is the only tier that addresses long-term traffic/intersection
  analysis, and it costs battery and bandwidth. Lower tiers are not equivalent.
