# Ghost Shield — Red-Team Regression Checklist

A runnable checklist an intern (or CI) can execute against a build to catch
privacy regressions. Each item has **steps**, **expected result**, and a
**pass/fail** criterion. The guiding rule from [THREAT_MODEL.md](./THREAT_MODEL.md):
a build **passes** when it leaks **no more** than the threat model documents —
finding a documented-undefended leak (e.g. a physical-layer sniff) is **not** a
failure; finding an **undocumented** leak, or a defended property not holding, is.

> Tooling note: items 1, 3, 5 need a second device / radio / app and are manual.
> Items 2 and 4 are scriptable and should run in CI. The unit suite
> (`npx vitest run --config vitest.shield.config.ts`) already covers the logic;
> this checklist validates the **built app on a real device**.

---

## 1. BLE advertisement: ID rotates AND interval/length vary

**Threat:** overlay correlation on a stable BLE advertisement (THREAT_MODEL #2),
and the honest limit that a physical sniffer still wins (#3).

**Steps**
1. Build and run the app; set Ghost Shield to **PHANTOM** on an Android device.
2. With a second device run a BLE scanner (e.g. `nRF Connect`, or
   `hcitool lescan --duplicates` / `btmon`), capturing for ≥ 5 minutes.
3. Record, per advertisement: the Kryptos overlay id in the payload, the
   advertising interval (time between adv events), and the payload length.

**Expected result**
- The advertised **overlay id changes** every 30–90 s (10–20 s at FULL_GHOST).
- Across rotations, the **advertising interval** takes more than one value (from
  the OS-default set ~100/250/1000 ms) and the **payload length** varies.
- The **hardware MAC** (and any radio-layer fingerprint) is *unchanged* — this is
  expected and documented.

**Pass/fail**
- **PASS:** overlay id rotates *and* interval/length vary across the capture.
- **PASS (documented):** the device remains physically linkable by MAC/PHY — note
  it; this is THREAT_MODEL #3, not a regression.
- **FAIL:** overlay id is static, or interval+length are constant across rotations
  (we are fingerprintable as "the Kryptos app" even though the id changed).
- **iOS note:** interval/length are OS-fixed; the module reports `degraded` with
  `ble_advertising_params_fixed_platform`. Confirm that report is surfaced — a
  *silent* failure to vary on iOS is a FAIL; an honest `degraded` is a PASS.

---

## 2. Decoy/cover classifier: can an attacker separate decoy vs real?

**Threat:** a decompiled-app attacker tries to statistically distinguish decoy/
cover traffic from real traffic (THREAT_MODEL #4, #7). The algorithm is public,
so separation must be ≈ chance.

**Steps**
1. At **FULL_GHOST**, capture all outbound frames with their send timestamps and
   on-wire sizes for ≥ 10 minutes (instrument the mesh adapter in a debug build,
   or sniff the transport).
2. Label frames real vs cover/decoy using the debug build's ground-truth tag
   (debug only — never ship the tag).
3. Run the bundled analysis (or the equivalent of the unit test
   `hardening.test.ts › single-threshold classifier`): for the **timing** channel
   and the **size** channel, find the best single-threshold classifier accuracy;
   also compute a 2-sample KS statistic between real and synthetic.

**Expected result**
- Best-threshold classifier accuracy is near 0.5 for both timing and size.
- Cover/decoy inter-arrivals are **not constant** (no fixed metronome) and their
  distribution overlaps the real one.

**Pass/fail**
- **PASS:** best-threshold accuracy < 0.65 on both channels; KS statistic small
  (distributions overlap).
- **FAIL:** any classifier ≥ 0.65, OR cover traffic shows a fixed/periodic
  inter-arrival, OR decoy sizes cluster at a value real traffic never uses.

---

## 3. Metadata capture: destination/relay IPs + SNI match the documented leak

**Threat:** relay/TURN metadata (THREAT_MODEL #5) and SNI exposure without ECH
(DnsGuard). The build must leak **no more** than documented.

**Steps**
1. Put the device behind a capture point (Wireshark on the AP, or a proxy you
   control). Set Ghost Shield to **GHOST** or higher (DoH on).
2. Exercise messaging and a voice call.
3. In the capture, enumerate: plaintext DNS queries (should be none), DoH
   connections, TLS `ClientHello` SNI values, and destination/relay IPs.

**Expected result**
- **No plaintext DNS** leaves the device (see item 4).
- DNS resolution rides DoH.
- **SNI is visible** for outbound TLS *unless* ECH is active — and the DnsGuard
  status shows `sni_leak_no_ech` when it is not. The set of destination/relay IPs
  matches what THREAT_MODEL #5 says the relay sees.

**Pass/fail**
- **PASS:** observed leakage = documented leakage (SNI + relay IP/timing, no
  plaintext DNS), and the SNI-leak state matches the `sni_leak_no_ech` report.
- **FAIL:** plaintext DNS observed; OR a destination/identifier leaks that the
  threat model does **not** list; OR status claims no SNI leak while SNI is on the
  wire.

---

## 4. DNS fail-closed: block the DoH resolver, confirm no plaintext escapes

**Threat:** silent fallback to plaintext DNS when DoH is unreachable (DnsGuard
fail-closed contract).

**Steps**
1. Set Ghost Shield to **STEALTH** or higher.
2. Make the DoH resolver unreachable: block its IP/hostname at the AP/firewall,
   or point the build at an unroutable resolver.
3. Trigger name resolutions (open chats, attempt a call) while capturing all
   traffic at the AP.

**Expected result**
- **Zero** plaintext DNS (UDP/TCP 53, DoT 853) leaves the device.
- DnsGuard status is `active: true, degraded: true, reason: doh_unreachable_failclosed`.
- Name resolution **fails** (expected — fail-closed trades connectivity for privacy).

**Pass/fail**
- **PASS:** no port-53/853 plaintext egress; status shows the fail-closed reason.
- **FAIL:** any plaintext DNS observed, OR the app silently resolved via the
  system resolver (fallback), OR status reports clean while DoH is down.

---

## 5. Co-resident: a notification listener / screen scraper reads nothing sensitive

**Threat:** a co-resident, non-rooted app observing via notifications, clipboard,
accessibility, or screen capture (THREAT_MODEL #6).

**Steps**
1. Install a dummy second app that (a) registers a `NotificationListenerService`
   (Android) and logs all notifications, (b) registers an accessibility service,
   (c) polls the clipboard every second.
2. In Kryptos: receive messages, copy a seed word / address / key, and start a
   screen recording (or cast) while a sensitive screen is open.
3. Inspect the dummy app's logs and start/raise Ghost Shield to **STEALTH+**.

**Expected result**
- Notifications contain **no** message content, keys, addresses, or peer ids
  (generic text only).
- The copied sensitive value is **cleared from the clipboard** within the
  configured window (default 30 s) after a guarded copy.
- When screen recording / an accessibility service is active, CoResidentGuard
  reports `degraded` (`screen_capture_active` / `accessibility_service_active`)
  and emits a `degraded` event (and auto-raises the tier if so configured).

**Pass/fail**
- **PASS:** no sensitive data in notifications; clipboard cleared within the
  window; capture/accessibility detected and surfaced as `degraded`.
- **PASS (documented):** detection is best-effort and may miss on some OS
  versions — a missed detection that is reported as
  `ondevice_detection_unsupported` is acceptable; a *silently* missed detection
  on a platform that claims support is a FAIL.
- **FAIL:** any sensitive value in a notification; clipboard not cleared; or an
  active capture/accessibility service that the guard claims support for but does
  not surface.

---

## Sign-off

| # | Check | Result | Notes |
|---|-------|--------|-------|
| 1 | BLE id rotates + interval/length vary | ☐ PASS ☐ FAIL | |
| 2 | Decoy/cover classifier ≈ chance | ☐ PASS ☐ FAIL | |
| 3 | Metadata leak = documented only | ☐ PASS ☐ FAIL | |
| 4 | DNS fail-closed, no plaintext | ☐ PASS ☐ FAIL | |
| 5 | Co-resident reads nothing sensitive | ☐ PASS ☐ FAIL | |

Build: ____________  Device/OS: ____________  Tester: ____________  Date: ____________
