/* Ghost Shield — GENERATED from ghostnet-expo/src/shield (real ShieldManager).
 * DO NOT EDIT BY HAND. Rebuild: cd ghostnet-expo && npm run build:shield-web
 * Capability-honest: web reports BLE/hardware unavailable; the phone (Capacitor)
 * runs hardware features for real. No MAC rotation, no WiFi-probe suppression. */
"use strict";
(() => {
  // src/shield/types.ts
  var TIER_RANK = {
    ["OFF" /* OFF */]: 0,
    ["STEALTH" /* STEALTH */]: 1,
    ["GHOST" /* GHOST */]: 2,
    ["PHANTOM" /* PHANTOM */]: 3,
    ["FULL_GHOST" /* FULL_GHOST */]: 4
  };

  // src/shield/config.ts
  var PADDING_BUCKETS = [256, 512, 1024, 4096];
  var DEFAULT_DOH_RESOLVER = "https://cloudflare-dns.com/dns-query";
  function resolveConfig(tier, options = {}) {
    const dohResolver = options.dohResolver ?? DEFAULT_DOH_RESOLVER;
    const rank = TIER_RANK[tier];
    const atLeast = (t) => rank >= TIER_RANK[t];
    const isFull = tier === "FULL_GHOST" /* FULL_GHOST */;
    return {
      tier,
      // STEALTH+ : silence our own BLE advertising + discovery beaconing.
      ble: {
        silenceAdvertising: atLeast("STEALTH" /* STEALTH */),
        silenceDiscoveryBeacon: atLeast("STEALTH" /* STEALTH */)
      },
      // STEALTH+ : force DoH, fail-closed.
      dns: {
        mode: atLeast("STEALTH" /* STEALTH */) ? "doh" : "system",
        dohResolver,
        failClosed: atLeast("STEALTH" /* STEALTH */)
      },
      // GHOST+ : length-pad + timing jitter. Cover traffic adaptive at GHOST/PHANTOM,
      // always-on at FULL_GHOST.
      traffic: {
        enabled: atLeast("GHOST" /* GHOST */),
        paddingBuckets: PADDING_BUCKETS,
        jitterMinMs: atLeast("GHOST" /* GHOST */) ? 20 : 0,
        jitterMaxMs: atLeast("GHOST" /* GHOST */) ? 250 : 0,
        coverTraffic: !atLeast("GHOST" /* GHOST */) ? "off" : isFull ? "always" : "adaptive",
        coverRatePerMin: isFull ? 60 : atLeast("GHOST" /* GHOST */) ? 20 : 0
      },
      // PHANTOM+ : force maximum mesh relay hop count.
      mesh: {
        enforceMinHops: atLeast("PHANTOM" /* PHANTOM */),
        minHops: atLeast("PHANTOM" /* PHANTOM */) ? 4 : 0
      },
      // PHANTOM+ : decoy peer announcements (2–4; max at FULL_GHOST).
      decoy: {
        enabled: atLeast("PHANTOM" /* PHANTOM */),
        minDecoys: atLeast("PHANTOM" /* PHANTOM */) ? isFull ? 4 : 2 : 0,
        maxDecoys: atLeast("PHANTOM" /* PHANTOM */) ? 4 : 0
      },
      // PHANTOM+ : rotate the advertised ephemeral node id (30–90s; aggressive
      // 10–20s at FULL_GHOST). 8s handoff grace keeps active sessions alive.
      // Each rotation also re-randomizes BLE advertising interval + payload length.
      nodeIdRotation: {
        enabled: atLeast("PHANTOM" /* PHANTOM */),
        minIntervalMs: atLeast("PHANTOM" /* PHANTOM */) ? isFull ? 1e4 : 3e4 : 0,
        maxIntervalMs: atLeast("PHANTOM" /* PHANTOM */) ? isFull ? 2e4 : 9e4 : 0,
        handoffGraceMs: 8e3,
        randomizeAdvertising: atLeast("PHANTOM" /* PHANTOM */)
      },
      // STEALTH+ : watch for on-device observation (screen capture, a11y, clipboard).
      coResident: {
        enabled: atLeast("STEALTH" /* STEALTH */),
        clipboardClearMs: 3e4
      },
      // STEALTH+ : check device integrity (root/jailbreak/hook/emulator) + attest.
      // Re-attest more aggressively at higher tiers.
      integrity: {
        enabled: atLeast("STEALTH" /* STEALTH */),
        reattestIntervalMs: atLeast("STEALTH" /* STEALTH */) ? isFull ? 5 * 6e4 : 15 * 6e4 : 0
      }
    };
  }
  function modulesForTier(tier) {
    const cfg = resolveConfig(tier);
    const ids = /* @__PURE__ */ new Set();
    if (cfg.ble.silenceAdvertising || cfg.ble.silenceDiscoveryBeacon) ids.add("ble-cloak" /* BleCloak */);
    if (cfg.dns.mode === "doh") ids.add("dns-guard" /* DnsGuard */);
    if (cfg.traffic.enabled) ids.add("traffic-shaper" /* TrafficShaper */);
    if (cfg.mesh.enforceMinHops) ids.add("mesh-routing" /* MeshRouting */);
    if (cfg.decoy.enabled) ids.add("decoy-engine" /* DecoyEngine */);
    if (cfg.nodeIdRotation.enabled) ids.add("node-id-rotator" /* NodeIdRotator */);
    if (cfg.coResident.enabled) ids.add("co-resident-guard" /* CoResidentGuard */);
    if (cfg.integrity.enabled) ids.add("device-integrity" /* DeviceIntegrity */);
    return ids;
  }

  // src/shield/capabilities.ts
  var REASON = {
    /** No BLE stack at all (plain web build, or native plugin failed to resolve).
     *  The host turns this into a platform-aware message, e.g.
     *  "BLE unavailable — web test context (no native plugin)". */
    BLE_UNAVAILABLE: "ble_unavailable_no_local_stack",
    BLE_ADV_UNSUPPORTED: "ble_advertising_control_unsupported",
    BLE_ADV_PARAMS_FIXED: "ble_advertising_params_fixed_platform",
    DOH_UNSUPPORTED: "doh_unsupported_on_platform",
    DOH_UNREACHABLE_FAILCLOSED: "doh_unreachable_failclosed",
    SNI_LEAK_NO_ECH: "sni_leak_no_ech",
    HOP_CONTROL_UNSUPPORTED: "mesh_hop_control_unsupported",
    NODE_ID_ROTATION_UNSUPPORTED: "node_id_rotation_unsupported",
    NO_ACTIVE_SESSIONS: "no_active_sessions_to_hand_off",
    SCREEN_CAPTURE_ACTIVE: "screen_capture_active",
    ACCESSIBILITY_SERVICE_ACTIVE: "accessibility_service_active",
    ONDEVICE_DETECTION_UNSUPPORTED: "ondevice_detection_unsupported",
    DEVICE_COMPROMISED: "device_compromised",
    DEVICE_SUSPECT: "device_suspect",
    INTEGRITY_UNKNOWN: "integrity_unknown"
  };

  // src/shield/modules/BleCloak.ts
  var BleCloak = class {
    constructor(ports) {
      this.ports = ports;
      this.id = "ble-cloak" /* BleCloak */;
      this.last = { id: this.id, requested: false, active: false, degraded: false };
    }
    async enable(cfg) {
      const requested = cfg.ble.silenceAdvertising || cfg.ble.silenceDiscoveryBeacon;
      if (!requested) {
        await this.disable();
        return this.last;
      }
      if (!this.ports.ble.isAvailable()) {
        this.last = {
          id: this.id,
          requested: true,
          active: false,
          degraded: true,
          reason: REASON.BLE_UNAVAILABLE
        };
        this.ports.log.warn("ble_cloak_unavailable", { reason: REASON.BLE_UNAVAILABLE });
        return this.last;
      }
      if (!this.ports.ble.supportsAdvertisingControl()) {
        await this.ports.ble.setDiscoveryBeaconEnabled(false);
        this.last = {
          id: this.id,
          requested: true,
          active: true,
          degraded: true,
          reason: REASON.BLE_ADV_UNSUPPORTED
        };
        this.ports.log.warn("ble_cloak_degraded", { reason: REASON.BLE_ADV_UNSUPPORTED });
        return this.last;
      }
      if (cfg.ble.silenceAdvertising) await this.ports.ble.stopAdvertising();
      if (cfg.ble.silenceDiscoveryBeacon) await this.ports.ble.setDiscoveryBeaconEnabled(false);
      this.last = { id: this.id, requested: true, active: true, degraded: false };
      this.ports.log.debug("ble_cloak_on");
      return this.last;
    }
    async disable() {
      if (this.ports.ble.isAvailable()) {
        if (this.ports.ble.supportsAdvertisingControl()) {
          await this.ports.ble.startAdvertising();
        }
        await this.ports.ble.setDiscoveryBeaconEnabled(true);
      }
      this.last = { id: this.id, requested: false, active: false, degraded: false };
    }
    report() {
      return this.last;
    }
  };

  // src/shield/modules/CoResidentGuard.ts
  function isRuntimeDetector(mod) {
    return typeof mod.setNotifier === "function";
  }
  var CoResidentGuard = class {
    constructor(ports) {
      this.ports = ports;
      this.id = "co-resident-guard" /* CoResidentGuard */;
      this.last = { id: this.id, requested: false, active: false, degraded: false };
      this.cfg = null;
      this.unsubscribeCapture = null;
      this.notify = null;
      this.clipboardTimer = null;
    }
    setNotifier(notify) {
      this.notify = notify;
    }
    async enable(cfg) {
      if (!cfg.coResident.enabled) {
        await this.disable();
        return this.last;
      }
      this.cfg = cfg;
      const screenCap = this.ports.coResident.supportsScreenCaptureDetection();
      const a11y = this.ports.coResident.supportsAccessibilityDetection();
      if (screenCap && this.unsubscribeCapture === null) {
        this.unsubscribeCapture = this.ports.coResident.subscribeScreenCapture((captured) => {
          this.evaluate(captured, true);
        });
      }
      if (!screenCap && !a11y) {
        this.last = {
          id: this.id,
          requested: true,
          active: false,
          degraded: true,
          reason: REASON.ONDEVICE_DETECTION_UNSUPPORTED
        };
        this.ports.log.warn("coresident_unsupported", { reason: REASON.ONDEVICE_DETECTION_UNSUPPORTED });
        return this.last;
      }
      this.evaluate(void 0, false);
      return this.last;
    }
    async disable() {
      if (this.unsubscribeCapture) {
        this.unsubscribeCapture();
        this.unsubscribeCapture = null;
      }
      if (this.clipboardTimer) {
        this.ports.clock.clearTimeout(this.clipboardTimer);
        this.clipboardTimer = null;
      }
      this.cfg = null;
      this.last = { id: this.id, requested: false, active: false, degraded: false };
    }
    report() {
      return this.last;
    }
    /**
     * Call after copying sensitive data (a key, seed word, address) to the system
     * clipboard. The clipboard is cleared after `clipboardClearMs` so a co-resident
     * clipboard-snooper has only a short window. Idempotent: re-arming resets the timer.
     */
    protectClipboard() {
      const cfg = this.cfg;
      if (!cfg) return;
      if (this.clipboardTimer) this.ports.clock.clearTimeout(this.clipboardTimer);
      this.clipboardTimer = this.ports.clock.setTimeout(() => {
        this.clipboardTimer = null;
        void this.ports.coResident.clearClipboard();
      }, cfg.coResident.clipboardClearMs);
    }
    /** Re-read detection state and update the report; optionally notify on a threat. */
    evaluate(capturedHint, notifyOnThreat) {
      const captured = this.ports.coResident.supportsScreenCaptureDetection() && (capturedHint ?? this.ports.coResident.isScreenCaptured());
      const a11y = this.ports.coResident.supportsAccessibilityDetection() && this.ports.coResident.isAccessibilityServiceActive();
      if (captured || a11y) {
        const reason = captured ? REASON.SCREEN_CAPTURE_ACTIVE : REASON.ACCESSIBILITY_SERVICE_ACTIVE;
        this.last = { id: this.id, requested: true, active: true, degraded: true, reason };
        this.ports.log.warn("coresident_threat", { reason });
        if (notifyOnThreat) this.notify?.(this.last);
        return;
      }
      this.last = { id: this.id, requested: true, active: true, degraded: false };
    }
  };

  // src/shield/modules/DecoyEngine.ts
  var POOL_TTL_MS = 45e3;
  var DECOY_ID_BYTES = 16;
  var DECOY_FALLBACK_MEAN_MS = 4e3;
  var DecoyEngine = class {
    constructor(ports, model) {
      this.ports = ports;
      this.model = model;
      this.id = "decoy-engine" /* DecoyEngine */;
      this.last = { id: this.id, requested: false, active: false, degraded: false };
      this.cfg = null;
      this.poolTimer = null;
      this.emitTimer = null;
      this.pool = [];
    }
    async enable(cfg) {
      if (!cfg.decoy.enabled) {
        await this.disable();
        return this.last;
      }
      this.cfg = cfg;
      this.refreshPool();
      if (this.poolTimer === null) {
        this.poolTimer = this.ports.clock.setInterval(() => this.refreshPool(), POOL_TTL_MS);
      }
      this.scheduleEmit();
      this.last = { id: this.id, requested: true, active: true, degraded: false };
      return this.last;
    }
    async disable() {
      if (this.poolTimer) {
        this.ports.clock.clearInterval(this.poolTimer);
        this.poolTimer = null;
      }
      if (this.emitTimer) {
        this.ports.clock.clearTimeout(this.emitTimer);
        this.emitTimer = null;
      }
      this.pool = [];
      this.cfg = null;
      this.last = { id: this.id, requested: false, active: false, degraded: false };
    }
    report() {
      return this.last;
    }
    /** Current decoy identity pool (for tests). */
    get decoyIds() {
      return this.pool;
    }
    /** Build a fresh pool of 2–4 (tier-dependent) decoy identities. */
    refreshPool() {
      const cfg = this.cfg;
      if (!cfg) return;
      const realId = this.ports.mesh.getCurrentNodeId();
      const size = this.ports.random.int(cfg.decoy.minDecoys, cfg.decoy.maxDecoys);
      const next = [];
      for (let i = 0; i < size; i++) {
        const id = bytesToHex(this.ports.random.bytes(DECOY_ID_BYTES));
        if (id !== realId) next.push(id);
      }
      this.pool = next;
      this.ports.log.debug("decoy_pool_refreshed", { size: next.length });
    }
    /** Schedule the next decoy announcement at a model-sampled inter-arrival. */
    scheduleEmit() {
      if (this.emitTimer !== null) return;
      const gapMs = this.model.sampleGapMs(DECOY_FALLBACK_MEAN_MS);
      const tick = () => {
        this.emitTimer = null;
        if (!this.cfg) return;
        void this.emitDecoy();
        this.scheduleEmit();
      };
      this.emitTimer = this.ports.clock.setTimeout(tick, gapMs);
    }
    /** Emit one announcement for a random pooled decoy, sized from the model. */
    async emitDecoy() {
      if (!this.cfg || this.pool.length === 0) return;
      const realId = this.ports.mesh.getCurrentNodeId();
      const ephemeralId = this.pool[this.ports.random.int(0, this.pool.length - 1)];
      if (ephemeralId === realId) return;
      const announcement = {
        ephemeralId,
        // Size drawn from the observed real size distribution; random content.
        payload: this.ports.random.bytes(this.model.sampleSizeBytes())
      };
      await this.ports.mesh.announceDecoyPeer(announcement);
    }
  };
  function bytesToHex(bytes) {
    let s = "";
    for (const b of bytes) s += b.toString(16).padStart(2, "0");
    return s;
  }

  // src/shield/integrity/attestation.ts
  async function runAttestation(provider, backend, log) {
    if (!provider.isSupported()) {
      log?.debug("attest_unavailable", { reason: "provider_unsupported" });
      return "UNAVAILABLE";
    }
    try {
      const nonce = await backend.requestNonce();
      const token = await provider.getToken(nonce);
      const { verdict } = await backend.verify(token);
      log?.debug("attest_result", { verdict });
      return verdict === "PASS" ? "PASS" : "FAIL";
    } catch {
      log?.warn("attest_unavailable", { reason: "transport_or_provider_error" });
      return "UNAVAILABLE";
    }
  }

  // src/shield/integrity/localSignals.ts
  var SU_PATHS = [
    "/system/bin/su",
    "/system/xbin/su",
    "/sbin/su",
    "/system/su",
    "/system/bin/.ext/.su",
    "/data/local/xbin/su",
    "/data/local/bin/su"
  ];
  var MAGISK_PATHS = ["/sbin/.magisk", "/cache/.disable_magisk", "/init.magisk.rc"];
  var ROOT_PACKAGES = [
    "com.topjohnwu.magisk",
    "eu.chainfire.supersu",
    "com.koushikdutta.superuser",
    "com.noshufou.android.su"
  ];
  var XPOSED_PACKAGES = ["de.robv.android.xposed.installer", "org.lsposed.manager"];
  var ANDROID_SIGNALS = [
    {
      id: "android.su_binary",
      platform: "android",
      weight: 35,
      evaluate: (p) => SU_PATHS.some((path) => p.fileExists(path))
    },
    {
      id: "android.busybox",
      platform: "android",
      weight: 15,
      evaluate: (p) => p.fileExists("/system/xbin/busybox") || p.fileExists("/system/bin/busybox")
    },
    {
      id: "android.magisk_artifacts",
      platform: "android",
      weight: 30,
      evaluate: (p) => MAGISK_PATHS.some((path) => p.fileExists(path))
    },
    {
      id: "android.prop_debuggable",
      platform: "android",
      weight: 15,
      evaluate: (p) => p.getSystemProp("ro.debuggable") === "1"
    },
    {
      id: "android.prop_not_secure",
      platform: "android",
      weight: 15,
      evaluate: (p) => p.getSystemProp("ro.secure") === "0"
    },
    {
      id: "android.test_keys",
      platform: "android",
      weight: 20,
      evaluate: (p) => (p.getSystemProp("ro.build.tags") ?? "").includes("test-keys")
    },
    {
      id: "android.writable_system",
      platform: "android",
      weight: 30,
      evaluate: (p) => p.canWrite("/system") || p.canWrite("/system/bin")
    },
    {
      id: "android.root_package",
      platform: "android",
      weight: 30,
      evaluate: (p) => ROOT_PACKAGES.some((pkg) => p.packageInstalled(pkg))
    },
    {
      id: "android.frida_port",
      platform: "android",
      weight: 30,
      evaluate: (p) => p.isPortOpen(27042) || p.isPortOpen(27043)
    },
    {
      id: "android.frida_lib",
      platform: "android",
      weight: 25,
      evaluate: (p) => p.loadedLibraries().some((l) => /frida|gadget|gum-js/i.test(l))
    },
    {
      id: "android.xposed",
      platform: "android",
      weight: 25,
      evaluate: (p) => p.loadedLibraries().some((l) => /xposed/i.test(l)) || XPOSED_PACKAGES.some((pkg) => p.packageInstalled(pkg))
    },
    {
      id: "android.emulator",
      platform: "android",
      weight: 20,
      evaluate: (p) => /generic|sdk_gphone|emulator|goldfish|ranchu|vbox|genymotion/i.test(p.buildFingerprint())
    }
  ];
  var JB_PATHS = [
    "/Applications/Cydia.app",
    "/Applications/Sileo.app",
    "/usr/sbin/sshd",
    "/bin/bash",
    "/bin/sh",
    "/etc/apt",
    "/private/var/lib/apt",
    "/private/var/lib/cydia",
    "/usr/libexec/cydia"
  ];
  var IOS_SIGNALS = [
    {
      id: "ios.jailbreak_paths",
      platform: "ios",
      weight: 35,
      evaluate: (p) => JB_PATHS.some((path) => p.fileExists(path))
    },
    {
      id: "ios.url_scheme",
      platform: "ios",
      weight: 25,
      evaluate: (p) => p.canOpenUrlScheme("cydia") || p.canOpenUrlScheme("sileo") || p.canOpenUrlScheme("zbra")
    },
    {
      id: "ios.write_outside_sandbox",
      platform: "ios",
      weight: 35,
      evaluate: (p) => p.canWrite("/private/jb_probe.txt") || p.canWrite("/private/var/mobile/jb.txt")
    },
    {
      id: "ios.inserted_dylibs",
      platform: "ios",
      weight: 30,
      evaluate: (p) => p.loadedLibraries().some((l) => /MobileSubstrate|substrate|SubstrateLoader|libhooker|TweakInject|frida/i.test(l))
    },
    {
      id: "ios.fork_succeeds",
      platform: "ios",
      weight: 25,
      evaluate: (p) => p.forkSucceeds()
    },
    {
      id: "ios.emulator",
      platform: "ios",
      weight: 15,
      evaluate: (p) => /simulator|x86_64|i386/i.test(p.buildFingerprint())
    }
  ];
  var ALL_SIGNALS = [...ANDROID_SIGNALS, ...IOS_SIGNALS];
  function signalsForPlatform(platform) {
    return ALL_SIGNALS.filter((s) => s.platform === platform || s.platform === "any");
  }
  function evaluateLocalSignals(probe) {
    const platform = probe.platform();
    const fired = [];
    let score = 0;
    for (const sig of signalsForPlatform(platform)) {
      let hit = false;
      try {
        hit = sig.evaluate(probe);
      } catch {
        hit = false;
      }
      if (hit) {
        fired.push(sig.id);
        score += sig.weight;
      }
    }
    return { score: Math.min(100, score), firedSignalIds: fired };
  }

  // src/shield/modules/DeviceIntegrity.ts
  var DEFAULT_LOCAL_RISK_THRESHOLD = 40;
  var INTEGRITY_REASON = {
    COMPROMISED: "device_compromised",
    SUSPECT: "device_suspect",
    UNKNOWN: "integrity_unknown"
  };
  var DEFAULT_INTEGRITY_POLICY = {
    TRUSTED: { blockSensitiveOps: false, allowRelay: true, raiseToTier: null, warn: false },
    // attestation passed but local tamper indicators are high: allow read/degraded,
    // block sensitive writes, don't relay others' traffic, raise tier + warn.
    SUSPECT: { blockSensitiveOps: true, allowRelay: false, raiseToTier: "PHANTOM" /* PHANTOM */, warn: true },
    // confirmed bad: block sensitive ops, never relay, force max cloak, warn.
    COMPROMISED: { blockSensitiveOps: true, allowRelay: false, raiseToTier: "FULL_GHOST" /* FULL_GHOST */, warn: true },
    // couldn't verify: allow the local user's own ops but flag it; never relay
    // others' traffic and never silently treat as trusted.
    UNKNOWN: { blockSensitiveOps: false, allowRelay: false, raiseToTier: null, warn: true }
  };
  function isIntegrityModule(mod) {
    return typeof mod.setIntegrityNotifier === "function";
  }
  var DeviceIntegrity = class {
    constructor(ports, options = {}) {
      this.ports = ports;
      this.id = "device-integrity" /* DeviceIntegrity */;
      this.last = { id: this.id, requested: false, active: false, degraded: false };
      this.cfg = null;
      this.state = null;
      this.timer = null;
      this.notify = null;
      this.policy = options.policy ?? DEFAULT_INTEGRITY_POLICY;
      this.threshold = options.localRiskThreshold ?? DEFAULT_LOCAL_RISK_THRESHOLD;
    }
    setIntegrityNotifier(notify) {
      this.notify = notify;
    }
    async enable(cfg) {
      if (!cfg.integrity.enabled) {
        await this.disable();
        return this.last;
      }
      this.cfg = cfg;
      if (this.timer === null && cfg.integrity.reattestIntervalMs > 0) {
        this.timer = this.ports.clock.setInterval(() => {
          void this.recheck();
        }, cfg.integrity.reattestIntervalMs);
      }
      await this.recheck();
      return this.last;
    }
    async disable() {
      if (this.timer) {
        this.ports.clock.clearInterval(this.timer);
        this.timer = null;
      }
      this.cfg = null;
      this.last = { id: this.id, requested: false, active: false, degraded: false };
    }
    report() {
      return this.last;
    }
    /** Latest integrity state, or null if no check has run. */
    getState() {
      return this.state;
    }
    /** Policy response for the current verdict (UNKNOWN-safe default before first check). */
    getResponse() {
      return this.policy[this.state?.verdict ?? "UNKNOWN"];
    }
    /** Convenience guards for the app to consult before acting. */
    canPerformSensitiveOp() {
      return !this.getResponse().blockSensitiveOps;
    }
    canRelayForOthers() {
      return this.getResponse().allowRelay;
    }
    /**
     * Re-run local heuristics + backend attestation, update state, and notify on a
     * verdict change. Call this on app foreground, before a sensitive op, and on
     * the periodic timer.
     */
    async recheck() {
      const { probe, provider, backend } = this.ports.integrity;
      const local = evaluateLocalSignals(probe);
      const attestation = await runAttestation(provider, backend, this.ports.log);
      const verdict = computeVerdict(local.score, attestation, this.threshold);
      const next = {
        verdict,
        localRiskScore: local.score,
        attestation,
        firedSignalIds: local.firedSignalIds,
        checkedAtMs: this.ports.clock.now()
      };
      const changed = this.state === null || this.state.verdict !== verdict;
      this.state = next;
      this.updateReport(next);
      this.ports.log.debug("integrity_checked", {
        verdict,
        score: local.score,
        attestation,
        signals: local.firedSignalIds.length
      });
      if (changed) this.notify?.({ state: next, response: this.policy[verdict] });
      return next;
    }
    updateReport(state) {
      if (state.verdict === "TRUSTED") {
        this.last = { id: this.id, requested: true, active: true, degraded: false };
        return;
      }
      const reason = state.verdict === "COMPROMISED" ? INTEGRITY_REASON.COMPROMISED : state.verdict === "SUSPECT" ? INTEGRITY_REASON.SUSPECT : INTEGRITY_REASON.UNKNOWN;
      this.last = { id: this.id, requested: true, active: true, degraded: true, reason };
    }
  };
  function computeVerdict(localRiskScore, attestation, threshold) {
    if (attestation === "FAIL") return "COMPROMISED";
    if (attestation === "UNAVAILABLE") return "UNKNOWN";
    return localRiskScore >= threshold ? "SUSPECT" : "TRUSTED";
  }

  // src/shield/modules/DnsGuard.ts
  var DnsGuard = class {
    constructor(ports) {
      this.ports = ports;
      this.id = "dns-guard" /* DnsGuard */;
      this.last = { id: this.id, requested: false, active: false, degraded: false };
    }
    async enable(cfg) {
      if (cfg.dns.mode !== "doh") {
        await this.disable();
        return this.last;
      }
      if (!this.ports.dns.supportsDoh()) {
        this.last = {
          id: this.id,
          requested: true,
          active: false,
          degraded: true,
          reason: REASON.DOH_UNSUPPORTED
        };
        this.ports.log.warn("dns_doh_unsupported", { reason: REASON.DOH_UNSUPPORTED });
        return this.last;
      }
      await this.ports.dns.setMode("doh", cfg.dns.dohResolver);
      const reachable = await this.ports.dns.probe(cfg.dns.dohResolver);
      if (!reachable && cfg.dns.failClosed) {
        await this.ports.dns.setPlaintextBlocked(true);
        this.last = {
          id: this.id,
          requested: true,
          // Active: it IS enforcing privacy (blocking the plaintext leak). It just
          // cannot resolve names right now — that is the fail-closed bargain.
          active: true,
          degraded: true,
          reason: REASON.DOH_UNREACHABLE_FAILCLOSED
        };
        this.ports.log.warn("dns_failclosed", { reason: REASON.DOH_UNREACHABLE_FAILCLOSED });
        return this.last;
      }
      await this.ports.dns.setPlaintextBlocked(false);
      if (!this.ports.dns.supportsEch()) {
        this.last = {
          id: this.id,
          requested: true,
          active: true,
          degraded: true,
          reason: REASON.SNI_LEAK_NO_ECH
        };
        this.ports.log.warn("dns_sni_leak", { reason: REASON.SNI_LEAK_NO_ECH });
        return this.last;
      }
      this.last = { id: this.id, requested: true, active: true, degraded: false };
      this.ports.log.debug("dns_doh_on");
      return this.last;
    }
    async disable() {
      await this.ports.dns.setPlaintextBlocked(false);
      await this.ports.dns.setMode("system", "");
      this.last = { id: this.id, requested: false, active: false, degraded: false };
    }
    report() {
      return this.last;
    }
  };

  // src/shield/modules/MeshRouting.ts
  var MeshRouting = class {
    constructor(ports) {
      this.ports = ports;
      this.id = "mesh-routing" /* MeshRouting */;
      this.last = { id: this.id, requested: false, active: false, degraded: false };
    }
    async enable(cfg) {
      if (!cfg.mesh.enforceMinHops) {
        await this.disable();
        return this.last;
      }
      if (!this.ports.mesh.supportsHopControl()) {
        this.last = {
          id: this.id,
          requested: true,
          active: false,
          degraded: true,
          reason: REASON.HOP_CONTROL_UNSUPPORTED
        };
        this.ports.log.warn("mesh_hops_unsupported", { reason: REASON.HOP_CONTROL_UNSUPPORTED });
        return this.last;
      }
      await this.ports.mesh.setMinHops(cfg.mesh.minHops);
      this.last = { id: this.id, requested: true, active: true, degraded: false };
      this.ports.log.debug("mesh_hops_on", { minHops: cfg.mesh.minHops });
      return this.last;
    }
    async disable() {
      if (this.ports.mesh.supportsHopControl()) {
        await this.ports.mesh.setMinHops(0);
      }
      this.last = { id: this.id, requested: false, active: false, degraded: false };
    }
    report() {
      return this.last;
    }
  };

  // src/shield/modules/NodeIdRotator.ts
  var ROTATED_ID_BYTES = 16;
  var OS_DEFAULT_ADV_INTERVALS_MS = [100, 250, 1e3];
  var ADV_PAYLOAD_MIN = 8;
  var ADV_PAYLOAD_MAX = 31;
  var NodeIdRotator = class {
    constructor(ports) {
      this.ports = ports;
      this.id = "node-id-rotator" /* NodeIdRotator */;
      this.last = { id: this.id, requested: false, active: false, degraded: false };
      this.cfg = null;
      this.rotateTimer = null;
      this.graceTimers = /* @__PURE__ */ new Set();
    }
    async enable(cfg) {
      if (!cfg.nodeIdRotation.enabled) {
        await this.disable();
        return this.last;
      }
      if (!this.ports.mesh.supportsNodeIdRotation()) {
        this.last = {
          id: this.id,
          requested: true,
          active: false,
          degraded: true,
          reason: REASON.NODE_ID_ROTATION_UNSUPPORTED
        };
        this.ports.log.warn("rotate_unsupported", { reason: REASON.NODE_ID_ROTATION_UNSUPPORTED });
        return this.last;
      }
      this.cfg = cfg;
      this.scheduleNextRotation();
      const advParamsOk = !cfg.nodeIdRotation.randomizeAdvertising || this.ports.ble.supportsAdvertisingParams();
      this.last = advParamsOk ? { id: this.id, requested: true, active: true, degraded: false } : { id: this.id, requested: true, active: true, degraded: true, reason: REASON.BLE_ADV_PARAMS_FIXED };
      return this.last;
    }
    async disable() {
      if (this.rotateTimer) {
        this.ports.clock.clearTimeout(this.rotateTimer);
        this.rotateTimer = null;
      }
      for (const t of this.graceTimers) this.ports.clock.clearTimeout(t);
      this.graceTimers.clear();
      this.cfg = null;
      this.last = { id: this.id, requested: false, active: false, degraded: false };
    }
    report() {
      return this.last;
    }
    scheduleNextRotation() {
      const cfg = this.cfg;
      if (!cfg) return;
      const delay = this.ports.random.int(cfg.nodeIdRotation.minIntervalMs, cfg.nodeIdRotation.maxIntervalMs);
      this.rotateTimer = this.ports.clock.setTimeout(() => {
        void this.rotate().finally(() => this.scheduleNextRotation());
      }, delay);
    }
    /**
     * Perform one session-safe rotation. Exposed for testing. The ordering here is
     * the contract: peers are handed off BEFORE the old id is retired.
     */
    async rotate() {
      const cfg = this.cfg;
      if (!cfg) return;
      const oldId = this.ports.mesh.getCurrentNodeId();
      const newId = bytesToHex2(this.ports.random.bytes(ROTATED_ID_BYTES));
      if (newId === oldId) return;
      const peers = this.ports.mesh.getActiveSessions();
      for (const peer of peers) {
        await this.ports.mesh.sendNodeIdHandoff(peer, oldId, newId);
      }
      await this.ports.mesh.adoptNodeId(newId);
      if (cfg.nodeIdRotation.randomizeAdvertising && this.ports.ble.supportsAdvertisingParams()) {
        await this.ports.ble.setAdvertisingParameters(this.randomAdvertisingParams());
      }
      const graceTimer = this.ports.clock.setTimeout(() => {
        this.graceTimers.delete(graceTimer);
        void this.ports.mesh.retireNodeId(oldId);
      }, cfg.nodeIdRotation.handoffGraceMs);
      this.graceTimers.add(graceTimer);
      this.ports.log.debug("rotated", { peers: peers.length });
    }
    /** A fresh advertising interval (from OS-default values) + payload length. */
    randomAdvertisingParams() {
      const intervalMs = OS_DEFAULT_ADV_INTERVALS_MS[this.ports.random.int(0, OS_DEFAULT_ADV_INTERVALS_MS.length - 1)];
      const payloadLength = this.ports.random.int(ADV_PAYLOAD_MIN, ADV_PAYLOAD_MAX);
      return { intervalMs, payloadLength };
    }
  };
  function bytesToHex2(bytes) {
    let s = "";
    for (const b of bytes) s += b.toString(16).padStart(2, "0");
    return s;
  }

  // src/shield/modules/TrafficShaper.ts
  var LEN_HEADER_BYTES = 4;
  var COVER_RAMP_STEPS = 4;
  var COVER_RAMP_INTERVAL_MS = 4e3;
  function selectBucket(byteLength, buckets) {
    if (byteLength < 0) throw new RangeError("byteLength must be non-negative");
    const max = buckets[buckets.length - 1];
    for (const b of buckets) {
      if (byteLength <= b) return b;
    }
    return Math.ceil(byteLength / max) * max;
  }
  function padFrame(frame, buckets, random) {
    const payload = frame.bytes;
    const needed = LEN_HEADER_BYTES + payload.length;
    const bucket = selectBucket(needed, buckets);
    const out = new Uint8Array(bucket);
    out[0] = payload.length >>> 24 & 255;
    out[1] = payload.length >>> 16 & 255;
    out[2] = payload.length >>> 8 & 255;
    out[3] = payload.length & 255;
    out.set(payload, LEN_HEADER_BYTES);
    const padLen = bucket - needed;
    if (padLen > 0) out.set(random.bytes(padLen), needed);
    return { bytes: out, to: frame.to };
  }
  var TrafficShaper = class {
    /**
     * @param model shared statistical model of real traffic. Cover-traffic timing
     *   is drawn from it so cover is not a fixed-rate metronome (which would itself
     *   be a fingerprint). Real sends are fed back into it via {@link send}.
     */
    constructor(ports, model) {
      this.ports = ports;
      this.model = model;
      this.id = "traffic-shaper" /* TrafficShaper */;
      this.last = { id: this.id, requested: false, active: false, degraded: false };
      this.cfg = null;
      // Jitter scheduling: monotonic high-water mark guarantees ordering.
      this.lastScheduledAt = 0;
      this.pendingTimers = /* @__PURE__ */ new Set();
      // Cover-traffic ramp state.
      this.coverTargetRatePerMin = 0;
      this.coverCurrentRatePerMin = 0;
      /** Constant per-step delta so the rate reaches the target linearly (and so a
       *  ramp-DOWN actually lands on 0 rather than decaying geometrically). */
      this.coverRampStep = 1;
      this.coverRampTimer = null;
      this.coverEmitTimer = null;
    }
    get clock() {
      return this.ports.clock;
    }
    async enable(cfg) {
      if (!cfg.traffic.enabled) {
        await this.disable();
        return this.last;
      }
      this.cfg = cfg;
      this.ports.mesh.setOutboundTransform((frame) => padFrame(frame, cfg.traffic.paddingBuckets, this.ports.random));
      this.setCoverTarget(cfg.traffic.coverTraffic === "off" ? 0 : cfg.traffic.coverRatePerMin);
      this.last = { id: this.id, requested: true, active: true, degraded: false };
      this.ports.log.debug("traffic_on", {
        cover: cfg.traffic.coverTraffic,
        rate: cfg.traffic.coverRatePerMin
      });
      return this.last;
    }
    async disable() {
      this.setCoverTarget(0);
      this.ports.mesh.setOutboundTransform(null);
      this.cfg = null;
      this.last = { id: this.id, requested: false, active: false, degraded: false };
    }
    report() {
      return this.last;
    }
    /**
     * Send a real frame with order-preserving jitter. The frame is delayed by a
     * random amount in [jitterMin, jitterMax]; padding is applied by the installed
     * transform inside `mesh.sendRaw`. A later call can never be scheduled before
     * an earlier one because we clamp each scheduled time to be ≥ the previous.
     */
    send(frame) {
      const cfg = this.cfg;
      if (!cfg) {
        void this.ports.mesh.sendRaw(frame);
        return;
      }
      const now = this.clock.now();
      const jitter = this.ports.random.int(cfg.traffic.jitterMinMs, cfg.traffic.jitterMaxMs);
      const scheduledAt = Math.max(now + jitter, this.lastScheduledAt + 1);
      this.lastScheduledAt = scheduledAt;
      let handle;
      const fire = () => {
        this.pendingTimers.delete(handle);
        const padded = padFrame(frame, cfg.traffic.paddingBuckets, this.ports.random);
        this.model.observe(padded.bytes.length, this.clock.now());
        void this.ports.mesh.sendRaw(frame);
      };
      handle = this.clock.setTimeout(fire, scheduledAt - now);
      this.pendingTimers.add(handle);
    }
    /** Current ramped cover rate (frames/min). Exposed for status/testing. */
    get coverRatePerMin() {
      return this.coverCurrentRatePerMin;
    }
    setCoverTarget(targetRatePerMin) {
      this.coverTargetRatePerMin = targetRatePerMin;
      const span = Math.max(this.coverCurrentRatePerMin, targetRatePerMin);
      this.coverRampStep = Math.max(1, Math.ceil(span / COVER_RAMP_STEPS));
      if (this.coverRampTimer === null) {
        this.coverRampTimer = this.clock.setInterval(() => this.stepCoverRamp(), COVER_RAMP_INTERVAL_MS);
      }
      this.stepCoverRamp();
    }
    stepCoverRamp() {
      const target = this.coverTargetRatePerMin;
      const step = this.coverRampStep;
      if (this.coverCurrentRatePerMin < target) {
        this.coverCurrentRatePerMin = Math.min(target, this.coverCurrentRatePerMin + step);
      } else if (this.coverCurrentRatePerMin > target) {
        this.coverCurrentRatePerMin = Math.max(target, this.coverCurrentRatePerMin - step);
      }
      if (this.coverCurrentRatePerMin > 0) {
        this.scheduleCoverEmit();
      }
      if (target === 0 && this.coverCurrentRatePerMin === 0) {
        if (this.coverRampTimer) {
          this.clock.clearInterval(this.coverRampTimer);
          this.coverRampTimer = null;
        }
        if (this.coverEmitTimer) {
          this.clock.clearTimeout(this.coverEmitTimer);
          this.coverEmitTimer = null;
        }
      }
    }
    scheduleCoverEmit() {
      if (this.coverEmitTimer !== null) return;
      const rate = this.coverCurrentRatePerMin;
      if (rate <= 0) return;
      const meanMs = 6e4 / rate;
      const gapMs = this.model.sampleGapMs(meanMs);
      const tick = () => {
        this.coverEmitTimer = null;
        if (this.coverCurrentRatePerMin <= 0) return;
        this.emitCoverFrame();
        this.scheduleCoverEmit();
      };
      this.coverEmitTimer = this.clock.setTimeout(tick, gapMs);
    }
    /**
     * Emit one dummy frame. It is random bytes broadcast (to: null); the mesh's
     * installed padding transform buckets it exactly like a real frame, so it is
     * indistinguishable on the wire and carries no real id or payload. The
     * receiving peer discards it after decrypt (cover frames decrypt to a tagged
     * no-op); a passive observer cannot tell real from cover.
     */
    emitCoverFrame() {
      const targetBucket = this.model.sampleSizeBytes();
      const bodyLen = Math.max(1, targetBucket - LEN_HEADER_BYTES);
      const body = this.ports.random.bytes(bodyLen);
      void this.ports.mesh.sendRaw({ bytes: body, to: null });
    }
  };

  // src/shield/traffic-model.ts
  var DEFAULT_RESERVOIR = 256;
  var TrafficModel = class {
    constructor(random, options) {
      this.random = random;
      this.gaps = [];
      this.gapWrite = 0;
      this.lastObservedAt = null;
      this.buckets = options.buckets;
      this.reservoirSize = options.reservoirSize ?? DEFAULT_RESERVOIR;
      this.minSamples = options.minSamplesForBootstrap ?? 8;
      this.bucketCounts = new Array(this.buckets.length).fill(0);
    }
    /** Record one real outbound frame: its (padded) size and the time it was sent. */
    observe(sizeBytes, atMs) {
      if (this.lastObservedAt !== null) {
        const gap = atMs - this.lastObservedAt;
        if (gap >= 0) this.recordGap(gap);
      }
      this.lastObservedAt = atMs;
      this.recordSize(sizeBytes);
    }
    /** Number of observed gaps currently retained (for tests/telemetry). */
    get sampleCount() {
      return this.gaps.length;
    }
    /**
     * Draw an inter-arrival delay (ms). Uses the observed distribution once enough
     * samples exist; otherwise an exponential with `fallbackMeanMs` (Poisson).
     */
    sampleGapMs(fallbackMeanMs) {
      if (this.gaps.length >= this.minSamples) {
        const idx = this.random.int(0, this.gaps.length - 1);
        const jitter = 0.85 + this.random.int(0, 30) / 100;
        return Math.max(1, Math.round(this.gaps[idx] * jitter));
      }
      return this.exponential(fallbackMeanMs);
    }
    /** Draw a frame size (a padding bucket) from the observed size histogram. */
    sampleSizeBytes() {
      const total = this.bucketCounts.reduce((a, b) => a + b, 0);
      if (total === 0) {
        return this.buckets[this.random.int(0, this.buckets.length - 1)];
      }
      let r = this.random.int(0, total - 1);
      for (let i = 0; i < this.buckets.length; i++) {
        if (r < this.bucketCounts[i]) return this.buckets[i];
        r -= this.bucketCounts[i];
      }
      return this.buckets[this.buckets.length - 1];
    }
    /** Exponential (Poisson-process) inter-arrival with the given mean. */
    exponential(meanMs) {
      const mean = Math.max(1, meanMs);
      const u = this.random.int(1, 1e6) / 1e6;
      return Math.max(1, Math.round(-mean * Math.log(u)));
    }
    recordGap(gap) {
      if (this.gaps.length < this.reservoirSize) {
        this.gaps.push(gap);
      } else {
        this.gaps[this.gapWrite] = gap;
        this.gapWrite = (this.gapWrite + 1) % this.reservoirSize;
      }
    }
    recordSize(sizeBytes) {
      for (let i = 0; i < this.buckets.length; i++) {
        if (sizeBytes <= this.buckets[i]) {
          this.bucketCounts[i]++;
          return;
        }
      }
      this.bucketCounts[this.buckets.length - 1]++;
    }
  };

  // src/shield/ShieldManager.ts
  var TIER_STORE_KEY = "ghostnet_shield_tier";
  var ShieldManager = class _ShieldManager {
    constructor(ports, options = {}) {
      this.currentTier = "OFF" /* OFF */;
      this.stable = true;
      /** Serializes setTier/panic so transitions never interleave. */
      this.queue = Promise.resolve();
      this.listeners = {
        tierChanged: /* @__PURE__ */ new Set(),
        degraded: /* @__PURE__ */ new Set(),
        integrityChanged: /* @__PURE__ */ new Set()
      };
      this.ports = ports;
      this.options = options;
      const mods = options.modules ?? _ShieldManager.defaultModules(ports);
      const map = /* @__PURE__ */ new Map();
      for (const m of mods) map.set(m.id, m);
      this.modules = map;
      for (const m of map.values()) {
        if (isRuntimeDetector(m)) {
          m.setNotifier((report) => this.onRuntimeDetection(report));
        }
        if (isIntegrityModule(m)) {
          m.setIntegrityNotifier((payload) => this.onIntegrityChange(payload));
        }
      }
    }
    /** Construct the real module set wired to the given platform ports. A single
     *  shared TrafficModel links the shaper (which observes real traffic) and the
     *  decoy engine (which mimics that distribution). */
    static defaultModules(ports) {
      const model = new TrafficModel(ports.random, { buckets: PADDING_BUCKETS });
      return [
        new BleCloak(ports),
        new DnsGuard(ports),
        new TrafficShaper(ports, model),
        new MeshRouting(ports),
        new DecoyEngine(ports, model),
        new NodeIdRotator(ports),
        new CoResidentGuard(ports),
        new DeviceIntegrity(ports)
      ];
    }
    // ── public API ──────────────────────────────────────────────────────────
    /** Set the active tier. Idempotent and atomic (rolls back on hard failure). */
    setTier(tier) {
      return this.enqueue(() => this.applyTier(tier));
    }
    /** Hard-jump to FULL_GHOST. Reachable from a global panic gesture. */
    panic() {
      return this.enqueue(async () => {
        await this.applyTier("FULL_GHOST" /* FULL_GHOST */);
      });
    }
    getStatus() {
      const reports = this.collectReports();
      return {
        tier: this.currentTier,
        stable: this.stable,
        degraded: reports.some((r) => r.degraded || r.requested && !r.active),
        modules: reports
      };
    }
    on(event, cb) {
      if (event === "tierChanged") {
        this.listeners.tierChanged.add(cb);
        return () => this.listeners.tierChanged.delete(cb);
      }
      if (event === "integrityChanged") {
        this.listeners.integrityChanged.add(cb);
        return () => this.listeners.integrityChanged.delete(cb);
      }
      this.listeners.degraded.add(cb);
      return () => this.listeners.degraded.delete(cb);
    }
    // ── device integrity (delegated to the DeviceIntegrity module) ────────────
    integrityModule() {
      const m = this.modules.get("device-integrity" /* DeviceIntegrity */);
      return m instanceof DeviceIntegrity ? m : null;
    }
    /** Latest device-integrity state, or null if the module isn't active/checked. */
    getIntegrityState() {
      return this.integrityModule()?.getState() ?? null;
    }
    /** Policy response for the current integrity verdict (UNKNOWN-safe default). */
    getIntegrityResponse() {
      return this.integrityModule()?.getResponse() ?? null;
    }
    /** Force a fresh integrity re-check + attestation (app foreground / pre-op). */
    recheckIntegrity() {
      const m = this.integrityModule();
      return m ? m.recheck() : Promise.resolve(null);
    }
    /** Restore the persisted tier on app launch. No-ops (stays OFF) if none saved. */
    async restore() {
      const saved = await this.ports.store.getItem(TIER_STORE_KEY);
      if (saved && isShieldTier(saved)) {
        return this.setTier(saved);
      }
      return this.getStatus();
    }
    // ── transition core ─────────────────────────────────────────────────────
    enqueue(task) {
      const run = this.queue.then(task, task);
      this.queue = run.then(
        () => void 0,
        () => void 0
      );
      return run;
    }
    /**
     * The atomic transition. Snapshots the previous stable tier, applies the
     * target, and on a hard failure re-applies the snapshot before surfacing the
     * error path as a rolled-back `degraded` event.
     */
    async applyTier(target) {
      const from = this.currentTier;
      this.stable = false;
      try {
        await this.reconcile(target);
        this.currentTier = target;
        this.stable = true;
        await this.persist(target);
        const status = this.getStatus();
        if (from !== target) {
          this.emitTierChanged({ from, to: target, status });
        }
        this.maybeEmitDegraded(target, false);
        return status;
      } catch (err) {
        this.ports.log.warn("transition_failed", { from, to: target });
        try {
          await this.reconcile(from);
        } catch {
          await this.reconcile("OFF" /* OFF */).catch(() => void 0);
          this.currentTier = "OFF" /* OFF */;
        }
        this.currentTier = this.currentTier === "OFF" /* OFF */ ? "OFF" /* OFF */ : from;
        this.stable = true;
        await this.persist(this.currentTier);
        this.emitDegraded({
          tier: this.currentTier,
          reports: this.collectReports(),
          rolledBack: true
        });
        return this.getStatus();
      }
    }
    /**
     * Bring the running module set in line with `target`: enable/reconfigure every
     * module the tier requires, disable every module it does not. A throw from any
     * enable() propagates to applyTier() to trigger rollback.
     */
    async reconcile(target) {
      const cfg = resolveConfig(target, this.options);
      const wanted = modulesForTier(target);
      for (const [id, mod] of this.modules) {
        if (!wanted.has(id)) await mod.disable();
      }
      for (const id of wanted) {
        const mod = this.modules.get(id);
        if (mod) await mod.enable(cfg);
      }
    }
    collectReports() {
      return [...this.modules.values()].map((m) => m.report());
    }
    maybeEmitDegraded(tier, rolledBack) {
      const degraded = this.collectReports().filter((r) => r.degraded || r.requested && !r.active);
      if (degraded.length > 0) {
        this.emitDegraded({ tier, reports: degraded, rolledBack });
      }
    }
    async persist(tier) {
      try {
        await this.ports.store.setItem(TIER_STORE_KEY, tier);
      } catch {
        this.ports.log.warn("persist_failed");
      }
    }
    /**
     * Out-of-band runtime detection from a detector module (CoResidentGuard).
     * Re-emit as a `degraded` event, and — if configured — auto-raise the tier.
     */
    onRuntimeDetection(report) {
      this.emitDegraded({ tier: this.currentTier, reports: [report], rolledBack: false });
      const raiseTo = this.options.autoRaiseOnCoResident;
      if (raiseTo && TIER_RANK[raiseTo] > TIER_RANK[this.currentTier]) {
        void this.enqueue(() => this.applyTier(raiseTo));
      }
    }
    /**
     * Device-integrity verdict changed. Emit `integrityChanged`, and force-raise
     * the tier if the verdict's policy demands it (e.g. COMPROMISED → FULL_GHOST).
     * Enforcement of blockSensitiveOps / allowRelay is the app's job — it consults
     * {@link getIntegrityResponse}.
     */
    onIntegrityChange(payload) {
      for (const cb of this.listeners.integrityChanged) cb(payload);
      const raiseTo = payload.response.raiseToTier;
      if (raiseTo && TIER_RANK[raiseTo] > TIER_RANK[this.currentTier]) {
        void this.enqueue(() => this.applyTier(raiseTo));
      }
    }
    emitTierChanged(p) {
      for (const cb of this.listeners.tierChanged) cb(p);
    }
    emitDegraded(p) {
      for (const cb of this.listeners.degraded) cb(p);
    }
  };
  function isShieldTier(value) {
    return Object.prototype.hasOwnProperty.call(TIER_RANK, value);
  }

  // src/shield/logger.ts
  var REDACTED = "[redacted]";
  var HEX_ID = /^(0x)?[0-9a-fA-F]{16,}$/;
  var GHOSTTAG = /^@?[A-Za-z0-9_]{3,}$/;
  var BASE64ISH = /^[A-Za-z0-9+/_-]{24,}={0,2}$/;
  function looksLikeIdentifier(value) {
    return HEX_ID.test(value) || BASE64ISH.test(value) || value.length > 12 && GHOSTTAG.test(value);
  }
  function scrub(fields) {
    const out = {};
    if (!fields) return out;
    for (const [k, v] of Object.entries(fields)) {
      out[k] = typeof v === "string" && looksLikeIdentifier(v) ? REDACTED : v;
    }
    return out;
  }
  function createLogger(options = {}) {
    const enabled = options.enabled ?? false;
    const sink = options.sink ?? ((line) => {
      console.log(line);
    });
    const emit = (level, code, fields) => {
      if (!enabled) return;
      const scrubbed = scrub(fields);
      const tail = Object.keys(scrubbed).length ? " " + JSON.stringify(scrubbed) : "";
      sink(`${level} shield:${code}${tail}`);
    };
    return {
      enabled,
      debug: (code, fields) => emit("debug", code, fields),
      warn: (code, fields) => emit("warn", code, fields)
    };
  }
  var NULL_LOGGER = createLogger({ enabled: false });

  // src/shield/web/reasons.ts
  function honestReason(report, platform) {
    const web = platform === "web";
    switch (report.reason) {
      case REASON.BLE_UNAVAILABLE:
        return web ? "BLE unavailable \u2014 web test context (no native BLE plugin)" : "BLE unavailable \u2014 native plugin failed to resolve";
      case REASON.BLE_ADV_UNSUPPORTED:
        return "BLE advertising control unsupported on this platform \u2014 discovery beacon silenced only";
      case REASON.BLE_ADV_PARAMS_FIXED:
        return web ? "BLE advertising-shape randomization unavailable \u2014 no BLE stack in web test context" : "BLE advertising parameters are fixed by this platform";
      case REASON.DOH_UNSUPPORTED:
        return "DNS-over-HTTPS unsupported on this platform";
      case REASON.DOH_UNREACHABLE_FAILCLOSED:
        return "DoH resolver unreachable \u2014 failing closed (plaintext DNS blocked)";
      case REASON.SNI_LEAK_NO_ECH:
        return "DNS query hidden via DoH, but TLS SNI still leaks (no ECH control in this build)";
      case REASON.HOP_CONTROL_UNSUPPORTED:
        return "Mesh min-hop enforcement unavailable \u2014 mesh transport not wired";
      case REASON.NODE_ID_ROTATION_UNSUPPORTED:
        return "Overlay node-id rotation unsupported by this mesh build";
      case REASON.NO_ACTIVE_SESSIONS:
        return "No active sessions to hand off";
      case REASON.SCREEN_CAPTURE_ACTIVE:
        return "Screen is being captured/recorded";
      case REASON.ACCESSIBILITY_SERVICE_ACTIVE:
        return "A third-party accessibility service is active";
      case REASON.ONDEVICE_DETECTION_UNSUPPORTED:
        return web ? "On-device observation detection unavailable in web test context" : "On-device observation detection unavailable \u2014 no native bridge wired";
      case INTEGRITY_REASON.COMPROMISED:
        return "Device integrity: COMPROMISED (attestation failed)";
      case INTEGRITY_REASON.SUSPECT:
        return "Device integrity: SUSPECT (local tamper indicators high)";
      case INTEGRITY_REASON.UNKNOWN:
        return web ? "Device integrity: UNKNOWN \u2014 attestation unavailable in web test context" : "Device integrity: UNKNOWN \u2014 could not attest";
      default:
        return report.reason ?? (report.active ? "running a reduced subset" : "inactive");
    }
  }

  // src/shield/web/facade.ts
  var TIER_BY_LEVEL = {
    0: "OFF" /* OFF */,
    1: "STEALTH" /* STEALTH */,
    2: "GHOST" /* GHOST */,
    3: "PHANTOM" /* PHANTOM */
  };
  function levelForTier(tier) {
    switch (tier) {
      case "OFF" /* OFF */:
        return 0;
      case "STEALTH" /* STEALTH */:
        return 1;
      case "GHOST" /* GHOST */:
        return 2;
      default:
        return 3;
    }
  }
  var DEFAULT_BLOCKED_KEY = "ghostnet_shield_blocked_macs";
  var GhostShieldFacade = class {
    constructor(manager, platform, mesh, options = {}) {
      this.manager = manager;
      this.platform = platform;
      this.mesh = mesh;
      this.startedAt = null;
      this.statsTimer = null;
      this.blockedMacs = /* @__PURE__ */ new Set();
      this.sink = options.sink ?? ((line) => console.log(line));
      this.blockedKey = options.blockedMacsKey ?? DEFAULT_BLOCKED_KEY;
      this.cached = manager.getStatus();
      this.restoreBlocked();
      manager.on("tierChanged", ({ from, to, status }) => {
        this.cached = status;
        this.onActiveEdge();
        this.log(`tier ${from} \u2192 ${to}  [platform: ${this.platform}]`);
        this.logReports(status.modules);
        this.emitStats();
      });
      manager.on("degraded", ({ reports, rolledBack }) => {
        this.cached = manager.getStatus();
        if (rolledBack) this.log("transition rolled back to last stable tier");
        this.logReports(reports);
        this.emitStats();
      });
      void manager.restore().then((status) => {
        this.cached = status;
        this.onActiveEdge();
        if (status.tier !== "OFF" /* OFF */) {
          this.log(`restored tier ${status.tier}  [platform: ${this.platform}]`);
          this.logReports(status.modules);
        }
        this.emitStats();
      });
    }
    // ── legacy level API the UI calls ─────────────────────────────────────────
    /** Toggle a cumulative level. Clicking the active top level steps down one. */
    enable(level) {
      const l = clampLevel(level);
      const currentRank = TIER_RANK[this.cached.tier];
      const isTop = currentRank === l && this.cached.tier !== "FULL_GHOST" /* FULL_GHOST */;
      const target = isTop ? l - 1 : l;
      this.applyLevel(target);
    }
    enableAll() {
      this.optimistic("FULL_GHOST" /* FULL_GHOST */);
      void this.manager.setTier("FULL_GHOST" /* FULL_GHOST */);
    }
    disableAll() {
      this.optimistic("OFF" /* OFF */);
      void this.manager.setTier("OFF" /* OFF */);
    }
    disable() {
      this.disableAll();
    }
    /** Panic gesture → FULL_GHOST immediately. */
    panic() {
      this.optimistic("FULL_GHOST" /* FULL_GHOST */);
      void this.manager.panic();
    }
    isActive() {
      return this.cached.tier !== "OFF" /* OFF */;
    }
    /** Stop the stats timer (SPA teardown / tests). Does not change the tier. */
    dispose() {
      this.stopStatsTimer();
    }
    getStatus() {
      const rank = TIER_RANK[this.cached.tier];
      return {
        platform: this.platform,
        tier: this.cached.tier,
        level: levelForTier(this.cached.tier),
        currentLevel: this.cached.tier === "FULL_GHOST" /* FULL_GHOST */ ? "ALL" : null,
        activeStates: { 1: rank >= 1, 2: rank >= 2, 3: rank >= 3 },
        degraded: this.cached.degraded,
        stable: this.cached.stable,
        modules: this.cached.modules,
        stats: {
          packetsProtected: this.mesh.framesSent + this.mesh.decoysSent,
          devicesBlocked: this.blockedMacs.size,
          nodeIdRotations: this.mesh.nodeIdRotations,
          uptime: this.startedAt ? Math.floor((Date.now() - this.startedAt) / 1e3) : 0
        }
      };
    }
    // ── app-level device block list (filtering, not a cloaking claim) ─────────
    blockDevice(mac) {
      if (!mac) return;
      this.blockedMacs.add(mac);
      this.mirrorBlocked();
      this.persistBlocked();
    }
    unblockDevice(mac) {
      if (!mac) return;
      this.blockedMacs.delete(mac);
      this.mirrorBlocked();
      this.persistBlocked();
    }
    // ── internals ─────────────────────────────────────────────────────────────
    applyLevel(level) {
      const tier = TIER_BY_LEVEL[level];
      this.optimistic(tier);
      void this.manager.setTier(tier);
    }
    /** Update the cached snapshot's tier immediately so the UI's synchronous
     *  read after a click reflects intent; the real report replaces it on resolve. */
    optimistic(tier) {
      this.cached = { ...this.cached, tier, stable: false };
      this.onActiveEdge();
    }
    onActiveEdge() {
      if (this.cached.tier !== "OFF" /* OFF */ && this.startedAt === null) {
        this.startedAt = Date.now();
        this.startStatsTimer();
      } else if (this.cached.tier === "OFF" /* OFF */) {
        this.startedAt = null;
        this.stopStatsTimer();
      }
    }
    startStatsTimer() {
      if (this.statsTimer !== null) return;
      this.statsTimer = setInterval(() => this.emitStats(), 2e3);
    }
    stopStatsTimer() {
      if (this.statsTimer !== null) {
        clearInterval(this.statsTimer);
        this.statsTimer = null;
      }
    }
    emitStats() {
      dispatch("ghostShield:statsUpdated", this.getStatus());
    }
    log(msg) {
      this.sink(`[Ghost Shield] ${msg}`);
    }
    /** Print one honest line per module: ACTIVE / DEGRADED / UNAVAILABLE + reason. */
    logReports(reports) {
      for (const r of reports) {
        if (!r.requested) continue;
        if (r.active && !r.degraded) {
          this.log(`${r.id}: ACTIVE`);
        } else if (r.active && r.degraded) {
          this.log(`${r.id}: DEGRADED \u2014 ${honestReason(r, this.platform)}`);
        } else {
          this.log(`${r.id}: UNAVAILABLE \u2014 ${honestReason(r, this.platform)}`);
        }
      }
    }
    mirrorBlocked() {
      const app = globalThis.app;
      if (app?.mesh) app.mesh.blockedMacs = [...this.blockedMacs];
    }
    persistBlocked() {
      try {
        const ls = globalThis.localStorage;
        ls?.setItem(this.blockedKey, JSON.stringify([...this.blockedMacs]));
      } catch {
      }
    }
    restoreBlocked() {
      try {
        const ls = globalThis.localStorage;
        const raw = ls?.getItem(this.blockedKey);
        if (!raw) return;
        const parsed = JSON.parse(raw);
        if (Array.isArray(parsed)) {
          for (const m of parsed) if (typeof m === "string" && m.length < 128) this.blockedMacs.add(m);
          this.mirrorBlocked();
        }
      } catch {
      }
    }
  };
  function clampLevel(level) {
    if (level <= 1) return 1;
    if (level >= 3) return 3;
    return 2;
  }
  function dispatch(name, detail) {
    const w = globalThis;
    if (typeof w.dispatchEvent === "function" && typeof w.CustomEvent === "function") {
      w.dispatchEvent(new w.CustomEvent(name, { detail }));
    }
  }

  // src/shield/web/runtime.ts
  function detectPlatform(globalRef = globalThis) {
    const cap = globalRef.Capacitor;
    if (cap && typeof cap.isNativePlatform === "function" && cap.isNativePlatform()) {
      return "native";
    }
    return "web";
  }
  var SystemClock = class {
    now() {
      return Date.now();
    }
    setTimeout(fn, ms) {
      return globalThis.setTimeout(fn, ms);
    }
    clearTimeout(handle) {
      globalThis.clearTimeout(handle);
    }
    setInterval(fn, ms) {
      return globalThis.setInterval(fn, ms);
    }
    clearInterval(handle) {
      globalThis.clearInterval(handle);
    }
  };
  var WebCryptoRandom = class {
    bytes(n) {
      const out = new Uint8Array(n);
      globalThis.crypto.getRandomValues(out);
      return out;
    }
    /** Uniform integer in [minInclusive, maxInclusive] via rejection sampling. */
    int(minInclusive, maxInclusive) {
      if (maxInclusive <= minInclusive) return minInclusive;
      const span = maxInclusive - minInclusive + 1;
      const maxUnbiased = Math.floor(4294967295 / span) * span;
      const buf = new Uint32Array(1);
      let v = 0;
      do {
        globalThis.crypto.getRandomValues(buf);
        v = buf[0];
      } while (v >= maxUnbiased);
      return minInclusive + v % span;
    }
  };
  var WebSecureStore = class {
    constructor(storage) {
      this.backing = storage ?? resolveStorage();
    }
    async getItem(key) {
      return this.backing.getItem(key);
    }
    async setItem(key, value) {
      this.backing.setItem(key, value);
    }
    async removeItem(key) {
      this.backing.removeItem(key);
    }
  };
  function resolveStorage() {
    try {
      const ls = globalThis.localStorage;
      if (ls) {
        const probe = "__ghost_shield_probe__";
        ls.setItem(probe, "1");
        ls.removeItem(probe);
        return ls;
      }
    } catch {
    }
    const mem = /* @__PURE__ */ new Map();
    return {
      getItem: (k) => mem.has(k) ? mem.get(k) : null,
      setItem: (k, v) => void mem.set(k, v),
      removeItem: (k) => void mem.delete(k)
    };
  }

  // src/shield/web/webPorts.ts
  var WebBleAdapter = class {
    isAvailable() {
      return false;
    }
    supportsAdvertisingControl() {
      return false;
    }
    async stopAdvertising() {
    }
    async startAdvertising() {
    }
    async setDiscoveryBeaconEnabled() {
    }
    async setAdvertisedNodeId() {
    }
    supportsAdvertisingParams() {
      return false;
    }
    async setAdvertisingParameters(_params) {
    }
  };
  var WebDnsAdapter = class {
    constructor(fetchFn = defaultFetch()) {
      this.fetchFn = fetchFn;
      this.mode = "system";
      this.resolver = "";
      this.plaintextBlocked = false;
    }
    supportsDoh() {
      return true;
    }
    async setMode(mode, dohResolver) {
      this.mode = mode;
      this.resolver = dohResolver;
    }
    async probe(dohResolver) {
      try {
        const resp = await this.fetchFn(`${dohResolver}?name=cloudflare.com&type=A`, {
          headers: { Accept: "application/dns-json" }
        });
        return resp.ok;
      } catch {
        return false;
      }
    }
    async setPlaintextBlocked(blocked) {
      this.plaintextBlocked = blocked;
    }
    supportsEch() {
      return false;
    }
    /** Current DoH mode (for status display/tests). */
    get currentMode() {
      return this.mode;
    }
    get isPlaintextBlocked() {
      return this.plaintextBlocked;
    }
    get currentResolver() {
      return this.resolver;
    }
  };
  function defaultFetch() {
    const f = globalThis.fetch;
    if (f) return f.bind(globalThis);
    return async () => ({ ok: false });
  }
  var WebMeshAdapter = class {
    constructor(bridge = {}, random = new WebCryptoRandom()) {
      this.bridge = bridge;
      this.random = random;
      this.transform = null;
      /** Honest activity counters the facade surfaces as real stats. */
      this.framesSent = 0;
      this.decoysSent = 0;
      this.nodeIdRotations = 0;
      this.minHops = 0;
      this.nodeId = bridge.getNodeId?.() ?? bytesToHex3(this.random.bytes(16));
    }
    getCurrentNodeId() {
      return this.bridge.getNodeId?.() ?? this.nodeId;
    }
    setOutboundTransform(transform) {
      this.transform = transform;
    }
    async sendRaw(frame) {
      const out = this.transform ? this.transform(frame) : frame;
      this.bridge.send?.({ bytes: out.bytes, to: out.to });
      this.framesSent++;
    }
    getActiveSessions() {
      return this.bridge.getActiveSessions?.() ?? [];
    }
    supportsHopControl() {
      return typeof this.bridge.setMinHops === "function" && (this.bridge.supportsMinHops?.() ?? true);
    }
    async setMinHops(hops) {
      this.minHops = hops;
      this.bridge.setMinHops?.(hops);
    }
    supportsNodeIdRotation() {
      return true;
    }
    async sendNodeIdHandoff(peerId, oldId, newId) {
      this.bridge.sendNodeIdHandoff?.(peerId, oldId, newId);
    }
    async adoptNodeId(newId) {
      this.nodeId = newId;
      this.bridge.adoptNodeId?.(newId);
      this.nodeIdRotations++;
    }
    async retireNodeId(oldId) {
      this.bridge.retireNodeId?.(oldId);
    }
    async announceDecoyPeer(announcement) {
      this.bridge.announceDecoy?.({ ephemeralId: announcement.ephemeralId, payload: announcement.payload });
      this.decoysSent++;
    }
  };
  var WebCoResidentAdapter = class {
    supportsScreenCaptureDetection() {
      return false;
    }
    isScreenCaptured() {
      return false;
    }
    subscribeScreenCapture(_cb) {
      return () => void 0;
    }
    supportsAccessibilityDetection() {
      return false;
    }
    isAccessibilityServiceActive() {
      return false;
    }
    async clearClipboard() {
      try {
        const nav = globalThis.navigator;
        await nav?.clipboard?.writeText("");
      } catch {
      }
    }
  };
  var WebLocalSignalProbe = class {
    platform() {
      return "android";
    }
    fileExists() {
      return false;
    }
    canWrite() {
      return false;
    }
    getSystemProp() {
      return null;
    }
    packageInstalled() {
      return false;
    }
    isPortOpen() {
      return false;
    }
    loadedLibraries() {
      return [];
    }
    canOpenUrlScheme() {
      return false;
    }
    forkSucceeds() {
      return false;
    }
    buildFingerprint() {
      return "web/browser";
    }
  };
  var WebAttestationProvider = class {
    isSupported() {
      return false;
    }
    async getToken() {
      throw new Error("attestation unsupported in web context");
    }
  };
  var WebAttestationBackend = class {
    async requestNonce() {
      throw new Error("attestation backend not reachable from web context");
    }
    async verify() {
      throw new Error("attestation backend not reachable from web context");
    }
  };
  function createWebIntegrity() {
    return {
      probe: new WebLocalSignalProbe(),
      provider: new WebAttestationProvider(),
      backend: new WebAttestationBackend()
    };
  }
  function createWebPorts(options = {}) {
    const random = new WebCryptoRandom();
    return {
      ble: new WebBleAdapter(),
      dns: new WebDnsAdapter(options.fetchFn),
      mesh: new WebMeshAdapter(options.meshBridge ?? {}, random),
      coResident: new WebCoResidentAdapter(),
      integrity: createWebIntegrity(),
      store: new WebSecureStore(),
      clock: new SystemClock(),
      random,
      log: options.logger ?? createLogger({ enabled: false })
    };
  }
  function bytesToHex3(bytes) {
    let s = "";
    for (const b of bytes) s += b.toString(16).padStart(2, "0");
    return s;
  }

  // src/shield/web/nativePorts.ts
  var CapacitorBleAdapter = class {
    constructor(bridge, log) {
      this.bridge = bridge;
      this.log = log;
    }
    isAvailable() {
      return this.bridge?.isReady() === true;
    }
    supportsAdvertisingControl() {
      return this.isAvailable() && this.bridge.supportsAdvertisingControl();
    }
    async stopAdvertising() {
      if (this.isAvailable()) await this.bridge.stopAdvertising();
    }
    async startAdvertising() {
      if (this.isAvailable()) await this.bridge.startAdvertising();
    }
    async setDiscoveryBeaconEnabled(enabled) {
      if (this.isAvailable()) await this.bridge.setDiscoveryBeaconEnabled(enabled);
    }
    async setAdvertisedNodeId(nodeId) {
      if (this.isAvailable()) await this.bridge.setAdvertisedNodeId(nodeId);
    }
    supportsAdvertisingParams() {
      return this.isAvailable() && this.bridge.supportsAdvertisingParams();
    }
    async setAdvertisingParameters(params) {
      if (this.supportsAdvertisingParams()) await this.bridge.setAdvertisingParameters(params);
    }
  };
  function createNativePorts(options = {}) {
    const g = options.globalRef ?? globalThis;
    const log = options.logger ?? createLogger({ enabled: false });
    const random = new WebCryptoRandom();
    const bleBridge = options.bleBridge ?? g.GhostNativeBle ?? null;
    const ble = new CapacitorBleAdapter(bleBridge, log);
    const coResident = options.coResident ?? g.GhostNativeCoResident ?? new WebCoResidentAdapter();
    const integrity = options.integrity ?? g.GhostNativeIntegrity ?? createWebIntegrity();
    const meshBridge = options.meshBridge ?? g.app?.mesh ?? {};
    const mesh = new WebMeshAdapter(meshBridge, random);
    return {
      ble,
      dns: new WebDnsAdapter(),
      mesh,
      coResident,
      integrity,
      store: new WebSecureStore(),
      clock: new SystemClock(),
      random,
      log
    };
  }

  // src/shield/web/entry.ts
  function createGhostShield(options = {}) {
    const platform = options.platform ?? detectPlatform();
    const verbose = options.verbose ?? true;
    const log = createLogger({ enabled: verbose, sink: (line) => console.log(`[Ghost Shield] ${line}`) });
    const ports = platform === "native" ? createNativePorts({ logger: log }) : createWebPorts({ logger: log });
    const manager = new ShieldManager(ports);
    const facade = new GhostShieldFacade(manager, platform, ports.mesh);
    return { platform, manager, facade };
  }
  function installGhostShield(globalRef = globalThis) {
    if (globalRef.GhostShield) return globalRef.GhostShield;
    const { facade } = createGhostShield();
    globalRef.GhostShield = facade;
    return facade;
  }
  if (typeof document !== "undefined") {
    installGhostShield();
  }
})();
