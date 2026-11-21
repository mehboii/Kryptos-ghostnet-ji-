/**
 * Ghost Radar — real passive signal scanner.
 *
 * BLE is the real core: it drives the native radio through window.KryptosBLE
 * (the same bridge Proximity Connect uses, backed by react-native-ble-plx). It
 * scans UNFILTERED for every nearby BLE device, tracks them live, and derives
 * vendor / category / proximity from the advertisement — NOTHING is invented or
 * simulated. If the native bridge is absent (browser / Expo Go) the radar shows
 * the honest "needs the installed app" state instead of pretending to scan.
 *
 * WiFi access-point scanning is ANDROID ONLY (the OS gates it; iOS has no public
 * API). It lists routers/hotspots — "nearby networks", never "devices". On iOS
 * or where the native module is absent, the WiFi section is reported unavailable
 * with a reason, never faked.
 *
 * Classification is deliberately restrained. In any public place dozens of
 * unknown BLE devices are normal (earbuds, watches, TVs); flagging them all is
 * useless and, for at-risk users, harmful. A device is "notable" ONLY on a
 * meaningful signal — a strong RSSI that has PERSISTED for many minutes
 * (possible following) — and the reason is always shown so the user judges.
 */
'use strict';

// How long a device may go unseen before it drops off the radar.
const RADAR_STALE_MS = 30 * 1000;
// "Notable" requires a strong signal that has persisted at least this long.
const NOTABLE_PERSIST_MS = 8 * 60 * 1000; // 8 minutes
const NOTABLE_RSSI_DBM = -55;             // "very close" band
const WIFI_NOTABLE_RSSI_DBM = -60;
// Cadence.
const UI_REFRESH_MS = 2000;
const WIFI_POLL_MS = 12 * 1000; // Android throttles WiFi scans hard; poll gently.

// BLE company identifiers (Bluetooth SIG, decimal) → vendor. Only confident
// mappings; an unknown id yields null (we never guess a brand).
const BLE_VENDORS = {
  76: 'Apple',
  6: 'Microsoft',
  117: 'Samsung',
  224: 'Google',
  89: 'Nordic Semiconductor',
  13: 'Texas Instruments',
  15: 'Broadcom',
  158: 'Bose',
  135: 'Garmin',
  171: 'Amazon',
  72: 'Logitech',
};

class GhostRadarEngine {
  constructor() {
    this.results = [];
    this.scanning = false;
    this.env = 'unknown'; // 'web' | 'expoGo' | 'native'
    this.permissionState = { ble: 'unknown', wifi: 'unknown' };
    this.wifi = { supported: false, available: false, reason: 'unknown', networks: [] };

    this._devices = new Map();   // deviceId -> live record
    this._bridgeWired = false;
    this._refreshTimer = null;
    this._wifiTimer = null;
    this._backgrounded = false;
  }

  get _ble() {
    return (typeof window !== 'undefined') ? window.KryptosBLE : null;
  }

  // ── Environment ─────────────────────────────────────────────
  // Synchronous, side-effect-free: reads the tag App.js set on the bridge.
  detectEnvironment() {
    const ble = this._ble;
    if (!ble || !ble.available) return 'web';
    return ble.env === 'expoGo' ? 'expoGo' : 'native';
  }

  isSupported() {
    this.env = this.detectEnvironment();
    return this.env === 'native';
  }

  // ── Permissions ─────────────────────────────────────────────
  async checkPermissions() {
    const ble = this._ble;
    if (!this.isSupported() || !ble) {
      this.permissionState.ble = 'denied';
      this._emitPermUpdate();
      return { ble: false, wifi: false };
    }
    let bleOk = false;
    try { bleOk = (await ble.requestPermissions()) !== false; } catch (_) { bleOk = false; }
    this.permissionState.ble = bleOk ? 'granted' : 'denied';

    // WiFi perms are Android-only and requested lazily by scanWifi(); reflect a
    // neutral state here so the UI doesn't imply WiFi works before the platform
    // check runs.
    this._emitPermUpdate();
    return { ble: bleOk, wifi: this.permissionState.wifi === 'granted' };
  }

  _emitPermUpdate() {
    if (typeof window !== 'undefined') {
      window.dispatchEvent(new CustomEvent('ghostRadar:permissionUpdate', { detail: this.permissionState }));
    }
  }

  // ── Lifecycle ───────────────────────────────────────────────
  async start() {
    if (!this.isSupported()) {
      // Browser / Expo Go: no radio. Surface honestly; never fake a scan.
      this.scanning = false;
      this._emitResults();
      return false;
    }
    const ble = this._ble;
    this._wireBridge();

    const granted = await this.checkPermissions();
    if (!granted.ble) {
      this.scanning = false;
      this._emitResults();
      return false;
    }

    const state = await ble.adapterState().catch(() => 'Unknown');
    if (state && state !== 'PoweredOn') {
      this.scanning = false;
      if (typeof window !== 'undefined') {
        window.dispatchEvent(new CustomEvent('ghostRadar:error', {
          detail: { phase: 'adapter', message: 'Bluetooth is off or unavailable (' + state + ')' }
        }));
      }
      this._emitResults();
      return false;
    }

    try {
      await ble.startRadarScan();
      this.scanning = true;
    } catch (e) {
      this.scanning = false;
      return false;
    }

    // Live UI refresh + stale pruning.
    clearInterval(this._refreshTimer);
    this._refreshTimer = setInterval(() => {
      this._prune();
      this._emitResults();
    }, UI_REFRESH_MS);

    // WiFi (Android only) — poll gently; degrade honestly elsewhere.
    this._startWifi();

    this._emitResults();
    return true;
  }

  // Back-compat for SignalIntelService (Ghost Shield): returns the CURRENT real
  // BLE devices. It does NOT force a background scan — the radar only runs while
  // its screen is visible (battery/privacy), so this reflects live data then and
  // the last-seen set otherwise. Never fabricates devices.
  async startScan() {
    return this.results;
  }

  async stop() {
    this.scanning = false;
    clearInterval(this._refreshTimer); this._refreshTimer = null;
    clearInterval(this._wifiTimer); this._wifiTimer = null;
    const ble = this._ble;
    if (ble) { try { await ble.stopRadarScan(); } catch (_) {} }
    this._emitResults();
  }

  // ── Bridge wiring ───────────────────────────────────────────
  _wireBridge() {
    const ble = this._ble;
    if (this._bridgeWired || !ble) return;
    this._bridgeWired = true;

    ble.on('radarDevice', (d) => this._onRadarDevice(d));
    ble.on('error', (e) => {
      if (typeof window !== 'undefined') {
        window.dispatchEvent(new CustomEvent('ghostRadar:error', { detail: e }));
      }
    });
    // Native tells us when the app backgrounds — the radio is already stopped
    // there for battery/privacy; pause our timers and reflect it in the UI.
    ble.on('appBackground', () => {
      this._backgrounded = true;
      this.scanning = false;
      clearInterval(this._refreshTimer); this._refreshTimer = null;
      clearInterval(this._wifiTimer); this._wifiTimer = null;
      this._emitResults();
    });
    ble.on('appForeground', () => {
      if (this._backgrounded) {
        this._backgrounded = false;
        // Resume only if the radar screen is active; the UI calls start() again.
      }
    });
  }

  // ── BLE device intake ───────────────────────────────────────
  _onRadarDevice(d) {
    if (!d || !d.deviceId) return;
    const now = d.timestamp || Date.now();
    const prev = this._devices.get(d.deviceId);

    const companyId = this._companyIdFromMfr(d.manufacturerData);
    const vendor = (companyId != null && BLE_VENDORS[companyId]) ? BLE_VENDORS[companyId] : null;

    const rec = prev || {
      id: d.deviceId,
      kind: 'ble',
      firstSeen: now,
      bestRssi: -999,
    };
    rec.lastSeen = now;
    rec.rssi = (typeof d.rssi === 'number') ? d.rssi : (rec.rssi ?? null);
    if (typeof rec.rssi === 'number' && rec.rssi > rec.bestRssi) rec.bestRssi = rec.rssi;
    // Keep the first real name we ever see; never overwrite a real name with null.
    if (d.name && !rec.name) rec.name = d.name;
    rec.serviceUUIDs = d.serviceUUIDs || rec.serviceUUIDs || null;
    if (companyId != null) rec.companyId = companyId;
    if (vendor) rec.vendor = vendor;

    rec.isGhostNode = this._isKryptosNode(rec);
    rec.category = this._categorize(rec);
    rec.proximity = this._proximity(rec.rssi);

    this._devices.set(d.deviceId, rec);
  }

  _companyIdFromMfr(b64) {
    if (!b64) return null;
    try {
      const bin = atob(b64);
      if (bin.length < 2) return null;
      // Little-endian 16-bit company identifier (first two bytes of mfr data).
      return (bin.charCodeAt(0) | (bin.charCodeAt(1) << 8));
    } catch (_) { return null; }
  }

  _isKryptosNode(rec) {
    const n = rec.name;
    if (!n) return false;
    return n.startsWith('GhostNode') || (n.startsWith('0x') && n.length === 42);
  }

  // Category inferred ONLY from advertised 16-bit service UUIDs / vendor — no
  // guessing beyond what the device actually broadcast.
  _categorize(rec) {
    const uuids = (rec.serviceUUIDs || []).map((u) => this._short16(u)).filter(Boolean);
    const has = (x) => uuids.includes(x);
    if (rec.isGhostNode) return 'Kryptos node';
    if (has('180d')) return 'Wearable / fitness';
    if (has('1812')) return 'Input device';
    if (has('fd5a') || has('fe2c') || has('fdcf')) return 'Audio / earbuds';
    if (has('feed') || has('fd44')) return 'Tracker tag';
    if (has('fd6f')) return 'Exposure beacon';
    if (rec.vendor === 'Apple') return 'Apple device';
    if (rec.vendor) return rec.vendor + ' device';
    return 'BLE device';
  }

  _short16(uuid) {
    if (!uuid) return null;
    const s = String(uuid).toLowerCase();
    // Full 128-bit base UUID → extract the 16-bit assigned-number segment.
    const m = s.match(/^0000([0-9a-f]{4})-0000-1000-8000-00805f9b34fb$/);
    if (m) return m[1];
    if (/^[0-9a-f]{4}$/.test(s)) return s;
    return null;
  }

  // Legacy device-type string consumed by SignalIntelService for its BLE/vendor
  // checks. Mapped from REAL vendor / node data — no guessing beyond that.
  _legacyType(rec) {
    if (rec.isGhostNode) return 'ghostnode';
    switch (rec.vendor) {
      case 'Apple': return 'apple_device';
      case 'Samsung': return 'samsung_device';
      case 'Microsoft': return 'windows_device';
      default: return 'bluetooth_device';
    }
  }

  _proximity(rssi) {
    if (typeof rssi !== 'number') return 'unknown';
    if (rssi >= -55) return 'very close';
    if (rssi >= -75) return 'nearby';
    return 'far';
  }

  // Restrained "notable": strong signal that has persisted for many minutes.
  _notable(rec, now) {
    const persisted = now - rec.firstSeen;
    const strong = (typeof rec.rssi === 'number') && rec.rssi >= NOTABLE_RSSI_DBM;
    if (strong && persisted >= NOTABLE_PERSIST_MS) {
      const mins = Math.floor(persisted / 60000);
      return { notable: true, reason: 'strong signal, seen for ' + mins + '+ minutes' };
    }
    return { notable: false, reason: null };
  }

  _prune() {
    const now = Date.now();
    for (const [id, rec] of this._devices) {
      if (now - rec.lastSeen > RADAR_STALE_MS) this._devices.delete(id);
    }
  }

  // ── WiFi (Android only) ─────────────────────────────────────
  _startWifi() {
    this._scanWifiOnce();
    clearInterval(this._wifiTimer);
    this._wifiTimer = setInterval(() => this._scanWifiOnce(), WIFI_POLL_MS);
  }

  async _scanWifiOnce() {
    const ble = this._ble;
    if (!ble || typeof ble.scanWifi !== 'function') {
      this.wifi = { supported: false, available: false, reason: 'unsupported', networks: [] };
      return;
    }
    try {
      // Lazily request WiFi/location perms on Android, once (no-op on iOS).
      if (!this._wifiPermAsked && typeof ble.requestWifiPermissions === 'function') {
        this._wifiPermAsked = true;
        try { await ble.requestWifiPermissions(); } catch (_) {}
      }
      const res = await ble.scanWifi();
      this.permissionState.wifi = (res && res.reason === 'permission-denied') ? 'denied'
        : (res && res.available) ? 'granted' : this.permissionState.wifi;

      if (!res || !res.available) {
        this.wifi = {
          supported: res ? res.reason !== 'ios-unsupported' && res.reason !== 'module-not-installed' : false,
          available: false,
          reason: (res && res.reason) || 'unavailable',
          networks: [],
        };
        this._emitPermUpdate();
        return;
      }
      const now = Date.now();
      const networks = (res.accessPoints || []).map((ap) => {
        const hidden = !ap.ssid;
        const rssi = (typeof ap.rssi === 'number') ? ap.rssi : null;
        const persistedStrong = hidden && rssi != null && rssi >= WIFI_NOTABLE_RSSI_DBM;
        return {
          id: ap.bssid || ap.ssid,
          kind: 'wifi',
          ssid: ap.ssid || '',
          bssid: ap.bssid || '',
          hidden,
          rssi,
          channel: this._freqToChannel(ap.frequency),
          security: this._securityOf(ap.capabilities),
          proximity: this._proximity(rssi),
          // Hidden SSID with a strong signal is the only WiFi "notable" trigger.
          notable: persistedStrong,
          notableReason: persistedStrong ? 'hidden network, strong signal' : null,
          lastSeen: now,
        };
      }).sort((a, b) => (b.rssi || -999) - (a.rssi || -999));

      this.wifi = { supported: true, available: true, reason: 'ok', networks };
      this._emitPermUpdate();
    } catch (e) {
      this.wifi = { supported: false, available: false, reason: e.message || 'scan-failed', networks: [] };
    }
  }

  _securityOf(caps) {
    const c = String(caps || '');
    if (/WPA3/i.test(c)) return 'WPA3';
    if (/WPA2/i.test(c)) return 'WPA2';
    if (/WPA/i.test(c)) return 'WPA';
    if (/WEP/i.test(c)) return 'WEP';
    if (/ESS/i.test(c) && !/WPA|WEP/i.test(c)) return 'Open';
    return c ? 'Secured' : 'Unknown';
  }

  _freqToChannel(freq) {
    if (!freq) return 0;
    if (freq === 2484) return 14;
    if (freq >= 2412 && freq <= 2472) return Math.floor((freq - 2412) / 5) + 1;
    if (freq >= 5170 && freq <= 5825) return Math.floor((freq - 5000) / 5);
    if (freq >= 5955 && freq <= 7115) return Math.floor((freq - 5950) / 5); // 6 GHz
    return 0;
  }

  // ── Output ──────────────────────────────────────────────────
  _emitResults() {
    const now = Date.now();
    const ble = [...this._devices.values()].map((rec) => {
      const n = this._notable(rec, now);
      return {
        id: rec.id,
        kind: 'ble',
        name: rec.name || null,        // null = unknown; UI must not invent
        vendor: rec.vendor || null,
        category: rec.category || 'BLE device',
        rssi: (typeof rec.rssi === 'number') ? rec.rssi : null,
        proximity: rec.proximity || 'unknown',
        isGhostNode: !!rec.isGhostNode,
        notable: n.notable,
        notableReason: n.reason,
        seenForMs: now - rec.firstSeen,
        // Back-compat fields for SignalIntelService (Ghost Shield) — all derived
        // from real advertisement data, never invented.
        type: this._legacyType(rec),
        source: 'real',
      };
    }).sort((a, b) => {
      if (a.isGhostNode !== b.isGhostNode) return a.isGhostNode ? -1 : 1;
      if (a.notable !== b.notable) return a.notable ? -1 : 1;
      return (b.rssi || -999) - (a.rssi || -999);
    });

    this.results = ble;

    if (typeof window !== 'undefined') {
      window.dispatchEvent(new CustomEvent('ghostRadar:scanComplete', {
        detail: {
          count: ble.length,
          results: ble,
          wifi: this.wifi,
          env: this.env,
          scanning: this.scanning,
        }
      }));
    }
  }
}

if (typeof window !== 'undefined') window.GhostRadar = new GhostRadarEngine();
