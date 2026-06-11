/**
 * ProximityBLE — native BLE transport for Proximity Connect.
 *
 * This is the half that MUST live in React Native, because neither the WebView
 * (no Web Bluetooth) nor a Capacitor plugin (wrong runtime) can touch the radio
 * here. It runs BOTH roles concurrently so the phone is discoverable while it
 * scans — the single requirement the old code failed:
 *
 *   - CENTRAL  (react-native-ble-plx): scan filtered by the rendezvous Service
 *     UUID, dedupe by device, track RSSI, connect, negotiate MTU up, and drive
 *     GATT client reads/writes/notifications.
 *   - PERIPHERAL (ghostnet-ble-peripheral local module): advertise the same
 *     Service UUID + rotating pseudonym, and run the GATT server.
 *
 * It deliberately holds NO crypto and NO handshake state. The handshake state
 * machine + Ed25519-style identity proof + session keys live in the web layer
 * (proximity-connect.js); this class only moves bytes and reports events. The
 * App.js WebView bridge wires the two together.
 *
 * Raw GATT payloads cross this boundary as base64 (ble-plx's native encoding);
 * the web side converts to/from its hex/JSON frames.
 */
'use strict';

import { Platform, PermissionsAndroid } from 'react-native';
import { BleManager, ScanMode } from 'react-native-ble-plx';
import { Buffer } from 'buffer';

import {
  SERVICE_UUID,
  CHAR_PEER_ID,
  CHAR_PUB_KEY,
  CHAR_DATA,
  MTU_TARGET_ANDROID,
  MTU_TARGET_IOS,
} from './uuids';
import * as Peripheral from '../../modules/ghostnet-ble-peripheral';

const SCAN_OPTIONS = {
  allowDuplicates: true, // keep RSSI fresh for proximity sorting
  scanMode: Platform.OS === 'android' ? ScanMode.LowLatency : undefined,
};

export default class ProximityBLE {
  constructor() {
    this.manager = null;
    this.scanning = false;
    this.radarScanning = false;
    this.advertising = false;
    this._seen = new Map(); // deviceId -> last RSSI/name (dedupe + freshen)
    this._monitors = new Map(); // deviceId -> Subscription
    this._peripheralSubs = [];
    this._listeners = {};
    this._destroyed = false;
  }

  // ── Event plumbing ─────────────────────────────────────────────
  on(event, fn) {
    (this._listeners[event] = this._listeners[event] || []).push(fn);
  }
  _emit(event, data) {
    (this._listeners[event] || []).forEach((fn) => {
      try { fn(data); } catch (e) { /* listener errors never break the radio */ }
    });
  }

  // ── Lifecycle ──────────────────────────────────────────────────
  async init() {
    if (!this.manager) this.manager = new BleManager();
    // Forward peripheral (GATT server) events straight through; the web layer
    // interprets them as the responder side of the handshake.
    if (Peripheral.isAvailable) {
      this._peripheralSubs.push(
        Peripheral.addListener('onCentralWrite', (e) =>
          this._emit('centralWrite', { deviceId: e.deviceId, base64: e.base64 })),
        Peripheral.addListener('onCentralConnected', (e) =>
          this._emit('centralConnected', { deviceId: e.deviceId })),
        Peripheral.addListener('onCentralDisconnected', (e) =>
          this._emit('centralDisconnected', { deviceId: e.deviceId })),
        Peripheral.addListener('onStateChange', (e) =>
          this._emit('peripheralState', { state: e.state })),
        Peripheral.addListener('onError', (e) =>
          this._emit('error', { phase: 'peripheral', message: e.message }))
      );
    }
    return true;
  }

  async requestPermissions() {
    if (Platform.OS !== 'android') return true; // iOS prompts on first BLE use
    const sdk = Platform.Version;
    try {
      if (sdk >= 31) {
        const res = await PermissionsAndroid.requestMultiple([
          PermissionsAndroid.PERMISSIONS.BLUETOOTH_SCAN,
          PermissionsAndroid.PERMISSIONS.BLUETOOTH_ADVERTISE,
          PermissionsAndroid.PERMISSIONS.BLUETOOTH_CONNECT,
        ]);
        return Object.values(res).every((v) => v === PermissionsAndroid.RESULTS.GRANTED);
      }
      // Pre-31: scanning requires fine location.
      const res = await PermissionsAndroid.request(
        PermissionsAndroid.PERMISSIONS.ACCESS_FINE_LOCATION
      );
      return res === PermissionsAndroid.RESULTS.GRANTED;
    } catch (e) {
      this._emit('error', { phase: 'permission', message: e.message });
      return false;
    }
  }

  /**
   * Ghost Radar WiFi scan permissions (Android only). Android gates nearby-AP
   * results behind location, plus NEARBY_WIFI_DEVICES on API 33+. iOS can't scan
   * access points at all, so this is a no-op there.
   */
  async requestWifiPermissions() {
    if (Platform.OS !== 'android') return false;
    try {
      const perms = [PermissionsAndroid.PERMISSIONS.ACCESS_FINE_LOCATION];
      if (Platform.Version >= 33 && PermissionsAndroid.PERMISSIONS.NEARBY_WIFI_DEVICES) {
        perms.push(PermissionsAndroid.PERMISSIONS.NEARBY_WIFI_DEVICES);
      }
      const res = await PermissionsAndroid.requestMultiple(perms);
      return Object.values(res).every((v) => v === PermissionsAndroid.RESULTS.GRANTED);
    } catch (e) {
      this._emit('error', { phase: 'wifiPermission', message: e.message });
      return false;
    }
  }

  /** Adapter power state: 'PoweredOn' | 'PoweredOff' | 'Unauthorized' | ... */
  async adapterState() {
    if (!this.manager) await this.init();
    return this.manager.state();
  }

  async isPeripheralSupported() {
    return Peripheral.isPeripheralSupported();
  }

  // ── Peripheral role (advertise + GATT server) ──────────────────
  async startAdvertising({ peerId, publicKeyHex, pseudonymHex }) {
    if (!Peripheral.isAvailable) {
      this._emit('error', { phase: 'advertise', message: 'Peripheral module unavailable — scan-only' });
      return false;
    }
    const supported = await Peripheral.isPeripheralSupported();
    if (!supported) {
      this._emit('error', { phase: 'advertise', message: 'Advertising unsupported on this device — scan-only' });
      return false;
    }
    await Peripheral.configure({
      peerId: String(peerId || ''),
      publicKeyHex: String(publicKeyHex || ''),
      charPeerIdUuid: CHAR_PEER_ID,
      charPubKeyUuid: CHAR_PUB_KEY,
      charDataUuid: CHAR_DATA,
    });
    const ok = await Peripheral.startAdvertising({ serviceUuid: SERVICE_UUID, pseudonymHex });
    this.advertising = ok;
    return ok;
  }

  async updatePseudonym(pseudonymHex) {
    if (!this.advertising) return;
    await Peripheral.updatePseudonym(pseudonymHex);
  }

  async stopAdvertising() {
    this.advertising = false;
    await Peripheral.stopAdvertising();
  }

  /** Peripheral-side response: notify connected central(s) on CHAR_DATA. */
  async notifyData(base64) {
    await Peripheral.notifyData(base64);
  }

  // ── Central role (scan + GATT client) ──────────────────────────
  startScan() {
    if (!this.manager) throw new Error('init() first');
    if (this.scanning) return;
    this.scanning = true;
    this._seen.clear();

    this.manager.startDeviceScan([SERVICE_UUID], SCAN_OPTIONS, (error, device) => {
      if (error) {
        this.scanning = false;
        this._emit('error', { phase: 'scan', message: error.message });
        return;
      }
      if (!device) return;

      const prev = this._seen.get(device.id);
      const entry = {
        deviceId: device.id,
        name: device.localName || device.name || 'GhostNet Device',
        rssi: device.rssi,
        timestamp: Date.now(),
      };
      this._seen.set(device.id, entry);
      // Emit on first sight; afterwards emit RSSI refreshes so the UI can
      // re-sort by proximity without spamming "new device".
      this._emit(prev ? 'deviceUpdated' : 'deviceFound', entry);
    });
  }

  stopScan() {
    if (this.manager && this.scanning) this.manager.stopDeviceScan();
    this.scanning = false;
  }

  // ── Radar role (UNFILTERED passive scan) ───────────────────────
  // Ghost Radar wants EVERY nearby BLE device, not just GhostNet peers, so it
  // scans with a null UUID filter and reports the richer advertisement payload
  // (manufacturer data + service UUIDs) the radar uses for vendor/category hints.
  // ble-plx allows a single active scan per manager, so this and startScan() are
  // mutually exclusive — callers use one screen at a time.
  startRadarScan() {
    if (!this.manager) throw new Error('init() first');
    if (this.radarScanning) return;
    this.radarScanning = true;

    this.manager.startDeviceScan(null, SCAN_OPTIONS, (error, device) => {
      if (error) {
        this.radarScanning = false;
        this._emit('error', { phase: 'radarScan', message: error.message });
        return;
      }
      if (!device) return;
      // Report only what the radio actually gave us — never invent a name.
      this._emit('radarDevice', {
        deviceId: device.id,
        name: device.localName || device.name || null,
        rssi: typeof device.rssi === 'number' ? device.rssi : null,
        // base64 (ble-plx native encoding) or null; the web layer decodes the
        // 2-byte little-endian company id for vendor mapping.
        manufacturerData: device.manufacturerData || null,
        serviceUUIDs: device.serviceUUIDs || null,
        txPowerLevel: typeof device.txPowerLevel === 'number' ? device.txPowerLevel : null,
        isConnectable: device.isConnectable === true,
        timestamp: Date.now(),
      });
    });
  }

  stopRadarScan() {
    if (this.manager && this.radarScanning) this.manager.stopDeviceScan();
    this.radarScanning = false;
  }

  async connect(deviceId) {
    if (!this.manager) throw new Error('init() first');
    const device = await this.manager.connectToDevice(deviceId, { requestMTU: this._mtuTarget() });
    await device.discoverAllServicesAndCharacteristics();
    try {
      // Some stacks ignore connect-time MTU; request again post-discovery.
      await device.requestMTU(this._mtuTarget());
    } catch (_) { /* MTU is best-effort */ }

    const sub = device.onDisconnected((err, d) => {
      this._teardownMonitor(deviceId);
      this._emit('disconnected', { deviceId, error: err ? err.message : null });
    });
    this._monitors.set(deviceId + ':disc', sub);
    return { deviceId, mtu: device.mtu };
  }

  async disconnect(deviceId) {
    this._teardownMonitor(deviceId);
    try { await this.manager.cancelDeviceConnection(deviceId); } catch (_) {}
  }

  /** Read a characteristic; returns base64. */
  async read(deviceId, charUuid) {
    const ch = await this.manager.readCharacteristicForDevice(deviceId, SERVICE_UUID, charUuid);
    return ch.value || '';
  }

  /** Write base64 to a characteristic (with response). */
  async write(deviceId, charUuid, base64) {
    await this.manager.writeCharacteristicWithResponseForDevice(
      deviceId, SERVICE_UUID, charUuid, base64
    );
    return true;
  }

  /** Subscribe to notifications on CHAR_DATA; emits 'notification'. */
  startNotifications(deviceId, charUuid = CHAR_DATA) {
    const key = deviceId + ':' + charUuid;
    if (this._monitors.has(key)) return;
    const sub = this.manager.monitorCharacteristicForDevice(
      deviceId, SERVICE_UUID, charUuid,
      (error, ch) => {
        if (error) {
          this._emit('error', { phase: 'notify', message: error.message, deviceId });
          return;
        }
        if (ch && ch.value) {
          this._emit('notification', { deviceId, charUuid, base64: ch.value });
        }
      }
    );
    this._monitors.set(key, sub);
  }

  _teardownMonitor(deviceId) {
    for (const [key, sub] of [...this._monitors.entries()]) {
      if (key.startsWith(deviceId)) {
        try { sub.remove(); } catch (_) {}
        this._monitors.delete(key);
      }
    }
  }

  _mtuTarget() {
    return Platform.OS === 'android' ? MTU_TARGET_ANDROID : MTU_TARGET_IOS;
  }

  // ── Encoding helpers used by the bridge ────────────────────────
  static utf8ToBase64(str) {
    return Buffer.from(str, 'utf8').toString('base64');
  }
  static base64ToUtf8(b64) {
    return Buffer.from(b64, 'base64').toString('utf8');
  }

  async destroy() {
    this._destroyed = true;
    this.stopScan();
    this.stopRadarScan();
    try { await this.stopAdvertising(); } catch (_) {}
    for (const sub of this._peripheralSubs) { try { sub.remove(); } catch (_) {} }
    this._peripheralSubs = [];
    for (const [, sub] of this._monitors) { try { sub.remove(); } catch (_) {} }
    this._monitors.clear();
    if (this.manager) { try { this.manager.destroy(); } catch (_) {} this.manager = null; }
  }
}
