/**
 * Ghost Shield — NATIVE (Capacitor WebView, i.e. the phone) platform adapters.
 *
 * The SAME bundle runs in a plain browser (web test) and inside the phone's
 * Capacitor WebView. {@link detectPlatform} picks this profile only when
 * Capacitor reports a native platform. Here the hardware-backed features can run
 * for real — but ONLY when the corresponding native bridge actually resolves.
 *
 * HONESTY CONTRACT FOR NATIVE:
 *   - BLE: if the native BLE bridge (the @capacitor-community/bluetooth-le plugin,
 *     wired by the host) is present, BLE is available and we drive Kryptos's own
 *     advertising for real. If the plugin FAILS TO RESOLVE, {@link CapacitorBleAdapter.isAvailable}
 *     is false and BleCloak reports `unavailable` — we never print "emitting decoy
 *     BLE profiles" while the BLE module is missing.
 *   - DNS over HTTPS, mesh overlay (node-id rotation, min-hops, decoy/cover
 *     traffic): these are JS/overlay behaviors that work the same inside the
 *     WebView, so they reuse the web adapters and run for real.
 *   - Co-resident / device integrity: real detection needs native plugins. Until
 *     those bridges are wired, they report unsupported/UNKNOWN — honest, not safe.
 *
 * There is NO MAC rotation and NO WiFi-probe suppression on native either: even a
 * native, non-rooted app cannot change the hardware MAC or silence the OS radio's
 * probe requests. Overlay node-id rotation is the real behavior.
 */

import { createLogger } from '../logger';
import type {
  AdvertisingParameters,
  BleAdapter,
  CoResidentAdapter,
  MacRandomizationResult,
  ShieldLogger,
  WifiSuggestionAdapter,
} from '../types';
import type { AttestationProvider, IntegrityPort, LocalSignalProbe, Platform } from '../integrity/types';
import { SystemClock, WebCryptoRandom, WebSecureStore } from './runtime';
import {
  WebCoResidentAdapter,
  WebDnsAdapter,
  WebMeshAdapter,
  createWebIntegrity,
  type MeshBridge,
  type ShieldHostPorts,
} from './webPorts';

/**
 * What the Shield needs from the host's native BLE plugin wiring. The host app
 * implements this against @capacitor-community/bluetooth-le; if it is not wired
 * (or the plugin failed to load) the adapter treats BLE as unavailable.
 */
export interface NativeBleBridge {
  /** True once the native plugin has resolved and initialized successfully. */
  isReady(): boolean;
  supportsAdvertisingControl(): boolean;
  supportsAdvertisingParams(): boolean;
  stopAdvertising(): Promise<void>;
  startAdvertising(): Promise<void>;
  setDiscoveryBeaconEnabled(enabled: boolean): Promise<void>;
  setAdvertisedNodeId(nodeId: string): Promise<void>;
  setAdvertisingParameters(params: AdvertisingParameters): Promise<void>;
}

/**
 * BLE adapter backed by the host's native bridge. Capability flags reflect the
 * bridge's REAL readiness: a missing/failed plugin reports unavailable rather than
 * pretending the radio responded.
 */
export class CapacitorBleAdapter implements BleAdapter {
  constructor(
    private readonly bridge: NativeBleBridge | null,
    private readonly log: ShieldLogger,
  ) {}

  isAvailable(): boolean {
    return this.bridge?.isReady() === true;
  }
  supportsAdvertisingControl(): boolean {
    return this.isAvailable() && this.bridge!.supportsAdvertisingControl();
  }
  async stopAdvertising(): Promise<void> {
    if (this.isAvailable()) await this.bridge!.stopAdvertising();
  }
  async startAdvertising(): Promise<void> {
    if (this.isAvailable()) await this.bridge!.startAdvertising();
  }
  async setDiscoveryBeaconEnabled(enabled: boolean): Promise<void> {
    if (this.isAvailable()) await this.bridge!.setDiscoveryBeaconEnabled(enabled);
  }
  async setAdvertisedNodeId(nodeId: string): Promise<void> {
    if (this.isAvailable()) await this.bridge!.setAdvertisedNodeId(nodeId);
  }
  supportsAdvertisingParams(): boolean {
    return this.isAvailable() && this.bridge!.supportsAdvertisingParams();
  }
  async setAdvertisingParameters(params: AdvertisingParameters): Promise<void> {
    if (this.supportsAdvertisingParams()) await this.bridge!.setAdvertisingParameters(params);
  }
}

/* ── Native Wi-Fi network suggestions (MAC randomization policy) ──────────── */

/**
 * What the Shield needs from the host's native Wi-Fi-suggestion wiring. The host
 * implements this against the `kryptos-wifi-suggest` Expo module: it knows the
 * platform/API level (so the sync probes are honest) and which networks are
 * Kryptos's OWN mesh/relay networks (so apply only ever touches those). On iOS or
 * a build without the module, the host either omits the bridge or returns
 * isReady()=false, and the adapter reports unavailable.
 */
export interface NativeWifiSuggestBridge {
  /** True once the native suggestion module has resolved (Android, linked). */
  isReady(): boolean;
  /** Android 12+ (API 31+) — can NON_PERSISTENT randomization be set on a suggestion? */
  supportsNonPersistentRandomization(): boolean;
  /** Apply the policy to Kryptos's OWN mesh/relay networks. The host supplies the
   *  network list; the Shield never enumerates the user's saved networks. */
  applyNonPersistentMacRandomization(): Promise<MacRandomizationResult>;
  /** Withdraw Kryptos's network suggestions. */
  clearSuggestions(): Promise<void>;
}

/**
 * Wi-Fi-suggestion adapter backed by the host's native bridge. Capability flags
 * reflect the bridge's REAL readiness and API level: a missing module or pre-12
 * Android reports the honest unavailable/unsupported state rather than pretending
 * a randomized MAC is in effect. Never reads, sets, or logs a MAC value.
 */
export class CapacitorWifiSuggestAdapter implements WifiSuggestionAdapter {
  constructor(private readonly bridge: NativeWifiSuggestBridge | null) {}

  isAvailable(): boolean {
    return this.bridge?.isReady() === true;
  }
  supportsNonPersistentRandomization(): boolean {
    return this.isAvailable() && this.bridge!.supportsNonPersistentRandomization();
  }
  async applyNonPersistentMacRandomization(): Promise<MacRandomizationResult> {
    if (!this.isAvailable()) {
      return { requested: true, active: false, reason: 'native_module_not_resolved' };
    }
    return this.bridge!.applyNonPersistentMacRandomization();
  }
  async clearSuggestions(): Promise<void> {
    if (this.isAvailable()) await this.bridge!.clearSuggestions();
  }
}

/* ── Native device integrity (optional bridge; UNKNOWN until wired) ───────── */

export interface NativeIntegrityBridge {
  readonly probe: LocalSignalProbe;
  readonly provider: AttestationProvider;
}

/* ── Optional global wiring the host can attach to the WebView ────────────── */

interface NativeGlobals {
  GhostNativeBle?: NativeBleBridge;
  GhostNativeCoResident?: CoResidentAdapter;
  GhostNativeIntegrity?: IntegrityPort;
  GhostNativeWifiSuggest?: NativeWifiSuggestBridge;
  app?: { mesh?: MeshBridge };
}

export interface NativePortsOptions {
  readonly bleBridge?: NativeBleBridge | null;
  readonly meshBridge?: MeshBridge;
  readonly coResident?: CoResidentAdapter;
  readonly integrity?: IntegrityPort;
  readonly wifiBridge?: NativeWifiSuggestBridge | null;
  readonly logger?: ShieldLogger;
  readonly globalRef?: NativeGlobals;
}

/**
 * Assemble the native port set. Hardware-backed adapters are taken from host
 * bridges if present; anything not wired falls back to the honest "unavailable"
 * web adapter so a missing plugin degrades rather than fabricates.
 */
export function createNativePorts(options: NativePortsOptions = {}): ShieldHostPorts {
  const g = options.globalRef ?? (globalThis as NativeGlobals);
  const log = options.logger ?? createLogger({ enabled: false });
  const random = new WebCryptoRandom();

  const bleBridge = options.bleBridge ?? g.GhostNativeBle ?? null;
  const ble = new CapacitorBleAdapter(bleBridge, log);

  // Co-resident + integrity use native bridges when wired; otherwise the honest
  // unsupported/UNKNOWN web adapters (never "safe").
  const coResident = options.coResident ?? g.GhostNativeCoResident ?? new WebCoResidentAdapter();
  const integrity = options.integrity ?? g.GhostNativeIntegrity ?? createWebIntegrity();

  const meshBridge = options.meshBridge ?? g.app?.mesh ?? {};
  const mesh = new WebMeshAdapter(meshBridge, random);

  // Wi-Fi network suggestions (MAC-randomization policy). Backed by the host's
  // native bridge when wired; absent/iOS/old-Android degrade honestly via the adapter.
  const wifiBridge = options.wifiBridge ?? g.GhostNativeWifiSuggest ?? null;
  const wifi = new CapacitorWifiSuggestAdapter(wifiBridge);

  return {
    ble,
    dns: new WebDnsAdapter(),
    mesh,
    coResident,
    wifi,
    integrity,
    store: new WebSecureStore(),
    clock: new SystemClock(),
    random,
    log,
  };
}
