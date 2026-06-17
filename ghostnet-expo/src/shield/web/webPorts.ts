/**
 * Ghost Shield — WEB (browser test surface) platform adapters.
 *
 * HONESTY CONTRACT FOR WEB (read before editing):
 *   A plain browser is the *test* surface, not the phone. Hardware-dependent
 *   capabilities are simply NOT reachable from a web page, and these adapters say
 *   so by returning the unsupported/unavailable flags — they NEVER fake the phone.
 *   The Shield modules then report `unavailable`/`degraded` with a real reason.
 *
 *   - BLE: no BLE stack in a browser → {@link WebBleAdapter.isAvailable} is false.
 *     BleCloak and the BLE-shape part of node-id rotation report unavailable.
 *   - DNS over HTTPS: the app CAN route its own name lookups through a DoH JSON
 *     resolver via fetch, so DoH is supported — but a browser exposes no ECH
 *     control, so DnsGuard honestly reports the residual SNI leak as degraded.
 *   - Mesh overlay (node-id rotation, min-hops, decoy + cover traffic): these are
 *     pure-overlay behaviors the app fully owns, so they run for real on web when
 *     the GhostNet mesh is wired; min-hop enforcement degrades honestly if the
 *     mesh transport is not present.
 *   - Co-resident / device-integrity: a browser cannot observe OS screen capture
 *     or detect root/jailbreak, so those report unsupported/UNKNOWN — never safe.
 *
 * There is intentionally NO MAC rotation and NO "WiFi probe suppression" here or
 * anywhere: an app (web OR native, rooted or not) cannot change the hardware MAC
 * or suppress the OS radio's probes. The real anti-tracking behavior is overlay
 * node-id rotation (see NodeIdRotator).
 */

import { createLogger } from '../logger';
import type {
  AdvertisingParameters,
  BleAdapter,
  CoResidentAdapter,
  DecoyAnnouncement,
  DnsAdapter,
  DnsMode,
  MacRandomizationResult,
  MeshAdapter,
  MeshFrame,
  OutboundTransform,
  ShieldLogger,
  ShieldPorts,
  WifiSuggestionAdapter,
} from '../types';
import type {
  AttestationBackend,
  AttestationProvider,
  IntegrityPort,
  LocalSignalProbe,
  Platform,
} from '../integrity/types';
import { SystemClock, WebCryptoRandom, WebSecureStore } from './runtime';

/* ── BLE: unavailable in a browser ───────────────────────────────────────── */

/**
 * There is no BLE stack reachable from a web page, so every probe is honest-false
 * and every action is a no-op that NEVER reports success. BleCloak turns this into
 * an `unavailable` capability report (active:false) with REASON.BLE_UNAVAILABLE.
 */
export class WebBleAdapter implements BleAdapter {
  isAvailable(): boolean {
    return false;
  }
  supportsAdvertisingControl(): boolean {
    return false;
  }
  async stopAdvertising(): Promise<void> {
    /* no BLE radio in a browser */
  }
  async startAdvertising(): Promise<void> {
    /* no BLE radio in a browser */
  }
  async setDiscoveryBeaconEnabled(): Promise<void> {
    /* no BLE radio in a browser */
  }
  async setAdvertisedNodeId(): Promise<void> {
    /* no BLE radio in a browser */
  }
  supportsAdvertisingParams(): boolean {
    return false;
  }
  async setAdvertisingParameters(_params: AdvertisingParameters): Promise<void> {
    void _params;
  }
}

/* ── Wi-Fi suggestions: no API in a browser ──────────────────────────────── */

/**
 * A web page cannot register Wi-Fi network suggestions or set any MAC-randomization
 * policy, so every probe is honest-false and apply is a no-op that NEVER reports
 * active. MacRandomizer turns this into an `unavailable` report (active:false) with
 * REASON.MAC_RANDO_UNAVAILABLE. There is no MAC value here to read, set, or log.
 */
export class WebWifiSuggestAdapter implements WifiSuggestionAdapter {
  isAvailable(): boolean {
    return false;
  }
  supportsNonPersistentRandomization(): boolean {
    return false;
  }
  async applyNonPersistentMacRandomization(): Promise<MacRandomizationResult> {
    return { requested: true, active: false, reason: 'web_test_context' };
  }
  async clearSuggestions(): Promise<void> {
    /* no suggestion API in a browser */
  }
}

/* ── DNS: app-level DoH JSON over fetch; no ECH control in a browser ──────── */

type FetchLike = (input: string, init?: { headers?: Record<string, string> }) => Promise<{ ok: boolean }>;

/**
 * Routes GhostNet's OWN hostname lookups through a DoH JSON resolver (RFC 8484
 * application/dns-json) using fetch. This hides the DNS *query* from the local
 * network. It does NOT — and honestly cannot from a browser — give us ECH, so the
 * TLS SNI of the connections that follow still leaks the destination host; DnsGuard
 * surfaces that residual leak as `degraded` (REASON.SNI_LEAK_NO_ECH).
 */
export class WebDnsAdapter implements DnsAdapter {
  private mode: DnsMode = 'system';
  private resolver = '';
  private plaintextBlocked = false;
  constructor(private readonly fetchFn: FetchLike = defaultFetch()) {}

  supportsDoh(): boolean {
    return true;
  }
  async setMode(mode: DnsMode, dohResolver: string): Promise<void> {
    this.mode = mode;
    this.resolver = dohResolver;
  }
  async probe(dohResolver: string): Promise<boolean> {
    try {
      const resp = await this.fetchFn(`${dohResolver}?name=cloudflare.com&type=A`, {
        headers: { Accept: 'application/dns-json' },
      });
      return resp.ok;
    } catch {
      return false;
    }
  }
  async setPlaintextBlocked(blocked: boolean): Promise<void> {
    // A web page cannot block the browser's own resolver; we only flag intent so
    // the app routes its app-level lookups through DoH. The honest residual risk
    // (other page traffic, SNI) is reported by DnsGuard, not hidden here.
    this.plaintextBlocked = blocked;
  }
  supportsEch(): boolean {
    // Browsers do not expose Encrypted Client Hello control to page JS.
    return false;
  }
  /** Current DoH mode (for status display/tests). */
  get currentMode(): DnsMode {
    return this.mode;
  }
  get isPlaintextBlocked(): boolean {
    return this.plaintextBlocked;
  }
  get currentResolver(): string {
    return this.resolver;
  }
}

function defaultFetch(): FetchLike {
  const f = (globalThis as { fetch?: FetchLike }).fetch;
  if (f) return f.bind(globalThis);
  // No fetch (non-browser test) → always-unreachable probe; DnsGuard fail-closes.
  return async () => ({ ok: false });
}

/* ── Mesh overlay: node-id rotation + min-hops + decoy/cover frames ───────── */

/**
 * What the Shield needs from the live GhostNet mesh. The real app wires this from
 * `window.app.mesh`; when it is absent (pure web playground) the adapter still
 * tracks overlay identity internally and reports hop-control as unsupported.
 */
export interface MeshBridge {
  getNodeId?(): string;
  send?(frame: { bytes: Uint8Array; to: string | null }): void;
  getActiveSessions?(): readonly string[];
  setMinHops?(hops: number): void;
  supportsMinHops?(): boolean;
  adoptNodeId?(newId: string): void;
  retireNodeId?(oldId: string): void;
  sendNodeIdHandoff?(peerId: string, oldId: string, newId: string): void;
  announceDecoy?(announcement: { ephemeralId: string; payload: Uint8Array }): void;
}

export class WebMeshAdapter implements MeshAdapter {
  private transform: OutboundTransform | null = null;
  private nodeId: string;
  /** Honest activity counters the facade surfaces as real stats. */
  framesSent = 0;
  decoysSent = 0;
  nodeIdRotations = 0;
  minHops = 0;

  constructor(
    private readonly bridge: MeshBridge = {},
    private readonly random: WebCryptoRandom = new WebCryptoRandom(),
  ) {
    this.nodeId = bridge.getNodeId?.() ?? bytesToHex(this.random.bytes(16));
  }

  getCurrentNodeId(): string {
    return this.bridge.getNodeId?.() ?? this.nodeId;
  }
  setOutboundTransform(transform: OutboundTransform | null): void {
    this.transform = transform;
  }
  async sendRaw(frame: MeshFrame): Promise<void> {
    const out = this.transform ? this.transform(frame) : frame;
    this.bridge.send?.({ bytes: out.bytes, to: out.to });
    this.framesSent++;
  }
  getActiveSessions(): readonly string[] {
    return this.bridge.getActiveSessions?.() ?? [];
  }
  supportsHopControl(): boolean {
    // Min-hop enforcement genuinely requires the mesh router. If the bridge does
    // not expose it, MeshRouting reports degraded rather than faking extra hops.
    return typeof this.bridge.setMinHops === 'function' && (this.bridge.supportsMinHops?.() ?? true);
  }
  async setMinHops(hops: number): Promise<void> {
    this.minHops = hops;
    this.bridge.setMinHops?.(hops);
  }
  supportsNodeIdRotation(): boolean {
    // The advertised overlay node id is pure application state the app owns, so
    // rotating it is genuinely achievable on web (this is the REAL anti-tracking
    // behavior — never the hardware MAC).
    return true;
  }
  async sendNodeIdHandoff(peerId: string, oldId: string, newId: string): Promise<void> {
    this.bridge.sendNodeIdHandoff?.(peerId, oldId, newId);
  }
  async adoptNodeId(newId: string): Promise<void> {
    this.nodeId = newId;
    this.bridge.adoptNodeId?.(newId);
    this.nodeIdRotations++;
  }
  async retireNodeId(oldId: string): Promise<void> {
    this.bridge.retireNodeId?.(oldId);
  }
  async announceDecoyPeer(announcement: DecoyAnnouncement): Promise<void> {
    this.bridge.announceDecoy?.({ ephemeralId: announcement.ephemeralId, payload: announcement.payload });
    this.decoysSent++;
  }
}

/* ── Co-resident: a browser cannot observe OS screen capture / a11y ──────── */

/**
 * A web page cannot tell whether the OS or another app is recording the screen,
 * nor enumerate accessibility services. Both detections report unsupported, so
 * CoResidentGuard reports `degraded` (ONDEVICE_DETECTION_UNSUPPORTED) rather than
 * implying the screen is private. Clipboard clearing IS available via the async
 * clipboard API (best-effort).
 */
export class WebCoResidentAdapter implements CoResidentAdapter {
  supportsScreenCaptureDetection(): boolean {
    return false;
  }
  isScreenCaptured(): boolean {
    return false;
  }
  subscribeScreenCapture(_cb: (captured: boolean) => void): () => void {
    void _cb;
    return () => undefined;
  }
  supportsAccessibilityDetection(): boolean {
    return false;
  }
  isAccessibilityServiceActive(): boolean {
    return false;
  }
  async clearClipboard(): Promise<void> {
    try {
      const nav = (globalThis as { navigator?: { clipboard?: { writeText(s: string): Promise<void> } } }).navigator;
      await nav?.clipboard?.writeText('');
    } catch {
      /* best-effort; clipboard write can reject without focus/permission */
    }
  }
}

/* ── Device integrity: not determinable from a browser → UNKNOWN ─────────── */

/**
 * A browser cannot run root/jailbreak heuristics (no filesystem/native probes)
 * and has no Play Integrity / App Attest. Local signals all read "clean" (score
 * 0) and attestation is unsupported, so DeviceIntegrity computes UNKNOWN — the
 * honest fail-toward-caution verdict — never TRUSTED.
 */
class WebLocalSignalProbe implements LocalSignalProbe {
  platform(): Platform {
    return 'android'; // arbitrary; no signals fire, so the value is inconsequential
  }
  fileExists(): boolean {
    return false;
  }
  canWrite(): boolean {
    return false;
  }
  getSystemProp(): string | null {
    return null;
  }
  packageInstalled(): boolean {
    return false;
  }
  isPortOpen(): boolean {
    return false;
  }
  loadedLibraries(): readonly string[] {
    return [];
  }
  canOpenUrlScheme(): boolean {
    return false;
  }
  forkSucceeds(): boolean {
    return false;
  }
  buildFingerprint(): string {
    return 'web/browser';
  }
}

class WebAttestationProvider implements AttestationProvider {
  isSupported(): boolean {
    return false; // no Play Integrity / App Attest in a browser
  }
  async getToken(): Promise<string> {
    throw new Error('attestation unsupported in web context');
  }
}

class WebAttestationBackend implements AttestationBackend {
  async requestNonce(): Promise<string> {
    throw new Error('attestation backend not reachable from web context');
  }
  async verify(): Promise<{ verdict: 'PASS' | 'FAIL' }> {
    throw new Error('attestation backend not reachable from web context');
  }
}

export function createWebIntegrity(): IntegrityPort {
  return {
    probe: new WebLocalSignalProbe(),
    provider: new WebAttestationProvider(),
    backend: new WebAttestationBackend(),
  };
}

/* ── Bundle ──────────────────────────────────────────────────────────────── */

export interface WebPortsOptions {
  readonly meshBridge?: MeshBridge;
  readonly fetchFn?: FetchLike;
  readonly logger?: ShieldLogger;
}

/**
 * Ports shared by both host profiles (web + native). Specializes only `mesh` to
 * the concrete {@link WebMeshAdapter} so the facade can read its honest activity
 * counters; everything else stays at the base interfaces so each profile can
 * supply its own BLE adapter (web no-op vs Capacitor bridge).
 */
export interface ShieldHostPorts extends ShieldPorts {
  readonly mesh: WebMeshAdapter;
}

export interface WebPorts extends ShieldHostPorts {
  readonly ble: WebBleAdapter;
  readonly dns: WebDnsAdapter;
  readonly wifi: WebWifiSuggestAdapter;
}

/** Assemble the honest web (browser test) port set. */
export function createWebPorts(options: WebPortsOptions = {}): WebPorts {
  const random = new WebCryptoRandom();
  return {
    ble: new WebBleAdapter(),
    dns: new WebDnsAdapter(options.fetchFn),
    mesh: new WebMeshAdapter(options.meshBridge ?? {}, random),
    coResident: new WebCoResidentAdapter(),
    wifi: new WebWifiSuggestAdapter(),
    integrity: createWebIntegrity(),
    store: new WebSecureStore(),
    clock: new SystemClock(),
    random,
    log: options.logger ?? createLogger({ enabled: false }),
  };
}

function bytesToHex(bytes: Uint8Array): string {
  let s = '';
  for (const b of bytes) s += b.toString(16).padStart(2, '0');
  return s;
}
