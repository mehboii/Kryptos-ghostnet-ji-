/**
 * Ghost Shield — shared types.
 *
 * Ghost Shield is a cumulative privacy state machine: OFF ⊂ STEALTH ⊂ GHOST ⊂
 * PHANTOM ⊂ FULL_GHOST. Each higher tier enables everything below it plus more.
 *
 * PLATFORM HONESTY (read this before touching a module):
 *   This runs on unprivileged iOS / non-rooted Android. We CANNOT change the
 *   hardware WiFi/BLE MAC and CANNOT suppress the OS radio's own probe requests.
 *   Everything here operates on GhostNet's *overlay* identity — the node id /
 *   advertised service payload an observer correlates on — never the hardware.
 *   Every module reports what it actually achieved via {@link CapabilityReport}
 *   and sets `degraded: true` (with a reason) when it can only run a subset.
 *   A module must never silently no-op and report success.
 */

/**
 * Cloaking tiers, in cumulative order. String values are stable identifiers
 * used for persistence — do not renumber or reorder without a migration.
 */
export enum ShieldTier {
  OFF = 'OFF',
  STEALTH = 'STEALTH',
  GHOST = 'GHOST',
  PHANTOM = 'PHANTOM',
  /** PHANTOM with every knob at max + cover traffic always-on (panic preset). */
  FULL_GHOST = 'FULL_GHOST',
}

/** Monotonic rank for cumulative comparisons. Higher = more cloaked. */
export const TIER_RANK: Readonly<Record<ShieldTier, number>> = {
  [ShieldTier.OFF]: 0,
  [ShieldTier.STEALTH]: 1,
  [ShieldTier.GHOST]: 2,
  [ShieldTier.PHANTOM]: 3,
  [ShieldTier.FULL_GHOST]: 4,
};

/** Stable identifiers for the Shield modules. */
export enum ModuleId {
  BleCloak = 'ble-cloak',
  DnsGuard = 'dns-guard',
  TrafficShaper = 'traffic-shaper',
  MeshRouting = 'mesh-routing',
  DecoyEngine = 'decoy-engine',
  NodeIdRotator = 'node-id-rotator',
  CoResidentGuard = 'co-resident-guard',
}

/** Cover-traffic policy. `adaptive` ramps in/out so toggling Shield is not a
 *  distinct on/off traffic signature; `always` keeps a constant floor. */
export type CoverTrafficMode = 'off' | 'adaptive' | 'always';

/** DNS handling. `doh` forces DNS-over-HTTPS; `system` is the OS resolver. */
export type DnsMode = 'system' | 'doh';

/**
 * Fully-resolved configuration for a tier. Produced in exactly one place
 * ({@link resolveConfig}) so the cumulative tier→behavior mapping cannot drift
 * between modules. Each module reads only its own slice.
 */
export interface ShieldConfig {
  readonly tier: ShieldTier;
  readonly ble: {
    /** Stop GhostNet's own BLE advertising. */
    readonly silenceAdvertising: boolean;
    /** Stop GhostNet's own active discovery beaconing (not the OS radio). */
    readonly silenceDiscoveryBeacon: boolean;
  };
  readonly dns: {
    readonly mode: DnsMode;
    readonly dohResolver: string;
    /** If DoH is unreachable, block plaintext DNS rather than falling back. */
    readonly failClosed: boolean;
  };
  readonly traffic: {
    readonly enabled: boolean;
    /** Ascending byte buckets; ciphertext is padded up to the next one. */
    readonly paddingBuckets: readonly number[];
    readonly jitterMinMs: number;
    readonly jitterMaxMs: number;
    readonly coverTraffic: CoverTrafficMode;
    /** Target dummy-frame rate (frames/min) when cover traffic is active. */
    readonly coverRatePerMin: number;
  };
  readonly mesh: {
    readonly enforceMinHops: boolean;
    readonly minHops: number;
  };
  readonly decoy: {
    readonly enabled: boolean;
    readonly minDecoys: number;
    readonly maxDecoys: number;
  };
  readonly nodeIdRotation: {
    readonly enabled: boolean;
    readonly minIntervalMs: number;
    readonly maxIntervalMs: number;
    /** Grace window an old id stays valid after a rotation, for session handoff. */
    readonly handoffGraceMs: number;
    /** Also re-randomize BLE advertising interval + payload length per rotation. */
    readonly randomizeAdvertising: boolean;
  };
  readonly coResident: {
    /** Monitor on-device observation risks (screen capture, a11y, clipboard). */
    readonly enabled: boolean;
    /** Clear the clipboard this long after a guarded sensitive copy. */
    readonly clipboardClearMs: number;
  };
}

/**
 * What a module actually achieved. The honesty contract: `requested` is what
 * the tier asked for, `active` is whether the module is doing real work, and
 * `degraded` flags that it could only run an achievable subset. `reason` is a
 * short, identifier-free code (never a node id, peer id, or address).
 */
export interface CapabilityReport {
  readonly id: ModuleId;
  /** Did the active tier ask this module to be on? */
  readonly requested: boolean;
  /** Is the module currently performing its function (possibly degraded)? */
  readonly active: boolean;
  /** True when running a reduced subset of the requested behavior. */
  readonly degraded: boolean;
  /** Short, redacted reason code for degraded/inactive state. No identifiers. */
  readonly reason?: string;
}

/** Every Shield module implements this. `enable` is idempotent: calling it again
 *  with a new config reconfigures in place. A thrown error from `enable` is a
 *  hard failure and triggers a tier rollback; a resolved (even degraded) report
 *  is a success. */
export interface ShieldModule {
  readonly id: ModuleId;
  enable(cfg: ShieldConfig): Promise<CapabilityReport>;
  disable(): Promise<void>;
  report(): CapabilityReport;
}

/** Snapshot returned by the manager. `stable` is false only mid-transition. */
export interface ShieldStatus {
  readonly tier: ShieldTier;
  readonly stable: boolean;
  readonly degraded: boolean;
  readonly modules: readonly CapabilityReport[];
}

export type ShieldEvent = 'tierChanged' | 'degraded';

export interface TierChangedPayload {
  readonly from: ShieldTier;
  readonly to: ShieldTier;
  readonly status: ShieldStatus;
}

export interface DegradedPayload {
  readonly tier: ShieldTier;
  /** Which modules reported degraded/inactive, with reasons. */
  readonly reports: readonly CapabilityReport[];
  /** True when the transition could not reach the target and rolled back. */
  readonly rolledBack: boolean;
}

/* ────────────────────────────────────────────────────────────────────────────
 * Platform ports (adapters).
 *
 * The Shield core depends only on these interfaces, never on react-native-ble-plx,
 * expo-secure-store, or the mesh transport directly. The host app wires real
 * implementations; tests inject fakes. This is what makes capability detection
 * honest (we probe the adapter) and the logic unit-testable off-device.
 * ──────────────────────────────────────────────────────────────────────────── */

/** A frame handed to the mesh for transmission. Opaque bytes to the Shield. */
export interface MeshFrame {
  /** Opaque, already-encrypted payload (the Shield never sees plaintext). */
  readonly bytes: Uint8Array;
  /** Routing destination (overlay node id) or null for broadcast/cover. */
  readonly to: string | null;
}

/** Transforms an outbound frame (e.g. length-padding). Returns the frame(s) to
 *  actually send, in order. Must be a pure, order-preserving function. */
export type OutboundTransform = (frame: MeshFrame) => MeshFrame;

/** Tunable advertising shape, re-randomized per node-id rotation so cadence and
 *  size don't become a stable fingerprint of "the GhostNet app". */
export interface AdvertisingParameters {
  /** Advertising interval in ms. Should be drawn from OS-default ranges. */
  readonly intervalMs: number;
  /** Advertised payload (scan-response) length in bytes, within legal bounds. */
  readonly payloadLength: number;
}

export interface BleAdapter {
  /** Does this platform/build expose programmatic BLE advertising control? */
  supportsAdvertisingControl(): boolean;
  stopAdvertising(): Promise<void>;
  startAdvertising(): Promise<void>;
  /** Toggle GhostNet's own active discovery beaconing. */
  setDiscoveryBeaconEnabled(enabled: boolean): Promise<void>;
  /** Set the overlay node id embedded in our advertisement payload. */
  setAdvertisedNodeId(nodeId: string): Promise<void>;
  /** Can this platform vary the advertising interval + payload length? Android
   *  exposes advertise modes; iOS CoreBluetooth fixes these (so: false). */
  supportsAdvertisingParams(): boolean;
  /** Apply a new advertising interval + payload length. */
  setAdvertisingParameters(params: AdvertisingParameters): Promise<void>;
}

export interface DnsAdapter {
  /** Can this platform route DNS through an app-controlled DoH resolver? */
  supportsDoh(): boolean;
  /** Point the resolver at DoH (or back to system). */
  setMode(mode: DnsMode, dohResolver: string): Promise<void>;
  /** Reachability probe for a DoH resolver. Resolves false if unreachable. */
  probe(dohResolver: string): Promise<boolean>;
  /** Block plaintext DNS entirely (fail-closed). */
  setPlaintextBlocked(blocked: boolean): Promise<void>;
  /**
   * Is Encrypted Client Hello available for outbound TLS on this platform/build?
   * DoH hides the DNS *query*, but without ECH the TLS SNI of the connections
   * that follow still leaks the destination hostname to an on-path observer.
   */
  supportsEch(): boolean;
}

export interface MeshAdapter {
  getCurrentNodeId(): string;
  /** Install/clear the outbound length-padding transform. */
  setOutboundTransform(transform: OutboundTransform | null): void;
  /**
   * Send a frame. CONTRACT: the installed {@link OutboundTransform} (if any) is
   * applied by the mesh before transmission, identically for every outbound
   * frame — real, jittered, or cover — so they are all bucketed the same way and
   * a caller never pre-pads. Used for cover traffic + the shaper's jittered sends.
   */
  sendRaw(frame: MeshFrame): Promise<void>;
  /** List overlay ids of peers with an established (encrypted) session. */
  getActiveSessions(): readonly string[];
  /** Does the mesh expose outbound min-hop enforcement? */
  supportsHopControl(): boolean;
  setMinHops(hops: number): Promise<void>;
  /** Does the mesh support advertising a rotated overlay node id? */
  supportsNodeIdRotation(): boolean;
  /**
   * Send an authenticated old→new id handoff to one established peer over the
   * existing encrypted channel, so the peer remaps before the old id expires.
   */
  sendNodeIdHandoff(peerId: string, oldId: string, newId: string): Promise<void>;
  /** Begin advertising/answering on a freshly rotated overlay node id. */
  adoptNodeId(newId: string): Promise<void>;
  /** Stop honoring an expired overlay node id after the handoff grace window. */
  retireNodeId(oldId: string): Promise<void>;
  /** Inject a decoy peer announcement into the mesh. Carries no real payload. */
  announceDecoyPeer(announcement: DecoyAnnouncement): Promise<void>;
}

/** A fabricated peer announcement. Unlinkable to the real node, carries no
 *  payload, and never embeds the real node id. */
export interface DecoyAnnouncement {
  /** Random ephemeral overlay id, distinct from the real node id. */
  readonly ephemeralId: string;
  /** Plausible advertised capabilities blob (random, well-formed). */
  readonly payload: Uint8Array;
}

/**
 * On-device observation surface. All detection here is best-effort and racy on
 * an unprivileged app — it raises the cost of casual on-device snooping, it is
 * NOT a defense against a rooted/compromised device (see THREAT_MODEL.md #6).
 */
export interface CoResidentAdapter {
  /** Can we observe screen-capture state (iOS UIScreen.isCaptured / Android MediaProjection)? */
  supportsScreenCaptureDetection(): boolean;
  /** Is the screen currently being recorded/captured/mirrored? */
  isScreenCaptured(): boolean;
  /** Subscribe to screen-capture state changes. Returns an unsubscribe fn. */
  subscribeScreenCapture(cb: (captured: boolean) => void): () => void;
  /** Can we enumerate active accessibility services (Android) / assistive use (iOS)? */
  supportsAccessibilityDetection(): boolean;
  /** Is a third-party accessibility service currently active? */
  isAccessibilityServiceActive(): boolean;
  /** Overwrite/clear the system clipboard. */
  clearClipboard(): Promise<void>;
}

/** Persistence port. Backed by expo-secure-store on device; in-memory in tests. */
export interface SecureStorePort {
  getItem(key: string): Promise<string | null>;
  setItem(key: string, value: string): Promise<void>;
  removeItem(key: string): Promise<void>;
}

export type TimerHandle = { readonly __brand: 'TimerHandle' };

/** Injectable clock + scheduler, so timing logic is testable with fake time. */
export interface Clock {
  now(): number;
  setTimeout(fn: () => void, ms: number): TimerHandle;
  clearTimeout(handle: TimerHandle): void;
  setInterval(fn: () => void, ms: number): TimerHandle;
  clearInterval(handle: TimerHandle): void;
}

/** Injectable randomness, so decoy/jitter/rotation logic is deterministic in tests. */
export interface RandomSource {
  /** n cryptographically-random bytes. */
  bytes(n: number): Uint8Array;
  /** Uniform integer in [minInclusive, maxInclusive]. */
  int(minInclusive: number, maxInclusive: number): number;
}

/** Everything a module needs from the platform, injected once at construction. */
export interface ShieldPorts {
  readonly ble: BleAdapter;
  readonly dns: DnsAdapter;
  readonly mesh: MeshAdapter;
  readonly coResident: CoResidentAdapter;
  readonly store: SecureStorePort;
  readonly clock: Clock;
  readonly random: RandomSource;
  /** Opt-in, local-only, redacted logger. See logger.ts. */
  readonly log: ShieldLogger;
}

/** Redacted, opt-in, local-only logger. No identifiers, no tier history off-device. */
export interface ShieldLogger {
  readonly enabled: boolean;
  debug(code: string, fields?: Readonly<Record<string, string | number | boolean>>): void;
  warn(code: string, fields?: Readonly<Record<string, string | number | boolean>>): void;
}
