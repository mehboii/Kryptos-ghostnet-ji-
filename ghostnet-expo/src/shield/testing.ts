/**
 * Ghost Shield — in-memory fakes for the platform ports.
 *
 * These let the Shield run off-device: in unit tests, in the usage example, and
 * in a playground. They are deterministic where it matters (fake clock, seeded
 * randomness) so timing/jitter/rotation logic is reproducible. They are NOT a
 * production wiring — the real app injects react-native-ble-plx, expo-secure-store,
 * and the live mesh transport behind the same interfaces.
 */

import { createLogger } from './logger';
import {
  type AdvertisingParameters,
  type BleAdapter,
  type Clock,
  type CoResidentAdapter,
  type DecoyAnnouncement,
  type DnsAdapter,
  type DnsMode,
  type MeshAdapter,
  type MeshFrame,
  type OutboundTransform,
  type RandomSource,
  type SecureStorePort,
  type ShieldLogger,
  type ShieldPorts,
  type TimerHandle,
} from './types';

/* ── Fake clock ──────────────────────────────────────────────────────────── */

interface ScheduledTimer {
  id: number;
  fireAt: number;
  intervalMs: number | null;
  fn: () => void;
  seq: number;
}

/** Manually-advanced clock. `advance(ms)` fires due timers in scheduled order. */
export class FakeClock implements Clock {
  private current = 0;
  private nextId = 1;
  private seqCounter = 0;
  private timers = new Map<number, ScheduledTimer>();

  now(): number {
    return this.current;
  }

  setTimeout(fn: () => void, ms: number): TimerHandle {
    return this.schedule(fn, ms, null);
  }

  setInterval(fn: () => void, ms: number): TimerHandle {
    return this.schedule(fn, ms, ms);
  }

  clearTimeout(handle: TimerHandle): void {
    this.timers.delete(toId(handle));
  }

  clearInterval(handle: TimerHandle): void {
    this.timers.delete(toId(handle));
  }

  /** Advance virtual time, firing timers (and rescheduling intervals) in order. */
  advance(ms: number): void {
    const target = this.current + ms;
    for (;;) {
      const due = [...this.timers.values()]
        .filter((t) => t.fireAt <= target)
        .sort((a, b) => a.fireAt - b.fireAt || a.seq - b.seq);
      if (due.length === 0) break;
      const t = due[0];
      this.current = t.fireAt;
      if (t.intervalMs === null) {
        this.timers.delete(t.id);
      } else {
        t.fireAt = t.fireAt + t.intervalMs;
        t.seq = this.seqCounter++;
      }
      t.fn();
    }
    this.current = target;
  }

  /** Number of live timers (for leak assertions in tests). */
  get pending(): number {
    return this.timers.size;
  }

  private schedule(fn: () => void, ms: number, intervalMs: number | null): TimerHandle {
    const id = this.nextId++;
    this.timers.set(id, { id, fireAt: this.current + ms, intervalMs, fn, seq: this.seqCounter++ });
    return fromId(id);
  }
}

function fromId(id: number): TimerHandle {
  return { __id: id } as unknown as TimerHandle;
}
function toId(handle: TimerHandle): number {
  return (handle as unknown as { __id: number }).__id;
}

/* ── Deterministic randomness ────────────────────────────────────────────── */

/** Seeded, non-cryptographic RNG. Deterministic for tests; do NOT use in prod. */
export class SeededRandom implements RandomSource {
  private state: number;
  constructor(seed = 0x1234_5678) {
    this.state = seed >>> 0;
  }
  private next(): number {
    // xorshift32
    let x = this.state;
    x ^= x << 13;
    x ^= x >>> 17;
    x ^= x << 5;
    this.state = x >>> 0;
    return this.state / 0xffff_ffff;
  }
  bytes(n: number): Uint8Array {
    const out = new Uint8Array(n);
    for (let i = 0; i < n; i++) out[i] = Math.floor(this.next() * 256) & 0xff;
    return out;
  }
  int(minInclusive: number, maxInclusive: number): number {
    if (maxInclusive < minInclusive) return minInclusive;
    const span = maxInclusive - minInclusive + 1;
    return minInclusive + Math.floor(this.next() * span);
  }
}

/* ── In-memory secure store ──────────────────────────────────────────────── */

export class MemoryStore implements SecureStorePort {
  private map = new Map<string, string>();
  async getItem(key: string): Promise<string | null> {
    return this.map.has(key) ? (this.map.get(key) as string) : null;
  }
  async setItem(key: string, value: string): Promise<void> {
    this.map.set(key, value);
  }
  async removeItem(key: string): Promise<void> {
    this.map.delete(key);
  }
}

/* ── Fake BLE adapter ────────────────────────────────────────────────────── */

export interface FakeBleOptions {
  readonly supportsAdvertisingControl?: boolean;
  readonly supportsAdvertisingParams?: boolean;
}

export class FakeBleAdapter implements BleAdapter {
  advertising = true;
  discoveryBeacon = true;
  advertisedNodeId = 'node-real';
  advertisingParams: AdvertisingParameters[] = [];
  private readonly supported: boolean;
  private readonly paramsSupported: boolean;
  constructor(opts: FakeBleOptions = {}) {
    this.supported = opts.supportsAdvertisingControl ?? true;
    this.paramsSupported = opts.supportsAdvertisingParams ?? true;
  }
  supportsAdvertisingControl(): boolean {
    return this.supported;
  }
  async stopAdvertising(): Promise<void> {
    this.advertising = false;
  }
  async startAdvertising(): Promise<void> {
    this.advertising = true;
  }
  async setDiscoveryBeaconEnabled(enabled: boolean): Promise<void> {
    this.discoveryBeacon = enabled;
  }
  async setAdvertisedNodeId(nodeId: string): Promise<void> {
    this.advertisedNodeId = nodeId;
  }
  supportsAdvertisingParams(): boolean {
    return this.paramsSupported;
  }
  async setAdvertisingParameters(params: AdvertisingParameters): Promise<void> {
    this.advertisingParams.push(params);
  }
}

/* ── Fake DNS adapter ────────────────────────────────────────────────────── */

export interface FakeDnsOptions {
  readonly supportsDoh?: boolean;
  readonly reachable?: boolean;
  readonly supportsEch?: boolean;
}

export class FakeDnsAdapter implements DnsAdapter {
  mode: DnsMode = 'system';
  resolver = '';
  plaintextBlocked = false;
  private readonly supported: boolean;
  private readonly echSupported: boolean;
  reachable: boolean;
  constructor(opts: FakeDnsOptions = {}) {
    this.supported = opts.supportsDoh ?? true;
    this.reachable = opts.reachable ?? true;
    this.echSupported = opts.supportsEch ?? true;
  }
  supportsDoh(): boolean {
    return this.supported;
  }
  async setMode(mode: DnsMode, dohResolver: string): Promise<void> {
    this.mode = mode;
    this.resolver = dohResolver;
  }
  async probe(): Promise<boolean> {
    return this.reachable;
  }
  async setPlaintextBlocked(blocked: boolean): Promise<void> {
    this.plaintextBlocked = blocked;
  }
  supportsEch(): boolean {
    return this.echSupported;
  }
}

/* ── Fake mesh adapter ───────────────────────────────────────────────────── */

export interface FakeMeshOptions {
  readonly supportsHopControl?: boolean;
  readonly supportsNodeIdRotation?: boolean;
  readonly activeSessions?: readonly string[];
  readonly nodeId?: string;
}

export interface HandoffRecord {
  readonly peerId: string;
  readonly oldId: string;
  readonly newId: string;
  readonly at: number;
}

export class FakeMeshAdapter implements MeshAdapter {
  transform: OutboundTransform | null = null;
  sent: MeshFrame[] = [];
  decoys: DecoyAnnouncement[] = [];
  minHops = 0;
  handoffs: HandoffRecord[] = [];
  adopted: string[] = [];
  retired: string[] = [];
  private nodeId: string;
  private sessions: string[];
  private readonly hopControl: boolean;
  private readonly rotation: boolean;
  private readonly clock?: Clock;

  constructor(opts: FakeMeshOptions = {}, clock?: Clock) {
    this.hopControl = opts.supportsHopControl ?? true;
    this.rotation = opts.supportsNodeIdRotation ?? true;
    this.sessions = [...(opts.activeSessions ?? [])];
    this.nodeId = opts.nodeId ?? 'node-real';
    this.clock = clock;
  }
  getCurrentNodeId(): string {
    return this.nodeId;
  }
  setOutboundTransform(transform: OutboundTransform | null): void {
    this.transform = transform;
  }
  async sendRaw(frame: MeshFrame): Promise<void> {
    // Honor the adapter contract: apply the installed outbound transform to
    // every frame, so real/jittered/cover frames are all bucketed identically.
    this.sent.push(this.transform ? this.transform(frame) : frame);
  }
  getActiveSessions(): readonly string[] {
    return this.sessions;
  }
  supportsHopControl(): boolean {
    return this.hopControl;
  }
  async setMinHops(hops: number): Promise<void> {
    this.minHops = hops;
  }
  supportsNodeIdRotation(): boolean {
    return this.rotation;
  }
  async sendNodeIdHandoff(peerId: string, oldId: string, newId: string): Promise<void> {
    this.handoffs.push({ peerId, oldId, newId, at: this.clock?.now() ?? 0 });
  }
  async adoptNodeId(newId: string): Promise<void> {
    this.adopted.push(newId);
    this.nodeId = newId;
  }
  async retireNodeId(oldId: string): Promise<void> {
    this.retired.push(oldId);
  }
  async announceDecoyPeer(announcement: DecoyAnnouncement): Promise<void> {
    this.decoys.push(announcement);
  }
}

/* ── Fake co-resident adapter ────────────────────────────────────────────── */

export interface FakeCoResidentOptions {
  readonly supportsScreenCaptureDetection?: boolean;
  readonly supportsAccessibilityDetection?: boolean;
  readonly screenCaptured?: boolean;
  readonly accessibilityActive?: boolean;
}

export class FakeCoResidentAdapter implements CoResidentAdapter {
  screenCaptured: boolean;
  accessibilityActive: boolean;
  clipboardCleared = 0;
  private readonly screenCapSupported: boolean;
  private readonly a11ySupported: boolean;
  private subscribers = new Set<(captured: boolean) => void>();

  constructor(opts: FakeCoResidentOptions = {}) {
    this.screenCapSupported = opts.supportsScreenCaptureDetection ?? true;
    this.a11ySupported = opts.supportsAccessibilityDetection ?? true;
    this.screenCaptured = opts.screenCaptured ?? false;
    this.accessibilityActive = opts.accessibilityActive ?? false;
  }
  supportsScreenCaptureDetection(): boolean {
    return this.screenCapSupported;
  }
  isScreenCaptured(): boolean {
    return this.screenCaptured;
  }
  subscribeScreenCapture(cb: (captured: boolean) => void): () => void {
    this.subscribers.add(cb);
    return () => this.subscribers.delete(cb);
  }
  supportsAccessibilityDetection(): boolean {
    return this.a11ySupported;
  }
  isAccessibilityServiceActive(): boolean {
    return this.accessibilityActive;
  }
  async clearClipboard(): Promise<void> {
    this.clipboardCleared++;
  }
  /** Test helper: simulate the OS reporting a screen-capture state change. */
  emitScreenCapture(captured: boolean): void {
    this.screenCaptured = captured;
    for (const cb of this.subscribers) cb(captured);
  }
}

/* ── Bundle ──────────────────────────────────────────────────────────────── */

export interface FakePortsOverrides {
  readonly ble?: FakeBleOptions;
  readonly dns?: FakeDnsOptions;
  readonly mesh?: FakeMeshOptions;
  readonly coResident?: FakeCoResidentOptions;
  readonly seed?: number;
  readonly logger?: ShieldLogger;
}

export interface FakePorts extends ShieldPorts {
  readonly ble: FakeBleAdapter;
  readonly dns: FakeDnsAdapter;
  readonly mesh: FakeMeshAdapter;
  readonly coResident: FakeCoResidentAdapter;
  readonly store: MemoryStore;
  readonly clock: FakeClock;
  readonly random: SeededRandom;
}

/** Assemble a complete set of in-memory ports. */
export function createFakePorts(overrides: FakePortsOverrides = {}): FakePorts {
  const clock = new FakeClock();
  const ble = new FakeBleAdapter(overrides.ble);
  const dns = new FakeDnsAdapter(overrides.dns);
  const mesh = new FakeMeshAdapter(overrides.mesh, clock);
  const coResident = new FakeCoResidentAdapter(overrides.coResident);
  const store = new MemoryStore();
  const random = new SeededRandom(overrides.seed);
  const log = overrides.logger ?? createLogger({ enabled: false });
  return { ble, dns, mesh, coResident, store, clock, random, log };
}
