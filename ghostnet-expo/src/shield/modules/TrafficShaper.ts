/**
 * TrafficShaper — length-pads outbound mesh frames into fixed buckets, adds
 * order-preserving timing jitter, and emits indistinguishable cover traffic.
 *
 * GOALS (defeat passive traffic analysis):
 *  - Length padding: an observer learns only which bucket a frame fell into
 *    ({256,512,1024,4096}), not the true ciphertext length.
 *  - Timing jitter: a random per-frame delay breaks send-time correlation.
 *  - Cover traffic: dummy frames, identical on the wire to real ones, so the
 *    presence/absence and rate of real traffic is masked. Adaptive at GHOST/
 *    PHANTOM, always-on at FULL_GHOST.
 *
 * TWO INVARIANTS THAT MUST NOT BREAK:
 *  1. E2EE integrity. Padding wraps the ALREADY-ENCRYPTED ciphertext in an outer
 *     length-prefixed envelope; it never touches plaintext or the crypto channel.
 *     {@link unpadFrame} is the exact inverse of {@link padFrame}.
 *  2. Message ordering. Jitter delays a frame by a random amount but a later
 *     frame can never be scheduled before an earlier one (see {@link send}).
 *
 * HONESTY: padding/jitter/cover are pure-overlay behaviors the app fully owns,
 * so they are always achievable — there is no platform gate to degrade against.
 */

import {
  ModuleId,
  type CapabilityReport,
  type Clock,
  type MeshFrame,
  type ShieldConfig,
  type ShieldModule,
  type ShieldPorts,
  type TimerHandle,
} from '../types';

/** 4-byte big-endian length header prepended before padding. */
const LEN_HEADER_BYTES = 4;

/** Ramp cover traffic in/out over this many discrete steps (no hard toggle). */
const COVER_RAMP_STEPS = 4;
/** How often the cover-rate ramp advances. */
const COVER_RAMP_INTERVAL_MS = 4_000;

/**
 * Smallest bucket that fits `byteLength`. If it exceeds the largest bucket, round
 * up to the next multiple of the largest bucket so even big frames stay bucketed.
 */
export function selectBucket(byteLength: number, buckets: readonly number[]): number {
  if (byteLength < 0) throw new RangeError('byteLength must be non-negative');
  const max = buckets[buckets.length - 1];
  for (const b of buckets) {
    if (byteLength <= b) return b;
  }
  return Math.ceil(byteLength / max) * max;
}

/**
 * Wrap ciphertext in a fixed-bucket, length-prefixed envelope.
 * Layout: [4B BE original length][ciphertext][random pad → bucket size].
 * Pure and reversible; does not inspect or mutate the ciphertext.
 */
export function padFrame(
  frame: MeshFrame,
  buckets: readonly number[],
  random: Pick<ShieldPorts['random'], 'bytes'>,
): MeshFrame {
  const payload = frame.bytes;
  const needed = LEN_HEADER_BYTES + payload.length;
  const bucket = selectBucket(needed, buckets);
  const out = new Uint8Array(bucket);

  // Big-endian length header.
  out[0] = (payload.length >>> 24) & 0xff;
  out[1] = (payload.length >>> 16) & 0xff;
  out[2] = (payload.length >>> 8) & 0xff;
  out[3] = payload.length & 0xff;

  out.set(payload, LEN_HEADER_BYTES);

  // Random pad — random (not zero) so padding bytes are indistinguishable from
  // ciphertext to an observer who only sees lengths and entropy.
  const padLen = bucket - needed;
  if (padLen > 0) out.set(random.bytes(padLen), needed);

  return { bytes: out, to: frame.to };
}

/** Exact inverse of {@link padFrame}: recover the original ciphertext frame. */
export function unpadFrame(padded: MeshFrame): MeshFrame {
  const b = padded.bytes;
  if (b.length < LEN_HEADER_BYTES) throw new RangeError('padded frame too short');
  const len = ((b[0] << 24) >>> 0) + (b[1] << 16) + (b[2] << 8) + b[3];
  if (len < 0 || LEN_HEADER_BYTES + len > b.length) throw new RangeError('corrupt padded frame');
  return { bytes: b.slice(LEN_HEADER_BYTES, LEN_HEADER_BYTES + len), to: padded.to };
}

export class TrafficShaper implements ShieldModule {
  readonly id = ModuleId.TrafficShaper;
  private last: CapabilityReport = { id: this.id, requested: false, active: false, degraded: false };
  private cfg: ShieldConfig | null = null;

  // Jitter scheduling: monotonic high-water mark guarantees ordering.
  private lastScheduledAt = 0;
  private readonly pendingTimers = new Set<TimerHandle>();

  // Cover-traffic ramp state.
  private coverTargetRatePerMin = 0;
  private coverCurrentRatePerMin = 0;
  /** Constant per-step delta so the rate reaches the target linearly (and so a
   *  ramp-DOWN actually lands on 0 rather than decaying geometrically). */
  private coverRampStep = 1;
  private coverRampTimer: TimerHandle | null = null;
  private coverEmitTimer: TimerHandle | null = null;

  constructor(private readonly ports: ShieldPorts) {}

  private get clock(): Clock {
    return this.ports.clock;
  }

  async enable(cfg: ShieldConfig): Promise<CapabilityReport> {
    if (!cfg.traffic.enabled) {
      await this.disable();
      return this.last;
    }
    this.cfg = cfg;

    // Install the synchronous padding transform so EVERY frame the mesh sends —
    // real, jittered, or cover — is bucketed identically.
    this.ports.mesh.setOutboundTransform((frame) => padFrame(frame, cfg.traffic.paddingBuckets, this.ports.random));

    // Drive cover traffic toward the configured rate, ramping (never hard-on).
    this.setCoverTarget(cfg.traffic.coverTraffic === 'off' ? 0 : cfg.traffic.coverRatePerMin);

    this.last = { id: this.id, requested: true, active: true, degraded: false };
    this.ports.log.debug('traffic_on', {
      cover: cfg.traffic.coverTraffic,
      rate: cfg.traffic.coverRatePerMin,
    });
    return this.last;
  }

  async disable(): Promise<void> {
    // Ramp cover traffic DOWN to zero rather than cutting it (a hard stop is
    // itself an observable signature). The ramp loop tears everything down once
    // the rate reaches zero.
    this.setCoverTarget(0);
    this.ports.mesh.setOutboundTransform(null);
    this.cfg = null;
    this.last = { id: this.id, requested: false, active: false, degraded: false };
  }

  report(): CapabilityReport {
    return this.last;
  }

  /**
   * Send a real frame with order-preserving jitter. The frame is delayed by a
   * random amount in [jitterMin, jitterMax]; padding is applied by the installed
   * transform inside `mesh.sendRaw`. A later call can never be scheduled before
   * an earlier one because we clamp each scheduled time to be ≥ the previous.
   */
  send(frame: MeshFrame): void {
    const cfg = this.cfg;
    if (!cfg) {
      // Shaper off: pass through immediately, preserving call order.
      void this.ports.mesh.sendRaw(frame);
      return;
    }
    const now = this.clock.now();
    const jitter = this.ports.random.int(cfg.traffic.jitterMinMs, cfg.traffic.jitterMaxMs);
    const scheduledAt = Math.max(now + jitter, this.lastScheduledAt + 1);
    this.lastScheduledAt = scheduledAt;

    let handle: TimerHandle;
    const fire = (): void => {
      this.pendingTimers.delete(handle);
      void this.ports.mesh.sendRaw(frame);
    };
    handle = this.clock.setTimeout(fire, scheduledAt - now);
    this.pendingTimers.add(handle);
  }

  /** Current ramped cover rate (frames/min). Exposed for status/testing. */
  get coverRatePerMin(): number {
    return this.coverCurrentRatePerMin;
  }

  private setCoverTarget(targetRatePerMin: number): void {
    this.coverTargetRatePerMin = targetRatePerMin;
    // Fixed linear step sized off the larger of where we are and where we're
    // going, so both ramp-up and ramp-down complete in COVER_RAMP_STEPS ticks.
    const span = Math.max(this.coverCurrentRatePerMin, targetRatePerMin);
    this.coverRampStep = Math.max(1, Math.ceil(span / COVER_RAMP_STEPS));
    if (this.coverRampTimer === null) {
      this.coverRampTimer = this.clock.setInterval(() => this.stepCoverRamp(), COVER_RAMP_INTERVAL_MS);
    }
    // Kick an immediate step so a freshly-enabled shaper begins ramping at once.
    this.stepCoverRamp();
  }

  private stepCoverRamp(): void {
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

    // Fully ramped down → stop the ramp + emit loops entirely.
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

  private scheduleCoverEmit(): void {
    if (this.coverEmitTimer !== null) return; // one emit loop at a time
    const rate = this.coverCurrentRatePerMin;
    if (rate <= 0) return;
    const intervalMs = Math.round(60_000 / rate);
    const tick = (): void => {
      this.coverEmitTimer = null;
      if (this.coverCurrentRatePerMin <= 0) return;
      this.emitCoverFrame();
      this.scheduleCoverEmit();
    };
    this.coverEmitTimer = this.clock.setTimeout(tick, intervalMs);
  }

  /**
   * Emit one dummy frame. It is random bytes broadcast (to: null); the mesh's
   * installed padding transform buckets it exactly like a real frame, so it is
   * indistinguishable on the wire and carries no real id or payload. The
   * receiving peer discards it after decrypt (cover frames decrypt to a tagged
   * no-op); a passive observer cannot tell real from cover.
   */
  private emitCoverFrame(): void {
    // Random body sized like a typical small real frame; the transform pads it.
    const body = this.ports.random.bytes(this.ports.random.int(16, 200));
    void this.ports.mesh.sendRaw({ bytes: body, to: null });
  }
}
