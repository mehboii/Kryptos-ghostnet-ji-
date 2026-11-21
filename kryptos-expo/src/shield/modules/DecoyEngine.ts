/**
 * DecoyEngine — maintains a pool of plausible fake peers and emits decoy
 * announcement traffic for them, so an observer counting "Kryptos nodes near
 * this device" sees noise and the real node's traffic does not stand out.
 *
 * THREAT ASSUMPTION (hardening): the attacker has DECOMPILED the app, so the
 * decoy algorithm is PUBLIC. Indistinguishability cannot come from secrecy — it
 * must be statistical. Therefore decoy timing and size are drawn from the SAME
 * {@link TrafficModel} that observes real traffic: inter-arrivals are sampled
 * from the observed gap distribution (Poisson fallback before data accrues), and
 * payload sizes are sampled from the observed size-bucket histogram. There is no
 * fixed/low-entropy cadence a classifier could lock onto.
 *
 * SECURITY REQUIREMENTS (unchanged):
 *  - Unlinkable: fresh random ephemeral ids; the pool rotates over time.
 *  - No real-id leak: a decoy NEVER contains the real overlay node id (asserted).
 *  - No payload: decoys carry only random, well-formed bytes — never real payload.
 *
 * Decoys are pure-overlay, so there is no platform capability to degrade against.
 */

import {
  ModuleId,
  type CapabilityReport,
  type DecoyAnnouncement,
  type ShieldConfig,
  type ShieldModule,
  type ShieldPorts,
  type TimerHandle,
} from '../types';
import type { TrafficModel } from '../traffic-model';

/** Rotate the decoy identity pool on this cadence so identities churn. */
const POOL_TTL_MS = 45_000;
/** Ephemeral decoy id length in bytes (hex-encoded when announced). */
const DECOY_ID_BYTES = 16;
/** Mean decoy inter-arrival used before the traffic model has observed data. */
const DECOY_FALLBACK_MEAN_MS = 4_000;

export class DecoyEngine implements ShieldModule {
  readonly id = ModuleId.DecoyEngine;
  private last: CapabilityReport = { id: this.id, requested: false, active: false, degraded: false };
  private cfg: ShieldConfig | null = null;
  private poolTimer: TimerHandle | null = null;
  private emitTimer: TimerHandle | null = null;
  private pool: string[] = [];

  constructor(
    private readonly ports: ShieldPorts,
    private readonly model: TrafficModel,
  ) {}

  async enable(cfg: ShieldConfig): Promise<CapabilityReport> {
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

  async disable(): Promise<void> {
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

  report(): CapabilityReport {
    return this.last;
  }

  /** Current decoy identity pool (for tests). */
  get decoyIds(): readonly string[] {
    return this.pool;
  }

  /** Build a fresh pool of 2–4 (tier-dependent) decoy identities. */
  refreshPool(): void {
    const cfg = this.cfg;
    if (!cfg) return;
    const realId = this.ports.mesh.getCurrentNodeId();
    const size = this.ports.random.int(cfg.decoy.minDecoys, cfg.decoy.maxDecoys);
    const next: string[] = [];
    for (let i = 0; i < size; i++) {
      const id = bytesToHex(this.ports.random.bytes(DECOY_ID_BYTES));
      // Defensive: a decoy must never echo the real id.
      if (id !== realId) next.push(id);
    }
    this.pool = next;
    this.ports.log.debug('decoy_pool_refreshed', { size: next.length });
  }

  /** Schedule the next decoy announcement at a model-sampled inter-arrival. */
  private scheduleEmit(): void {
    if (this.emitTimer !== null) return;
    const gapMs = this.model.sampleGapMs(DECOY_FALLBACK_MEAN_MS);
    const tick = (): void => {
      this.emitTimer = null;
      if (!this.cfg) return;
      void this.emitDecoy();
      this.scheduleEmit();
    };
    this.emitTimer = this.ports.clock.setTimeout(tick, gapMs);
  }

  /** Emit one announcement for a random pooled decoy, sized from the model. */
  async emitDecoy(): Promise<void> {
    if (!this.cfg || this.pool.length === 0) return;
    const realId = this.ports.mesh.getCurrentNodeId();
    const ephemeralId = this.pool[this.ports.random.int(0, this.pool.length - 1)];
    if (ephemeralId === realId) return; // never leak the real id
    const announcement: DecoyAnnouncement = {
      ephemeralId,
      // Size drawn from the observed real size distribution; random content.
      payload: this.ports.random.bytes(this.model.sampleSizeBytes()),
    };
    await this.ports.mesh.announceDecoyPeer(announcement);
  }
}

function bytesToHex(bytes: Uint8Array): string {
  let s = '';
  for (const b of bytes) s += b.toString(16).padStart(2, '0');
  return s;
}
