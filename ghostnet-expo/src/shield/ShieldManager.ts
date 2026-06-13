/**
 * ShieldManager — public API and the OFF/STEALTH/GHOST/PHANTOM/FULL_GHOST state
 * machine.
 *
 * RESPONSIBILITIES
 *  - Resolve a tier into its module set via the single-source {@link resolveConfig}.
 *  - Apply transitions ATOMICALLY: enable/reconfigure the modules a tier needs and
 *    disable the rest. If any module hard-fails (its enable() throws), roll the
 *    whole transition back to the last stable tier and emit `degraded`.
 *  - Treat per-module `degraded` (achievable-subset) as success, but still emit a
 *    `degraded` event so the UI can explain partial cloaking.
 *  - Persist the last stable tier (single value, not history) and restore it.
 *  - panic(): jump straight to FULL_GHOST.
 *
 * No-leak: this class never logs the node id, peer ids, or a tier timeline. The
 * persisted value is a single overwritten key, not an append-only history.
 */

import { modulesForTier, resolveConfig, type ConfigOptions } from './config';
import { createLogger } from './logger';
import { BleCloak } from './modules/BleCloak';
import { DecoyEngine } from './modules/DecoyEngine';
import { DnsGuard } from './modules/DnsGuard';
import { MeshRouting } from './modules/MeshRouting';
import { NodeIdRotator } from './modules/NodeIdRotator';
import { TrafficShaper } from './modules/TrafficShaper';
import {
  ModuleId,
  ShieldTier,
  TIER_RANK,
  type CapabilityReport,
  type DegradedPayload,
  type ShieldModule,
  type ShieldPorts,
  type ShieldStatus,
  type TierChangedPayload,
} from './types';

/** Secure-store key holding the last stable tier (overwritten, never appended). */
export const TIER_STORE_KEY = 'ghostnet_shield_tier';

type Listeners = {
  tierChanged: Set<(p: TierChangedPayload) => void>;
  degraded: Set<(p: DegradedPayload) => void>;
};

export interface ShieldManagerOptions extends ConfigOptions {
  /** Pre-built modules (for tests). Defaults to the six real modules. */
  readonly modules?: readonly ShieldModule[];
}

export class ShieldManager {
  private readonly ports: ShieldPorts;
  private readonly options: ShieldManagerOptions;
  private readonly modules: ReadonlyMap<ModuleId, ShieldModule>;

  private currentTier: ShieldTier = ShieldTier.OFF;
  private stable = true;
  /** Serializes setTier/panic so transitions never interleave. */
  private queue: Promise<unknown> = Promise.resolve();

  private readonly listeners: Listeners = { tierChanged: new Set(), degraded: new Set() };

  constructor(ports: ShieldPorts, options: ShieldManagerOptions = {}) {
    this.ports = ports;
    this.options = options;
    const mods = options.modules ?? ShieldManager.defaultModules(ports);
    const map = new Map<ModuleId, ShieldModule>();
    for (const m of mods) map.set(m.id, m);
    this.modules = map;
  }

  /** Construct the six real modules wired to the given platform ports. */
  static defaultModules(ports: ShieldPorts): readonly ShieldModule[] {
    return [
      new BleCloak(ports),
      new DnsGuard(ports),
      new TrafficShaper(ports),
      new MeshRouting(ports),
      new DecoyEngine(ports),
      new NodeIdRotator(ports),
    ];
  }

  // ── public API ──────────────────────────────────────────────────────────

  /** Set the active tier. Idempotent and atomic (rolls back on hard failure). */
  setTier(tier: ShieldTier): Promise<ShieldStatus> {
    return this.enqueue(() => this.applyTier(tier));
  }

  /** Hard-jump to FULL_GHOST. Reachable from a global panic gesture. */
  panic(): Promise<void> {
    return this.enqueue(async () => {
      await this.applyTier(ShieldTier.FULL_GHOST);
    });
  }

  getStatus(): ShieldStatus {
    const reports = this.collectReports();
    return {
      tier: this.currentTier,
      stable: this.stable,
      degraded: reports.some((r) => r.degraded || (r.requested && !r.active)),
      modules: reports,
    };
  }

  on(event: 'tierChanged', cb: (p: TierChangedPayload) => void): () => void;
  on(event: 'degraded', cb: (p: DegradedPayload) => void): () => void;
  on(event: 'tierChanged' | 'degraded', cb: (p: never) => void): () => void {
    if (event === 'tierChanged') {
      this.listeners.tierChanged.add(cb as (p: TierChangedPayload) => void);
      return () => this.listeners.tierChanged.delete(cb as (p: TierChangedPayload) => void);
    }
    this.listeners.degraded.add(cb as (p: DegradedPayload) => void);
    return () => this.listeners.degraded.delete(cb as (p: DegradedPayload) => void);
  }

  /** Restore the persisted tier on app launch. No-ops (stays OFF) if none saved. */
  async restore(): Promise<ShieldStatus> {
    const saved = await this.ports.store.getItem(TIER_STORE_KEY);
    if (saved && isShieldTier(saved)) {
      return this.setTier(saved);
    }
    return this.getStatus();
  }

  // ── transition core ─────────────────────────────────────────────────────

  private enqueue<T>(task: () => Promise<T>): Promise<T> {
    const run = this.queue.then(task, task);
    // Keep the chain alive even if a task rejects, without unhandled rejections.
    this.queue = run.then(
      () => undefined,
      () => undefined,
    );
    return run;
  }

  /**
   * The atomic transition. Snapshots the previous stable tier, applies the
   * target, and on a hard failure re-applies the snapshot before surfacing the
   * error path as a rolled-back `degraded` event.
   */
  private async applyTier(target: ShieldTier): Promise<ShieldStatus> {
    const from = this.currentTier;

    // Idempotent: re-applying the same tier still reconciles modules (cheap) so
    // a caller can use it to recover from external drift, but emits no event if
    // nothing changed.
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
      // Hard failure mid-transition → roll back to the last stable tier.
      this.ports.log.warn('transition_failed', { from, to: target });
      try {
        await this.reconcile(from);
      } catch {
        // If even rollback fails, drop to OFF as the safe floor.
        await this.reconcile(ShieldTier.OFF).catch(() => undefined);
        this.currentTier = ShieldTier.OFF;
      }
      this.currentTier = this.currentTier === ShieldTier.OFF ? ShieldTier.OFF : from;
      this.stable = true;
      await this.persist(this.currentTier);

      this.emitDegraded({
        tier: this.currentTier,
        reports: this.collectReports(),
        rolledBack: true,
      });
      void err; // error detail is intentionally not surfaced/logged with identifiers
      return this.getStatus();
    }
  }

  /**
   * Bring the running module set in line with `target`: enable/reconfigure every
   * module the tier requires, disable every module it does not. A throw from any
   * enable() propagates to applyTier() to trigger rollback.
   */
  private async reconcile(target: ShieldTier): Promise<void> {
    const cfg = resolveConfig(target, this.options);
    const wanted = modulesForTier(target);

    // Disable unwanted modules first (lower attack surface before enabling more).
    for (const [id, mod] of this.modules) {
      if (!wanted.has(id)) await mod.disable();
    }
    // Enable/reconfigure wanted modules. enable() is idempotent.
    for (const id of wanted) {
      const mod = this.modules.get(id);
      if (mod) await mod.enable(cfg);
    }
  }

  private collectReports(): CapabilityReport[] {
    return [...this.modules.values()].map((m) => m.report());
  }

  private maybeEmitDegraded(tier: ShieldTier, rolledBack: boolean): void {
    const degraded = this.collectReports().filter((r) => r.degraded || (r.requested && !r.active));
    if (degraded.length > 0) {
      this.emitDegraded({ tier, reports: degraded, rolledBack });
    }
  }

  private async persist(tier: ShieldTier): Promise<void> {
    try {
      await this.ports.store.setItem(TIER_STORE_KEY, tier);
    } catch {
      // Persistence failure must not break cloaking; it only affects restore.
      this.ports.log.warn('persist_failed');
    }
  }

  private emitTierChanged(p: TierChangedPayload): void {
    for (const cb of this.listeners.tierChanged) cb(p);
  }

  private emitDegraded(p: DegradedPayload): void {
    for (const cb of this.listeners.degraded) cb(p);
  }
}

function isShieldTier(value: string): value is ShieldTier {
  return Object.prototype.hasOwnProperty.call(TIER_RANK, value);
}
