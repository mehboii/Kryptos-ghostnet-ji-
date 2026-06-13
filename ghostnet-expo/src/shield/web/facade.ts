/**
 * Ghost Shield — web facade.
 *
 * Bridges the real {@link ShieldManager} (the OFF/STEALTH/GHOST/PHANTOM/FULL_GHOST
 * tier machine in src/shield) to the level-based `window.GhostShield` API the
 * existing GhostNet UI calls. There is NO mock engine behind this — every status
 * field is derived from the real manager's capability reports, and every console
 * line is the honest per-platform truth.
 *
 * WHAT THIS DELIBERATELY DOES NOT DO (the dishonest theater that was removed):
 *   - It never logs "MAC rotated → …" or "MAC rotation started". An app cannot
 *     change the hardware MAC; the real behavior is overlay node-id rotation and
 *     the stat below counts REAL rotations.
 *   - It never logs "WiFi probe suppression active". An app cannot suppress the OS
 *     radio's probe requests.
 *   - It never claims BLE features are active when no BLE stack is present; on web
 *     (and on native with a missing plugin) BLE reports `unavailable`.
 */

import type { ShieldManager } from '../ShieldManager';
import { ShieldTier, TIER_RANK, type CapabilityReport, type ShieldStatus } from '../types';
import { honestReason } from './reasons';
import type { ShieldPlatform } from './runtime';
import type { WebMeshAdapter } from './webPorts';

/** Tier selected for each numeric UI level (cumulative: 3 ⊃ 2 ⊃ 1). */
const TIER_BY_LEVEL: Readonly<Record<0 | 1 | 2 | 3, ShieldTier>> = {
  0: ShieldTier.OFF,
  1: ShieldTier.STEALTH,
  2: ShieldTier.GHOST,
  3: ShieldTier.PHANTOM,
};

/** UI level for a tier. FULL_GHOST maps to the top level (its "ALL" badge comes
 *  from currentLevel, not the number). */
function levelForTier(tier: ShieldTier): 0 | 1 | 2 | 3 {
  switch (tier) {
    case ShieldTier.OFF:
      return 0;
    case ShieldTier.STEALTH:
      return 1;
    case ShieldTier.GHOST:
      return 2;
    default:
      return 3; // PHANTOM and FULL_GHOST
  }
}

export interface FacadeStats {
  /** Real overlay frames the shaper/decoy engine put on the wire (cover + decoy). */
  readonly packetsProtected: number;
  /** App-level blocked device count. */
  readonly devicesBlocked: number;
  /** REAL overlay node-id rotations performed (NOT MAC rotations — those do not exist). */
  readonly nodeIdRotations: number;
  /** Seconds since the Shield left OFF. */
  readonly uptime: number;
}

export interface FacadeStatus {
  readonly platform: ShieldPlatform;
  readonly tier: ShieldTier;
  readonly level: 0 | 1 | 2 | 3;
  readonly currentLevel: 'ALL' | null;
  readonly activeStates: Readonly<Record<1 | 2 | 3, boolean>>;
  readonly degraded: boolean;
  readonly stable: boolean;
  readonly modules: readonly CapabilityReport[];
  readonly stats: FacadeStats;
}

type Sink = (line: string) => void;

export interface FacadeOptions {
  /** Where honest console lines go. Defaults to console.log. */
  readonly sink?: Sink;
  /** Persisted block-list key + mirror target lookup (the live app mesh). */
  readonly blockedMacsKey?: string;
}

const DEFAULT_BLOCKED_KEY = 'ghostnet_shield_blocked_macs';

/**
 * The object assigned to `window.GhostShield`. Mirrors the legacy method surface
 * the UI calls, but backed by the real ShieldManager.
 */
export class GhostShieldFacade {
  private cached: ShieldStatus;
  private startedAt: number | null = null;
  private statsTimer: ReturnType<typeof setInterval> | null = null;
  private readonly sink: Sink;
  private readonly blockedKey: string;
  readonly blockedMacs = new Set<string>();

  constructor(
    private readonly manager: ShieldManager,
    private readonly platform: ShieldPlatform,
    private readonly mesh: WebMeshAdapter,
    options: FacadeOptions = {},
  ) {
    this.sink = options.sink ?? ((line) => console.log(line));
    this.blockedKey = options.blockedMacsKey ?? DEFAULT_BLOCKED_KEY;
    this.cached = manager.getStatus();
    this.restoreBlocked();

    manager.on('tierChanged', ({ from, to, status }) => {
      this.cached = status;
      this.onActiveEdge();
      this.log(`tier ${from} → ${to}  [platform: ${this.platform}]`);
      this.logReports(status.modules);
      this.emitStats();
    });
    manager.on('degraded', ({ reports, rolledBack }) => {
      this.cached = manager.getStatus();
      if (rolledBack) this.log('transition rolled back to last stable tier');
      this.logReports(reports);
      this.emitStats();
    });

    // Restore the persisted tier (async; UI reads optimistic cache meanwhile).
    void manager.restore().then((status) => {
      this.cached = status;
      this.onActiveEdge();
      if (status.tier !== ShieldTier.OFF) {
        this.log(`restored tier ${status.tier}  [platform: ${this.platform}]`);
        this.logReports(status.modules);
      }
      this.emitStats();
    });
  }

  // ── legacy level API the UI calls ─────────────────────────────────────────

  /** Toggle a cumulative level. Clicking the active top level steps down one. */
  enable(level: number): void {
    const l = clampLevel(level);
    const currentRank = TIER_RANK[this.cached.tier];
    const isTop = currentRank === l && this.cached.tier !== ShieldTier.FULL_GHOST;
    const target = (isTop ? l - 1 : l) as 0 | 1 | 2 | 3;
    this.applyLevel(target);
  }

  enableAll(): void {
    this.optimistic(ShieldTier.FULL_GHOST);
    void this.manager.setTier(ShieldTier.FULL_GHOST);
  }

  disableAll(): void {
    this.optimistic(ShieldTier.OFF);
    void this.manager.setTier(ShieldTier.OFF);
  }

  disable(): void {
    this.disableAll();
  }

  /** Panic gesture → FULL_GHOST immediately. */
  panic(): void {
    this.optimistic(ShieldTier.FULL_GHOST);
    void this.manager.panic();
  }

  isActive(): boolean {
    return this.cached.tier !== ShieldTier.OFF;
  }

  /** Stop the stats timer (SPA teardown / tests). Does not change the tier. */
  dispose(): void {
    this.stopStatsTimer();
  }

  getStatus(): FacadeStatus {
    const rank = TIER_RANK[this.cached.tier];
    return {
      platform: this.platform,
      tier: this.cached.tier,
      level: levelForTier(this.cached.tier),
      currentLevel: this.cached.tier === ShieldTier.FULL_GHOST ? 'ALL' : null,
      activeStates: { 1: rank >= 1, 2: rank >= 2, 3: rank >= 3 },
      degraded: this.cached.degraded,
      stable: this.cached.stable,
      modules: this.cached.modules,
      stats: {
        packetsProtected: this.mesh.framesSent + this.mesh.decoysSent,
        devicesBlocked: this.blockedMacs.size,
        nodeIdRotations: this.mesh.nodeIdRotations,
        uptime: this.startedAt ? Math.floor((Date.now() - this.startedAt) / 1000) : 0,
      },
    };
  }

  // ── app-level device block list (filtering, not a cloaking claim) ─────────

  blockDevice(mac: string): void {
    if (!mac) return;
    this.blockedMacs.add(mac);
    this.mirrorBlocked();
    this.persistBlocked();
  }

  unblockDevice(mac: string): void {
    if (!mac) return;
    this.blockedMacs.delete(mac);
    this.mirrorBlocked();
    this.persistBlocked();
  }

  // ── internals ─────────────────────────────────────────────────────────────

  private applyLevel(level: 0 | 1 | 2 | 3): void {
    const tier = TIER_BY_LEVEL[level];
    this.optimistic(tier);
    void this.manager.setTier(tier);
  }

  /** Update the cached snapshot's tier immediately so the UI's synchronous
   *  read after a click reflects intent; the real report replaces it on resolve. */
  private optimistic(tier: ShieldTier): void {
    this.cached = { ...this.cached, tier, stable: false };
    this.onActiveEdge();
  }

  private onActiveEdge(): void {
    if (this.cached.tier !== ShieldTier.OFF && this.startedAt === null) {
      this.startedAt = Date.now();
      this.startStatsTimer();
    } else if (this.cached.tier === ShieldTier.OFF) {
      this.startedAt = null;
      this.stopStatsTimer();
    }
  }

  private startStatsTimer(): void {
    if (this.statsTimer !== null) return;
    this.statsTimer = setInterval(() => this.emitStats(), 2000);
  }

  private stopStatsTimer(): void {
    if (this.statsTimer !== null) {
      clearInterval(this.statsTimer);
      this.statsTimer = null;
    }
  }

  private emitStats(): void {
    dispatch('ghostShield:statsUpdated', this.getStatus());
  }

  private log(msg: string): void {
    this.sink(`[Ghost Shield] ${msg}`);
  }

  /** Print one honest line per module: ACTIVE / DEGRADED / UNAVAILABLE + reason. */
  private logReports(reports: readonly CapabilityReport[]): void {
    for (const r of reports) {
      if (!r.requested) continue;
      if (r.active && !r.degraded) {
        this.log(`${r.id}: ACTIVE`);
      } else if (r.active && r.degraded) {
        this.log(`${r.id}: DEGRADED — ${honestReason(r, this.platform)}`);
      } else {
        this.log(`${r.id}: UNAVAILABLE — ${honestReason(r, this.platform)}`);
      }
    }
  }

  private mirrorBlocked(): void {
    // Mirror into the live mesh's filter list if the app exposes one. App-level
    // filtering only; never represented as cloaking.
    const app = (globalThis as { app?: { mesh?: { blockedMacs?: string[] } } }).app;
    if (app?.mesh) app.mesh.blockedMacs = [...this.blockedMacs];
  }

  private persistBlocked(): void {
    try {
      const ls = (globalThis as { localStorage?: Storage }).localStorage;
      ls?.setItem(this.blockedKey, JSON.stringify([...this.blockedMacs]));
    } catch {
      /* persistence is best-effort */
    }
  }

  private restoreBlocked(): void {
    try {
      const ls = (globalThis as { localStorage?: Storage }).localStorage;
      const raw = ls?.getItem(this.blockedKey);
      if (!raw) return;
      const parsed: unknown = JSON.parse(raw);
      if (Array.isArray(parsed)) {
        for (const m of parsed) if (typeof m === 'string' && m.length < 128) this.blockedMacs.add(m);
        this.mirrorBlocked();
      }
    } catch {
      /* ignore malformed persisted state */
    }
  }
}

function clampLevel(level: number): 1 | 2 | 3 {
  if (level <= 1) return 1;
  if (level >= 3) return 3;
  return 2;
}

function dispatch(name: string, detail: FacadeStatus): void {
  const w = globalThis as { dispatchEvent?: (e: Event) => boolean; CustomEvent?: typeof CustomEvent };
  if (typeof w.dispatchEvent === 'function' && typeof w.CustomEvent === 'function') {
    w.dispatchEvent(new w.CustomEvent(name, { detail }));
  }
}
