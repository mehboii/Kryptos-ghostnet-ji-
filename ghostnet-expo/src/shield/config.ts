/**
 * Ghost Shield — the single source of truth for the cumulative tier→behavior
 * mapping. Every module reads its slice of the {@link ShieldConfig} produced
 * here; nothing else decides "what does GHOST turn on". Keeping it in one pure
 * function is what makes the cumulative guarantee (each tier ⊇ the one below)
 * auditable and testable.
 */

import { ModuleId, ShieldTier, TIER_RANK, type ShieldConfig } from './types';

/** Length buckets for traffic padding (ascending). Spec-defined. */
export const PADDING_BUCKETS: readonly number[] = [256, 512, 1024, 4096];

/** Default DoH resolver. Overridable via {@link resolveConfig} options. */
export const DEFAULT_DOH_RESOLVER = 'https://cloudflare-dns.com/dns-query';

export interface ConfigOptions {
  /** Override the DoH resolver endpoint. */
  readonly dohResolver?: string;
}

/**
 * Resolve a tier into its fully-expanded configuration.
 *
 * Cumulative by construction: each branch falls through to enable everything in
 * the tiers below it. FULL_GHOST is PHANTOM with every knob pinned at max and
 * cover traffic always-on.
 */
export function resolveConfig(tier: ShieldTier, options: ConfigOptions = {}): ShieldConfig {
  const dohResolver = options.dohResolver ?? DEFAULT_DOH_RESOLVER;
  const rank = TIER_RANK[tier];

  const atLeast = (t: ShieldTier): boolean => rank >= TIER_RANK[t];
  const isFull = tier === ShieldTier.FULL_GHOST;

  return {
    tier,
    // STEALTH+ : silence our own BLE advertising + discovery beaconing.
    ble: {
      silenceAdvertising: atLeast(ShieldTier.STEALTH),
      silenceDiscoveryBeacon: atLeast(ShieldTier.STEALTH),
    },
    // STEALTH+ : force DoH, fail-closed.
    dns: {
      mode: atLeast(ShieldTier.STEALTH) ? 'doh' : 'system',
      dohResolver,
      failClosed: atLeast(ShieldTier.STEALTH),
    },
    // GHOST+ : length-pad + timing jitter. Cover traffic adaptive at GHOST/PHANTOM,
    // always-on at FULL_GHOST.
    traffic: {
      enabled: atLeast(ShieldTier.GHOST),
      paddingBuckets: PADDING_BUCKETS,
      jitterMinMs: atLeast(ShieldTier.GHOST) ? 20 : 0,
      jitterMaxMs: atLeast(ShieldTier.GHOST) ? 250 : 0,
      coverTraffic: !atLeast(ShieldTier.GHOST) ? 'off' : isFull ? 'always' : 'adaptive',
      coverRatePerMin: isFull ? 60 : atLeast(ShieldTier.GHOST) ? 20 : 0,
    },
    // PHANTOM+ : force maximum mesh relay hop count.
    mesh: {
      enforceMinHops: atLeast(ShieldTier.PHANTOM),
      minHops: atLeast(ShieldTier.PHANTOM) ? 4 : 0,
    },
    // PHANTOM+ : decoy peer announcements (2–4; max at FULL_GHOST).
    decoy: {
      enabled: atLeast(ShieldTier.PHANTOM),
      minDecoys: atLeast(ShieldTier.PHANTOM) ? (isFull ? 4 : 2) : 0,
      maxDecoys: atLeast(ShieldTier.PHANTOM) ? 4 : 0,
    },
    // PHANTOM+ : rotate the advertised ephemeral node id (30–90s; aggressive
    // 10–20s at FULL_GHOST). 8s handoff grace keeps active sessions alive.
    nodeIdRotation: {
      enabled: atLeast(ShieldTier.PHANTOM),
      minIntervalMs: atLeast(ShieldTier.PHANTOM) ? (isFull ? 10_000 : 30_000) : 0,
      maxIntervalMs: atLeast(ShieldTier.PHANTOM) ? (isFull ? 20_000 : 90_000) : 0,
      handoffGraceMs: 8_000,
    },
  };
}

/**
 * The set of modules a tier requires active. Derived from {@link resolveConfig}
 * so it can never disagree with the behavior config.
 */
export function modulesForTier(tier: ShieldTier): ReadonlySet<ModuleId> {
  const cfg = resolveConfig(tier);
  const ids = new Set<ModuleId>();
  if (cfg.ble.silenceAdvertising || cfg.ble.silenceDiscoveryBeacon) ids.add(ModuleId.BleCloak);
  if (cfg.dns.mode === 'doh') ids.add(ModuleId.DnsGuard);
  if (cfg.traffic.enabled) ids.add(ModuleId.TrafficShaper);
  if (cfg.mesh.enforceMinHops) ids.add(ModuleId.MeshRouting);
  if (cfg.decoy.enabled) ids.add(ModuleId.DecoyEngine);
  if (cfg.nodeIdRotation.enabled) ids.add(ModuleId.NodeIdRotator);
  return ids;
}
