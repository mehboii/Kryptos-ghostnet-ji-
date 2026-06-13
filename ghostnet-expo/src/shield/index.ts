/**
 * Ghost Shield — public barrel.
 *
 * Typical use:
 *   import { ShieldManager, ShieldTier } from './shield';
 *   const shield = new ShieldManager(ports);   // ports = your RN platform wiring
 *   await shield.restore();                     // re-apply last tier on launch
 *   await shield.setTier(ShieldTier.GHOST);
 *
 * See example.ts for a full wiring walkthrough and README.md for the honesty
 * matrix (what is real vs platform-gated per OS).
 */

export { ShieldManager, TIER_STORE_KEY, type ShieldManagerOptions } from './ShieldManager';
export {
  resolveConfig,
  modulesForTier,
  PADDING_BUCKETS,
  DEFAULT_DOH_RESOLVER,
  type ConfigOptions,
} from './config';
export { probeCapabilities, REASON, type CapabilitySet } from './capabilities';
export { createLogger, NULL_LOGGER, type LoggerOptions } from './logger';
export { TrafficModel, type TrafficModelOptions } from './traffic-model';
export { CoResidentGuard, isRuntimeDetector, type RuntimeDetector } from './modules/CoResidentGuard';

// Pure traffic-shaping helpers (handy for the mesh receive side / tests).
export { selectBucket, padFrame, unpadFrame } from './modules/TrafficShaper';

export {
  ShieldTier,
  ModuleId,
  TIER_RANK,
  type ShieldConfig,
  type CapabilityReport,
  type ShieldModule,
  type ShieldStatus,
  type ShieldEvent,
  type TierChangedPayload,
  type DegradedPayload,
  type ShieldPorts,
  type BleAdapter,
  type AdvertisingParameters,
  type DnsAdapter,
  type MeshAdapter,
  type CoResidentAdapter,
  type SecureStorePort,
  type Clock,
  type RandomSource,
  type ShieldLogger,
  type MeshFrame,
  type OutboundTransform,
  type DecoyAnnouncement,
  type DnsMode,
  type CoverTrafficMode,
  type TimerHandle,
} from './types';
