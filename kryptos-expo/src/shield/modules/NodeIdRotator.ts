/**
 * NodeIdRotator — rotates Kryptos's advertised ephemeral overlay node id on an
 * interval so an observer cannot use a stable overlay identifier to track the
 * device across time.
 *
 * HONESTY: this rotates the OVERLAY id Kryptos advertises (the value a peer or
 * observer correlates on), NOT the hardware BLE/WiFi MAC, which an unprivileged
 * app cannot change. If the mesh build cannot advertise a rotated id, the module
 * reports `degraded` instead of pretending the id changed.
 *
 * SESSION-SAFE HANDOFF (must not drop active sessions):
 *   On each rotation we
 *     1. generate a fresh random id,
 *     2. send an authenticated old→new handoff to every established peer over
 *        the EXISTING encrypted channel (so they remap before the old id dies),
 *     3. adopt the new id for advertising/answering,
 *     4. keep the old id alive for `handoffGraceMs`, then retire it.
 *   The grace window guarantees in-flight traffic addressed to the old id still
 *   lands while peers update.
 *
 * ANTI-FINGERPRINT (hardening): a stable advertising *cadence* or *payload size*
 * would re-identify "the Kryptos app" even as the id rotates. So each rotation
 * also re-randomizes the BLE advertising interval (drawn from OS-default ranges,
 * so we blend in rather than standing out) and the advertised payload length.
 * NOTE: this is overlay only. A co-located physical-layer sniffer correlating on
 * the hardware MAC still defeats it — see THREAT_MODEL.md #3.
 */

import { REASON } from '../capabilities';
import {
  ModuleId,
  type AdvertisingParameters,
  type CapabilityReport,
  type ShieldConfig,
  type ShieldModule,
  type ShieldPorts,
  type TimerHandle,
} from '../types';

const ROTATED_ID_BYTES = 16;

/**
 * Advertising intervals (ms) that match common OS defaults so our cadence is not
 * a distinctive value. These mirror Android's advertise modes
 * (LOW_LATENCY ~100, BALANCED ~250, LOW_POWER ~1000); picking among them keeps us
 * inside the population of ordinary BLE advertisers.
 */
const OS_DEFAULT_ADV_INTERVALS_MS: readonly number[] = [100, 250, 1000];
/** Legal advertised payload (scan-response) length window, in bytes. */
const ADV_PAYLOAD_MIN = 8;
const ADV_PAYLOAD_MAX = 31;

export class NodeIdRotator implements ShieldModule {
  readonly id = ModuleId.NodeIdRotator;
  private last: CapabilityReport = { id: this.id, requested: false, active: false, degraded: false };
  private cfg: ShieldConfig | null = null;
  private rotateTimer: TimerHandle | null = null;
  private readonly graceTimers = new Set<TimerHandle>();

  constructor(private readonly ports: ShieldPorts) {}

  async enable(cfg: ShieldConfig): Promise<CapabilityReport> {
    if (!cfg.nodeIdRotation.enabled) {
      await this.disable();
      return this.last;
    }

    if (!this.ports.mesh.supportsNodeIdRotation()) {
      this.last = {
        id: this.id,
        requested: true,
        active: false,
        degraded: true,
        reason: REASON.NODE_ID_ROTATION_UNSUPPORTED,
      };
      this.ports.log.warn('rotate_unsupported', { reason: REASON.NODE_ID_ROTATION_UNSUPPORTED });
      return this.last;
    }

    this.cfg = cfg;
    this.scheduleNextRotation();

    // Id rotation works; advertising-shape randomization is a bonus hardening
    // that is platform-gated. If we can't vary interval/length (e.g. iOS fixes
    // them), stay active but report degraded so the limitation is visible.
    const advParamsOk = !cfg.nodeIdRotation.randomizeAdvertising || this.ports.ble.supportsAdvertisingParams();
    this.last = advParamsOk
      ? { id: this.id, requested: true, active: true, degraded: false }
      : { id: this.id, requested: true, active: true, degraded: true, reason: REASON.BLE_ADV_PARAMS_FIXED };
    return this.last;
  }

  async disable(): Promise<void> {
    if (this.rotateTimer) {
      this.ports.clock.clearTimeout(this.rotateTimer);
      this.rotateTimer = null;
    }
    for (const t of this.graceTimers) this.ports.clock.clearTimeout(t);
    this.graceTimers.clear();
    this.cfg = null;
    this.last = { id: this.id, requested: false, active: false, degraded: false };
  }

  report(): CapabilityReport {
    return this.last;
  }

  private scheduleNextRotation(): void {
    const cfg = this.cfg;
    if (!cfg) return;
    const delay = this.ports.random.int(cfg.nodeIdRotation.minIntervalMs, cfg.nodeIdRotation.maxIntervalMs);
    this.rotateTimer = this.ports.clock.setTimeout(() => {
      void this.rotate().finally(() => this.scheduleNextRotation());
    }, delay);
  }

  /**
   * Perform one session-safe rotation. Exposed for testing. The ordering here is
   * the contract: peers are handed off BEFORE the old id is retired.
   */
  async rotate(): Promise<void> {
    const cfg = this.cfg;
    if (!cfg) return;

    const oldId = this.ports.mesh.getCurrentNodeId();
    const newId = bytesToHex(this.ports.random.bytes(ROTATED_ID_BYTES));
    if (newId === oldId) return; // astronomically unlikely; skip rather than churn

    // 1. Hand off to every established peer over the encrypted channel first.
    const peers = this.ports.mesh.getActiveSessions();
    for (const peer of peers) {
      await this.ports.mesh.sendNodeIdHandoff(peer, oldId, newId);
    }

    // 2. Adopt the new id for advertising/answering.
    await this.ports.mesh.adoptNodeId(newId);

    // 2b. Re-randomize advertising shape so cadence/size aren't a fingerprint.
    if (cfg.nodeIdRotation.randomizeAdvertising && this.ports.ble.supportsAdvertisingParams()) {
      await this.ports.ble.setAdvertisingParameters(this.randomAdvertisingParams());
    }

    // 3. Keep the old id alive for the grace window, then retire it. This is what
    //    prevents dropped sessions: traffic to the old id still lands meanwhile.
    const graceTimer = this.ports.clock.setTimeout(() => {
      this.graceTimers.delete(graceTimer);
      void this.ports.mesh.retireNodeId(oldId);
    }, cfg.nodeIdRotation.handoffGraceMs);
    this.graceTimers.add(graceTimer);

    this.ports.log.debug('rotated', { peers: peers.length });
  }

  /** A fresh advertising interval (from OS-default values) + payload length. */
  private randomAdvertisingParams(): AdvertisingParameters {
    const intervalMs = OS_DEFAULT_ADV_INTERVALS_MS[this.ports.random.int(0, OS_DEFAULT_ADV_INTERVALS_MS.length - 1)];
    const payloadLength = this.ports.random.int(ADV_PAYLOAD_MIN, ADV_PAYLOAD_MAX);
    return { intervalMs, payloadLength };
  }
}

function bytesToHex(bytes: Uint8Array): string {
  let s = '';
  for (const b of bytes) s += b.toString(16).padStart(2, '0');
  return s;
}
