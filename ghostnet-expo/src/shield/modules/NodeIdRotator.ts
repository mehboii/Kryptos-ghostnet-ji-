/**
 * NodeIdRotator — rotates GhostNet's advertised ephemeral overlay node id on an
 * interval so an observer cannot use a stable overlay identifier to track the
 * device across time.
 *
 * HONESTY: this rotates the OVERLAY id GhostNet advertises (the value a peer or
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
 */

import { REASON } from '../capabilities';
import {
  ModuleId,
  type CapabilityReport,
  type ShieldConfig,
  type ShieldModule,
  type ShieldPorts,
  type TimerHandle,
} from '../types';

const ROTATED_ID_BYTES = 16;

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
    this.last = { id: this.id, requested: true, active: true, degraded: false };
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

    // 3. Keep the old id alive for the grace window, then retire it. This is what
    //    prevents dropped sessions: traffic to the old id still lands meanwhile.
    const graceTimer = this.ports.clock.setTimeout(() => {
      this.graceTimers.delete(graceTimer);
      void this.ports.mesh.retireNodeId(oldId);
    }, cfg.nodeIdRotation.handoffGraceMs);
    this.graceTimers.add(graceTimer);

    this.ports.log.debug('rotated', { peers: peers.length });
  }
}

function bytesToHex(bytes: Uint8Array): string {
  let s = '';
  for (const b of bytes) s += b.toString(16).padStart(2, '0');
  return s;
}
