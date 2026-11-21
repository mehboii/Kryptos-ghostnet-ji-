/**
 * MeshRouting — forces a minimum outbound relay hop count so traffic analysis
 * at the first hop cannot trivially infer that this node is the origin.
 *
 * HONESTY: this only affects routes the Kryptos mesh itself controls. It does
 * nothing to the underlying IP/transport path. If the mesh build does not expose
 * hop-count control, it reports `degraded` instead of pretending hops increased.
 */

import { REASON } from '../capabilities';
import { ModuleId, type CapabilityReport, type ShieldConfig, type ShieldModule, type ShieldPorts } from '../types';

export class MeshRouting implements ShieldModule {
  readonly id = ModuleId.MeshRouting;
  private last: CapabilityReport = { id: this.id, requested: false, active: false, degraded: false };

  constructor(private readonly ports: ShieldPorts) {}

  async enable(cfg: ShieldConfig): Promise<CapabilityReport> {
    if (!cfg.mesh.enforceMinHops) {
      await this.disable();
      return this.last;
    }

    if (!this.ports.mesh.supportsHopControl()) {
      this.last = {
        id: this.id,
        requested: true,
        active: false,
        degraded: true,
        reason: REASON.HOP_CONTROL_UNSUPPORTED,
      };
      this.ports.log.warn('mesh_hops_unsupported', { reason: REASON.HOP_CONTROL_UNSUPPORTED });
      return this.last;
    }

    await this.ports.mesh.setMinHops(cfg.mesh.minHops);
    this.last = { id: this.id, requested: true, active: true, degraded: false };
    this.ports.log.debug('mesh_hops_on', { minHops: cfg.mesh.minHops });
    return this.last;
  }

  async disable(): Promise<void> {
    if (this.ports.mesh.supportsHopControl()) {
      await this.ports.mesh.setMinHops(0);
    }
    this.last = { id: this.id, requested: false, active: false, degraded: false };
  }

  report(): CapabilityReport {
    return this.last;
  }
}
