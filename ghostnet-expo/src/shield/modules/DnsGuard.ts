/**
 * DnsGuard — forces DNS over HTTPS (DoH), fail-closed.
 *
 * FAIL-CLOSED CONTRACT: if the DoH resolver is unreachable we BLOCK plaintext
 * DNS rather than silently falling back to the system resolver (which would
 * leak every lookup to the local network / ISP). Blocking-but-can't-resolve is
 * an intentional, honest degraded state — the user chose privacy over
 * connectivity at STEALTH+. We surface `degraded: true` with a reason so the UI
 * can explain why name resolution is failing.
 *
 * HONESTY: on a platform with no app-controlled DoH path at all, we cannot
 * force DoH; we report `degraded`/inactive rather than claiming DNS is private.
 */

import { REASON } from '../capabilities';
import { ModuleId, type CapabilityReport, type ShieldConfig, type ShieldModule, type ShieldPorts } from '../types';

export class DnsGuard implements ShieldModule {
  readonly id = ModuleId.DnsGuard;
  private last: CapabilityReport = { id: this.id, requested: false, active: false, degraded: false };

  constructor(private readonly ports: ShieldPorts) {}

  async enable(cfg: ShieldConfig): Promise<CapabilityReport> {
    if (cfg.dns.mode !== 'doh') {
      await this.disable();
      return this.last;
    }

    if (!this.ports.dns.supportsDoh()) {
      this.last = {
        id: this.id,
        requested: true,
        active: false,
        degraded: true,
        reason: REASON.DOH_UNSUPPORTED,
      };
      this.ports.log.warn('dns_doh_unsupported', { reason: REASON.DOH_UNSUPPORTED });
      return this.last;
    }

    // Point the resolver at DoH first.
    await this.ports.dns.setMode('doh', cfg.dns.dohResolver);

    // Live reachability check. If unreachable and fail-closed, block plaintext.
    const reachable = await this.ports.dns.probe(cfg.dns.dohResolver);
    if (!reachable && cfg.dns.failClosed) {
      await this.ports.dns.setPlaintextBlocked(true);
      this.last = {
        id: this.id,
        requested: true,
        // Active: it IS enforcing privacy (blocking the plaintext leak). It just
        // cannot resolve names right now — that is the fail-closed bargain.
        active: true,
        degraded: true,
        reason: REASON.DOH_UNREACHABLE_FAILCLOSED,
      };
      this.ports.log.warn('dns_failclosed', { reason: REASON.DOH_UNREACHABLE_FAILCLOSED });
      return this.last;
    }

    // DoH reachable: ensure plaintext stays unblocked and resolve via DoH.
    await this.ports.dns.setPlaintextBlocked(false);

    // DoH hides the DNS *query*, but the TLS SNI of the connections that follow
    // still leaks the destination hostname to an on-path observer UNLESS ECH is
    // available. Surface that honestly rather than implying DoH hides the host.
    if (!this.ports.dns.supportsEch()) {
      this.last = {
        id: this.id,
        requested: true,
        active: true,
        degraded: true,
        reason: REASON.SNI_LEAK_NO_ECH,
      };
      this.ports.log.warn('dns_sni_leak', { reason: REASON.SNI_LEAK_NO_ECH });
      return this.last;
    }

    this.last = { id: this.id, requested: true, active: true, degraded: false };
    this.ports.log.debug('dns_doh_on');
    return this.last;
  }

  async disable(): Promise<void> {
    await this.ports.dns.setPlaintextBlocked(false);
    await this.ports.dns.setMode('system', '');
    this.last = { id: this.id, requested: false, active: false, degraded: false };
  }

  report(): CapabilityReport {
    return this.last;
  }
}
