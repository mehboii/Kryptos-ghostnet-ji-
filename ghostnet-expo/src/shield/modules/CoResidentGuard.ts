/**
 * CoResidentGuard — detects ON-DEVICE observation risks, without root.
 *
 * THREAT (THREAT_MODEL.md #6): a co-resident app or an over-the-shoulder
 * recording can capture GhostNet content even though our memory and keys are
 * sandbox-protected. On a non-rooted device the realistic risks are *observation*:
 *  - active screen recording / casting (Android MediaProjection, iOS UIScreen.isCaptured),
 *  - a third-party accessibility service scraping the screen,
 *  - clipboard snooping after a sensitive copy,
 *  - sensitive data leaking into notification text.
 *
 * HONESTY: every detector here is best-effort and racy on an unprivileged app.
 * It raises the cost of casual snooping; it is NOT a defense against a rooted or
 * OS-compromised device. Where the platform exposes no detection at all, the
 * module reports `degraded` with a reason instead of pretending to be safe.
 *
 * On detection it (a) updates its CapabilityReport to degraded, (b) notifies the
 * manager (which re-emits a `degraded` event and may auto-raise the tier), and
 * (c) leaves remediation policy — warn user, blur screen — to the host UI.
 */

import { REASON } from '../capabilities';
import { ModuleId, type CapabilityReport, type ShieldConfig, type ShieldModule, type ShieldPorts } from '../types';

/** A module that pushes runtime detections to the manager out-of-band. */
export interface RuntimeDetector {
  setNotifier(notify: (report: CapabilityReport) => void): void;
}

export function isRuntimeDetector(mod: ShieldModule): mod is ShieldModule & RuntimeDetector {
  return typeof (mod as Partial<RuntimeDetector>).setNotifier === 'function';
}

export class CoResidentGuard implements ShieldModule, RuntimeDetector {
  readonly id = ModuleId.CoResidentGuard;
  private last: CapabilityReport = { id: this.id, requested: false, active: false, degraded: false };
  private cfg: ShieldConfig | null = null;
  private unsubscribeCapture: (() => void) | null = null;
  private notify: ((report: CapabilityReport) => void) | null = null;
  private clipboardTimer: ReturnType<ShieldPorts['clock']['setTimeout']> | null = null;

  constructor(private readonly ports: ShieldPorts) {}

  setNotifier(notify: (report: CapabilityReport) => void): void {
    this.notify = notify;
  }

  async enable(cfg: ShieldConfig): Promise<CapabilityReport> {
    if (!cfg.coResident.enabled) {
      await this.disable();
      return this.last;
    }
    this.cfg = cfg;

    const screenCap = this.ports.coResident.supportsScreenCaptureDetection();
    const a11y = this.ports.coResident.supportsAccessibilityDetection();

    // Subscribe to live screen-capture state changes. A *live* change notifies
    // the manager out-of-band; the initial enable-time evaluation does not (the
    // manager's own post-transition degraded check surfaces that).
    if (screenCap && this.unsubscribeCapture === null) {
      this.unsubscribeCapture = this.ports.coResident.subscribeScreenCapture((captured) => {
        this.evaluate(captured, true);
      });
    }

    if (!screenCap && !a11y) {
      // Nothing observable on this platform/build — say so, don't fake safety.
      this.last = {
        id: this.id,
        requested: true,
        active: false,
        degraded: true,
        reason: REASON.ONDEVICE_DETECTION_UNSUPPORTED,
      };
      this.ports.log.warn('coresident_unsupported', { reason: REASON.ONDEVICE_DETECTION_UNSUPPORTED });
      return this.last;
    }

    // Active monitor: evaluate current state immediately (no out-of-band notify;
    // the manager emits degraded for the enable-time report itself).
    this.evaluate(undefined, false);
    return this.last;
  }

  async disable(): Promise<void> {
    if (this.unsubscribeCapture) {
      this.unsubscribeCapture();
      this.unsubscribeCapture = null;
    }
    if (this.clipboardTimer) {
      this.ports.clock.clearTimeout(this.clipboardTimer);
      this.clipboardTimer = null;
    }
    this.cfg = null;
    this.last = { id: this.id, requested: false, active: false, degraded: false };
  }

  report(): CapabilityReport {
    return this.last;
  }

  /**
   * Call after copying sensitive data (a key, seed word, address) to the system
   * clipboard. The clipboard is cleared after `clipboardClearMs` so a co-resident
   * clipboard-snooper has only a short window. Idempotent: re-arming resets the timer.
   */
  protectClipboard(): void {
    const cfg = this.cfg;
    if (!cfg) return;
    if (this.clipboardTimer) this.ports.clock.clearTimeout(this.clipboardTimer);
    this.clipboardTimer = this.ports.clock.setTimeout(() => {
      this.clipboardTimer = null;
      void this.ports.coResident.clearClipboard();
    }, cfg.coResident.clipboardClearMs);
  }

  /** Re-read detection state and update the report; optionally notify on a threat. */
  private evaluate(capturedHint: boolean | undefined, notifyOnThreat: boolean): void {
    const captured =
      this.ports.coResident.supportsScreenCaptureDetection() &&
      (capturedHint ?? this.ports.coResident.isScreenCaptured());
    const a11y =
      this.ports.coResident.supportsAccessibilityDetection() &&
      this.ports.coResident.isAccessibilityServiceActive();

    if (captured || a11y) {
      const reason = captured ? REASON.SCREEN_CAPTURE_ACTIVE : REASON.ACCESSIBILITY_SERVICE_ACTIVE;
      this.last = { id: this.id, requested: true, active: true, degraded: true, reason };
      this.ports.log.warn('coresident_threat', { reason });
      if (notifyOnThreat) this.notify?.(this.last);
      return;
    }

    this.last = { id: this.id, requested: true, active: true, degraded: false };
  }
}
