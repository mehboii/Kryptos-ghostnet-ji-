// Android Play Integrity verifier + server-side policy checks.
//
// The Google API (google.ts) does the cryptographic decode. Here we (a) wrap that
// as the AndroidVerifier the orchestration depends on, and (b) apply OUR policy to
// the decoded verdict. Every check fails CLOSED.

import { decodeIntegrityToken } from './google.ts';
import type {
  AndroidConfig,
  AndroidVerifier,
  DeviceIntegrityBar,
  PlayIntegrityPayload,
  VerifierResult,
} from './types.ts';

function isPayload(v: unknown): v is PlayIntegrityPayload {
  return typeof v === 'object' && v !== null;
}

/** Real AndroidVerifier backed by Google's decodeIntegrityToken. */
export class GooglePlayIntegrityVerifier implements AndroidVerifier {
  constructor(
    private readonly serviceAccountJson: string,
    private readonly packageName: string,
  ) {}

  async decode(token: string): Promise<VerifierResult<PlayIntegrityPayload>> {
    try {
      const decoded = await decodeIntegrityToken(this.serviceAccountJson, this.packageName, token);
      if (!isPayload(decoded)) return { ok: false, reason: 'android_decode_empty' };
      return { ok: true, value: decoded };
    } catch (_e) {
      return { ok: false, reason: 'android_decode_failed' };
    }
  }
}

/**
 * Apply policy to a decoded Play Integrity payload. Order of the device-integrity
 * bar from weakest → strongest, so a STRONG verdict also satisfies a DEVICE bar.
 */
const BAR_IMPLIES: Record<DeviceIntegrityBar, readonly string[]> = {
  MEETS_BASIC_INTEGRITY: ['MEETS_BASIC_INTEGRITY', 'MEETS_DEVICE_INTEGRITY', 'MEETS_STRONG_INTEGRITY'],
  MEETS_DEVICE_INTEGRITY: ['MEETS_DEVICE_INTEGRITY', 'MEETS_STRONG_INTEGRITY'],
  MEETS_STRONG_INTEGRITY: ['MEETS_STRONG_INTEGRITY'],
};

export function checkAndroidPolicy(
  payload: PlayIntegrityPayload,
  expectedNonce: string,
  config: AndroidConfig,
): VerifierResult<true> {
  if (payload.requestDetails?.nonce !== expectedNonce) {
    return { ok: false, reason: 'android_nonce_mismatch' };
  }
  if (payload.appIntegrity?.packageName !== config.packageName) {
    return { ok: false, reason: 'android_package_mismatch' };
  }
  const digests = payload.appIntegrity?.certificateSha256Digest ?? [];
  if (!digests.some((d) => config.certSha256Digests.includes(d))) {
    return { ok: false, reason: 'android_cert_mismatch' };
  }
  if (payload.appIntegrity?.appRecognitionVerdict !== 'PLAY_RECOGNIZED') {
    return { ok: false, reason: 'android_app_not_play_recognized' };
  }
  const verdicts = payload.deviceIntegrity?.deviceRecognitionVerdict ?? [];
  const accepted = BAR_IMPLIES[config.deviceIntegrityBar];
  if (!verdicts.some((v) => accepted.includes(v))) {
    return { ok: false, reason: 'android_device_integrity_below_bar' };
  }
  return { ok: true, value: true };
}
