// Attestation grading — the server-side trust decision.
//
// Pure orchestration over injected dependencies (VerifyDeps), so it is fully
// unit-testable by mocking Google/Apple verification and the nonce store. The
// Edge Function (attest-verify/index.ts) wires the real implementations.
//
// REPLAY DEFENSE: the nonce is consumed ATOMICALLY (single UPDATE) before the
// policy/identity checks run, so a replayed token races to a single winner and
// every subsequent attempt sees 'already_used'.
//   - Android: the nonce lives INSIDE the signed token, so we must let Google
//     decrypt/verify first to read it, then consume, then apply policy.
//   - iOS: the client states which issued nonce it used; we consume it, then the
//     App Attest verification proves the attestation is cryptographically bound
//     to exactly that nonce (clientDataHash), so a lie fails the binding check.

import { checkAndroidPolicy } from './playIntegrity.ts';
import type {
  AttestVerifyRequest,
  AttestVerifyResponse,
  NonceConsumeStatus,
  VerifyDeps,
} from './types.ts';

function fail(reason: string): AttestVerifyResponse {
  return { verdict: 'FAIL', reason };
}

function nonceFailReason(status: NonceConsumeStatus): string {
  switch (status) {
    case 'not_found':
      return 'nonce_not_found';
    case 'already_used':
      return 'nonce_replayed';
    case 'expired':
      return 'nonce_expired';
    default:
      return 'nonce_invalid';
  }
}

export async function gradeAttestation(
  req: AttestVerifyRequest,
  deps: VerifyDeps,
): Promise<AttestVerifyResponse> {
  if (req.platform !== 'android' && req.platform !== 'ios') return fail('bad_platform');
  if (typeof req.token !== 'string' || req.token.length === 0) return fail('missing_token');

  if (req.platform === 'android') {
    // 1. Decode (Google verifies/decrypts) so we can read the embedded nonce.
    const decoded = await deps.android.decode(req.token);
    if (!decoded.ok) return fail(decoded.reason);
    const nonce = decoded.value.requestDetails?.nonce;
    if (!nonce) return fail('no_nonce_in_token');

    // 2. Consume atomically BEFORE applying policy (replay defense).
    const status = await deps.nonce.consume(nonce);
    if (status !== 'ok') return fail(nonceFailReason(status));

    // 3. Policy/identity checks on the server-decoded verdict.
    const policy = checkAndroidPolicy(decoded.value, nonce, deps.androidConfig);
    if (!policy.ok) return fail(policy.reason);

    return { verdict: 'PASS', session: await deps.issueSession('android') };
  }

  // iOS
  if (typeof req.keyId !== 'string' || req.keyId.length === 0) return fail('missing_keyid');
  if (typeof req.nonce !== 'string' || req.nonce.length === 0) return fail('missing_nonce');

  // 1. Consume the issued nonce atomically (replay defense).
  const status = await deps.nonce.consume(req.nonce);
  if (status !== 'ok') return fail(nonceFailReason(status));

  // 2. App Attest verification proves the attestation is bound to this exact nonce.
  const v = await deps.ios.verify({ token: req.token, keyId: req.keyId, nonce: req.nonce }, deps.iosConfig);
  if (!v.ok) return fail(v.reason);

  return { verdict: 'PASS', session: await deps.issueSession('ios') };
}
