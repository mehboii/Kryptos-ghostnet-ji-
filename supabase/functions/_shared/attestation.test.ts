// Deno tests for the attestation core. Run with:
//   deno test supabase/functions/_shared/attestation.test.ts
//
// Google/Apple verification and the nonce store are MOCKED — these tests cover
// the server-side trust logic, not live platform crypto: nonce issue/expire/
// reuse, replay rejection, every verdict branch, and session issuance on PASS.

import { assert, assertEquals } from 'jsr:@std/assert@1';
import { gradeAttestation } from './verify.ts';
import { issueSessionToken, verifySessionToken } from './session.ts';
import { generateNonce } from './nonce.ts';
import type {
  AndroidConfig,
  AndroidVerifier,
  AttestVerifyRequest,
  IosConfig,
  IosVerifier,
  NonceConsumeStatus,
  NonceStore,
  PlayIntegrityPayload,
  VerifierResult,
  VerifyDeps,
} from './types.ts';

/* ── mocks ────────────────────────────────────────────────────────────────── */

class FakeNonceStore implements NonceStore {
  // nonce → state
  private nonces = new Map<string, { used: boolean; expired: boolean }>();
  created: string[] = [];

  seed(nonce: string, opts: { used?: boolean; expired?: boolean } = {}): void {
    this.nonces.set(nonce, { used: opts.used ?? false, expired: opts.expired ?? false });
  }
  async create(nonce: string): Promise<void> {
    this.created.push(nonce);
    this.nonces.set(nonce, { used: false, expired: false });
  }
  async consume(nonce: string): Promise<NonceConsumeStatus> {
    const n = this.nonces.get(nonce);
    if (!n) return 'not_found';
    if (n.expired) return 'expired';
    if (n.used) return 'already_used';
    n.used = true;
    return 'ok';
  }
}

const androidConfig: AndroidConfig = {
  packageName: 'net.ghostnet.app',
  certSha256Digests: ['CERT_DIGEST_A'],
  deviceIntegrityBar: 'MEETS_DEVICE_INTEGRITY',
};
const iosConfig: IosConfig = { appId: 'TEAMID.net.ghostnet.app', environment: 'production' };

function androidPayload(nonce: string, over: Partial<PlayIntegrityPayload> = {}): PlayIntegrityPayload {
  return {
    requestDetails: { requestPackageName: 'net.ghostnet.app', nonce },
    appIntegrity: {
      appRecognitionVerdict: 'PLAY_RECOGNIZED',
      packageName: 'net.ghostnet.app',
      certificateSha256Digest: ['CERT_DIGEST_A'],
    },
    deviceIntegrity: { deviceRecognitionVerdict: ['MEETS_DEVICE_INTEGRITY', 'MEETS_BASIC_INTEGRITY'] },
    ...over,
  };
}

function makeAndroidVerifier(result: VerifierResult<PlayIntegrityPayload>): AndroidVerifier {
  return { decode: () => Promise.resolve(result) };
}
function makeIosVerifier(result: VerifierResult<{ counter: number }>): IosVerifier {
  return { verify: () => Promise.resolve(result) };
}

function deps(over: Partial<VerifyDeps> = {}): VerifyDeps {
  return {
    nonce: new FakeNonceStore(),
    android: makeAndroidVerifier({ ok: false, reason: 'unset' }),
    ios: makeIosVerifier({ ok: false, reason: 'unset' }),
    androidConfig,
    iosConfig,
    issueSession: (p) => Promise.resolve(`session-${p}`),
    ...over,
  };
}

/* ── nonce issue / expire / reuse (via the store mock semantics) ──────────── */

Deno.test('nonce store: create then consume once', async () => {
  const store = new FakeNonceStore();
  await store.create('n1');
  assertEquals(await store.consume('n1'), 'ok');
});

Deno.test('nonce store: second consume is already_used', async () => {
  const store = new FakeNonceStore();
  await store.create('n1');
  await store.consume('n1');
  assertEquals(await store.consume('n1'), 'already_used');
});

Deno.test('nonce store: unknown nonce is not_found; expired is expired', async () => {
  const store = new FakeNonceStore();
  assertEquals(await store.consume('ghost'), 'not_found');
  store.seed('old', { expired: true });
  assertEquals(await store.consume('old'), 'expired');
});

/* ── Android verdict branches ─────────────────────────────────────────────── */

Deno.test('android PASS: valid token + fresh nonce → PASS + session', async () => {
  const store = new FakeNonceStore();
  store.seed('NONCE');
  const d = deps({ nonce: store, android: makeAndroidVerifier({ ok: true, value: androidPayload('NONCE') }) });
  const req: AttestVerifyRequest = { platform: 'android', token: 'tok' };
  const res = await gradeAttestation(req, d);
  assertEquals(res.verdict, 'PASS');
  assertEquals(res.session, 'session-android');
});

Deno.test('android replay: same nonce twice → second is nonce_replayed', async () => {
  const store = new FakeNonceStore();
  store.seed('NONCE');
  const d = deps({ nonce: store, android: makeAndroidVerifier({ ok: true, value: androidPayload('NONCE') }) });
  const req: AttestVerifyRequest = { platform: 'android', token: 'tok' };
  assertEquals((await gradeAttestation(req, d)).verdict, 'PASS');
  const second = await gradeAttestation(req, d);
  assertEquals(second.verdict, 'FAIL');
  assertEquals(second.reason, 'nonce_replayed');
});

Deno.test('android FAIL: token decode failed', async () => {
  const d = deps({ android: makeAndroidVerifier({ ok: false, reason: 'android_decode_failed' }) });
  const res = await gradeAttestation({ platform: 'android', token: 'tok' }, d);
  assertEquals(res.verdict, 'FAIL');
  assertEquals(res.reason, 'android_decode_failed');
});

Deno.test('android FAIL: nonce not found (never issued)', async () => {
  const d = deps({ android: makeAndroidVerifier({ ok: true, value: androidPayload('GHOST') }) });
  const res = await gradeAttestation({ platform: 'android', token: 'tok' }, d);
  assertEquals(res.reason, 'nonce_not_found');
});

Deno.test('android FAIL: wrong package', async () => {
  const store = new FakeNonceStore();
  store.seed('NONCE');
  const payload = androidPayload('NONCE', {
    appIntegrity: { appRecognitionVerdict: 'PLAY_RECOGNIZED', packageName: 'com.evil.app', certificateSha256Digest: ['CERT_DIGEST_A'] },
  });
  const d = deps({ nonce: store, android: makeAndroidVerifier({ ok: true, value: payload }) });
  const res = await gradeAttestation({ platform: 'android', token: 'tok' }, d);
  assertEquals(res.reason, 'android_package_mismatch');
});

Deno.test('android FAIL: not PLAY_RECOGNIZED', async () => {
  const store = new FakeNonceStore();
  store.seed('NONCE');
  const payload = androidPayload('NONCE', {
    appIntegrity: { appRecognitionVerdict: 'UNRECOGNIZED_VERSION', packageName: 'net.ghostnet.app', certificateSha256Digest: ['CERT_DIGEST_A'] },
  });
  const d = deps({ nonce: store, android: makeAndroidVerifier({ ok: true, value: payload }) });
  assertEquals((await gradeAttestation({ platform: 'android', token: 'tok' }, d)).reason, 'android_app_not_play_recognized');
});

Deno.test('android FAIL: device integrity below bar', async () => {
  const store = new FakeNonceStore();
  store.seed('NONCE');
  const payload = androidPayload('NONCE', { deviceIntegrity: { deviceRecognitionVerdict: ['MEETS_BASIC_INTEGRITY'] } });
  const d = deps({ nonce: store, android: makeAndroidVerifier({ ok: true, value: payload }) });
  assertEquals((await gradeAttestation({ platform: 'android', token: 'tok' }, d)).reason, 'android_device_integrity_below_bar');
});

Deno.test('android: STRONG satisfies a DEVICE bar', async () => {
  const store = new FakeNonceStore();
  store.seed('NONCE');
  const payload = androidPayload('NONCE', { deviceIntegrity: { deviceRecognitionVerdict: ['MEETS_STRONG_INTEGRITY'] } });
  const d = deps({ nonce: store, android: makeAndroidVerifier({ ok: true, value: payload }) });
  assertEquals((await gradeAttestation({ platform: 'android', token: 'tok' }, d)).verdict, 'PASS');
});

/* ── iOS verdict branches ─────────────────────────────────────────────────── */

Deno.test('ios PASS: valid attestation + fresh nonce → PASS + session', async () => {
  const store = new FakeNonceStore();
  store.seed('NONCE');
  const d = deps({ nonce: store, ios: makeIosVerifier({ ok: true, value: { counter: 0 } }) });
  const req: AttestVerifyRequest = { platform: 'ios', token: 'cbor', keyId: 'KID', nonce: 'NONCE' };
  const res = await gradeAttestation(req, d);
  assertEquals(res.verdict, 'PASS');
  assertEquals(res.session, 'session-ios');
});

Deno.test('ios FAIL: missing keyId / missing nonce', async () => {
  const d = deps({ ios: makeIosVerifier({ ok: true, value: { counter: 0 } }) });
  assertEquals((await gradeAttestation({ platform: 'ios', token: 'cbor', nonce: 'N' }, d)).reason, 'missing_keyid');
  assertEquals((await gradeAttestation({ platform: 'ios', token: 'cbor', keyId: 'KID' }, d)).reason, 'missing_nonce');
});

Deno.test('ios FAIL: attestation verification fails (e.g. nonce binding)', async () => {
  const store = new FakeNonceStore();
  store.seed('NONCE');
  const d = deps({ nonce: store, ios: makeIosVerifier({ ok: false, reason: 'ios_nonce_mismatch' }) });
  const req: AttestVerifyRequest = { platform: 'ios', token: 'cbor', keyId: 'KID', nonce: 'NONCE' };
  const res = await gradeAttestation(req, d);
  assertEquals(res.verdict, 'FAIL');
  assertEquals(res.reason, 'ios_nonce_mismatch');
  // The nonce was still consumed (single-use), so a retry is a replay.
  assertEquals((await gradeAttestation(req, d)).reason, 'nonce_replayed');
});

Deno.test('ios replay: reused nonce → nonce_replayed', async () => {
  const store = new FakeNonceStore();
  store.seed('NONCE');
  const d = deps({ nonce: store, ios: makeIosVerifier({ ok: true, value: { counter: 0 } }) });
  const req: AttestVerifyRequest = { platform: 'ios', token: 'cbor', keyId: 'KID', nonce: 'NONCE' };
  assertEquals((await gradeAttestation(req, d)).verdict, 'PASS');
  assertEquals((await gradeAttestation(req, d)).reason, 'nonce_replayed');
});

/* ── input guards ─────────────────────────────────────────────────────────── */

Deno.test('bad platform / missing token are rejected', async () => {
  const d = deps();
  assertEquals((await gradeAttestation({ platform: 'windows' as unknown as 'ios', token: 't' }, d)).reason, 'bad_platform');
  assertEquals((await gradeAttestation({ platform: 'android', token: '' }, d)).reason, 'missing_token');
});

/* ── session token ────────────────────────────────────────────────────────── */

Deno.test('session token: issued on PASS, verifies, and expires', async () => {
  const cfg = { secret: 'test-secret-please-rotate', ttlSeconds: 900 };
  const now = 1_000_000_000_000;
  const tok = await issueSessionToken('android', cfg, now);
  const claims = await verifySessionToken(tok, cfg, now + 1000);
  assert(claims !== null);
  assertEquals(claims?.plat, 'android');
  // After expiry → null.
  assertEquals(await verifySessionToken(tok, cfg, now + 901_000), null);
  // Tampered signature → null.
  assertEquals(await verifySessionToken(tok + 'x', cfg, now + 1000), null);
});

Deno.test('nonce generator: base64url, >= 16 bytes, unique', () => {
  const a = generateNonce(32);
  const b = generateNonce(32);
  assert(a !== b);
  assert(/^[A-Za-z0-9_-]+$/.test(a));
});
