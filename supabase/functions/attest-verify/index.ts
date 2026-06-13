// attest-verify — the server-side trust decision.
//
// POST { platform, token, keyId?, nonce? }. Verifies the SIGNED attestation
// (Android: Google Play Integrity decode + policy; iOS: Apple App Attest), and on
// PASS issues a short-lived signed session token the app presents for sensitive
// ops. NEVER trusts any verdict field the client sends.
//
// Logs ONLY the verdict + reason + platform (server-side console). Never logs the
// raw token, device fingerprints, peer ids, or node ids.

import { json, preflight, rateLimitKey, readJson } from '../_shared/http.ts';
import { createServiceClient, SupabaseNonceStore, SupabaseRateLimiter } from '../_shared/nonceStore.ts';
import { GooglePlayIntegrityVerifier } from '../_shared/playIntegrity.ts';
import { AppleAppAttestVerifier } from '../_shared/appAttest.ts';
import { issueSessionToken } from '../_shared/session.ts';
import { gradeAttestation } from '../_shared/verify.ts';
import {
  loadAndroidConfig,
  loadGoogleServiceAccount,
  loadIosConfig,
  loadSessionConfig,
  loadSupabase,
} from '../_shared/config.ts';
import type { AttestVerifyRequest, Platform, VerifyDeps } from '../_shared/types.ts';

// Per-client cap: 20 verify attempts / minute.
const RL_MAX = 20;
const RL_WINDOW_SECONDS = 60;

Deno.serve(async (req: Request): Promise<Response> => {
  const pre = preflight(req);
  if (pre) return pre;
  if (req.method !== 'POST') return json({ error: 'method_not_allowed' }, 405);

  const body = await readJson<AttestVerifyRequest>(req);
  if (!body || (body.platform !== 'android' && body.platform !== 'ios')) {
    return json({ verdict: 'FAIL', reason: 'bad_request' }, 400);
  }

  let deps: VerifyDeps;
  let db: ReturnType<typeof createServiceClient>;
  try {
    const { url, serviceRoleKey } = loadSupabase();
    db = createServiceClient(url, serviceRoleKey);
    const androidConfig = loadAndroidConfig();
    const iosConfig = loadIosConfig();
    const sessionConfig = loadSessionConfig();
    deps = {
      nonce: new SupabaseNonceStore(db),
      android: new GooglePlayIntegrityVerifier(loadGoogleServiceAccount(), androidConfig.packageName),
      ios: new AppleAppAttestVerifier(),
      androidConfig,
      iosConfig,
      issueSession: (platform: Platform) => issueSessionToken(platform, sessionConfig),
    };
  } catch (_e) {
    return json({ verdict: 'FAIL', reason: 'server_misconfigured' }, 500);
  }

  const limiter = new SupabaseRateLimiter(db);
  const key = await rateLimitKey('attest-verify', req);
  if (!(await limiter.take(key, RL_MAX, RL_WINDOW_SECONDS))) {
    return json({ verdict: 'FAIL', reason: 'rate_limited' }, 429);
  }

  const result = await gradeAttestation(body, deps);

  // Server-side verdict log ONLY — no token, fingerprint, or identifiers.
  console.log(JSON.stringify({ evt: 'attest_verify', platform: body.platform, verdict: result.verdict, reason: result.reason ?? null }));

  return json(result, result.verdict === 'PASS' ? 200 : 401);
});
