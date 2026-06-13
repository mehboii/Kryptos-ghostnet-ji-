// attest-nonce — issues a fresh, single-use, short-TTL challenge nonce.
//
// POST (optional body { deviceHint }). Returns { nonce }. The nonce is stored in
// attestation_nonces with a 5-minute expiry and used=false; attest-verify
// consumes it exactly once. deviceHint is accepted but NOT stored (no device
// fingerprints retained).

import { json, preflight, rateLimitKey, readJson } from '../_shared/http.ts';
import { generateNonce } from '../_shared/nonce.ts';
import { createServiceClient, SupabaseNonceStore, SupabaseRateLimiter } from '../_shared/nonceStore.ts';
import { loadSupabase } from '../_shared/config.ts';

const NONCE_TTL_SECONDS = 5 * 60;
// Per-client cap: 30 nonce requests / minute (defends against nonce flooding).
const RL_MAX = 30;
const RL_WINDOW_SECONDS = 60;

Deno.serve(async (req: Request): Promise<Response> => {
  const pre = preflight(req);
  if (pre) return pre;
  if (req.method !== 'POST') return json({ error: 'method_not_allowed' }, 405);

  // Body is optional; ignore parse errors (deviceHint is non-essential, unstored).
  await readJson<{ deviceHint?: string }>(req);

  let db: ReturnType<typeof createServiceClient>;
  try {
    const { url, serviceRoleKey } = loadSupabase();
    db = createServiceClient(url, serviceRoleKey);
  } catch (_e) {
    return json({ error: 'server_misconfigured' }, 500);
  }

  const limiter = new SupabaseRateLimiter(db);
  const key = await rateLimitKey('attest-nonce', req);
  if (!(await limiter.take(key, RL_MAX, RL_WINDOW_SECONDS))) {
    return json({ error: 'rate_limited' }, 429);
  }

  const store = new SupabaseNonceStore(db);
  const nonce = generateNonce(32);
  try {
    await store.create(nonce, NONCE_TTL_SECONDS);
  } catch (_e) {
    return json({ error: 'nonce_issue_failed' }, 500);
  }

  return json({ nonce });
});
