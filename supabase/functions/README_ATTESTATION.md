# Device Attestation Backend (`attest-nonce` + `attest-verify`)

Server-side trust anchor for the phone-side `DeviceIntegrity` module. The client
relays a **signed** attestation token (Android Play Integrity / iOS App Attest);
**the verdict is decided here**, never on the device.

- **Project:** `cypmjgbtcfowsqlwkzfu` ("ghost net site", ap-southeast-2)
- **Functions:** `attest-nonce` (issue single-use challenge), `attest-verify`
  (grade the token, issue a 15-min session token on PASS)
- **Migration:** `supabase/migrations/20260613210000_attestation.sql`
- **Tests:** `supabase/functions/_shared/attestation.test.ts`

> Nothing here was deployed. Apply the migration, set the secrets, and deploy the
> two functions manually (commands below).

## Flow

```
app → POST /attest-nonce                 → { nonce }                 (single-use, 5-min TTL)
app → run Play Integrity / App Attest with that nonce as the challenge
app → POST /attest-verify { platform, token, keyId?, nonce? }
        server: decode/verify the SIGNED token, consume the nonce atomically,
                apply policy → { verdict: "PASS"|"FAIL", reason?, session? }
```

- **Android:** the nonce is embedded in the token; the server reads it after
  Google decodes the token, then consumes it, then applies policy.
- **iOS:** the client sends the `nonce` it used; the server consumes it, then the
  App Attest verification proves the attestation is cryptographically bound to
  exactly that nonce (a lie fails the binding check).

## 1. Apply the migration

```bash
supabase link --project-ref cypmjgbtcfowsqlwkzfu
supabase db push     # applies supabase/migrations/20260613210000_attestation.sql
```

Creates `attestation_nonces` + `rate_limits` (RLS on, **no policies** → service-role
only, matching the project's existing posture), the atomic `consume_attestation_nonce`
/ `rl_take` / `cleanup_attestation` functions, and a **pg_cron** cleanup job every 5
minutes. ⚠️ This is the **first pg_cron job in this project** — there was no existing
"kb cleanup" cron to mirror, so it uses the standard Supabase idiom. If you don't want
pg_cron, delete the `pg_cron` block at the end of the migration and schedule
`select public.cleanup_attestation();` elsewhere.

## 2. Set the secrets

These are Supabase **Function secrets** (never in code). `SUPABASE_URL` and
`SUPABASE_SERVICE_ROLE_KEY` are injected automatically — do **not** set them.

```bash
# Session signing key for the short-lived PASS token (generate a fresh random one):
supabase secrets set ATTEST_SESSION_SECRET="$(openssl rand -base64 48)" --project-ref cypmjgbtcfowsqlwkzfu
# Optional: session TTL (default 900s / 15 min)
supabase secrets set ATTEST_SESSION_TTL_SECONDS="900" --project-ref cypmjgbtcfowsqlwkzfu

# ── Android (Play Integrity) ──
supabase secrets set ANDROID_PACKAGE_NAME="net.ghostnet.app" --project-ref cypmjgbtcfowsqlwkzfu
# Comma-separated accepted signing-cert SHA-256 digests, base64url (as Play Integrity reports them):
supabase secrets set ANDROID_CERT_SHA256="<base64url-sha256-of-signing-cert>" --project-ref cypmjgbtcfowsqlwkzfu
# Optional bar: MEETS_BASIC_INTEGRITY | MEETS_DEVICE_INTEGRITY (default) | MEETS_STRONG_INTEGRITY
supabase secrets set ANDROID_DEVICE_INTEGRITY_BAR="MEETS_DEVICE_INTEGRITY" --project-ref cypmjgbtcfowsqlwkzfu
# Full service-account JSON (single line) with Play Integrity API access:
supabase secrets set GOOGLE_SERVICE_ACCOUNT_JSON='{"type":"service_account",...}' --project-ref cypmjgbtcfowsqlwkzfu

# ── iOS (App Attest) ──
supabase secrets set IOS_TEAM_ID="ABCDE12345" --project-ref cypmjgbtcfowsqlwkzfu
supabase secrets set IOS_BUNDLE_ID="net.ghostnet.app" --project-ref cypmjgbtcfowsqlwkzfu
supabase secrets set APP_ATTEST_ENV="production" --project-ref cypmjgbtcfowsqlwkzfu   # or "development"
# Official Apple App Attest Root CA G1 PEM (see step 4 — REQUIRED for iOS):
supabase secrets set APPLE_APP_ATTEST_ROOT_PEM="$(cat AppleAppAttestRootCA.pem)" --project-ref cypmjgbtcfowsqlwkzfu
```

| Secret | Used by | Required |
|---|---|---|
| `ATTEST_SESSION_SECRET` | both | ✅ |
| `ATTEST_SESSION_TTL_SECONDS` | verify | optional (900) |
| `ANDROID_PACKAGE_NAME` | verify | ✅ (Android) |
| `ANDROID_CERT_SHA256` | verify | ✅ (Android) |
| `ANDROID_DEVICE_INTEGRITY_BAR` | verify | optional |
| `GOOGLE_SERVICE_ACCOUNT_JSON` | verify | ✅ (Android) |
| `IOS_TEAM_ID`, `IOS_BUNDLE_ID` | verify | ✅ (iOS) |
| `APP_ATTEST_ENV` | verify | optional (production) |
| `APPLE_APP_ATTEST_ROOT_PEM` | verify | ✅ (iOS) — see step 4 |

## 3. Deploy the functions

These are **pre-auth** endpoints (the device has no Supabase user yet), so deploy
with `--no-verify-jwt`; the functions do their own per-IP rate limiting and never
trust client input. (Alternatively keep JWT verification and have the app send the
anon key — your choice.)

```bash
supabase functions deploy attest-nonce  --project-ref cypmjgbtcfowsqlwkzfu --no-verify-jwt
supabase functions deploy attest-verify --project-ref cypmjgbtcfowsqlwkzfu --no-verify-jwt
```

## 4. Console steps YOU still have to do

### Google (Android / Play Integrity)
1. **Play Console → your app → App integrity** → enable the **Play Integrity API**.
2. **Link a Google Cloud project** to the app.
3. **Cloud Console** → enable *Play Integrity API* → create a **service account** →
   create a **JSON key** → put it in `GOOGLE_SERVICE_ACCOUNT_JSON`.
4. **App signing cert digest:** Play Console → App integrity → App signing → take the
   **SHA-256** of the signing certificate. Play Integrity reports it as **base64url of
   the DER SHA-256**; set `ANDROID_CERT_SHA256` in that exact format (you can list
   several, comma-separated, e.g. upload + Play-managed keys).

### Apple (iOS / App Attest)
1. Enable the **App Attest** capability/entitlement in the app
   (`com.apple.developer.devicecheck.appattest-environment`).
2. Confirm your **Team ID** + **Bundle ID** (→ `TEAMID.BUNDLEID`) and the environment
   (`production` vs `development`).
3. **Download the official _Apple App Attest Root CA G1_** certificate from
   <https://www.apple.com/certificateauthority/private/>, convert to PEM, and set it as
   `APPLE_APP_ATTEST_ROOT_PEM` (or paste it into `appAttest.ts`).

   ⚠️ **REQUIRED:** the root PEM shipped in `appAttest.ts` is a **labeled placeholder**.
   Until you supply the real Apple root, iOS verification **fails closed** (never
   wrongly PASSes). The whole iOS chain check (`x509.ts`) is implemented from first
   principles and **must be validated against Apple's sample attestations** before you
   rely on it in production — consider backing it with a maintained X.509 library.

## 5. Run the tests

Deno (Supabase Edge runtime). Google/Apple verification + the nonce store are
**mocked**, so these cover the server-side trust logic (nonce issue/expire/reuse,
replay rejection, every verdict branch, session issuance) without live platform crypto:

```bash
deno test supabase/functions/_shared/attestation.test.ts
```

> Note: these tests were written but **not executed in the authoring environment**
> (no Deno runtime there). Run the command above to confirm green before deploying.

## Security posture (what this enforces)

- **Server is the judge.** No client-sent verdict field is trusted — only the Google-
  decoded payload / Apple-verified attestation.
- **Replay defense.** Nonces are single-use + 5-min TTL, consumed in one atomic UPDATE
  before policy checks; a replayed token loses the race and sees `nonce_replayed`.
- **Bounded PASS.** A PASS mints a 15-min HMAC-signed session token; an old PASS can't
  be replayed forever.
- **Rate limited** per coarse hashed client key (30/min nonce, 20/min verify); the
  limiter fails **closed**.
- **Minimal retention / no leakage.** Only nonces + hashed rate buckets are stored, RLS
  service-role-only, cron-pruned. Logs record **verdict + reason + platform only** —
  never raw tokens, device fingerprints, peer ids, or node ids.
