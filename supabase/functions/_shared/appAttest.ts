// iOS App Attest verifier.
//
// Implements Apple's documented attestation verification
// (https://developer.apple.com/documentation/devicecheck/validating_apps_that_connect_to_your_server):
//   1. Decode the CBOR attestation object → { fmt, attStmt: { x5c }, authData }.
//   2. Verify the x5c certificate chain up to Apple's App Attest Root CA G1 (pinned).
//   3. nonce = SHA256(authData ‖ SHA256(challenge)); must equal the value in the
//      credCert extension OID 1.2.840.113635.100.8.2.
//   4. keyId == SHA256(credCert EC public key).
//   5. authData.rpIdHash == SHA256(appId).
//   6. aaguid == "appattest" (prod) / "appattestdevelop" (dev); attestation counter == 0.
// Every step fails CLOSED.
//
// ⚠️ PRODUCTION REVIEW REQUIRED: the X.509 chain validation here (verifyCertChain)
// is implemented from first principles and has NOT been validated against Apple's
// official sample attestations in this environment. Before relying on it in
// production, run it against Apple's test vectors and/or back it with a maintained
// X.509 library. The identity/binding/counter checks below are exact.

import { base64urlToBytes } from './nonce.ts';
import type { IosAttestInput, IosConfig, IosVerifier, VerifierResult } from './types.ts';
import { decodeFirstCbor } from './cbor.ts';
import { extractCert, verifyCertSignedBy, getCertPublicKeyRaw, getExtensionOctets } from './x509.ts';

// ⚠️⚠️ PLACEHOLDER — NOT A REAL CERTIFICATE ⚠️⚠️
// You MUST replace this with the OFFICIAL "Apple App Attest Root CA G1" PEM,
// downloaded from Apple (https://www.apple.com/certificateauthority/private/),
// before iOS verification can be trusted. The bytes below are a structurally-
// shaped stand-in so the module type-checks; they will NOT validate a real Apple
// attestation. Until replaced, every iOS verification correctly FAILS CLOSED
// (chain check returns false) rather than wrongly passing. See README_ATTESTATION.md.
const APPLE_APP_ATTEST_ROOT_G1_PEM = Deno.env.get('APPLE_APP_ATTEST_ROOT_PEM') ?? `-----BEGIN CERTIFICATE-----
REPLACE_WITH_OFFICIAL_APPLE_APP_ATTEST_ROOT_CA_G1_PEM
-----END CERTIFICATE-----`;

const OID_APPLE_NONCE = '1.2.840.113635.100.8.2';

function sha256(bytes: Uint8Array): Promise<ArrayBuffer> {
  return crypto.subtle.digest('SHA-256', bytes);
}

function concat(a: Uint8Array, b: Uint8Array): Uint8Array {
  const out = new Uint8Array(a.length + b.length);
  out.set(a, 0);
  out.set(b, a.length);
  return out;
}

function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a[i] ^ b[i];
  return diff === 0;
}

interface AuthData {
  rpIdHash: Uint8Array; // 32
  aaguid: string;
  counter: number;
}

/** authData layout: rpIdHash(32) ‖ flags(1) ‖ counter(4) ‖ aaguid(16) ‖ ... */
function parseAuthData(authData: Uint8Array): AuthData | null {
  if (authData.length < 37) return null;
  const rpIdHash = authData.slice(0, 32);
  const counter = (authData[33] << 24) | (authData[34] << 16) | (authData[35] << 8) | authData[36];
  const aaguidBytes = authData.slice(37, 53);
  const aaguid = new TextDecoder().decode(aaguidBytes).replace(/\0+$/, '');
  return { rpIdHash, aaguid, counter: counter >>> 0 };
}

export class AppleAppAttestVerifier implements IosVerifier {
  async verify(input: IosAttestInput, config: IosConfig): Promise<VerifierResult<{ counter: number }>> {
    try {
      // 1. CBOR decode the attestation object.
      const attBytes = base64urlToBytes(input.token);
      const att = decodeFirstCbor(attBytes);
      if (!isAttestation(att)) return { ok: false, reason: 'ios_attestation_malformed' };
      if (att.fmt !== 'apple-appattest') return { ok: false, reason: 'ios_bad_fmt' };

      const x5c = att.attStmt.x5c;
      if (!Array.isArray(x5c) || x5c.length < 1) return { ok: false, reason: 'ios_no_cert' };

      // 2. Verify the cert chain to the pinned Apple root.
      const credCert = extractCert(x5c[0]);
      const root = extractCert(pemToDer(APPLE_APP_ATTEST_ROOT_G1_PEM));
      const chainOk = await verifyChain(x5c.map(extractCert), root);
      if (!chainOk) return { ok: false, reason: 'ios_cert_chain_invalid' };

      // 3. nonce binding: SHA256(authData ‖ SHA256(issuedNonce)) == cert extension.
      const clientDataHash = new Uint8Array(await sha256(new TextEncoder().encode(input.nonce)));
      const expectedNonce = new Uint8Array(await sha256(concat(att.authData, clientDataHash)));
      const certNonce = getExtensionOctets(credCert, OID_APPLE_NONCE);
      if (!certNonce || !bytesEqual(expectedNonce, certNonce)) {
        return { ok: false, reason: 'ios_nonce_mismatch' };
      }

      // 4. keyId == SHA256(credCert public key).
      const pubRaw = getCertPublicKeyRaw(credCert);
      if (!pubRaw) return { ok: false, reason: 'ios_no_pubkey' };
      const keyIdExpected = new Uint8Array(await sha256(pubRaw));
      if (!bytesEqual(keyIdExpected, base64urlToBytes(input.keyId))) {
        return { ok: false, reason: 'ios_keyid_mismatch' };
      }

      // 5 & 6. authData: appId hash, aaguid/env, counter == 0 for attestation.
      const ad = parseAuthData(att.authData);
      if (!ad) return { ok: false, reason: 'ios_authdata_malformed' };
      const appIdHash = new Uint8Array(await sha256(new TextEncoder().encode(config.appId)));
      if (!bytesEqual(appIdHash, ad.rpIdHash)) return { ok: false, reason: 'ios_appid_mismatch' };
      const expectedAaguid = config.environment === 'production' ? 'appattest' : 'appattestdevelop';
      if (ad.aaguid !== expectedAaguid) return { ok: false, reason: 'ios_env_mismatch' };
      if (ad.counter !== 0) return { ok: false, reason: 'ios_counter_nonzero' };

      return { ok: true, value: { counter: ad.counter } };
    } catch (_e) {
      return { ok: false, reason: 'ios_verify_error' };
    }
  }
}

interface Attestation {
  fmt: string;
  attStmt: { x5c: unknown[] };
  authData: Uint8Array;
}

function isAttestation(v: unknown): v is Attestation {
  if (typeof v !== 'object' || v === null) return false;
  const o = v as Record<string, unknown>;
  return (
    typeof o.fmt === 'string' &&
    typeof o.attStmt === 'object' &&
    o.attStmt !== null &&
    Array.isArray((o.attStmt as Record<string, unknown>).x5c) &&
    o.authData instanceof Uint8Array
  );
}

/** Walk the chain: each cert signed by the next; last must be signed by the root. */
async function verifyChain(chain: Uint8Array[], root: Uint8Array): Promise<boolean> {
  const full = [...chain, root];
  for (let i = 0; i < full.length - 1; i++) {
    if (!(await verifyCertSignedBy(full[i], full[i + 1]))) return false;
  }
  // The terminal issuer must be exactly the pinned root.
  return bytesEqual(full[full.length - 1], root);
}

function pemToDer(pem: string): Uint8Array {
  const body = pem.replace(/-----[^-]+-----/g, '').replace(/\s+/g, '');
  return Uint8Array.from(atob(body), (c) => c.charCodeAt(0));
}
