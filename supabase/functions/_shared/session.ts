// Short-lived, HMAC-signed session token issued on a PASS verdict.
//
// WHY: a PASS is a point-in-time statement. Without a bounded session, an old
// PASS could be replayed forever. The app presents this token for sensitive ops;
// it expires (default 15 min) and must be re-minted via a fresh attestation.
//
// Format: compact JWS, HS256 — header.payload.signature, all base64url. Self-
// contained and verifiable by any service that holds ATTEST_SESSION_SECRET.

import { base64url, base64urlToBytes } from './nonce.ts';
import type { Platform, SessionConfig } from './types.ts';

interface SessionClaims {
  sub: 'attestation';
  plat: Platform;
  iat: number;
  exp: number;
  jti: string;
}

function encodeJson(obj: unknown): string {
  return base64url(new TextEncoder().encode(JSON.stringify(obj)));
}

async function hmacKey(secret: string): Promise<CryptoKey> {
  return crypto.subtle.importKey(
    'raw',
    new TextEncoder().encode(secret),
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign', 'verify'],
  );
}

/** Issue a signed session token bound to the attested platform. */
export async function issueSessionToken(
  platform: Platform,
  config: SessionConfig,
  nowMs: number = Date.now(),
): Promise<string> {
  const iat = Math.floor(nowMs / 1000);
  const claims: SessionClaims = {
    sub: 'attestation',
    plat: platform,
    iat,
    exp: iat + config.ttlSeconds,
    jti: crypto.randomUUID(),
  };
  const header = { alg: 'HS256', typ: 'JWT' };
  const signingInput = `${encodeJson(header)}.${encodeJson(claims)}`;
  const key = await hmacKey(config.secret);
  const sig = await crypto.subtle.sign('HMAC', key, new TextEncoder().encode(signingInput));
  return `${signingInput}.${base64url(new Uint8Array(sig))}`;
}

/**
 * Verify a session token (signature + expiry). Returns the claims or null.
 * Provided so other server code can validate the token before a sensitive op.
 */
export async function verifySessionToken(
  token: string,
  config: SessionConfig,
  nowMs: number = Date.now(),
): Promise<SessionClaims | null> {
  const parts = token.split('.');
  if (parts.length !== 3) return null;
  const [h, p, s] = parts;
  const key = await hmacKey(config.secret);
  const ok = await crypto.subtle.verify(
    'HMAC',
    key,
    base64urlToBytes(s),
    new TextEncoder().encode(`${h}.${p}`),
  );
  if (!ok) return null;
  try {
    const claims = JSON.parse(new TextDecoder().decode(base64urlToBytes(p))) as SessionClaims;
    if (claims.sub !== 'attestation') return null;
    if (typeof claims.exp !== 'number' || claims.exp * 1000 <= nowMs) return null;
    return claims;
  } catch {
    return null;
  }
}
