// Google service-account OAuth + Play Integrity decodeIntegrityToken.
//
// This is the SERVER side of Android attestation: we hand Google the integrity
// token and Google performs the cryptographic decryption/verification, returning
// the decoded verdict. We then apply our policy (playIntegrity.ts). We never
// decrypt the token on-device or trust client-parsed fields.

import { base64url } from './nonce.ts';

interface ServiceAccount {
  client_email: string;
  private_key: string;
  token_uri?: string;
}

const PLAY_INTEGRITY_SCOPE = 'https://www.googleapis.com/auth/playintegrity';
const DEFAULT_TOKEN_URI = 'https://oauth2.googleapis.com/token';

/** Import a PEM PKCS#8 RSA private key for RS256 signing. */
async function importPkcs8(pem: string): Promise<CryptoKey> {
  const body = pem
    .replace(/-----BEGIN PRIVATE KEY-----/, '')
    .replace(/-----END PRIVATE KEY-----/, '')
    .replace(/\s+/g, '');
  const der = Uint8Array.from(atob(body), (c) => c.charCodeAt(0));
  return crypto.subtle.importKey(
    'pkcs8',
    der,
    { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' },
    false,
    ['sign'],
  );
}

/** Mint a short-lived OAuth access token for the Play Integrity scope. */
async function getAccessToken(sa: ServiceAccount, nowMs = Date.now()): Promise<string> {
  const iat = Math.floor(nowMs / 1000);
  const tokenUri = sa.token_uri ?? DEFAULT_TOKEN_URI;
  const header = base64url(new TextEncoder().encode(JSON.stringify({ alg: 'RS256', typ: 'JWT' })));
  const claims = base64url(
    new TextEncoder().encode(
      JSON.stringify({
        iss: sa.client_email,
        scope: PLAY_INTEGRITY_SCOPE,
        aud: tokenUri,
        iat,
        exp: iat + 3600,
      }),
    ),
  );
  const signingInput = `${header}.${claims}`;
  const key = await importPkcs8(sa.private_key);
  const sig = await crypto.subtle.sign(
    'RSASSA-PKCS1-v1_5',
    key,
    new TextEncoder().encode(signingInput),
  );
  const assertion = `${signingInput}.${base64url(new Uint8Array(sig))}`;

  const res = await fetch(tokenUri, {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({
      grant_type: 'urn:ietf:params:oauth:grant-type:jwt-bearer',
      assertion,
    }),
  });
  if (!res.ok) throw new Error(`oauth token failed: ${res.status}`);
  const body = (await res.json()) as { access_token?: string };
  if (!body.access_token) throw new Error('oauth token missing access_token');
  return body.access_token;
}

/**
 * Call playintegrity.googleapis.com decodeIntegrityToken. Returns the decoded
 * `tokenPayloadExternal` as untyped JSON (the caller type-guards it).
 */
export async function decodeIntegrityToken(
  serviceAccountJson: string,
  packageName: string,
  integrityToken: string,
): Promise<unknown> {
  const sa = JSON.parse(serviceAccountJson) as ServiceAccount;
  const accessToken = await getAccessToken(sa);
  const url = `https://playintegrity.googleapis.com/v1/${encodeURIComponent(packageName)}:decodeIntegrityToken`;
  const res = await fetch(url, {
    method: 'POST',
    headers: {
      Authorization: `Bearer ${accessToken}`,
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({ integrity_token: integrityToken }),
  });
  if (!res.ok) throw new Error(`decodeIntegrityToken failed: ${res.status}`);
  const body = (await res.json()) as { tokenPayloadExternal?: unknown };
  return body.tokenPayloadExternal ?? null;
}
