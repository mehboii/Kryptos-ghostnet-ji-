// Tiny HTTP helpers for the attestation Edge Functions.

export const CORS_HEADERS: Record<string, string> = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Headers': 'authorization, x-client-info, apikey, content-type',
  'Access-Control-Allow-Methods': 'POST, OPTIONS',
};

export function json(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { ...CORS_HEADERS, 'Content-Type': 'application/json' },
  });
}

/** Handle CORS preflight; returns a Response for OPTIONS, else null. */
export function preflight(req: Request): Response | null {
  if (req.method === 'OPTIONS') return new Response('ok', { headers: CORS_HEADERS });
  return null;
}

/** Parse a JSON body, returning null on any error (never throws). */
export async function readJson<T>(req: Request): Promise<T | null> {
  try {
    return (await req.json()) as T;
  } catch {
    return null;
  }
}

/**
 * A coarse, privacy-preserving rate-limit key: SHA-256 of (fn + client ip + ua).
 * Never stores or returns the raw IP. Falls back to 'unknown' when headers absent.
 */
export async function rateLimitKey(fn: string, req: Request): Promise<string> {
  const ip =
    req.headers.get('x-forwarded-for')?.split(',')[0]?.trim() ||
    req.headers.get('cf-connecting-ip') ||
    'unknown';
  const ua = req.headers.get('user-agent') ?? '';
  const data = new TextEncoder().encode(`${fn}|${ip}|${ua}`);
  const digest = await crypto.subtle.digest('SHA-256', data);
  return `${fn}:${base64urlNoPad(new Uint8Array(digest))}`;
}

function base64urlNoPad(bytes: Uint8Array): string {
  let bin = '';
  for (const b of bytes) bin += String.fromCharCode(b);
  return btoa(bin).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}
