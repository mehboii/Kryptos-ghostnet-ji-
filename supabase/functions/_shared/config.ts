// Reads attestation configuration from environment (Supabase Function secrets).
// Secrets are NEVER hardcoded. See README_ATTESTATION.md for the full list.

import type { AndroidConfig, DeviceIntegrityBar, IosConfig, SessionConfig } from './types.ts';

function req(name: string): string {
  const v = Deno.env.get(name);
  if (!v) throw new Error(`missing required secret: ${name}`);
  return v;
}

function opt(name: string, fallback: string): string {
  return Deno.env.get(name) ?? fallback;
}

const VALID_BARS: DeviceIntegrityBar[] = [
  'MEETS_BASIC_INTEGRITY',
  'MEETS_DEVICE_INTEGRITY',
  'MEETS_STRONG_INTEGRITY',
];

export function loadAndroidConfig(): AndroidConfig {
  const bar = opt('ANDROID_DEVICE_INTEGRITY_BAR', 'MEETS_DEVICE_INTEGRITY') as DeviceIntegrityBar;
  return {
    packageName: req('ANDROID_PACKAGE_NAME'),
    certSha256Digests: req('ANDROID_CERT_SHA256').split(',').map((s) => s.trim()).filter(Boolean),
    deviceIntegrityBar: VALID_BARS.includes(bar) ? bar : 'MEETS_DEVICE_INTEGRITY',
  };
}

export function loadIosConfig(): IosConfig {
  const env = opt('APP_ATTEST_ENV', 'production');
  return {
    appId: `${req('IOS_TEAM_ID')}.${req('IOS_BUNDLE_ID')}`,
    environment: env === 'development' ? 'development' : 'production',
  };
}

export function loadSessionConfig(): SessionConfig {
  return {
    secret: req('ATTEST_SESSION_SECRET'),
    ttlSeconds: Number(opt('ATTEST_SESSION_TTL_SECONDS', '900')), // 15 min
  };
}

/** The Google service-account JSON used to call the Play Integrity API. */
export function loadGoogleServiceAccount(): string {
  return req('GOOGLE_SERVICE_ACCOUNT_JSON');
}

// Supabase injects these into the Edge runtime automatically.
export function loadSupabase(): { url: string; serviceRoleKey: string } {
  return { url: req('SUPABASE_URL'), serviceRoleKey: req('SUPABASE_SERVICE_ROLE_KEY') };
}
