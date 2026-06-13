// Shared types for the device-attestation Edge Functions.
//
// TRUST MODEL: the client relays a SIGNED attestation token. The TRUST DECISION
// is made HERE, server-side. We never trust any verdict field the client sends —
// only what we derive from the signed blob (Android: Google's decoded verdict;
// iOS: the App Attest object verified against Apple's root).

export type Platform = 'android' | 'ios';

export type Verdict = 'PASS' | 'FAIL';

/** Result of attempting to consume a nonce (atomic, single-use). */
export type NonceConsumeStatus = 'ok' | 'not_found' | 'already_used' | 'expired';

/** Generic verifier result; expected failures are values, not thrown errors. */
export type VerifierResult<T> = { ok: true; value: T } | { ok: false; reason: string };

/** Subset of the Play Integrity token payload we rely on (server-decoded). */
export interface PlayIntegrityPayload {
  requestDetails?: {
    requestPackageName?: string;
    nonce?: string;
    timestampMillis?: string;
  };
  appIntegrity?: {
    appRecognitionVerdict?: string;
    packageName?: string;
    certificateSha256Digest?: string[];
  };
  deviceIntegrity?: {
    deviceRecognitionVerdict?: string[];
  };
  accountDetails?: {
    appLicensingVerdict?: string;
  };
}

/** iOS App Attest request shape (the client states which nonce it used). */
export interface IosAttestInput {
  token: string;
  keyId: string;
  /** The nonce/challenge the client used to build the attestation. */
  nonce: string;
}

/** The verify endpoint request body. */
export interface AttestVerifyRequest {
  platform: Platform;
  token: string;
  keyId?: string;
  /** Required for iOS (the issued nonce the attestation is bound to). */
  nonce?: string;
}

export interface AttestVerifyResponse {
  verdict: Verdict;
  reason?: string;
  /** Short-lived signed session token, present only on PASS. */
  session?: string;
}

/** Server-side policy bar for Android device integrity. */
export type DeviceIntegrityBar = 'MEETS_BASIC_INTEGRITY' | 'MEETS_DEVICE_INTEGRITY' | 'MEETS_STRONG_INTEGRITY';

export interface AndroidConfig {
  packageName: string;
  /** Accepted signing-cert SHA-256 digests (base64url, as Play Integrity reports). */
  certSha256Digests: string[];
  deviceIntegrityBar: DeviceIntegrityBar;
}

export interface IosConfig {
  /** TEAMID.BUNDLEID — the App ID the attestation must bind to. */
  appId: string;
  environment: 'production' | 'development';
}

export interface SessionConfig {
  secret: string;
  ttlSeconds: number;
}

/* ── Injected dependencies (so the orchestration is testable without network) ── */

export interface NonceStore {
  /** Insert a fresh nonce with the given TTL. */
  create(nonce: string, ttlSeconds: number): Promise<void>;
  /** Atomically mark a nonce used; reports the outcome. */
  consume(nonce: string): Promise<NonceConsumeStatus>;
}

export interface RateLimiter {
  /** Returns true if the call is within the limit for the bucket. */
  take(bucketKey: string, max: number, windowSeconds: number): Promise<boolean>;
}

/** Decrypts/verifies an Android Play Integrity token via Google (server-side). */
export interface AndroidVerifier {
  decode(token: string): Promise<VerifierResult<PlayIntegrityPayload>>;
}

/** Verifies an iOS App Attest object against Apple's root + the issued nonce. */
export interface IosVerifier {
  verify(input: IosAttestInput, config: IosConfig): Promise<VerifierResult<{ counter: number }>>;
}

export interface VerifyDeps {
  nonce: NonceStore;
  android: AndroidVerifier;
  ios: IosVerifier;
  androidConfig: AndroidConfig;
  iosConfig: IosConfig;
  issueSession: (platform: Platform) => Promise<string>;
}
