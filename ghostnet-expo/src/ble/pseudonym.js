/**
 * Rotating ephemeral pseudonym for BLE advertisements.
 *
 * THREAT MODEL: a passive observer must never be able to (a) recover the real
 * identity from an advertisement, or (b) correlate two advertisements from the
 * same device across rotation windows. GhostNet's whole premise ("privacy by
 * mathematics") fails if we advertise any stable identifier — GhostTag, raw
 * public key, node id, MAC-derived value, etc.
 *
 * CONSTRUCTION: pseudonym = HMAC-SHA256(pseudonymSecret, windowCounter)[0..N).
 *   - `pseudonymSecret` is per-device key material that never leaves the device.
 *     HMAC is a PRF, so without the secret the output is indistinguishable from
 *     random — not reversible to the identity, and unlinkable across windows
 *     (each window counter yields an independent-looking value).
 *   - `windowCounter = floor(epochMs / ROTATION_MS)` rotates every ~15 minutes.
 *   - Truncated to PSEUDONYM_BYTES (default 4) because Android BLE service data
 *     is tiny and the value is only a non-static beacon tag, not an identifier
 *     the protocol relies on (identity is exchanged only after GATT + handshake).
 *
 * This module is the reference implementation; the web layer derives the same
 * shape with Web Crypto so the native side can simply advertise whatever bytes
 * it is handed. Devices never recompute each other's pseudonyms, so the two
 * implementations do not need to be bit-identical — only individually sound.
 */
'use strict';

const { hmac } = require('@noble/hashes/hmac.js');
const { sha256 } = require('@noble/hashes/sha2.js');

const ROTATION_MS = 15 * 60 * 1000; // 15 minutes
const PSEUDONYM_BYTES = 4;

/** Rotation window index for a given time. */
function windowFor(nowMs = Date.now()) {
  return Math.floor(nowMs / ROTATION_MS);
}

/** Milliseconds until the current pseudonym rotates. Useful for scheduling. */
function msUntilRotation(nowMs = Date.now()) {
  return ROTATION_MS - (nowMs % ROTATION_MS);
}

function toBytes(secret) {
  if (secret instanceof Uint8Array) return secret;
  if (typeof secret === 'string') return new TextEncoder().encode(secret);
  throw new TypeError('pseudonymSecret must be a string or Uint8Array');
}

/** 8-byte big-endian encoding of the window counter (stable across JS engines). */
function windowToBytes(win) {
  const out = new Uint8Array(8);
  let v = win >>> 0;            // low 32 bits
  const hi = Math.floor(win / 2 ** 32) >>> 0; // high 32 bits
  out[0] = (hi >>> 24) & 0xff;
  out[1] = (hi >>> 16) & 0xff;
  out[2] = (hi >>> 8) & 0xff;
  out[3] = hi & 0xff;
  out[4] = (v >>> 24) & 0xff;
  out[5] = (v >>> 16) & 0xff;
  out[6] = (v >>> 8) & 0xff;
  out[7] = v & 0xff;
  return out;
}

/**
 * Derive the rotating pseudonym bytes for a window.
 * @param {string|Uint8Array} pseudonymSecret - per-device secret (never advertised raw)
 * @param {number} [nowMs]
 * @param {number} [len]
 * @returns {Uint8Array}
 */
function pseudonymBytes(pseudonymSecret, nowMs = Date.now(), len = PSEUDONYM_BYTES) {
  const mac = hmac(sha256, toBytes(pseudonymSecret), windowToBytes(windowFor(nowMs)));
  return mac.slice(0, len);
}

/** Hex form of {@link pseudonymBytes}. */
function pseudonymHex(pseudonymSecret, nowMs = Date.now(), len = PSEUDONYM_BYTES) {
  return Array.from(pseudonymBytes(pseudonymSecret, nowMs, len))
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');
}

module.exports = {
  ROTATION_MS,
  PSEUDONYM_BYTES,
  windowFor,
  msUntilRotation,
  pseudonymBytes,
  pseudonymHex,
};
