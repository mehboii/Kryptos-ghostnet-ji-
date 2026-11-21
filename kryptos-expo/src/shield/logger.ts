/**
 * Ghost Shield — redacted, opt-in, local-only logger.
 *
 * No-leak contract: telemetry, logs, and analytics must never record the real
 * node id, tier *history*, or peer identifiers. Logging is OFF by default and
 * is local-only (it never ships anywhere). Even when enabled, callers pass a
 * short event `code` plus a small, scalar `fields` bag — and this logger scrubs
 * any value that looks like an identifier (long hex strings, 0x-addresses,
 * @GhostTags, base64-ish blobs) before it is emitted.
 *
 * This protects against an accidental `log.debug('rotated', { newId })` leaking
 * an overlay id into a local log buffer a forensic tool could later read.
 */

import type { ShieldLogger } from './types';

type Fields = Readonly<Record<string, string | number | boolean>>;

const REDACTED = '[redacted]';

// Heuristics for "this string is probably an identifier, don't store it".
const HEX_ID = /^(0x)?[0-9a-fA-F]{16,}$/;
const GHOSTTAG = /^@?[A-Za-z0-9_]{3,}$/; // err on the side of redaction for tag-like strings
const BASE64ISH = /^[A-Za-z0-9+/_-]{24,}={0,2}$/;

function looksLikeIdentifier(value: string): boolean {
  return HEX_ID.test(value) || BASE64ISH.test(value) || (value.length > 12 && GHOSTTAG.test(value));
}

function scrub(fields?: Fields): Record<string, string | number | boolean> {
  const out: Record<string, string | number | boolean> = {};
  if (!fields) return out;
  for (const [k, v] of Object.entries(fields)) {
    out[k] = typeof v === 'string' && looksLikeIdentifier(v) ? REDACTED : v;
  }
  return out;
}

export interface LoggerOptions {
  /** Opt-in switch. Default false. */
  readonly enabled?: boolean;
  /** Sink for local-only delivery. Defaults to console when enabled. */
  readonly sink?: (line: string) => void;
}

/**
 * Create a Shield logger. Disabled → every call is a no-op (zero retention).
 * Enabled → emits `level shield:<code> {scrubbed fields}` to the local sink only.
 */
export function createLogger(options: LoggerOptions = {}): ShieldLogger {
  const enabled = options.enabled ?? false;
  const sink = options.sink ?? ((line: string) => { console.log(line); });

  const emit = (level: string, code: string, fields?: Fields): void => {
    if (!enabled) return;
    const scrubbed = scrub(fields);
    const tail = Object.keys(scrubbed).length ? ' ' + JSON.stringify(scrubbed) : '';
    sink(`${level} shield:${code}${tail}`);
  };

  return {
    enabled,
    debug: (code, fields) => emit('debug', code, fields),
    warn: (code, fields) => emit('warn', code, fields),
  };
}

/** Shared no-op logger for when callers don't supply one. */
export const NULL_LOGGER: ShieldLogger = createLogger({ enabled: false });
