/**
 * Ghost Shield — web/WebView runtime primitives + platform detection.
 *
 * These are the small, NON-hardware ports (clock, randomness, persistence) plus
 * the runtime platform probe. They behave identically on the phone WebView and a
 * plain browser; the honesty split (what hardware is reachable) lives in the
 * BLE / DNS / mesh / co-resident / integrity adapters, not here.
 */

import type { Clock, RandomSource, SecureStorePort, TimerHandle } from '../types';

/* ── Platform detection ──────────────────────────────────────────────────── */

export type ShieldPlatform = 'native' | 'web';

/** Minimal shape of the Capacitor global we probe (no @capacitor/core dependency). */
interface CapacitorGlobal {
  isNativePlatform?: () => boolean;
  getPlatform?: () => string;
  Plugins?: Record<string, unknown>;
}

interface PlatformGlobal {
  Capacitor?: CapacitorGlobal;
}

/**
 * Detect whether we are running inside a Capacitor native WebView (the phone)
 * or a plain browser (the web test surface). This is the single switch that
 * decides which capability profile the Shield reports — it never fakes the
 * phone profile while on web.
 */
export function detectPlatform(globalRef: PlatformGlobal = globalThis as PlatformGlobal): ShieldPlatform {
  const cap = globalRef.Capacitor;
  if (cap && typeof cap.isNativePlatform === 'function' && cap.isNativePlatform()) {
    return 'native';
  }
  return 'web';
}

/* ── System clock (wraps the real browser timers) ────────────────────────── */

export class SystemClock implements Clock {
  now(): number {
    return Date.now();
  }
  setTimeout(fn: () => void, ms: number): TimerHandle {
    return globalThis.setTimeout(fn, ms) as unknown as TimerHandle;
  }
  clearTimeout(handle: TimerHandle): void {
    globalThis.clearTimeout(handle as unknown as ReturnType<typeof setTimeout>);
  }
  setInterval(fn: () => void, ms: number): TimerHandle {
    return globalThis.setInterval(fn, ms) as unknown as TimerHandle;
  }
  clearInterval(handle: TimerHandle): void {
    globalThis.clearInterval(handle as unknown as ReturnType<typeof setInterval>);
  }
}

/* ── Cryptographic randomness (WebCrypto) ────────────────────────────────── */

export class WebCryptoRandom implements RandomSource {
  bytes(n: number): Uint8Array {
    const out = new Uint8Array(n);
    globalThis.crypto.getRandomValues(out);
    return out;
  }
  /** Uniform integer in [minInclusive, maxInclusive] via rejection sampling. */
  int(minInclusive: number, maxInclusive: number): number {
    if (maxInclusive <= minInclusive) return minInclusive;
    const span = maxInclusive - minInclusive + 1;
    // Reject the biased tail so every value in the span is equally likely.
    const maxUnbiased = Math.floor(0xffff_ffff / span) * span;
    const buf = new Uint32Array(1);
    let v = 0;
    do {
      globalThis.crypto.getRandomValues(buf);
      v = buf[0];
    } while (v >= maxUnbiased);
    return minInclusive + (v % span);
  }
}

/* ── Persistence (localStorage, with a memory fallback) ──────────────────── */

interface WebStorage {
  getItem(key: string): string | null;
  setItem(key: string, value: string): void;
  removeItem(key: string): void;
}

/**
 * SecureStore-shaped persistence. On web/WebView the only durable store is
 * localStorage; the Shield persists ONLY the single last-tier key here (a scalar,
 * never an id or a history — see ShieldManager's no-leak contract). When
 * localStorage is unavailable (private mode, SSR), it degrades to in-memory so a
 * persistence failure never breaks cloaking.
 */
export class WebSecureStore implements SecureStorePort {
  private readonly backing: WebStorage;
  constructor(storage?: WebStorage) {
    this.backing = storage ?? resolveStorage();
  }
  async getItem(key: string): Promise<string | null> {
    return this.backing.getItem(key);
  }
  async setItem(key: string, value: string): Promise<void> {
    this.backing.setItem(key, value);
  }
  async removeItem(key: string): Promise<void> {
    this.backing.removeItem(key);
  }
}

function resolveStorage(): WebStorage {
  try {
    const ls = (globalThis as { localStorage?: WebStorage }).localStorage;
    if (ls) {
      // Probe: localStorage throws on access in some sandboxed/private contexts.
      const probe = '__ghost_shield_probe__';
      ls.setItem(probe, '1');
      ls.removeItem(probe);
      return ls;
    }
  } catch {
    /* fall through to memory */
  }
  const mem = new Map<string, string>();
  return {
    getItem: (k) => (mem.has(k) ? (mem.get(k) as string) : null),
    setItem: (k, v) => void mem.set(k, v),
    removeItem: (k) => void mem.delete(k),
  };
}
