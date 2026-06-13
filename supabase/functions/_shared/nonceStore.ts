// Supabase-backed NonceStore + RateLimiter implementations (service role).

import { createClient, type SupabaseClient } from 'jsr:@supabase/supabase-js@2';
import type { NonceConsumeStatus, NonceStore, RateLimiter } from './types.ts';

export function createServiceClient(url: string, serviceRoleKey: string): SupabaseClient {
  return createClient(url, serviceRoleKey, {
    auth: { persistSession: false, autoRefreshToken: false },
  });
}

export class SupabaseNonceStore implements NonceStore {
  constructor(private readonly db: SupabaseClient) {}

  async create(nonce: string, ttlSeconds: number): Promise<void> {
    const expiresAt = new Date(Date.now() + ttlSeconds * 1000).toISOString();
    const { error } = await this.db
      .from('attestation_nonces')
      .insert({ nonce, expires_at: expiresAt, used: false });
    if (error) throw new Error(`nonce insert failed: ${error.message}`);
  }

  async consume(nonce: string): Promise<NonceConsumeStatus> {
    // Atomic mark-used via the SECURITY DEFINER RPC (single UPDATE + classify).
    const { data, error } = await this.db.rpc('consume_attestation_nonce', { p_nonce: nonce });
    if (error) throw new Error(`nonce consume failed: ${error.message}`);
    const status = String(data);
    if (status === 'ok' || status === 'already_used' || status === 'expired' || status === 'not_found') {
      return status;
    }
    return 'not_found';
  }
}

export class SupabaseRateLimiter implements RateLimiter {
  constructor(private readonly db: SupabaseClient) {}

  async take(bucketKey: string, max: number, windowSeconds: number): Promise<boolean> {
    const { data, error } = await this.db.rpc('rl_take', {
      p_bucket: bucketKey,
      p_max: max,
      p_window_seconds: windowSeconds,
    });
    if (error) {
      // Fail OPEN on limiter errors would let abuse through; fail CLOSED instead.
      return false;
    }
    return data === true;
  }
}
