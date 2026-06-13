-- Device attestation backend — schema, atomic nonce consumption, rate limiting,
-- and scheduled cleanup.
--
-- Privacy posture (matches public.chatbot_knowledge): RLS is ENABLED with NO
-- policies, so anon/authenticated are denied by default and only the service_role
-- (used by the Edge Functions) can touch these tables. We store NO device
-- fingerprints, tokens, peer ids, or node ids — only single-use nonces and a
-- coarse hashed rate-limit bucket.
--
-- NOTE: this introduces the FIRST pg_cron job in this project. There was no
-- pre-existing pg_cron cleanup to mirror (the RAG/kb feature ships no cron), so
-- this uses the standard Supabase pg_cron idiom. If you would rather not enable
-- pg_cron, delete the "pg_cron" section at the bottom and run cleanup_attestation()
-- from an external scheduler or a scheduled Edge Function instead.

-- ──────────────────────────────────────────────────────────────────────────
-- Tables
-- ──────────────────────────────────────────────────────────────────────────

create table if not exists public.attestation_nonces (
  nonce       text primary key,
  created_at  timestamptz not null default now(),
  expires_at  timestamptz not null,
  used        boolean     not null default false
);

comment on table public.attestation_nonces is
  'Single-use, short-TTL challenge nonces for device attestation. Service-role only (RLS on, no policies). Cleaned by cron. No device data stored.';

create index if not exists attestation_nonces_expires_at_idx
  on public.attestation_nonces (expires_at);

alter table public.attestation_nonces enable row level security;
-- Intentionally NO policies: only service_role (which bypasses RLS) may access.

-- Shared-state rate limiting. Edge Functions are stateless, so per-IP/device
-- limits need a tiny server-side counter table. The bucket key is a SHA-256 hash
-- (function + coarse client key), never a raw IP.
create table if not exists public.rate_limits (
  bucket        text primary key,
  window_start  timestamptz not null default now(),
  count         integer     not null default 0
);

comment on table public.rate_limits is
  'Coarse fixed-window rate-limit counters for attestation endpoints. Service-role only. Bucket keys are hashes, never raw IPs.';

alter table public.rate_limits enable row level security;
-- Intentionally NO policies: service_role only.

-- ──────────────────────────────────────────────────────────────────────────
-- Atomic nonce consumption (prevents replay races)
-- ──────────────────────────────────────────────────────────────────────────

-- Marks a nonce used in a single atomic UPDATE and reports the outcome. The
-- caller MUST treat anything other than 'ok' as a verification failure.
create or replace function public.consume_attestation_nonce(p_nonce text)
returns text
language plpgsql
security definer
set search_path = public
as $$
declare
  v_used boolean;
  v_exp  timestamptz;
begin
  update public.attestation_nonces
     set used = true
   where nonce = p_nonce
     and used = false
     and expires_at > now();
  if found then
    return 'ok';
  end if;

  select used, expires_at into v_used, v_exp
    from public.attestation_nonces
   where nonce = p_nonce;
  if not found then return 'not_found'; end if;
  if v_used then return 'already_used'; end if;
  if v_exp <= now() then return 'expired'; end if;
  return 'not_found';
end;
$$;

revoke all on function public.consume_attestation_nonce(text) from public, anon, authenticated;

-- ──────────────────────────────────────────────────────────────────────────
-- Fixed-window rate limiter. Returns TRUE if the call is allowed.
-- ──────────────────────────────────────────────────────────────────────────

create or replace function public.rl_take(p_bucket text, p_max integer, p_window_seconds integer)
returns boolean
language plpgsql
security definer
set search_path = public
as $$
declare
  v_now   timestamptz := now();
  v_count integer;
begin
  insert into public.rate_limits as r (bucket, window_start, count)
  values (p_bucket, v_now, 1)
  on conflict (bucket) do update
     set count = case
                   when r.window_start < v_now - make_interval(secs => p_window_seconds) then 1
                   else r.count + 1
                 end,
         window_start = case
                          when r.window_start < v_now - make_interval(secs => p_window_seconds) then v_now
                          else r.window_start
                        end
  returning count into v_count;
  return v_count <= p_max;
end;
$$;

revoke all on function public.rl_take(text, integer, integer) from public, anon, authenticated;

-- ──────────────────────────────────────────────────────────────────────────
-- Cleanup: drop used/expired nonces and stale rate-limit rows.
-- ──────────────────────────────────────────────────────────────────────────

create or replace function public.cleanup_attestation()
returns void
language sql
security definer
set search_path = public
as $$
  delete from public.attestation_nonces where used or expires_at < now();
  delete from public.rate_limits where window_start < now() - interval '1 hour';
$$;

revoke all on function public.cleanup_attestation() from public, anon, authenticated;

-- ──────────────────────────────────────────────────────────────────────────
-- pg_cron: run cleanup every 5 minutes. (First cron job in this project.)
-- ──────────────────────────────────────────────────────────────────────────

create extension if not exists pg_cron;

-- Idempotent (re)schedule.
select cron.unschedule('cleanup-attestation')
  where exists (select 1 from cron.job where jobname = 'cleanup-attestation');

select cron.schedule(
  'cleanup-attestation',
  '*/5 * * * *',
  $$ select public.cleanup_attestation(); $$
);
