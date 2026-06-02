-- GhostNet Supabase Migration 003 — Security hardening (RLS + grants)
--
-- THREAT FIXED: messages/conversations/nodes had RLS disabled and the public PostgREST
-- roles (anon/authenticated) held full CRUD+TRUNCATE. Anyone with the publishable anon
-- key could read, modify, or delete ALL data directly via https://<ref>.supabase.co/rest/v1/,
-- completely bypassing the application server and its auth checks.
--
-- WHY THIS IS SAFE FOR THE APP: the server connects as the `postgres` role, which OWNS
-- these tables and has rolbypassrls=true. Enabling RLS and revoking anon/authenticated
-- grants therefore has ZERO effect on the server's access — it only closes the public
-- REST path. The app does not use PostgREST/anon for messages/conversations/nodes.

-- 1) Enable Row Level Security. With no permissive policies, the only access is via
--    roles that bypass RLS (the owner/service role used by the server).
ALTER TABLE public.messages      ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.conversations ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.nodes         ENABLE ROW LEVEL SECURITY;

-- 2) Revoke all privileges from the public API roles (defense in depth alongside RLS).
REVOKE ALL ON public.messages      FROM anon, authenticated;
REVOKE ALL ON public.conversations FROM anon, authenticated;
REVOKE ALL ON public.nodes         FROM anon, authenticated;

-- 3) WAITLIST — keep public signups (INSERT) working, but stop email harvesting and
--    destructive access. The "allow anon count" SELECT policy used USING(true), which
--    let anon read every email via ?select=email — drop it.
DROP POLICY IF EXISTS "allow anon count" ON public.waitlist;

-- Remove destructive/read grants; allow only INSERT for new signups.
REVOKE ALL ON public.waitlist FROM anon, authenticated;
GRANT INSERT ON public.waitlist TO anon, authenticated;
-- The existing "insert only" INSERT policy (WITH CHECK true) remains in force, so signups
-- still work; with no SELECT policy + no SELECT grant, emails can no longer be read.

-- 4) Provide a count WITHOUT exposing rows/emails, so any "N people joined" UI keeps
--    working via rpc('waitlist_count') instead of selecting the table directly.
CREATE OR REPLACE FUNCTION public.waitlist_count()
  RETURNS bigint
  LANGUAGE sql
  STABLE
  SECURITY DEFINER
  SET search_path = public
AS $$ SELECT count(*) FROM public.waitlist $$;

REVOKE ALL ON FUNCTION public.waitlist_count() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.waitlist_count() TO anon, authenticated;
