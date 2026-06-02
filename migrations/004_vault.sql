-- GhostNet Supabase Migration 004 — Durable file vault
--
-- Replaces the ephemeral vault-meta.json and vault-keys.json (wiped on every Railway
-- redeploy) with Postgres tables. The encrypted file BLOBS live in Supabase Storage
-- (private 'vault' bucket); these tables hold only metadata + the (already PIN-wrapped)
-- key material. Files are encrypted client-side (AES-GCM) before upload — the server
-- and DB only ever see ciphertext.

CREATE TABLE IF NOT EXISTS vault_files (
  file_id       UUID PRIMARY KEY,
  owner         TEXT NOT NULL,
  file_name     TEXT,
  file_size     BIGINT,
  original_size BIGINT,
  file_hash     TEXT,
  iv            TEXT,
  auth_tag      TEXT,
  storage_path  TEXT NOT NULL,
  uploaded_at   TIMESTAMPTZ DEFAULT NOW(),
  deleted       BOOLEAN DEFAULT FALSE,
  deleted_at    TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS idx_vault_files_owner
  ON vault_files(owner) WHERE deleted = FALSE;

-- Per-user wrapped vault key (encrypted under the user's PIN-derived key — zero-knowledge).
CREATE TABLE IF NOT EXISTS vault_keys (
  owner      TEXT PRIMARY KEY,
  key_data   JSONB NOT NULL,
  updated_at TIMESTAMPTZ DEFAULT NOW()
);

-- Same lockdown as migration 003: RLS on, no public API-role access. The server reaches
-- these as the postgres owner role (bypasses RLS); the anon key cannot touch them.
ALTER TABLE vault_files ENABLE ROW LEVEL SECURITY;
ALTER TABLE vault_keys  ENABLE ROW LEVEL SECURITY;
REVOKE ALL ON vault_files FROM anon, authenticated;
REVOKE ALL ON vault_keys  FROM anon, authenticated;
