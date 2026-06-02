-- GhostNet Supabase Migration 002 — Conversations
-- Persists conversation metadata so chat history survives server restarts/redeploys.
-- Without this, conversations lived only in the ephemeral conversations.json and were
-- wiped on every Railway redeploy, making /history return 404 even though the messages
-- were safely stored in the messages table.

CREATE TABLE IF NOT EXISTS conversations (
  id TEXT PRIMARY KEY,
  participants JSONB NOT NULL DEFAULT '[]'::jsonb,
  contact_name TEXT,
  last_message TEXT,
  updated_at TIMESTAMPTZ DEFAULT NOW(),
  created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_conversations_updated
  ON conversations(updated_at DESC);

-- GIN index so "find conversations containing participant X" stays fast.
CREATE INDEX IF NOT EXISTS idx_conversations_participants
  ON conversations USING GIN (participants);
