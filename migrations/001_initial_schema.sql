-- GhostNet Supabase Migration 001 — Initial Schema
-- Run this in the Supabase SQL Editor (Dashboard > SQL Editor > New Query)
-- This replaces messages.json and nodes.json with Postgres tables.

CREATE TABLE IF NOT EXISTS messages (
  id BIGSERIAL PRIMARY KEY,
  msg_id TEXT NOT NULL UNIQUE,
  convo_id TEXT,
  recipient_id TEXT NOT NULL,
  sender_id TEXT NOT NULL,
  content TEXT,
  ciphertext BYTEA,
  created_at TIMESTAMPTZ DEFAULT NOW(),
  delivered BOOLEAN DEFAULT FALSE,
  delivered_at TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS idx_messages_recipient_pending
  ON messages(recipient_id, created_at DESC)
  WHERE delivered_at IS NULL;

CREATE INDEX IF NOT EXISTS idx_messages_cleanup
  ON messages(created_at);

CREATE INDEX IF NOT EXISTS idx_messages_convo
  ON messages(convo_id, created_at DESC);

CREATE INDEX IF NOT EXISTS idx_messages_msg_id
  ON messages(msg_id);

CREATE TABLE IF NOT EXISTS nodes (
  node_id TEXT PRIMARY KEY,
  display_name TEXT,
  owner_id TEXT,
  public_key TEXT,
  short_code TEXT,
  avatar TEXT,
  ghost_code TEXT,
  last_seen TIMESTAMPTZ DEFAULT NOW(),
  registered_at TIMESTAMPTZ DEFAULT NOW(),
  created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_nodes_owner
  ON nodes(owner_id);

CREATE INDEX IF NOT EXISTS idx_nodes_short_code
  ON nodes(short_code) WHERE short_code IS NOT NULL;
