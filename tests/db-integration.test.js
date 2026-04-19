/**
 * Integration tests for the Postgres storage layer.
 *
 * Requires DATABASE_URL pointing at a test database.
 * Run: DATABASE_URL=postgres://... node --test tests/db-integration.test.js
 *
 * These tests create and clean up their own rows using unique prefixed IDs.
 */

import { describe, it, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { pool } from '../db/client.js';
import {
  storeMessage,
  getPendingMessages,
  markDelivered,
  markMultipleDelivered,
  getMessagesByConvo,
  deleteExpiredMessages,
} from '../db/messageStore.js';
import {
  upsertNode,
  updateLastSeen,
  getNode,
  getAllNodes,
  getNodesByOwner,
  countNodesByOwner,
} from '../db/nodeStore.js';

const TEST_PREFIX = `test_${Date.now()}_`;

async function ensureTablesExist() {
  await pool.query(`
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
  `);
}

async function cleanupTestData() {
  await pool.query(`DELETE FROM messages WHERE msg_id LIKE $1`, [`${TEST_PREFIX}%`]);
  await pool.query(`DELETE FROM nodes WHERE node_id LIKE $1`, [`${TEST_PREFIX}%`]);
}

before(async () => {
  if (!process.env.DATABASE_URL) {
    console.log('Skipping DB tests — DATABASE_URL not set.');
    process.exit(0);
  }
  await ensureTablesExist();
  await cleanupTestData();
});

after(async () => {
  await cleanupTestData();
  await pool.end();
});

// ─── Message Store Tests ────────────────────────────────────────────────────

describe('messageStore', () => {
  const msgId1 = `${TEST_PREFIX}msg_001`;
  const msgId2 = `${TEST_PREFIX}msg_002`;
  const msgId3 = `${TEST_PREFIX}msg_003`;
  const convoId = `${TEST_PREFIX}convo_001`;
  const recipientId = `${TEST_PREFIX}recipient`;
  const senderId = `${TEST_PREFIX}sender`;

  it('storeMessage — inserts a message and returns id', async () => {
    const result = await storeMessage(msgId1, convoId, recipientId, senderId, 'hello world');
    assert.ok(result.id, 'should return a numeric id');
    assert.equal(result.msg_id, msgId1);
  });

  it('storeMessage — rejects duplicate msg_id', async () => {
    await assert.rejects(
      () => storeMessage(msgId1, convoId, recipientId, senderId, 'duplicate'),
      { message: /duplicate key/ }
    );
  });

  it('getPendingMessages — returns undelivered messages for recipient', async () => {
    await storeMessage(msgId2, convoId, recipientId, senderId, 'pending msg');
    const pending = await getPendingMessages(recipientId);
    assert.ok(pending.length >= 2, `expected >= 2 pending, got ${pending.length}`);
    const ids = pending.map(m => m.msg_id);
    assert.ok(ids.includes(msgId1));
    assert.ok(ids.includes(msgId2));
  });

  it('markDelivered — marks a single message delivered', async () => {
    await markDelivered(msgId1);
    const pending = await getPendingMessages(recipientId);
    const ids = pending.map(m => m.msg_id);
    assert.ok(!ids.includes(msgId1), 'msgId1 should no longer be pending');
  });

  it('markMultipleDelivered — marks multiple messages delivered', async () => {
    await storeMessage(msgId3, convoId, recipientId, senderId, 'another');
    await markMultipleDelivered([msgId2, msgId3]);
    const pending = await getPendingMessages(recipientId);
    assert.equal(pending.length, 0, 'all should be delivered');
  });

  it('getMessagesByConvo — returns messages ordered by created_at DESC', async () => {
    const msgs = await getMessagesByConvo(convoId);
    assert.ok(msgs.length >= 3);
    assert.equal(msgs[0].convo_id, convoId);
  });

  it('deleteExpiredMessages — deletes old messages', async () => {
    // Backdate one message
    await pool.query(
      `UPDATE messages SET created_at = NOW() - INTERVAL '30 days' WHERE msg_id = $1`,
      [msgId1]
    );
    const count = await deleteExpiredMessages(7);
    assert.ok(count >= 1, `expected at least 1 deleted, got ${count}`);

    // Verify it's gone
    const result = await pool.query(`SELECT 1 FROM messages WHERE msg_id = $1`, [msgId1]);
    assert.equal(result.rows.length, 0);
  });
});

// ─── Node Store Tests ───────────────────────────────────────────────────────

describe('nodeStore', () => {
  const nodeId = `${TEST_PREFIX}node_001`;
  const ownerId = `${TEST_PREFIX}owner_001`;

  it('upsertNode — inserts a new node', async () => {
    await upsertNode(nodeId, {
      displayName: 'TestNode',
      ownerId,
      publicKey: '0xabc123',
    });
    const node = await getNode(nodeId);
    assert.ok(node);
    assert.equal(node.nodeId, nodeId);
    assert.equal(node.displayName, 'TestNode');
    assert.equal(node.ownerId, ownerId);
    assert.equal(node.publicKey, '0xabc123');
  });

  it('upsertNode — updates existing node on conflict', async () => {
    await upsertNode(nodeId, {
      displayName: 'UpdatedName',
      ownerId,
      avatar: 'data:image/png;base64,abc',
    });
    const node = await getNode(nodeId);
    assert.equal(node.displayName, 'UpdatedName');
    assert.equal(node.avatar, 'data:image/png;base64,abc');
    assert.equal(node.publicKey, '0xabc123', 'should preserve existing publicKey');
  });

  it('updateLastSeen — updates timestamp', async () => {
    const before = (await getNode(nodeId)).lastSeen;
    // Small delay to ensure timestamp difference
    await new Promise(r => setTimeout(r, 50));
    await updateLastSeen(nodeId);
    const after = (await getNode(nodeId)).lastSeen;
    assert.ok(new Date(after) >= new Date(before));
  });

  it('getNode — returns null for non-existent node', async () => {
    const node = await getNode(`${TEST_PREFIX}nonexistent`);
    assert.equal(node, null);
  });

  it('getAllNodes — returns array including test node', async () => {
    const nodes = await getAllNodes();
    assert.ok(Array.isArray(nodes));
    assert.ok(nodes.some(n => n.nodeId === nodeId));
  });

  it('getNodesByOwner — returns node IDs for owner', async () => {
    const ids = await getNodesByOwner(ownerId);
    assert.ok(ids.includes(nodeId));
  });

  it('countNodesByOwner — returns correct count', async () => {
    const count = await countNodesByOwner(ownerId);
    assert.ok(count >= 1);
  });
});
