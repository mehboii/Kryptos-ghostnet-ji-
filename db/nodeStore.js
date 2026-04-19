import { pool } from './client.js';

async function upsertNode(nodeId, { displayName, ownerId, publicKey, shortCode, avatar, ghostCode } = {}) {
  try {
    await pool.query(
      `INSERT INTO nodes (node_id, display_name, owner_id, public_key, short_code, avatar, ghost_code, registered_at, last_seen)
       VALUES ($1, $2, $3, $4, $5, $6, $7, NOW(), NOW())
       ON CONFLICT (node_id) DO UPDATE SET
         display_name = COALESCE($2, nodes.display_name),
         owner_id = COALESCE($3, nodes.owner_id),
         public_key = COALESCE($4, nodes.public_key),
         short_code = COALESCE($5, nodes.short_code),
         avatar = COALESCE($6, nodes.avatar),
         ghost_code = COALESCE($7, nodes.ghost_code),
         last_seen = NOW()`,
      [nodeId, displayName || null, ownerId || null, publicKey || null, shortCode || null, avatar || null, ghostCode || null]
    );
  } catch (err) {
    console.error('[NodeStore] upsertNode error:', err.message);
    throw err;
  }
}

async function updateLastSeen(nodeId) {
  try {
    await pool.query(
      `UPDATE nodes SET last_seen = NOW() WHERE node_id = $1`,
      [nodeId]
    );
  } catch (err) {
    console.error('[NodeStore] updateLastSeen error:', err.message);
    throw err;
  }
}

async function getNode(nodeId) {
  try {
    const result = await pool.query(
      `SELECT node_id, display_name, owner_id, public_key, short_code, avatar, ghost_code, last_seen, registered_at
       FROM nodes WHERE node_id = $1`,
      [nodeId]
    );
    if (!result.rows.length) return null;
    const row = result.rows[0];
    return {
      nodeId: row.node_id,
      displayName: row.display_name,
      ownerId: row.owner_id,
      publicKey: row.public_key,
      shortCode: row.short_code,
      avatar: row.avatar,
      ghostCode: row.ghost_code,
      lastSeen: row.last_seen,
      registeredAt: row.registered_at,
    };
  } catch (err) {
    console.error('[NodeStore] getNode error:', err.message);
    throw err;
  }
}

async function getAllNodes() {
  try {
    const result = await pool.query(
      `SELECT node_id, display_name, owner_id, public_key, short_code, avatar, ghost_code, last_seen, registered_at
       FROM nodes ORDER BY last_seen DESC`
    );
    return result.rows.map(row => ({
      nodeId: row.node_id,
      displayName: row.display_name,
      ownerId: row.owner_id,
      publicKey: row.public_key,
      shortCode: row.short_code,
      avatar: row.avatar,
      ghostCode: row.ghost_code,
      lastSeen: row.last_seen,
      registeredAt: row.registered_at,
    }));
  } catch (err) {
    console.error('[NodeStore] getAllNodes error:', err.message);
    throw err;
  }
}

async function getNodesByOwner(ownerId) {
  try {
    const result = await pool.query(
      `SELECT node_id FROM nodes WHERE owner_id = $1`,
      [ownerId]
    );
    return result.rows.map(r => r.node_id);
  } catch (err) {
    console.error('[NodeStore] getNodesByOwner error:', err.message);
    throw err;
  }
}

async function countNodesByOwner(ownerId) {
  try {
    const result = await pool.query(
      `SELECT COUNT(*) AS count FROM nodes WHERE owner_id = $1`,
      [ownerId]
    );
    return parseInt(result.rows[0].count, 10);
  } catch (err) {
    console.error('[NodeStore] countNodesByOwner error:', err.message);
    throw err;
  }
}

export {
  upsertNode,
  updateLastSeen,
  getNode,
  getAllNodes,
  getNodesByOwner,
  countNodesByOwner,
};
