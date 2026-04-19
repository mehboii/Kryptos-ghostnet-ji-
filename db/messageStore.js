import { pool } from './client.js';

async function storeMessage(msgId, convoId, recipientId, senderId, content) {
  try {
    const result = await pool.query(
      `INSERT INTO messages (msg_id, convo_id, recipient_id, sender_id, content, created_at)
       VALUES ($1, $2, $3, $4, $5, NOW())
       RETURNING id, msg_id`,
      [msgId, convoId, recipientId, senderId, content]
    );
    return result.rows[0];
  } catch (err) {
    console.error('[MessageStore] storeMessage error:', err.message);
    throw err;
  }
}

async function getPendingMessages(recipientId) {
  try {
    const result = await pool.query(
      `SELECT id, msg_id, convo_id, recipient_id, sender_id, content, created_at
       FROM messages
       WHERE recipient_id = $1 AND delivered = FALSE
       ORDER BY created_at ASC`,
      [recipientId]
    );
    return result.rows;
  } catch (err) {
    console.error('[MessageStore] getPendingMessages error:', err.message);
    throw err;
  }
}

async function markDelivered(msgId) {
  try {
    await pool.query(
      `UPDATE messages SET delivered = TRUE, delivered_at = NOW()
       WHERE msg_id = $1`,
      [msgId]
    );
  } catch (err) {
    console.error('[MessageStore] markDelivered error:', err.message);
    throw err;
  }
}

async function markMultipleDelivered(msgIds) {
  if (!msgIds.length) return;
  try {
    await pool.query(
      `UPDATE messages SET delivered = TRUE, delivered_at = NOW()
       WHERE msg_id = ANY($1)`,
      [msgIds]
    );
  } catch (err) {
    console.error('[MessageStore] markMultipleDelivered error:', err.message);
    throw err;
  }
}

async function getMessagesByConvo(convoId, limit = 50, offset = 0) {
  try {
    const result = await pool.query(
      `SELECT id, msg_id, convo_id, recipient_id, sender_id, content, created_at, delivered
       FROM messages
       WHERE convo_id = $1
       ORDER BY created_at DESC
       LIMIT $2 OFFSET $3`,
      [convoId, limit, offset]
    );
    return result.rows;
  } catch (err) {
    console.error('[MessageStore] getMessagesByConvo error:', err.message);
    throw err;
  }
}

async function deleteExpiredMessages(olderThanDays = 7) {
  try {
    const result = await pool.query(
      `DELETE FROM messages
       WHERE created_at < NOW() - INTERVAL '1 day' * $1
       RETURNING id`,
      [olderThanDays]
    );
    return result.rowCount;
  } catch (err) {
    console.error('[MessageStore] deleteExpiredMessages error:', err.message);
    throw err;
  }
}

export {
  storeMessage,
  getPendingMessages,
  markDelivered,
  markMultipleDelivered,
  getMessagesByConvo,
  deleteExpiredMessages,
};
