import { pool } from './client.js';

// Persist (insert or update) a conversation. `convo` is the in-memory shape:
// { id, participants: string[], contactName, lastMessage, updated (epoch ms) }
async function upsertConversation(convo) {
  if (!convo?.id) return;
  try {
    await pool.query(
      `INSERT INTO conversations (id, participants, contact_name, last_message, updated_at)
       VALUES ($1, $2::jsonb, $3, $4, to_timestamp($5 / 1000.0))
       ON CONFLICT (id) DO UPDATE SET
         participants = EXCLUDED.participants,
         contact_name = COALESCE(EXCLUDED.contact_name, conversations.contact_name),
         last_message = EXCLUDED.last_message,
         updated_at    = EXCLUDED.updated_at`,
      [
        convo.id,
        JSON.stringify(convo.participants || []),
        convo.contactName || null,
        convo.lastMessage || null,
        convo.updated || Date.now(),
      ]
    );
  } catch (err) {
    console.error('[ConversationStore] upsertConversation error:', err.message);
    throw err;
  }
}

// Load every conversation back into the in-memory shape used by the server.
async function loadAllConversations() {
  const result = await pool.query(
    `SELECT id, participants, contact_name, last_message,
            EXTRACT(EPOCH FROM updated_at) * 1000 AS updated
     FROM conversations`
  );
  return result.rows.map(row => ({
    id: row.id,
    // pg returns JSONB already parsed
    participants: Array.isArray(row.participants) ? row.participants : (row.participants || []),
    contactName: row.contact_name || null,
    lastMessage: row.last_message || null,
    updated: Number(row.updated) || Date.now(),
  }));
}

async function deleteConversation(convoId) {
  try {
    await pool.query('DELETE FROM conversations WHERE id = $1', [convoId]);
  } catch (err) {
    console.error('[ConversationStore] deleteConversation error:', err.message);
    throw err;
  }
}

export { upsertConversation, loadAllConversations, deleteConversation };
