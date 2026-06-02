import { pool } from './client.js';

// ── File metadata ────────────────────────────────────────────────────────────
async function insertFile(r) {
  await pool.query(
    `INSERT INTO vault_files
       (file_id, owner, file_name, file_size, original_size, file_hash, iv, auth_tag, storage_path, uploaded_at, deleted)
     VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9, to_timestamp($10 / 1000.0), FALSE)
     ON CONFLICT (file_id) DO NOTHING`,
    [r.fileId, r.owner, r.fileName, r.fileSize, r.originalSize, r.fileHash,
     r.iv || null, r.authTag || null, r.storagePath, r.uploadedAt || Date.now()]
  );
}

// Returns the in-memory record shape the server already uses.
async function loadAllFiles() {
  const res = await pool.query(
    `SELECT file_id, owner, file_name, file_size, original_size, file_hash, iv, auth_tag,
            storage_path, EXTRACT(EPOCH FROM uploaded_at) * 1000 AS uploaded_at, deleted
     FROM vault_files WHERE deleted = FALSE`
  );
  return res.rows.map(row => ({
    fileId: row.file_id,
    owner: row.owner,
    fileName: row.file_name,
    fileSize: Number(row.file_size),
    originalSize: Number(row.original_size),
    fileHash: row.file_hash,
    iv: row.iv || null,
    authTag: row.auth_tag || null,
    storagePath: row.storage_path,
    uploadedAt: Number(row.uploaded_at) || Date.now(),
    deleted: row.deleted,
  }));
}

async function markFileDeleted(fileId) {
  await pool.query('UPDATE vault_files SET deleted = TRUE, deleted_at = NOW() WHERE file_id = $1', [fileId]);
}

// ── Wrapped per-user vault keys ──────────────────────────────────────────────
async function upsertKey(owner, keyData) {
  await pool.query(
    `INSERT INTO vault_keys (owner, key_data, updated_at)
     VALUES ($1, $2::jsonb, NOW())
     ON CONFLICT (owner) DO UPDATE SET key_data = EXCLUDED.key_data, updated_at = NOW()`,
    [owner, JSON.stringify(keyData)]
  );
}

async function loadAllKeys() {
  const res = await pool.query('SELECT owner, key_data FROM vault_keys');
  const out = {};
  for (const row of res.rows) out[row.owner] = row.key_data;
  return out;
}

export { insertFile, loadAllFiles, markFileDeleted, upsertKey, loadAllKeys };
