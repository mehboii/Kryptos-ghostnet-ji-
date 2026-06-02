// Thin client for Supabase Storage (object storage) over its REST API.
// Used server-side only, with the service-role key, to broker access to the private
// 'vault' bucket. Files are already client-side encrypted before they reach here.

const RAW_URL = (process.env.SUPABASE_URL || '').replace(/\/+$/, '');
const KEY = process.env.SUPABASE_SERVICE_ROLE_KEY || '';
const BUCKET = process.env.VAULT_BUCKET || 'vault';
const STORAGE_URL = RAW_URL ? `${RAW_URL}/storage/v1` : '';

// True only when both the URL and service key are configured. Callers fall back to
// local-disk storage when this is false, so dev/unconfigured environments still work.
function storageConfigured() {
  return !!(RAW_URL && KEY);
}

function authHeaders(extra = {}) {
  return { apikey: KEY, Authorization: `Bearer ${KEY}`, ...extra };
}

function objectUrl(objectPath) {
  return `${STORAGE_URL}/object/${BUCKET}/${encodeURIComponent(objectPath)}`;
}

async function uploadObject(objectPath, buffer, contentType = 'application/octet-stream') {
  const res = await fetch(objectUrl(objectPath), {
    method: 'POST',
    headers: authHeaders({ 'Content-Type': contentType, 'x-upsert': 'true' }),
    body: buffer,
  });
  if (!res.ok) {
    throw new Error(`Storage upload failed: ${res.status} ${await res.text().catch(() => '')}`);
  }
  return res.json().catch(() => ({}));
}

async function downloadObject(objectPath) {
  const res = await fetch(objectUrl(objectPath), { headers: authHeaders() });
  if (!res.ok) throw new Error(`Storage download failed: ${res.status}`);
  return Buffer.from(await res.arrayBuffer());
}

async function deleteObject(objectPath) {
  const res = await fetch(objectUrl(objectPath), { method: 'DELETE', headers: authHeaders() });
  if (!res.ok && res.status !== 404) {
    throw new Error(`Storage delete failed: ${res.status}`);
  }
}

export { storageConfigured, uploadObject, downloadObject, deleteObject, BUCKET };
