import * as SecureStore from 'expo-secure-store';

const REGISTRY_KEY = 'ghostnet_tofu_registry';

/**
 * @typedef {Object} PeerRecord
 * @property {string} publicKey - hex-encoded public key
 * @property {number} firstSeen - Unix timestamp (ms) of first handshake
 * @property {number} lastSeen - Unix timestamp (ms) of most recent handshake
 * @property {boolean} trusted - user has explicitly trusted this key
 */

/**
 * @typedef {Object} TofuResult
 * @property {'new'|'trusted'|'key_changed'} status
 * @property {PeerRecord} peer - the current peer record
 * @property {string} [previousKey] - only present when status === 'key_changed'
 * @property {string} [warning] - human-readable warning for key_changed
 */

/**
 * Load the full peer registry from SecureStore.
 * @returns {Promise<Record<string, PeerRecord>>}
 */
async function loadRegistry() {
  const raw = await SecureStore.getItemAsync(REGISTRY_KEY);
  if (!raw) return {};
  try {
    return JSON.parse(raw);
  } catch {
    return {};
  }
}

/**
 * Persist the full peer registry to SecureStore.
 * @param {Record<string, PeerRecord>} registry
 * @returns {Promise<void>}
 */
async function saveRegistry(registry) {
  await SecureStore.setItemAsync(REGISTRY_KEY, JSON.stringify(registry));
}

/**
 * Process a BLE handshake: register or verify a peer's public key.
 *
 * - First contact: stores the key, returns status 'new'
 * - Key matches stored: updates lastSeen, returns 'trusted'
 * - Key differs from stored: returns 'key_changed' with warning
 *   (does NOT auto-block — the caller must surface this to the user)
 *
 * Fully local — no server calls.
 *
 * @param {string} peerId - stable peer identifier (BLE device ID or nodeId)
 * @param {string} publicKey - hex-encoded public key received in handshake
 * @returns {Promise<TofuResult>}
 */
export async function verifyPeer(peerId, publicKey) {
  if (!peerId || !publicKey) {
    throw new Error('peerId and publicKey are required');
  }

  const registry = await loadRegistry();
  const now = Date.now();
  const existing = registry[peerId];

  if (!existing) {
    const peer = {
      publicKey,
      firstSeen: now,
      lastSeen: now,
      trusted: true,
    };
    registry[peerId] = peer;
    await saveRegistry(registry);
    return { status: 'new', peer };
  }

  if (existing.publicKey === publicKey) {
    existing.lastSeen = now;
    await saveRegistry(registry);
    return { status: 'trusted', peer: existing };
  }

  return {
    status: 'key_changed',
    peer: existing,
    previousKey: existing.publicKey,
    warning:
      "This peer's identity key has changed. " +
      'Could be a reinstall or a MITM attempt. Verify before trusting.',
  };
}

/**
 * Accept a key change — overwrite the stored key for a peer.
 * Call this only after the user has explicitly confirmed they trust the new key.
 * @param {string} peerId
 * @param {string} newPublicKey - hex-encoded new public key
 * @returns {Promise<PeerRecord>}
 */
export async function acceptKeyChange(peerId, newPublicKey) {
  const registry = await loadRegistry();
  const now = Date.now();
  const existing = registry[peerId];

  registry[peerId] = {
    publicKey: newPublicKey,
    firstSeen: existing ? existing.firstSeen : now,
    lastSeen: now,
    trusted: true,
  };
  await saveRegistry(registry);
  return registry[peerId];
}

/**
 * Look up a peer's stored public key.
 * @param {string} peerId
 * @returns {Promise<string|null>} hex public key or null if unknown
 */
export async function getPeerPublicKey(peerId) {
  const registry = await loadRegistry();
  const entry = registry[peerId];
  return entry ? entry.publicKey : null;
}

/**
 * Get the full record for a peer.
 * @param {string} peerId
 * @returns {Promise<PeerRecord|null>}
 */
export async function getPeerRecord(peerId) {
  const registry = await loadRegistry();
  return registry[peerId] || null;
}

/**
 * List all known peers in the registry.
 * @returns {Promise<Array<{ peerId: string } & PeerRecord>>}
 */
export async function listPeers() {
  const registry = await loadRegistry();
  return Object.entries(registry).map(([peerId, record]) => ({
    peerId,
    ...record,
  }));
}

/**
 * Remove a peer from the registry entirely.
 * @param {string} peerId
 * @returns {Promise<boolean>} true if the peer existed and was removed
 */
export async function removePeer(peerId) {
  const registry = await loadRegistry();
  if (!registry[peerId]) return false;
  delete registry[peerId];
  await saveRegistry(registry);
  return true;
}

/**
 * Wipe the entire peer registry. Destructive.
 * @returns {Promise<void>}
 */
export async function clearRegistry() {
  await SecureStore.deleteItemAsync(REGISTRY_KEY);
}
