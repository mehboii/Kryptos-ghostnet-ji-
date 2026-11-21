import * as SecureStore from 'expo-secure-store';

const REGISTRY_KEY = 'kryptos_tofu_registry';
const MAX_PEERS = 500;
const MAX_PEER_ID_LENGTH = 256;
const MIN_PUBKEY_HEX_LENGTH = 66;
const MAX_PUBKEY_HEX_LENGTH = 130;
const HEX_REGEX = /^[0-9a-fA-F]+$/;

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
 * Validate a peerId: non-empty string, printable, bounded length, no null bytes.
 * @param {string} peerId
 * @returns {boolean}
 */
function isValidPeerId(peerId) {
  if (!peerId || typeof peerId !== 'string') return false;
  if (peerId.trim().length === 0) return false;
  if (peerId.length > MAX_PEER_ID_LENGTH) return false;
  if (/\x00/.test(peerId)) return false;
  return true;
}

/**
 * Validate a public key: hex-encoded, correct length for compressed (33B) or uncompressed (65B) P-256.
 * @param {string} publicKey
 * @returns {boolean}
 */
function isValidPublicKey(publicKey) {
  if (!publicKey || typeof publicKey !== 'string') return false;
  if (!HEX_REGEX.test(publicKey)) return false;
  if (publicKey.length < MIN_PUBKEY_HEX_LENGTH || publicKey.length > MAX_PUBKEY_HEX_LENGTH) return false;
  return true;
}

/**
 * Load the full peer registry from SecureStore.
 * Recovers gracefully from any corruption.
 * @returns {Promise<Record<string, PeerRecord>>}
 */
async function loadRegistry() {
  const raw = await SecureStore.getItemAsync(REGISTRY_KEY);
  if (!raw) return {};
  try {
    const parsed = JSON.parse(raw);
    if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) return {};
    return parsed;
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

let _registryLock = Promise.resolve();

/**
 * Serialize registry writes to prevent TOCTOU race conditions.
 * @param {Function} fn - async function to run while holding the lock
 * @returns {Promise<*>}
 */
async function withRegistryLock(fn) {
  const prev = _registryLock;
  let resolve;
  _registryLock = new Promise((r) => { resolve = r; });
  await prev;
  try {
    return await fn();
  } finally {
    resolve();
  }
}

/**
 * Process a BLE handshake: register or verify a peer's public key.
 *
 * - First contact: stores the key, returns status 'new'
 * - Key matches stored: updates lastSeen, returns 'trusted'
 * - Key differs from stored: returns 'key_changed' with warning
 *   (does NOT auto-block — the caller must surface this to the user)
 *
 * Fully local — no server calls. Serialized to prevent TOCTOU races.
 *
 * @param {string} peerId - stable peer identifier (BLE device ID or nodeId)
 * @param {string} publicKey - hex-encoded public key received in handshake
 * @returns {Promise<TofuResult>}
 */
export async function verifyPeer(peerId, publicKey) {
  if (!isValidPeerId(peerId)) {
    throw new Error('Invalid peerId: must be 1-' + MAX_PEER_ID_LENGTH + ' printable chars, no null bytes');
  }
  if (!isValidPublicKey(publicKey)) {
    throw new Error('Invalid publicKey: must be ' + MIN_PUBKEY_HEX_LENGTH + '-' + MAX_PUBKEY_HEX_LENGTH + ' hex chars');
  }

  return withRegistryLock(async () => {
    const registry = await loadRegistry();
    const now = Date.now();

    const existing = Object.prototype.hasOwnProperty.call(registry, peerId)
      ? registry[peerId]
      : undefined;

    if (!existing) {
      if (Object.keys(registry).length >= MAX_PEERS) {
        throw new Error('Peer registry full (' + MAX_PEERS + ' max). Remove unused peers first.');
      }

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
  });
}

/**
 * Accept a key change — overwrite the stored key for a peer.
 * Call this only after the user has explicitly confirmed they trust the new key.
 * @param {string} peerId
 * @param {string} newPublicKey - hex-encoded new public key
 * @returns {Promise<PeerRecord>}
 */
export async function acceptKeyChange(peerId, newPublicKey) {
  if (!isValidPeerId(peerId)) {
    throw new Error('Invalid peerId');
  }
  if (!isValidPublicKey(newPublicKey)) {
    throw new Error('Invalid publicKey format');
  }

  return withRegistryLock(async () => {
    const registry = await loadRegistry();
    const now = Date.now();
    const existing = Object.prototype.hasOwnProperty.call(registry, peerId)
      ? registry[peerId]
      : undefined;

    if (!existing) {
      throw new Error('Cannot accept key change for unknown peer. Use verifyPeer for first contact.');
    }

    if (Object.keys(registry).length >= MAX_PEERS && !existing) {
      throw new Error('Peer registry full (' + MAX_PEERS + ' max).');
    }

    registry[peerId] = {
      publicKey: newPublicKey,
      firstSeen: existing.firstSeen,
      lastSeen: now,
      trusted: true,
    };
    await saveRegistry(registry);
    return registry[peerId];
  });
}

/**
 * Look up a peer's stored public key.
 * @param {string} peerId
 * @returns {Promise<string|null>} hex public key or null if unknown
 */
export async function getPeerPublicKey(peerId) {
  const registry = await loadRegistry();
  if (!Object.prototype.hasOwnProperty.call(registry, peerId)) return null;
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
  if (!Object.prototype.hasOwnProperty.call(registry, peerId)) return null;
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
  return withRegistryLock(async () => {
    const registry = await loadRegistry();
    if (!Object.prototype.hasOwnProperty.call(registry, peerId)) return false;
    delete registry[peerId];
    await saveRegistry(registry);
    return true;
  });
}

/**
 * Wipe the entire peer registry. Destructive.
 * @returns {Promise<void>}
 */
export async function clearRegistry() {
  return withRegistryLock(async () => {
    await SecureStore.deleteItemAsync(REGISTRY_KEY);
  });
}
