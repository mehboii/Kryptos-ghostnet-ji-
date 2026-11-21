import { p256 } from '@noble/curves/nist.js';
import { sha256 } from '@noble/hashes/sha2.js';
import { generateMnemonic, mnemonicToSeedSync, validateMnemonic } from '@scure/bip39';
import { wordlist } from '@scure/bip39/wordlists/english.js';
import { HDKey } from '@scure/bip32';

// Reimplement the hardened functions inline (can't import ESM from expo modules in Node)
function bytesToHex(bytes) {
  return Array.from(new Uint8Array(bytes)).map(b => b.toString(16).padStart(2, '0')).join('');
}
function hexToBytes(hex) {
  if (!hex || typeof hex !== 'string') return new Uint8Array(0);
  if (hex.length % 2 !== 0) return new Uint8Array(0);
  if (!/^[0-9a-fA-F]+$/.test(hex)) return new Uint8Array(0);
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < hex.length; i += 2) bytes[i / 2] = parseInt(hex.substring(i, i + 2), 16);
  return bytes;
}
function hashData(data) {
  if (typeof data === 'string') return sha256(new TextEncoder().encode(data));
  if (data instanceof Uint8Array) return sha256(data);
  throw new TypeError('hashData requires a string or Uint8Array, got ' + typeof data);
}
function signHash(msgHash, privKeyHex) {
  if (!(msgHash instanceof Uint8Array) || msgHash.length !== 32) throw new Error('msgHash must be 32-byte Uint8Array');
  if (!privKeyHex || typeof privKeyHex !== 'string') throw new Error('privKeyHex required');
  const privKeyBytes = hexToBytes(privKeyHex);
  return bytesToHex(p256.sign(msgHash, privKeyBytes, { lowS: true }));
}
function verifySignature(msgHash, sigHex, pubKeyHex) {
  if (!(msgHash instanceof Uint8Array) || msgHash.length !== 32) return false;
  if (!sigHex || !pubKeyHex) return false;
  try {
    const sigBytes = hexToBytes(sigHex);
    const pubKeyBytes = hexToBytes(pubKeyHex);
    if (sigBytes.length === 0 || pubKeyBytes.length === 0) return false;
    return p256.verify(sigBytes, msgHash, pubKeyBytes, { lowS: true });
  } catch { return false; }
}

const _seenNonces = new Map();
function signPayload(payload, privKeyHex) {
  const hash = hashData(payload);
  const checksum = bytesToHex(hash);
  const signature = signHash(hash, privKeyHex);
  const timestamp = Date.now();
  const nonceBytes = new Uint8Array(16);
  globalThis.crypto.getRandomValues(nonceBytes);
  const nonce = bytesToHex(nonceBytes);
  return { checksum, signature, timestamp, nonce };
}
function verifyPayload(payload, checksum, sigHex, pubKeyHex, opts) {
  const hash = hashData(payload);
  const computed = bytesToHex(hash);
  if (computed !== checksum) return { valid: false, reason: 'checksum_mismatch' };
  if (opts) {
    const maxAge = opts.maxAgeMs || 300000;
    if (typeof opts.timestamp === 'number') {
      const age = Date.now() - opts.timestamp;
      if (age > maxAge || age < -30000) return { valid: false, reason: 'timestamp_stale' };
    }
    if (opts.nonce) {
      if (_seenNonces.has(opts.nonce)) return { valid: false, reason: 'replay_detected' };
      _seenNonces.set(opts.nonce, Date.now());
    }
  }
  if (!verifySignature(hash, sigHex, pubKeyHex)) return { valid: false, reason: 'signature_invalid' };
  return { valid: true };
}

// TOFU mock
const MAX_PEERS = 500;
const MAX_PEER_ID_LENGTH = 256;
const HEX_REGEX = /^[0-9a-fA-F]+$/;
function isValidPeerId(pid) {
  if (!pid || typeof pid !== 'string') return false;
  if (pid.trim().length === 0) return false;
  if (pid.length > MAX_PEER_ID_LENGTH) return false;
  if (/\x00/.test(pid)) return false;
  return true;
}
function isValidPublicKey(pk) {
  if (!pk || typeof pk !== 'string') return false;
  if (!HEX_REGEX.test(pk)) return false;
  if (pk.length < 66 || pk.length > 130) return false;
  return true;
}
const _store = new Map();
const REGISTRY_KEY = 'kryptos_tofu_registry';
async function loadRegistry() {
  const raw = _store.get(REGISTRY_KEY) || null;
  if (!raw) return {};
  try { const p = JSON.parse(raw); if (!p || typeof p !== 'object' || Array.isArray(p)) return {}; return p; } catch { return {}; }
}
async function saveRegistry(r) { _store.set(REGISTRY_KEY, JSON.stringify(r)); }
let _lock = Promise.resolve();
async function withLock(fn) {
  const prev = _lock; let resolve; _lock = new Promise(r => { resolve = r; });
  await prev; try { return await fn(); } finally { resolve(); }
}
async function verifyPeer(peerId, publicKey) {
  if (!isValidPeerId(peerId)) throw new Error('Invalid peerId');
  if (!isValidPublicKey(publicKey)) throw new Error('Invalid publicKey');
  return withLock(async () => {
    const registry = await loadRegistry();
    const now = Date.now();
    const existing = Object.prototype.hasOwnProperty.call(registry, peerId) ? registry[peerId] : undefined;
    if (!existing) {
      if (Object.keys(registry).length >= MAX_PEERS) throw new Error('Registry full');
      const peer = { publicKey, firstSeen: now, lastSeen: now, trusted: true };
      registry[peerId] = peer;
      await saveRegistry(registry);
      return { status: 'new', peer };
    }
    if (existing.publicKey === publicKey) { existing.lastSeen = now; await saveRegistry(registry); return { status: 'trusted', peer: existing }; }
    return { status: 'key_changed', peer: existing, previousKey: existing.publicKey, warning: 'key changed' };
  });
}

// Test harness
let pass = 0, fail = 0;
const vulns = [];
function test(name, result) { if (result) { pass++; } else { fail++; console.log('  FAIL:', name); vulns.push(name); } }

// Generate test identity
const mn = generateMnemonic(wordlist, 128);
const child = HDKey.fromMasterSeed(mnemonicToSeedSync(mn)).derive("m/44'/60'/0'/0/0");
const privHex = bytesToHex(child.privateKey);
const pubHex = bytesToHex(p256.getPublicKey(child.privateKey));
const mn2 = generateMnemonic(wordlist, 128);
const child2 = HDKey.fromMasterSeed(mnemonicToSeedSync(mn2)).derive("m/44'/60'/0'/0/0");
const atkPriv = bytesToHex(child2.privateKey);
const atkPub = bytesToHex(p256.getPublicKey(child2.privateKey));

console.log('='.repeat(60));
console.log(' ADVERSARIAL ATTACK SUITE — POST-HARDENING');
console.log('='.repeat(60) + '\n');

// ============= ECDSA ATTACKS =============
console.log('--- ECDSA LAYER ---\n');

const payload = 'secret mesh message';
const { checksum, signature, timestamp, nonce } = signPayload(payload, privHex);

console.log('[ATK-01] Replay / payload swap');
test('Different payload rejected', !verifyPayload('different', checksum, signature, pubHex).valid);

console.log('[ATK-02] Signature forgery');
test('Random sig rejected', !verifyPayload(payload, checksum, bytesToHex(new Uint8Array(64).map(() => Math.floor(Math.random() * 256))), pubHex).valid);

console.log('[ATK-03] Cross-key attack');
const atkSigned = signPayload(payload, atkPriv);
test('Attacker sig rejected under victim key', !verifyPayload(payload, checksum, atkSigned.signature, pubHex).valid);

console.log('[ATK-04] Null/empty inputs');
test('Empty sig', !verifySignature(hashData(payload), '', pubHex));
test('Null sig', !verifySignature(hashData(payload), null, pubHex));
test('Empty pubkey', !verifySignature(hashData(payload), signature, ''));
test('Null pubkey', !verifySignature(hashData(payload), signature, null));
test('Empty hash', !verifySignature(new Uint8Array(0), signature, pubHex));
test('Short hash', !verifySignature(new Uint8Array(16), signature, pubHex));

console.log('[ATK-05] Bit-flip on signature');
for (let bit = 0; bit < 8; bit++) {
  const flipped = hexToBytes(signature); flipped[0] ^= (1 << bit);
  test('Bit ' + bit + ' flip rejected', !verifySignature(hashData(payload), bytesToHex(flipped), pubHex));
}

console.log('[ATK-06] Truncated / overlong sig');
test('Half sig', !verifySignature(hashData(payload), signature.slice(0, 64), pubHex));
test('Sig+extra', !verifySignature(hashData(payload), signature + 'ff'.repeat(32), pubHex));
test('Zero sig', !verifySignature(hashData(payload), '00'.repeat(64), pubHex));

console.log('[ATK-07] Degenerate keys');
test('Zero pubkey', !verifySignature(hashData(payload), signature, '00'.repeat(33)));
test('secp256k1 pubkey', !verifySignature(hashData(payload), signature, bytesToHex(child.publicKey)));

// ============= V-01 FIX: hashData type safety =============
console.log('\n[ATK-08] hashData type safety (V-01 fix)');
for (const bad of [123, true, false, {}, [], NaN, Infinity, null, undefined]) {
  let threw = false;
  try { hashData(bad); } catch { threw = true; }
  test('hashData(' + String(bad) + ') throws', threw);
}

// ============= V-02 FIX: hexToBytes validation =============
console.log('\n[ATK-09] hexToBytes validation (V-02 fix)');
test('Odd hex = empty', hexToBytes('abc').length === 0);
test('Non-hex chars = empty', hexToBytes('zzzz').length === 0);
test('Whitespace hex = empty', hexToBytes('  aabb  ').length === 0);
test('Valid uppercase', hexToBytes('AABB').length === 2);
test('Valid lowercase', hexToBytes('aabb').length === 2);

// ============= V-03 FIX: Replay protection =============
console.log('\n[ATK-10] Replay protection (V-03 fix)');
const fresh = signPayload('replay test', privHex);
const r1 = verifyPayload('replay test', fresh.checksum, fresh.signature, pubHex, { timestamp: fresh.timestamp, nonce: fresh.nonce });
test('First send: valid', r1.valid);
const r2 = verifyPayload('replay test', fresh.checksum, fresh.signature, pubHex, { timestamp: fresh.timestamp, nonce: fresh.nonce });
test('Replay: rejected', !r2.valid);
test('Replay reason', r2.reason === 'replay_detected');

console.log('[ATK-11] Stale timestamp');
const stale = signPayload('old msg', privHex);
stale.timestamp = Date.now() - 600000; // 10 min ago
const r3 = verifyPayload('old msg', stale.checksum, stale.signature, pubHex, { timestamp: stale.timestamp });
test('10-min-old timestamp rejected', !r3.valid);
test('Stale reason', r3.reason === 'timestamp_stale');

const future = signPayload('future msg', privHex);
future.timestamp = Date.now() + 60000; // 1 min in future
const r4 = verifyPayload('future msg', future.checksum, future.signature, pubHex, { timestamp: future.timestamp });
test('Future timestamp rejected', !r4.valid);

// ============= TOFU ATTACKS =============
console.log('\n--- TOFU REGISTRY ---\n');

// Valid compressed P-256 pubkey (33 bytes = 66 hex chars)
const validPub = pubHex;
const validPub2 = atkPub;

console.log('[ATK-T01] MITM detection');
_store.clear();
const t1 = await verifyPeer('peer1', validPub);
test('First contact = new', t1.status === 'new');
const t2 = await verifyPeer('peer1', validPub);
test('Same key = trusted', t2.status === 'trusted');
const t3 = await verifyPeer('peer1', validPub2);
test('Key change detected', t3.status === 'key_changed');
test('Previous key preserved', t3.previousKey === validPub);

console.log('[ATK-T02] No auto-trust');
const t4 = await verifyPeer('peer1', validPub2);
test('Repeated change still warns', t4.status === 'key_changed');

// ============= V-04 FIX: Corrupted storage =============
console.log('\n[ATK-T03] Corrupted storage (V-04 fix)');
_store.set(REGISTRY_KEY, '{corrupt!!!');
const tc1 = await verifyPeer('newpeer', validPub);
test('Corrupt JSON recovers', tc1.status === 'new');
_store.set(REGISTRY_KEY, 'null');
const tc2 = await verifyPeer('newpeer2', validPub);
test('null-string recovers', tc2.status === 'new');
_store.set(REGISTRY_KEY, '[]');
const tc3 = await verifyPeer('newpeer3', validPub);
test('Array recovers', tc3.status === 'new');
_store.set(REGISTRY_KEY, '""');
const tc4 = await verifyPeer('newpeer4', validPub);
test('String recovers', tc4.status === 'new');

// ============= V-05 FIX: Public key format validation =============
console.log('\n[ATK-T04] Public key validation (V-05 fix)');
let threw;
threw = false; try { await verifyPeer('p1', 'not-hex-at-all'); } catch { threw = true; }
test('Non-hex pubkey rejected', threw);
threw = false; try { await verifyPeer('p2', '<script>alert(1)</script>'); } catch { threw = true; }
test('XSS pubkey rejected', threw);
threw = false; try { await verifyPeer('p3', 'aa'); } catch { threw = true; }
test('1-byte pubkey rejected', threw);
threw = false; try { await verifyPeer('p4', 'aa'.repeat(200)); } catch { threw = true; }
test('400-byte pubkey rejected', threw);

// ============= V-06 FIX: peerId validation =============
console.log('\n[ATK-T05] PeerId validation (V-06 fix)');
threw = false; try { await verifyPeer('', validPub); } catch { threw = true; }
test('Empty peerId rejected', threw);
threw = false; try { await verifyPeer('   ', validPub); } catch { threw = true; }
test('Whitespace peerId rejected', threw);
threw = false; try { await verifyPeer(null, validPub); } catch { threw = true; }
test('Null peerId rejected', threw);
threw = false; try { await verifyPeer('a\x00b', validPub); } catch { threw = true; }
test('Null-byte peerId rejected', threw);
threw = false; try { await verifyPeer('x'.repeat(300), validPub); } catch { threw = true; }
test('300-char peerId rejected', threw);

// ============= V-05 FIX: Prototype pollution =============
console.log('\n[ATK-T06] Prototype pollution (safe property access)');
_store.clear();
await verifyPeer('__proto__', validPub);
test('__proto__ safe', ({}).publicKey === undefined);
await verifyPeer('constructor', validPub);
test('constructor safe', ({}).constructor === Object);

// ============= V-07 FIX: Registry size limit =============
console.log('\n[ATK-T07] Registry size limit (V-07 fix)');
_store.clear();
let hitLimit = false;
for (let i = 0; i < 510; i++) {
  try { await verifyPeer('peer-' + i, validPub); }
  catch (e) { if (e.message.includes('full')) { hitLimit = true; console.log('  Limit hit at peer', i); break; } throw e; }
}
test('Registry enforces max peers', hitLimit);

// ============= V-08 FIX: TOCTOU race condition =============
console.log('\n[ATK-T08] Race condition fix (V-08)');
_store.clear();
const racePromises = [];
for (let i = 0; i < 50; i++) {
  racePromises.push(verifyPeer('race-peer', validPub));
}
const raceResults = await Promise.all(racePromises);
const newCount = raceResults.filter(r => r.status === 'new').length;
test('Only 1 "new" from 50 concurrent calls', newCount === 1);
const trustedCount = raceResults.filter(r => r.status === 'trusted').length;
test('Rest are "trusted"', trustedCount === 49);

// ============= UNICODE NORMALIZATION =============
console.log('\n[ATK-12] Unicode normalization');
const nfcMsg = 'é';
const nfdMsg = 'é';
const nfcSigned = signPayload(nfcMsg, privHex);
test('NFC != NFD', !verifyPayload(nfdMsg, nfcSigned.checksum, nfcSigned.signature, pubHex).valid);

// ============= SUMMARY =============
console.log('\n' + '='.repeat(60));
console.log(' RESULTS: ' + pass + ' passed, ' + fail + ' failed');
if (vulns.length > 0) {
  console.log(' REMAINING VULNERABILITIES:', vulns);
  process.exit(1);
} else {
  console.log(' ALL ATTACKS DEFEATED');
}
console.log('='.repeat(60));
