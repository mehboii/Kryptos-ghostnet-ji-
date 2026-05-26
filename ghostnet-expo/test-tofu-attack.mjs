// TOFU attack suite — mock SecureStore in-memory
const _store = new Map();
const SecureStore = {
  getItemAsync: async (k) => _store.get(k) || null,
  setItemAsync: async (k,v) => _store.set(k,v),
  deleteItemAsync: async (k) => _store.delete(k),
};

const REGISTRY_KEY = 'ghostnet_tofu_registry';
async function loadRegistry() {
  const raw = await SecureStore.getItemAsync(REGISTRY_KEY);
  if (!raw) return {};
  try { return JSON.parse(raw); } catch { return {}; }
}
async function saveRegistry(r) { await SecureStore.setItemAsync(REGISTRY_KEY, JSON.stringify(r)); }
async function verifyPeer(peerId, publicKey) {
  if (!peerId || !publicKey) throw new Error('peerId and publicKey are required');
  const registry = await loadRegistry();
  const now = Date.now();
  const existing = registry[peerId];
  if (!existing) {
    const peer = { publicKey, firstSeen: now, lastSeen: now, trusted: true };
    registry[peerId] = peer;
    await saveRegistry(registry);
    return { status: 'new', peer };
  }
  if (existing.publicKey === publicKey) {
    existing.lastSeen = now;
    await saveRegistry(registry);
    return { status: 'trusted', peer: existing };
  }
  return { status: 'key_changed', peer: existing, previousKey: existing.publicKey, warning: 'key changed' };
}
async function acceptKeyChange(peerId, newPublicKey) {
  const registry = await loadRegistry();
  const now = Date.now();
  const existing = registry[peerId];
  registry[peerId] = { publicKey: newPublicKey, firstSeen: existing ? existing.firstSeen : now, lastSeen: now, trusted: true };
  await saveRegistry(registry);
  return registry[peerId];
}

let pass = 0, fail = 0;
const vulns = [];
function test(name, result) { if(result){pass++} else{fail++;console.log('  VULN:', name); vulns.push(name);} }

console.log('========================================');
console.log('ATTACK SUITE 3: TOFU REGISTRY ATTACKS');
console.log('========================================\n');

// --- ATK-T01: MITM key swap detection ---
console.log('[ATK-T01] MITM key swap');
_store.clear();
const r1 = await verifyPeer('peer1', 'aaaa');
test('First contact = new', r1.status === 'new');
const r2 = await verifyPeer('peer1', 'aaaa');
test('Same key = trusted', r2.status === 'trusted');
const r3 = await verifyPeer('peer1', 'bbbb');
test('Changed key detected', r3.status === 'key_changed');
test('Previous key preserved', r3.previousKey === 'aaaa');
test('Warning present', !!r3.warning);

// --- ATK-T02: Key change does NOT auto-update ---
console.log('[ATK-T02] No auto-trust on key change');
const r4 = await verifyPeer('peer1', 'bbbb');
test('Still warns on repeated changed key', r4.status === 'key_changed');
test('Original key still stored', r4.previousKey === 'aaaa');

// --- ATK-T03: acceptKeyChange updates correctly ---
console.log('[ATK-T03] Explicit trust update');
await acceptKeyChange('peer1', 'bbbb');
const r5 = await verifyPeer('peer1', 'bbbb');
test('After accept: trusted', r5.status === 'trusted');
const r6 = await verifyPeer('peer1', 'aaaa');
test('Old key now warns', r6.status === 'key_changed');

// --- ATK-T04: Empty/null inputs ---
console.log('[ATK-T04] Null/empty input fuzzing');
let threw;
threw = false; try { await verifyPeer('', 'key'); } catch { threw = true; }
test('Empty peerId throws', threw);
threw = false; try { await verifyPeer('peer', ''); } catch { threw = true; }
test('Empty publicKey throws', threw);
threw = false; try { await verifyPeer(null, 'key'); } catch { threw = true; }
test('Null peerId throws', threw);
threw = false; try { await verifyPeer('peer', null); } catch { threw = true; }
test('Null publicKey throws', threw);
threw = false; try { await verifyPeer(undefined, 'key'); } catch { threw = true; }
test('Undefined peerId throws', threw);

// --- ATK-T05: Prototype pollution via peerId ---
console.log('[ATK-T05] Prototype pollution');
_store.clear();
await verifyPeer('__proto__', 'evilkey');
const cleanObj = {};
test('__proto__ peerId safe', cleanObj.publicKey === undefined);
await verifyPeer('constructor', 'evilkey');
test('constructor peerId safe', ({}).constructor === Object);
await verifyPeer('toString', 'evilkey');
test('toString still works', ({}).toString() === '[object Object]');

// --- ATK-T06: JSON injection in peerId ---
console.log('[ATK-T06] JSON injection');
_store.clear();
await verifyPeer('"}},{"__proto__":{"polluted":true', 'key1');
const after = JSON.parse(await SecureStore.getItemAsync(REGISTRY_KEY));
test('JSON injection contained', !({}).polluted);
test('Registry still parseable', typeof after === 'object');

// --- ATK-T07: Very long peerId / publicKey ---
console.log('[ATK-T07] Large input DoS');
_store.clear();
const bigPeerId = 'x'.repeat(100000);
const bigPubKey = 'a'.repeat(100000);
threw = false;
try { await verifyPeer(bigPeerId, bigPubKey); } catch { threw = true; }
test('100K peerId does not crash', !threw);
const stored = await SecureStore.getItemAsync(REGISTRY_KEY);
test('VULN: No size limit on peerId (storage DoS)', stored.length < 1000);

// --- ATK-T08: Race condition — concurrent verifyPeer ---
console.log('[ATK-T08] Race condition (TOCTOU)');
_store.clear();
const promises = [];
for (let i = 0; i < 50; i++) {
  promises.push(verifyPeer('race-peer', 'key-' + (i % 2 === 0 ? 'A' : 'B')));
}
const results = await Promise.all(promises);
const finalReg = JSON.parse(await SecureStore.getItemAsync(REGISTRY_KEY));
test('Race: registry valid JSON', typeof finalReg === 'object');
test('Race: peer exists', !!finalReg['race-peer']?.publicKey);
const statuses = results.map(r => r.status);
const newCount = statuses.filter(s => s === 'new').length;
test('VULN: Race allows multiple "new" for same peer', newCount <= 1);

// --- ATK-T09: Corrupted SecureStore data ---
console.log('[ATK-T09] Corrupted storage');
_store.set(REGISTRY_KEY, '{corrupt json!!!');
const r9 = await verifyPeer('newpeer', 'key9');
test('Corrupted storage recovers', r9.status === 'new');
_store.set(REGISTRY_KEY, '');
const r10 = await verifyPeer('newpeer2', 'key10');
test('Empty storage recovers', r10.status === 'new');
_store.set(REGISTRY_KEY, 'null');
const r11 = await verifyPeer('newpeer3', 'key11');
test('Null-string storage recovers', r11.status === 'new');

// --- ATK-T10: No key format validation ---
console.log('[ATK-T10] Key format validation');
_store.clear();
const r12 = await verifyPeer('peer-badkey', 'not-a-real-hex-key');
test('VULN: Non-hex publicKey accepted', r12.status === 'new');
const r13 = await verifyPeer('peer-xss', '<script>alert(1)</script>');
test('VULN: XSS payload accepted as publicKey', r13.status === 'new');
const r14 = await verifyPeer('peer-short', 'aa');
test('VULN: 1-byte publicKey accepted', r14.status === 'new');

// --- ATK-T11: peerId with special chars ---
console.log('[ATK-T11] Special character peerIds');
_store.clear();
const specialIds = ['../../../etc/passwd', '\x00null\x00byte', '   ', '\n\r\t', 'a'.repeat(10000)];
for (const id of specialIds) {
  threw = false;
  try { await verifyPeer(id, 'validkey'); } catch { threw = true; }
  // Whitespace-only should arguably be rejected
  if (id.trim() === '') {
    test('Whitespace-only peerId: ' + JSON.stringify(id).slice(0,20), threw);
  }
}

// --- ATK-T12: Registry size explosion ---
console.log('[ATK-T12] Registry size explosion');
_store.clear();
for (let i = 0; i < 1000; i++) {
  await verifyPeer('peer-' + i, 'key-' + i);
}
const regSize = (await SecureStore.getItemAsync(REGISTRY_KEY)).length;
console.log('  Registry size after 1000 peers:', regSize, 'bytes');
test('VULN: No max peer count limit', regSize < 50000); // Will fail — no limit exists

console.log('\n========================================');
console.log('RESULTS: ' + pass + ' passed, ' + fail + ' failed');
if (vulns.length > 0) console.log('VULNERABILITIES:', vulns);
console.log('========================================');
