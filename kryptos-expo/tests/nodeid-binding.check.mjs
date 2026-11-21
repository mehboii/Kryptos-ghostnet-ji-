/**
 * Ad-hoc verification (not part of the suite) that _assertNodeIdBinding
 * accepts the genuine nodeId derivation and rejects a spoofed nodeId.
 * Run: node tests/nodeid-binding.check.mjs   (from kryptos-expo/)
 */
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import path from 'node:path';
import vm from 'node:vm';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const REPO = path.resolve(__dirname, '..', '..');

const ethers = (() => {
  const ctx = { window: {}, console, crypto: globalThis.crypto, TextEncoder, TextDecoder };
  ctx.globalThis = ctx;
  ctx.self = ctx;
  vm.createContext(ctx);
  vm.runInContext(readFileSync(path.join(REPO, 'ethers.umd.min.js'), 'utf8'), ctx);
  return ctx.window.ethers || ctx.ethers;
})();

// Same canonical derivation as crypto-identity.js generateNodeId.
function generateNodeId(publicKey, displayName) {
  if (!publicKey) return null;
  const pk = String(publicKey);
  const name = String(displayName);
  return ethers.id(`${pk.length}:${pk}|${name.length}:${name}`);
}

const win = {
  GhostIdentity: { generateNodeId },
};
const sandbox = {
  window: win,
  crypto: globalThis.crypto,
  TextEncoder, TextDecoder, atob, btoa,
  ethers, console,
  setTimeout, clearTimeout, setInterval, clearInterval,
  Date, Math, JSON, Promise, Array, Uint8Array, DataView, Error, String,
};
sandbox.globalThis = sandbox;
vm.createContext(sandbox);
vm.runInContext(readFileSync(path.join(REPO, 'proximity-connect.js'), 'utf8'), sandbox);
const inst = win.ProximityConnect;

let pass = 0, fail = 0;
const ok = (name, cond) => {
  if (cond) { pass++; console.log('  ✓ ' + name); }
  else { fail++; console.log('  ✗ ' + name); }
};
const throws = (fn) => { try { fn(); return null; } catch (e) { return e.message; } };

// Victim + attacker identities, exactly as crypto-identity creates them.
const victim = ethers.Wallet.createRandom();
const attacker = ethers.Wallet.createRandom();
const victimPub = victim.signingKey.publicKey;        // 0x04… uncompressed
const attackerPub = attacker.signingKey.publicKey;
const victimNodeId = generateNodeId(victimPub, 'Alice');
const attackerNodeId = generateNodeId(attackerPub, 'Mallory');

// 1. Genuine: claimed nodeId derives from the presented key + displayName.
ok('accepts a genuine nodeId/key/displayName binding',
  throws(() => inst._assertNodeIdBinding(victimNodeId, victimPub.slice(2), 'Alice')) === null);

// 2. Compressed key form of the same identity still verifies.
const victimCompressed = ethers.SigningKey.computePublicKey(victimPub, true);
ok('accepts the same identity presented as a compressed key',
  throws(() => inst._assertNodeIdBinding(victimNodeId, victimCompressed.slice(2), 'Alice')) === null);

// 3. SPOOF: attacker claims the victim's nodeId with their own key.
ok('rejects a victim nodeId claimed with an attacker key (GhostTag spoofing)',
  /impersonation blocked/.test(throws(() => inst._assertNodeIdBinding(victimNodeId, attackerPub.slice(2), 'Mallory')) || ''));

// 4. SPOOF: right key, wrong displayName (changes the derivation).
ok('rejects a tampered displayName',
  /impersonation blocked/.test(throws(() => inst._assertNodeIdBinding(victimNodeId, victimPub.slice(2), 'Eve')) || ''));

// 5. Garbage key fails closed.
ok('rejects a non-secp256k1 identity key',
  throws(() => inst._assertNodeIdBinding(attackerNodeId, 'deadbeef', 'Mallory')) !== null);

console.log(`\n${pass} passed, ${fail} failed`);
process.exit(fail ? 1 : 0);
