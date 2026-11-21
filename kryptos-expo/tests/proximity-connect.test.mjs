/**
 * Focused tests for the security-critical, runtime-independent logic in
 * proximity-connect.js. The native BLE layer + WebView bridge can only be
 * verified on a device, but these pieces are pure JS and MUST be correct:
 *
 *   T1  Fragmentation: large handshake frames survive chunk → wire → reassemble
 *       (regression guard for the BLE notify MTU truncation bug).
 *   T2  Key agreement: two ephemeral ECDH parties derive the SAME session key +
 *       verification code, and AES-GCM round-trips between them.
 *   T3  Identity auth: the real _signIdentity / _verifyIdentitySig pair accepts a
 *       genuine signature and REJECTS a wrong-key signature and a tampered
 *       transcript (the MITM / impersonation defense).
 *
 * Run: node tests/proximity-connect.test.mjs   (from kryptos-expo/)
 */
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import path from 'node:path';
import vm from 'node:vm';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const REPO = path.resolve(__dirname, '..', '..');
const SRC = path.join(REPO, 'proximity-connect.js');

// Use the SAME ethers UMD (v6) the WebView bundle uses — the npm `ethers` here
// is v5 with a different (utils.*) API, so importing it would not reflect runtime.
const ethers = (() => {
  const ctx = { window: {}, console, crypto: globalThis.crypto, TextEncoder, TextDecoder };
  ctx.globalThis = ctx;
  ctx.self = ctx;
  vm.createContext(ctx);
  vm.runInContext(readFileSync(path.join(REPO, 'ethers.umd.min.js'), 'utf8'), ctx);
  const e = ctx.window.ethers || ctx.ethers;
  // ethers v6 lets you register the RNG explicitly; ensure it's wired.
  if (e.randomBytes && e.registerRng) {
    try { e.registerRng((n) => globalThis.crypto.getRandomValues(new Uint8Array(n))); } catch (_) {}
  }
  return e;
})();

let pass = 0, fail = 0;
function ok(name, cond) {
  if (cond) { pass++; console.log('  ✓ ' + name); }
  else { fail++; console.log('  ✗ ' + name); }
}

// ── Load the class under a minimal browser-ish sandbox ─────────────────────
function loadProximityClass(getSessionPrivateKey) {
  const win = {};
  const sandbox = {
    window: win,
    crypto: globalThis.crypto,
    TextEncoder, TextDecoder,
    atob, btoa,
    ethers,
    console,
    setTimeout, clearTimeout, setInterval, clearInterval,
    Date, Math, JSON, Promise, Array, Uint8Array, DataView, Error,
  };
  sandbox.globalThis = sandbox;
  win.GhostIdentity = { getSessionPrivateKey };
  win.KryptosBLE = { on() {}, }; // presence satisfies init()'s guard
  vm.createContext(sandbox);
  vm.runInContext(readFileSync(SRC, 'utf8'), sandbox);
  return { PC: win.ProximityConnect.constructor, win };
}

async function main() {
  const wallet = ethers.Wallet.createRandom();
  const walletPub = new ethers.SigningKey(wallet.privateKey).publicKey;
  const { PC } = loadProximityClass(async () => wallet.privateKey);

  // ── T1: fragmentation round-trip ───────────────────────────────────────
  console.log('T1 fragmentation');
  {
    const inst = new PC();
    const wires = [];
    Object.defineProperty(inst, '_ble', { get: () => ({
      write: async (_d, _c, b64) => wires.push(b64),
      notifyData: async (b64) => wires.push(b64),
    })});

    const big = {
      type: 'HANDSHAKE_ACCEPT',
      nodeId: '0x' + 'a'.repeat(64),
      identityPub: '04' + 'b'.repeat(128),  // 65-byte uncompressed key
      ephemeralPub: '04' + 'c'.repeat(128),
      ts: Date.now(),
    };
    await inst._sendData('DEV', big, true);
    ok('large frame fragments into multiple chunks', wires.length > 1);

    let reassembled = null;
    for (const w of wires) {
      const f = inst._ingest('DEV', inst._b64ToStr(w));
      if (f) reassembled = f;
    }
    ok('reassembles to the original frame', JSON.stringify(reassembled) === JSON.stringify(big));

    // Out-of-order delivery still reassembles.
    const inst2 = new PC();
    const got = [];
    for (const w of [...wires].reverse()) {
      const f = inst2._ingest('DEV', inst2._b64ToStr(w));
      if (f) got.push(f);
    }
    ok('reassembles despite reversed fragment order', got.length === 1 && got[0].type === 'HANDSHAKE_ACCEPT');
  }

  // ── T2: ECDH session agreement + AES-GCM round-trip ────────────────────
  console.log('T2 key agreement');
  {
    const a = new PC(); const b = new PC();
    a.localEphemeral = await crypto.subtle.generateKey({ name: 'ECDH', namedCurve: 'P-256' }, false, ['deriveBits']);
    b.localEphemeral = await crypto.subtle.generateKey({ name: 'ECDH', namedCurve: 'P-256' }, false, ['deriveBits']);
    a._ephemeralPubHex = a._bufToHex(await crypto.subtle.exportKey('raw', a.localEphemeral.publicKey));
    b._ephemeralPubHex = b._bufToHex(await crypto.subtle.exportKey('raw', b.localEphemeral.publicKey));

    const sharedA = await a._deriveShared(b._ephemeralPubHex);
    const sharedB = await b._deriveShared(a._ephemeralPubHex);
    const codeA = await a._deriveVerificationCode(sharedA);
    const codeB = await b._deriveVerificationCode(sharedB);
    ok('both sides derive the same 6-digit verification code', codeA === codeB && /^\d{6}$/.test(codeA));

    const salt = crypto.getRandomValues(new Uint8Array(16));
    a.sessionKeys = await a._deriveSessionKeys(sharedA, salt);
    b.sessionKeys = await b._deriveSessionKeys(sharedB, salt);
    const enc = await a.sendEncrypted('ghost ping over BLE');
    const dec = await b.decryptMessage(enc);
    ok('AES-GCM session message round-trips A→B', dec === 'ghost ping over BLE');
  }

  // ── T3: identity signature accept / reject ─────────────────────────────
  console.log('T3 identity auth (MITM/forgery rejection)');
  {
    const inst = new PC();
    inst.localIdentity = { nodeId: 'n', publicKeyHex: inst._normalizePub(walletPub) };
    const nonce = 'a1b2c3d4';
    const ephA = '04' + '1'.repeat(128);
    const ephB = '04' + '2'.repeat(128);

    const sig = await inst._signIdentity(nonce, ephA, ephB);
    const myPub = inst._normalizePub(walletPub);
    const okGenuine = await inst._verifyIdentitySig(myPub, nonce, ephA, ephB, sig);
    ok('accepts a genuine signature from the matching identity key', okGenuine === true);

    const other = ethers.Wallet.createRandom();
    const otherPub = new ethers.SigningKey(other.privateKey).publicKey;
    const okWrongKey = await inst._verifyIdentitySig(inst._normalizePub(otherPub), nonce, ephA, ephB, sig);
    ok('rejects the signature against a DIFFERENT identity key (impersonation)', okWrongKey === false);

    const okTamperNonce = await inst._verifyIdentitySig(myPub, 'deadbeef', ephA, ephB, sig);
    ok('rejects when the signed nonce is tampered (replay/forge)', okTamperNonce === false);

    const okTamperEph = await inst._verifyIdentitySig(myPub, nonce, ephA, '04' + '9'.repeat(128), sig);
    ok('rejects when a bound ephemeral key is swapped (MITM)', okTamperEph === false);
  }

  // ── T4: identity public-key resolution ─────────────────────────────────
  console.log('T4 identity pubkey resolution');
  {
    const inst = new PC();
    const fakeNodeId = '0x' + '12'.repeat(32); // 64 hex = keccak hash, NOT a key
    ok('rejects a nodeId as a public key', inst._isRealPublicKey(inst._normalizePub(fakeNodeId)) === false);
    ok('accepts an uncompressed secp256k1 key', inst._isRealPublicKey('04' + 'a'.repeat(128)) === true);

    // identity.pub is the nodeId → must fall back to deriving from the private key.
    const resolved = await inst._resolveIdentityPublicKey({ nodeId: fakeNodeId, pub: fakeNodeId });
    ok('derives the real pubkey from the private key when identity has only a nodeId',
      inst._isRealPublicKey(resolved) && resolved === inst._normalizePub(walletPub));
  }

  console.log(`\n${pass} passed, ${fail} failed`);
  process.exit(fail ? 1 : 0);
}

main().catch((e) => { console.error(e); process.exit(1); });
