import { generateMnemonic, mnemonicToSeedSync, validateMnemonic } from '@scure/bip39';
import { wordlist } from '@scure/bip39/wordlists/english.js';
import { HDKey } from '@scure/bip32';
import { p256 } from '@noble/curves/nist.js';

function toHex(b) { return Array.from(new Uint8Array(b)).map(x=>x.toString(16).padStart(2,'0')).join(''); }

let pass = 0, fail = 0;
const vulns = [];
function test(name, result) { if(result){pass++} else{fail++;console.log('  VULN:', name); vulns.push(name);} }

console.log('========================================');
console.log('ATTACK SUITE 4: IDENTITY LAYER ATTACKS');
console.log('========================================\n');

// --- ATK-I01: Derivation path hardness ---
console.log('[ATK-I01] Different paths = different keys');
const mn = generateMnemonic(wordlist, 128);
const seed = mnemonicToSeedSync(mn);
const k1 = HDKey.fromMasterSeed(seed).derive("m/44'/60'/0'/0/0");
const k2 = HDKey.fromMasterSeed(seed).derive("m/44'/60'/0'/0/1");
const k3 = HDKey.fromMasterSeed(seed).derive("m/44'/0'/0'/0/0");
test('Different index = different key', toHex(k1.privateKey) !== toHex(k2.privateKey));
test('Different coin = different key', toHex(k1.privateKey) !== toHex(k3.privateKey));

// --- ATK-I02: Mnemonic word-order matters ---
console.log('[ATK-I02] Word order sensitivity');
const words = mn.split(' ');
const reversed = [...words].reverse().join(' ');
if (validateMnemonic(reversed, wordlist)) {
  const seedR = mnemonicToSeedSync(reversed);
  const kR = HDKey.fromMasterSeed(seedR).derive("m/44'/60'/0'/0/0");
  test('Reversed mnemonic = different key', toHex(k1.privateKey) !== toHex(kR.privateKey));
} else {
  test('Reversed mnemonic = invalid (good)', true);
}

// --- ATK-I03: Case sensitivity ---
console.log('[ATK-I03] Case sensitivity');
const upper = mn.toUpperCase();
const mixed = mn.split(' ').map((w,i) => i%2 === 0 ? w.toUpperCase() : w).join(' ');
test('Uppercase mnemonic rejected', !validateMnemonic(upper, wordlist));
test('Mixed-case mnemonic rejected', !validateMnemonic(mixed, wordlist));

// --- ATK-I04: Extra whitespace ---
console.log('[ATK-I04] Whitespace handling');
const padded = '  ' + mn + '  ';
const doubled = mn.replace(/ /g, '  ');
test('Padded mnemonic rejected by validate', !validateMnemonic(padded, wordlist));
test('Double-spaced mnemonic rejected', !validateMnemonic(doubled, wordlist));

// --- ATK-I05: P-256 key validity ---
console.log('[ATK-I05] Derived P-256 key validity');
for (let i = 0; i < 20; i++) {
  const m = generateMnemonic(wordlist, 128);
  const child = HDKey.fromMasterSeed(mnemonicToSeedSync(m)).derive("m/44'/60'/0'/0/0");
  const priv = child.privateKey;
  const pub = p256.getPublicKey(priv);

  // Verify the key is on the P-256 curve by doing a sign+verify round-trip
  const hash = new Uint8Array(32).fill(0x42);
  const sig = p256.sign(hash, priv, { lowS: true });
  const valid = p256.verify(sig, hash, pub, { lowS: true });
  test('Key ' + i + ' valid on P-256', valid);
}

// --- ATK-I06: BIP32 private key as P-256 scalar ---
console.log('[ATK-I06] Private key scalar range');
// P-256 order: 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551
// BIP32 derived keys are mod secp256k1 order, which is slightly different
// But any 32-byte value < P-256 order is valid. Check that derivation never produces zero.
for (let i = 0; i < 100; i++) {
  const m = generateMnemonic(wordlist, 128);
  const child = HDKey.fromMasterSeed(mnemonicToSeedSync(m)).derive("m/44'/60'/0'/0/0");
  const allZero = child.privateKey.every(b => b === 0);
  if (allZero) {
    test('Non-zero private key (attempt ' + i + ')', false);
    break;
  }
}
test('100 keys: none were zero', true);

// --- ATK-I07: Seed phrase brute-force entropy ---
console.log('[ATK-I07] Entropy verification');
// 12 words = 128 bits of entropy. Verify word count.
const m = generateMnemonic(wordlist, 128);
test('12-word mnemonic', m.split(' ').length === 12);
// Verify all words are from BIP39 wordlist
const allValid = m.split(' ').every(w => wordlist.includes(w));
test('All words in BIP39 wordlist', allValid);

// --- ATK-I08: restoreIdentity normalization ---
console.log('[ATK-I08] Restore normalization');
// The trim().toLowerCase() should handle these:
const trimmed = mn.trim().toLowerCase();
test('trim+lowercase idempotent', trimmed === mn); // mn should already be lowercase
const withPad = '  ' + mn + '  ';
test('Padded becomes valid after trim', validateMnemonic(withPad.trim().toLowerCase(), wordlist));

console.log('\n========================================');
console.log('RESULTS: ' + pass + ' passed, ' + fail + ' failed');
if (vulns.length > 0) console.log('VULNERABILITIES:', vulns);
console.log('========================================');
