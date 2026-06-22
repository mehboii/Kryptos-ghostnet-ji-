/**
 * build-blake3-browser.mjs
 * ────────────────────────
 * Vendors @noble/hashes BLAKE3 into a single classic-script browser global,
 * `window.GhostBlake3`, so the no-bundler static site (`build: echo 'static site'`)
 * can call BLAKE3 in the browser identity flow.
 *
 * WHY: crypto-identity.js is a classic <script> (no bundler, no ESM). @noble ships
 * ESM with relative imports, which is exactly why BLAKE3 was dead in the browser.
 * This concatenates the audited @noble source files (no re-implementation) and
 * SELF-VALIDATES the output against the official BLAKE3 test vectors. It refuses to
 * emit a bundle that does not reproduce them.
 *
 * Run: node tools/build-blake3-browser.mjs
 * Output: blake3.browser.js  (vendored, regenerable)
 */
import { readFileSync, writeFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import vm from 'node:vm';

const __dirname = dirname(fileURLToPath(import.meta.url));
const ROOT = join(__dirname, '..');
const NOBLE = join(ROOT, 'node_modules', '@noble', 'hashes');

// Dependency order (topologically sorted by the import graph).
const FILES = ['utils.js', '_blake.js', '_u64.js', '_md.js', 'blake2.js', 'blake3.js'];

// _u64.js is consumed via `import * as u64`. After concatenation there is no module
// namespace, but _u64.js already declares `const u64 = { ... }` (its default export,
// same member set as the named exports), so `u64.add3L` etc. resolve from that object.
// We simply strip the `export default u64;` line and keep the file-local const.

// Strip ESM import/export syntax while preserving declarations.
function stripModuleSyntax(src) {
  return src
    .replace(/^\s*import\b[^\n]*$/gm, '')                  // drop all imports
    .replace(/^\s*export\s+default\b[^\n]*$/gm, '')        // drop `export default ...`
    .replace(/^\s*export\s*\{[^}]*\}\s*;?\s*$/gm, '')      // drop `export { ... };`
    .replace(/^\s*export\s+(?=(?:async\s+)?(?:function|const|let|var|class)\b)/gm, ''); // unwrap `export decl`
}

let body = '';
for (const f of FILES) {
  const raw = readFileSync(join(NOBLE, f), 'utf8');
  body += `\n// ───── @noble/hashes/${f} ─────\n` + stripModuleSyntax(raw) + '\n';
}

const banner = `/**
 * GhostNet vendored BLAKE3 (browser global) — GENERATED, DO NOT EDIT BY HAND.
 * Source: @noble/hashes BLAKE3. Regenerate: node tools/build-blake3-browser.mjs
 * Exposes: window.GhostBlake3 = { blake3, bytesToHex, hexToBytes, utf8ToBytes }
 */`;

const bundle = `${banner}
;(function (root) {
  'use strict';
${body}
  var __api = { blake3: blake3, bytesToHex: bytesToHex, hexToBytes: hexToBytes, utf8ToBytes: utf8ToBytes };
  if (typeof module === 'object' && module.exports) { module.exports = __api; }
  if (root) { root.GhostBlake3 = __api; }
})(typeof self !== 'undefined' ? self : (typeof globalThis !== 'undefined' ? globalThis : this));
`;

// ── SELF-VALIDATION: run the generated bundle and check official BLAKE3 vectors ──
const sandbox = { self: {}, module: undefined, crypto: globalThis.crypto, TextEncoder, TextDecoder };
vm.createContext(sandbox);
vm.runInContext(bundle, sandbox, { filename: 'blake3.browser.js' });
const api = sandbox.self.GhostBlake3;
if (!api || typeof api.blake3 !== 'function') {
  throw new Error('Validation failed: GhostBlake3.blake3 not exported by generated bundle.');
}
const VECTORS = {
  '':    'af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262',
  'abc': '6437b3ac38465133ffb63b75273a8db548c558465d79db03fd359c6cd5bd9d85',
};
for (const [input, expected] of Object.entries(VECTORS)) {
  const got = api.bytesToHex(api.blake3(new TextEncoder().encode(input)));
  if (got !== expected) {
    throw new Error(`Validation FAILED for "${input}": got ${got}, expected ${expected}. Bundle NOT written.`);
  }
}

writeFileSync(join(ROOT, 'blake3.browser.js'), bundle);
console.log('OK: blake3.browser.js written and validated against official BLAKE3 vectors.');
console.log('   empty =', api.bytesToHex(api.blake3(new Uint8Array(0))));
console.log('   abc   =', api.bytesToHex(api.blake3(new TextEncoder().encode('abc'))));
