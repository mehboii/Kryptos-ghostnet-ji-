/**
 * Build the canonical Ghost Shield web bundle.
 *
 * Compiles the REAL Shield (src/shield, via src/shield/web/entry.ts) into a single
 * browser IIFE and writes it to `antigravity/ghost-shield.js` — the file the site
 * loads. This replaces the old hand-written mock engine; there is no separate
 * source of truth for the served Shield anymore.
 *
 * The output is intentionally UNMINIFIED so the served Shield stays auditable
 * (the whole point is capability honesty you can read in DevTools).
 *
 * Run:  npm run build:shield-web   (from ghostnet-expo/)
 */
const esbuild = require('esbuild');
const path = require('path');
const fs = require('fs');

const expoRoot = path.resolve(__dirname, '..');
const antigravityRoot = path.resolve(expoRoot, '..');
const entry = path.join(expoRoot, 'src', 'shield', 'web', 'entry.ts');

// Primary served file + mirrored build-artifact copies (only those that exist).
const outputs = [
  path.join(antigravityRoot, 'ghost-shield.js'),
  path.join(antigravityRoot, 'dist', 'ghost-shield.js'),
  path.join(antigravityRoot, 'ghostnet-dist', 'ghost-shield.js'),
];

const banner = `/* Ghost Shield — GENERATED from ghostnet-expo/src/shield (real ShieldManager).
 * DO NOT EDIT BY HAND. Rebuild: cd ghostnet-expo && npm run build:shield-web
 * Capability-honest: web reports BLE/hardware unavailable; the phone (Capacitor)
 * runs hardware features for real. No MAC rotation, no WiFi-probe suppression. */`;

async function main() {
  const result = await esbuild.build({
    entryPoints: [entry],
    bundle: true,
    format: 'iife',
    platform: 'browser',
    target: 'es2020',
    minify: false,
    sourcemap: false,
    legalComments: 'none',
    banner: { js: banner },
    write: false,
  });

  const [file] = result.outputFiles;
  let written = 0;
  for (const out of outputs) {
    const dir = path.dirname(out);
    if (out === outputs[0] || fs.existsSync(dir)) {
      fs.mkdirSync(dir, { recursive: true });
      fs.writeFileSync(out, file.contents);
      console.log(`  wrote ${path.relative(antigravityRoot, out)} (${file.contents.length} bytes)`);
      written++;
    }
  }
  console.log(`Ghost Shield bundle built → ${written} file(s).`);
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
