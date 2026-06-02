// GhostNet migration runner.
// Applies every migrations/*.sql file in filename order against DATABASE_URL.
// Usage: node db/migrate.js   (loads .env via dotenv)
import 'dotenv/config';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { pool, healthCheck, shutdown } from './client.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const migrationsDir = path.join(__dirname, '..', 'migrations');

async function run() {
  if (!process.env.DATABASE_URL) {
    console.error('[Migrate] DATABASE_URL is not set. Add it to .env first.');
    process.exit(1);
  }

  const ok = await healthCheck();
  if (!ok) {
    console.error('[Migrate] Cannot reach the database — aborting.');
    process.exit(1);
  }

  const files = fs.readdirSync(migrationsDir)
    .filter(f => f.endsWith('.sql'))
    .sort();

  for (const file of files) {
    const sql = fs.readFileSync(path.join(migrationsDir, file), 'utf8');
    process.stdout.write(`[Migrate] Applying ${file} ... `);
    await pool.query(sql);
    console.log('done');
  }

  console.log(`[Migrate] Applied ${files.length} migration(s).`);
  await shutdown();
}

run().catch(async (err) => {
  console.error('[Migrate] FAILED:', err.message);
  await shutdown().catch(() => {});
  process.exit(1);
});
