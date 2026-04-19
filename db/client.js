import pg from 'pg';

const pool = new pg.Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false },
  max: 20,
  idleTimeoutMillis: 30000,
  connectionTimeoutMillis: 5000,
});

pool.on('error', (err) => {
  console.error('[DB] Unexpected pool error:', err.message);
});

async function healthCheck() {
  try {
    const result = await pool.query('SELECT NOW() AS now');
    console.log(`[DB] Connected to Postgres — server time: ${result.rows[0].now}`);
    return true;
  } catch (err) {
    console.error('[DB] Health check FAILED:', err.message);
    return false;
  }
}

async function checkMigrationsRan() {
  try {
    await pool.query("SELECT 1 FROM information_schema.tables WHERE table_name = 'messages'");
    const result = await pool.query(
      "SELECT EXISTS (SELECT 1 FROM information_schema.tables WHERE table_name = 'messages') AS exists"
    );
    if (!result.rows[0].exists) {
      console.warn('[DB] WARNING: messages table does not exist. Run migrations/001_initial_schema.sql in Supabase SQL Editor.');
      return false;
    }
    console.log('[DB] Migration check passed — tables exist.');
    return true;
  } catch (err) {
    console.error('[DB] Migration check error:', err.message);
    return false;
  }
}

async function shutdown() {
  await pool.end();
  console.log('[DB] Pool closed.');
}

export { pool, healthCheck, checkMigrationsRan, shutdown };
