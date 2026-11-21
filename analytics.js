/**
 * Kryptos Privacy-Respecting Analytics
 *
 * - No personal data, no IPs, no tracking cookies
 * - Anonymous daily-rotating hashed IDs
 * - All data stays on-server (self-hosted SQLite)
 * - Auto-purge after 90 days
 */

import { createHash, randomBytes } from 'crypto';
import sqlite3Pkg from 'sqlite3';
import { open } from 'sqlite';
import { resolve, dirname } from 'path';
import { fileURLToPath } from 'url';

const __dirname = dirname(fileURLToPath(import.meta.url));
const DB_PATH = resolve(__dirname, 'analytics.db');
const RETENTION_DAYS = 90;

let db = null;

async function getDb() {
  if (db) return db;
  db = await open({
    filename: DB_PATH,
    driver: sqlite3Pkg.Database
  });
  await db.exec('PRAGMA journal_mode = WAL');
  await db.exec('PRAGMA busy_timeout = 5000');
  await db.exec(`
    CREATE TABLE IF NOT EXISTS daily_active (
      date TEXT NOT NULL,
      anon_id TEXT NOT NULL,
      PRIMARY KEY (date, anon_id)
    );

    CREATE TABLE IF NOT EXISTS events (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      date TEXT NOT NULL,
      category TEXT NOT NULL,
      action TEXT NOT NULL,
      count INTEGER DEFAULT 1,
      ts INTEGER NOT NULL
    );

    CREATE TABLE IF NOT EXISTS feature_usage (
      date TEXT NOT NULL,
      feature TEXT NOT NULL,
      hits INTEGER DEFAULT 0,
      PRIMARY KEY (date, feature)
    );

    CREATE INDEX IF NOT EXISTS idx_events_date ON events(date);
    CREATE INDEX IF NOT EXISTS idx_events_category ON events(category);
  `);
  return db;
}

function todayStr() {
  return new Date().toISOString().slice(0, 10);
}

function anonHash(sessionId) {
  const daily = todayStr();
  return createHash('sha256')
    .update(`${daily}:${sessionId}:kryptos`)
    .digest('hex')
    .slice(0, 16);
}

// --- Public API ---

async function trackActiveUser(sessionId) {
  const d = await getDb();
  const date = todayStr();
  const anon = anonHash(sessionId);
  await d.run(
    'INSERT OR IGNORE INTO daily_active (date, anon_id) VALUES (?, ?)',
    [date, anon]
  );
}

async function trackEvent(category, action, count = 1) {
  const d = await getDb();
  const date = todayStr();
  await d.run(
    'INSERT INTO events (date, category, action, count, ts) VALUES (?, ?, ?, ?, ?)',
    [date, category, action, count, Date.now()]
  );
}

async function trackFeature(feature) {
  const d = await getDb();
  const date = todayStr();
  await d.run(
    `INSERT INTO feature_usage (date, feature, hits) VALUES (?, ?, 1)
     ON CONFLICT(date, feature) DO UPDATE SET hits = hits + 1`,
    [date, feature]
  );
}

async function getDashboard(days = 30) {
  const d = await getDb();
  const since = new Date(Date.now() - days * 86400000).toISOString().slice(0, 10);

  const [dau, totalMessages, shieldActivations, features, dailyTrend] = await Promise.all([
    d.all(
      `SELECT date, COUNT(DISTINCT anon_id) as users
       FROM daily_active WHERE date >= ? GROUP BY date ORDER BY date`,
      [since]
    ),
    d.get(
      `SELECT COALESCE(SUM(count), 0) as total
       FROM events WHERE category = 'message' AND action = 'sent' AND date >= ?`,
      [since]
    ),
    d.get(
      `SELECT COALESCE(SUM(count), 0) as total
       FROM events WHERE category = 'shield' AND action = 'activated' AND date >= ?`,
      [since]
    ),
    d.all(
      `SELECT feature, SUM(hits) as total
       FROM feature_usage WHERE date >= ? GROUP BY feature ORDER BY total DESC`,
      [since]
    ),
    d.all(
      `SELECT date,
         (SELECT COUNT(DISTINCT anon_id) FROM daily_active da WHERE da.date = e.date) as dau,
         COALESCE(SUM(CASE WHEN category='message' AND action='sent' THEN count END), 0) as messages,
         COALESCE(SUM(CASE WHEN category='shield' AND action='activated' THEN count END), 0) as shield
       FROM events e WHERE e.date >= ? GROUP BY e.date ORDER BY e.date`,
      [since]
    )
  ]);

  return {
    period: { from: since, to: todayStr(), days },
    summary: {
      dauToday: dau.find(r => r.date === todayStr())?.users || 0,
      dauAvg: dau.length ? Math.round(dau.reduce((s, r) => s + r.users, 0) / dau.length) : 0,
      totalMessages: totalMessages.total,
      shieldActivations: shieldActivations.total,
      topFeatures: features.slice(0, 10)
    },
    daily: dailyTrend,
    dau
  };
}

async function purgeOldData() {
  const d = await getDb();
  const cutoff = new Date(Date.now() - RETENTION_DAYS * 86400000).toISOString().slice(0, 10);
  await Promise.all([
    d.run('DELETE FROM daily_active WHERE date < ?', [cutoff]),
    d.run('DELETE FROM events WHERE date < ?', [cutoff]),
    d.run('DELETE FROM feature_usage WHERE date < ?', [cutoff])
  ]);
}

let purgeInterval = null;

async function init() {
  await getDb();
  await purgeOldData();
  purgeInterval = setInterval(purgeOldData, 24 * 60 * 60 * 1000);
}

function shutdown() {
  if (purgeInterval) clearInterval(purgeInterval);
  if (db) db.close();
  db = null;
}

export {
  init,
  shutdown,
  trackActiveUser,
  trackEvent,
  trackFeature,
  getDashboard,
  purgeOldData
};
