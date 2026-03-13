import express from 'express';
import sqlite3 from 'sqlite3';
import { open } from 'sqlite';
import cors from 'cors';
import { requireAuth } from '../auth/auth.middleware.js';

const app = express();
const PORT = 8090;

// Middleware
app.use(express.json());
app.use(cors());

let db;

// Init DB
async function initDB() {
    db = await open({
        filename: './database.sqlite',
        driver: sqlite3.Database
    });

    // Create Tables
    await db.exec(`
        CREATE TABLE IF NOT EXISTS users (
            id TEXT PRIMARY KEY,
            created_at INTEGER
        );

        CREATE TABLE IF NOT EXISTS messages (
            id TEXT PRIMARY KEY,
            user_id TEXT,
            content TEXT,
            timestamp INTEGER
        );
    `);

    console.log("✅ SQLite Database Initialized");
}

initDB().catch(console.error);

// --- ENDPOINTS ---

// 1. Save Message (authenticated, userId from token)
app.post('/message', requireAuth, async (req, res) => {
    const { content } = req.body;
    const userId = req.userId;

    if (!userId) {
        return res.status(401).json({ error: "Authentication required" });
    }
    if (!content || typeof content !== 'string' || content.length > 4096) {
        return res.status(400).json({ error: "Invalid content" });
    }

    try {
        // Ensure user exists (Upsert)
        await db.run(
            `INSERT OR IGNORE INTO users (id, created_at) VALUES (?, ?)`,
            userId, Date.now()
        );

        const msgId = Date.now().toString(36) + Math.random().toString(36).substr(2);
        const timestamp = Date.now();

        await db.run(
            `INSERT INTO messages (id, user_id, content, timestamp) VALUES (?, ?, ?, ?)`,
            msgId, userId, JSON.stringify(content), timestamp
        );

        res.json({ success: true, id: msgId });
    } catch (e) {
        console.error(e);
        res.status(500).json({ error: "DB Error" });
    }
});

// 2. Get History (authenticated, scoped to caller)
app.get('/history', requireAuth, async (req, res) => {
    const userId = req.userId;
    if (!userId) {
        return res.status(401).json({ error: "Authentication required" });
    }
    try {
        const rows = await db.all(
            'SELECT * FROM messages WHERE user_id = ? ORDER BY timestamp ASC',
            userId
        );

        // Parse content JSON
        const history = rows.map(r => ({
            ...r,
            content: JSON.parse(r.content)
        }));

        res.json(history);
    } catch (e) {
        console.error(e);
        res.status(500).json({ error: "DB Error" });
    }
});

// 3. Get Users (authenticated, minimal fields only)
app.get('/users', requireAuth, async (req, res) => {
    try {
        const users = await db.all('SELECT id FROM users');
        res.json(users.map(u => ({ id: u.id, displayName: u.id })));
    } catch (e) {
        res.status(500).json({ error: "DB Error" });
    }
});

// 4. Cleanup
app.delete('/cleanup', async (req, res) => {
    const { ttl } = req.query; // Time to live in ms
    if (!ttl) return res.status(400).json({ error: "Missing ttl (ms)" });

    const cutoff = Date.now() - parseInt(ttl);

    try {
        const result = await db.run('DELETE FROM messages WHERE timestamp < ?', cutoff);
        res.json({ deleted: result.changes });
    } catch (e) {
        res.status(500).json({ error: "DB Error" });
    }
});

const BIND_HOST = process.env.NODE_ENV === 'production'
    ? '0.0.0.0'
    : '127.0.0.1';

app.listen(PORT, BIND_HOST, () => {
    console.log(`🗄️ Message Service running on ${BIND_HOST}:${PORT}`);
});
