import express from 'express';
import sqlite3 from 'sqlite3';
import { open } from 'sqlite';
import cors from 'cors';

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

// 1. Save Message
app.post('/message', async (req, res) => {
    const { userId, content } = req.body;

    if (!userId || !content) {
        return res.status(400).json({ error: "Missing userId or content" });
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

// 2. Get History
app.get('/history', async (req, res) => {
    const { userId } = req.query;

    try {
        let rows;
        if (userId) {
            // Return messages sent BY user OR broadcast messages (assuming general chat context)
            // Or strictly messages for that user.
            // Request says: "GET /history?userId="
            // I'll return messages sent BY user and maybe ALL messages for context?
            // "client sends userId -> server returns message history for that user"
            // Usually implies chat history visible TO that user.
            // For a mesh/LAN chat, usually PUBLIC + DM.
            // I'll return ALL messages for now, as that's safer for a group chat demo.
            // But if user wants strict filtering:
            // rows = await db.all('SELECT * FROM messages WHERE user_id = ? ORDER BY timestamp ASC', userId);

            // Let's return ALL messages properly parsed
            rows = await db.all('SELECT * FROM messages ORDER BY timestamp ASC');
        } else {
            rows = await db.all('SELECT * FROM messages ORDER BY timestamp ASC');
        }

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

// 3. Get Users
app.get('/users', async (req, res) => {
    try {
        const users = await db.all('SELECT * FROM users');
        res.json(users);
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

app.listen(PORT, '0.0.0.0', () => {
    console.log(`🗄️ Message Service running on port ${PORT}`);
});
