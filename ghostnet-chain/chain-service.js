/**
 * GhostNet Chain Service — Blockchain Abstraction HTTP API
 * =========================================================
 * This is THE ONLY service that talks to the blockchain.
 * All other services (vault, server, bridge) call this API.
 * 
 * Endpoints:
 *   POST   /chain/anchor           — anchor a file hash on-chain
 *   GET    /chain/verify/:fileId    — verify a file hash
 *   GET    /chain/files/:owner      — list files by owner
 *   DELETE /chain/file/:fileId      — delete a file record
 *   GET    /chain/info              — chain status & health
 *   GET    /health                  — service health check
 * 
 * Port: 4000 (configurable via GHOSTNET_CHAIN_PORT)
 */

import 'dotenv/config';
import express from 'express';
import cors from 'cors';
import { getProvider } from './providers/index.js';

const app = express();
const PORT = process.env.GHOSTNET_CHAIN_PORT || 4000;

app.use(cors());
app.use(express.json());

// ─── Initialize Chain Provider ─────────────────────────────
const chain = getProvider();

(async () => {
    await chain.connect();
    console.log(`⛓️  Chain provider "${chain.name}" initialized`);
})();

// ─── API: Anchor File Hash ─────────────────────────────────
app.post('/chain/anchor', async (req, res) => {
    const { fileId, fileHash, metadata } = req.body;

    if (!fileId || !fileHash) {
        return res.status(400).json({ error: 'fileId and fileHash are required' });
    }

    try {
        const result = await chain.anchorFileHash(fileId, fileHash, metadata || {});
        res.json({ success: true, record: result });
    } catch (err) {
        console.error('Anchor error:', err);
        res.status(500).json({ error: err.message });
    }
});

// ─── API: Verify File Hash ─────────────────────────────────
app.get('/chain/verify/:fileId', async (req, res) => {
    try {
        const record = await chain.verifyFileHash(req.params.fileId);
        if (!record) return res.status(404).json({ error: 'File not found on chain' });
        res.json({ verified: true, record });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// ─── API: List Files by Owner ──────────────────────────────
app.get('/chain/files/:owner', async (req, res) => {
    try {
        const files = await chain.getFilesByOwner(req.params.owner);
        res.json({ files });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// ─── API: Delete File Record ───────────────────────────────
app.delete('/chain/file/:fileId', async (req, res) => {
    const { owner } = req.body;
    if (!owner) return res.status(400).json({ error: 'owner is required' });

    try {
        const result = await chain.deleteFileRecord(req.params.fileId, owner);
        res.json({ success: true, ...result });
    } catch (err) {
        res.status(err.message.includes('not found') ? 404 : 403).json({ error: err.message });
    }
});

// ─── API: Chain Info ───────────────────────────────────────
app.get('/chain/info', async (req, res) => {
    try {
        const info = await chain.getChainInfo();
        res.json({ provider: chain.name, connected: chain.isConnected(), ...info });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// ─── Health ────────────────────────────────────────────────
app.get('/health', (req, res) => {
    res.json({
        status: 'ok',
        service: 'ghostnet-chain',
        provider: chain.name,
        connected: chain.isConnected(),
        uptime: process.uptime()
    });
});

// ─── Start ─────────────────────────────────────────────────
app.listen(PORT, '0.0.0.0', () => {
    console.log(`\n⛓️  GhostNet Chain Service running on port ${PORT}`);
    console.log(`   Provider: ${chain.name}`);
    console.log(`   Health:   http://localhost:${PORT}/health`);
});
