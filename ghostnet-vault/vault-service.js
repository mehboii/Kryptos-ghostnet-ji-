/**
 * GhostNet Vault Service — Encrypted File Storage Backend
 * =========================================================
 * Files arrive ALREADY encrypted (E2E from the browser).
 * This service:
 *   1. Stores the encrypted blob to disk
 *   2. Calls the Chain Service to anchor the file hash on-chain
 *   3. Tracks metadata in a local JSON store
 *   4. Serves files back (still encrypted — only the user can decrypt)
 *   5. Handles deletion on explicit user command
 * 
 * Endpoints:
 *   POST   /vault/upload            — upload an encrypted file
 *   GET    /vault/files/:owner      — list files for user
 *   GET    /vault/download/:fileId  — download encrypted file
 *   DELETE /vault/file/:fileId      — delete file (user command only)
 *   GET    /vault/verify/:fileId    — verify file against blockchain
 *   GET    /health                  — service health
 * 
 * Port: 4001 (configurable via GHOSTNET_VAULT_PORT)
 */

import 'dotenv/config';
import express from 'express';
import cors from 'cors';
import multer from 'multer';
import fs from 'fs';
import path from 'path';
import crypto from 'crypto';
import { fileURLToPath } from 'url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));

const app = express();
const PORT = process.env.GHOSTNET_VAULT_PORT || 4001;
const CHAIN_URL = process.env.GHOSTNET_CHAIN_URL || 'http://127.0.0.1:4000';

// ─── Storage Directories ────────────────────────────────────
const VAULT_DIR = path.join(__dirname, 'vault-data');
const META_FILE = path.join(__dirname, 'vault-meta.json');

if (!fs.existsSync(VAULT_DIR)) fs.mkdirSync(VAULT_DIR, { recursive: true });

// ─── Metadata Store ─────────────────────────────────────────
let fileMeta = [];
try {
    if (fs.existsSync(META_FILE)) {
        fileMeta = JSON.parse(fs.readFileSync(META_FILE, 'utf-8'));
    }
} catch { fileMeta = []; }

function saveMeta() {
    fs.writeFileSync(META_FILE, JSON.stringify(fileMeta, null, 2));
}

// ─── Multer Config ──────────────────────────────────────────
const upload = multer({
    storage: multer.memoryStorage(),
    limits: { fileSize: 100 * 1024 * 1024 } // 100MB max
});

app.use(cors());
app.use(express.json());

// ─── Helper: Call Chain Service ─────────────────────────────
async function chainAPI(method, endpoint, body = null) {
    const opts = {
        method,
        headers: { 'Content-Type': 'application/json' }
    };
    if (body) opts.body = JSON.stringify(body);

    try {
        const res = await fetch(`${CHAIN_URL}${endpoint}`, opts);
        return await res.json();
    } catch (err) {
        console.warn(`⚠️  Chain service unreachable: ${err.message}`);
        return { error: 'Chain service unavailable', fallback: true };
    }
}

// ─── API: Upload Encrypted File ─────────────────────────────
app.post('/vault/upload', upload.single('file'), async (req, res) => {
    if (!req.file) return res.status(400).json({ error: 'No file uploaded' });

    const { owner, fileName, iv, authTag, originalSize } = req.body;
    if (!owner) return res.status(400).json({ error: 'owner is required' });

    try {
        const fileId = crypto.randomUUID();
        const encryptedBuffer = req.file.buffer;

        // SHA-256 hash of the encrypted content (for blockchain integrity verification)
        const fileHash = crypto.createHash('sha256').update(encryptedBuffer).digest('hex');

        // Store encrypted file to disk
        const filePath = path.join(VAULT_DIR, `${fileId}.enc`);
        fs.writeFileSync(filePath, encryptedBuffer);

        // Build metadata record
        const record = {
            fileId,
            fileName: fileName || req.file.originalname || 'encrypted_file',
            fileSize: encryptedBuffer.length,
            originalSize: parseInt(originalSize) || encryptedBuffer.length,
            fileHash,
            owner,
            iv: iv || null,
            authTag: authTag || null,
            uploadedAt: Date.now(),
            chainAnchored: false,
            txHash: null,
            deleted: false
        };

        // Anchor hash on blockchain via Chain Service
        const chainResult = await chainAPI('POST', '/chain/anchor', {
            fileId,
            fileHash,
            metadata: {
                owner,
                fileName: record.fileName,
                fileSize: record.fileSize
            }
        });

        if (chainResult.record) {
            record.chainAnchored = true;
            record.txHash = chainResult.record.txHash;
            record.blockNumber = chainResult.record.blockNumber;
        }

        fileMeta.push(record);
        saveMeta();

        console.log(`📦 Vault: File stored — ${record.fileName} (${formatBytes(record.fileSize)}) → ${fileId}`);

        res.json({
            success: true,
            file: {
                fileId: record.fileId,
                fileName: record.fileName,
                fileSize: record.fileSize,
                originalSize: record.originalSize,
                fileHash: record.fileHash,
                chainAnchored: record.chainAnchored,
                txHash: record.txHash,
                uploadedAt: record.uploadedAt
            }
        });

    } catch (err) {
        console.error('Upload error:', err);
        res.status(500).json({ error: 'Upload failed: ' + err.message });
    }
});

// ─── API: List Files for Owner ──────────────────────────────
app.get('/vault/files/:owner', (req, res) => {
    const ownerFiles = fileMeta.filter(f => f.owner === req.params.owner && !f.deleted);
    res.json({
        files: ownerFiles.map(f => ({
            fileId: f.fileId,
            fileName: f.fileName,
            fileSize: f.fileSize,
            originalSize: f.originalSize,
            fileHash: f.fileHash,
            chainAnchored: f.chainAnchored,
            txHash: f.txHash,
            uploadedAt: f.uploadedAt
        }))
    });
});

// ─── API: Download Encrypted File ───────────────────────────
app.get('/vault/download/:fileId', (req, res) => {
    const record = fileMeta.find(f => f.fileId === req.params.fileId && !f.deleted);
    if (!record) return res.status(404).json({ error: 'File not found' });

    const filePath = path.join(VAULT_DIR, `${record.fileId}.enc`);
    if (!fs.existsSync(filePath)) return res.status(404).json({ error: 'File data missing' });

    // Return the encrypted file with metadata in headers
    res.setHeader('X-File-Id', record.fileId);
    res.setHeader('X-File-Name', encodeURIComponent(record.fileName));
    res.setHeader('X-File-Hash', record.fileHash);
    res.setHeader('X-IV', record.iv || '');
    res.setHeader('X-Auth-Tag', record.authTag || '');
    res.setHeader('X-Original-Size', record.originalSize);
    res.setHeader('Content-Type', 'application/octet-stream');
    res.setHeader('Content-Disposition', `attachment; filename="${record.fileId}.enc"`);

    const stream = fs.createReadStream(filePath);
    stream.pipe(res);
});

// ─── API: Delete File (User Command Only) ───────────────────
app.delete('/vault/file/:fileId', async (req, res) => {
    const { owner } = req.body;
    if (!owner) return res.status(400).json({ error: 'owner is required' });

    const record = fileMeta.find(f => f.fileId === req.params.fileId);
    if (!record) return res.status(404).json({ error: 'File not found' });
    if (record.owner !== owner) return res.status(403).json({ error: 'Unauthorized' });

    // Delete the encrypted file from disk
    const filePath = path.join(VAULT_DIR, `${record.fileId}.enc`);
    if (fs.existsSync(filePath)) fs.unlinkSync(filePath);

    // Mark as deleted in metadata
    record.deleted = true;
    record.deletedAt = Date.now();
    saveMeta();

    // Anchor deletion on chain
    await chainAPI('DELETE', `/chain/file/${record.fileId}`, { owner });

    console.log(`🗑️  Vault: File deleted — ${record.fileName} (${record.fileId})`);
    res.json({ success: true, deleted: record.fileId });
});

// ─── API: Verify File Against Blockchain ────────────────────
app.get('/vault/verify/:fileId', async (req, res) => {
    const record = fileMeta.find(f => f.fileId === req.params.fileId && !f.deleted);
    if (!record) return res.status(404).json({ error: 'File not found' });

    // Verify hash on disk matches what we stored
    const filePath = path.join(VAULT_DIR, `${record.fileId}.enc`);
    let diskHash = null;
    if (fs.existsSync(filePath)) {
        const buf = fs.readFileSync(filePath);
        diskHash = crypto.createHash('sha256').update(buf).digest('hex');
    }

    const integrity = diskHash === record.fileHash;

    // Check blockchain
    const chainData = await chainAPI('GET', `/chain/verify/${record.fileId}`);

    res.json({
        fileId: record.fileId,
        fileName: record.fileName,
        diskIntegrity: integrity,
        storedHash: record.fileHash,
        diskHash,
        chainVerified: chainData.verified || false,
        chainRecord: chainData.record || null,
        txHash: record.txHash
    });
});

// ─── Health ─────────────────────────────────────────────────
app.get('/health', (req, res) => {
    const totalFiles = fileMeta.filter(f => !f.deleted).length;
    const totalSize = fileMeta.filter(f => !f.deleted).reduce((s, f) => s + f.fileSize, 0);
    res.json({
        status: 'ok',
        service: 'ghostnet-vault',
        files: totalFiles,
        totalSize: formatBytes(totalSize),
        uptime: process.uptime()
    });
});

function formatBytes(bytes) {
    if (bytes === 0) return '0 B';
    const k = 1024;
    const sizes = ['B', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(1)) + ' ' + sizes[i];
}

// ─── Start ──────────────────────────────────────────────────
app.listen(PORT, '0.0.0.0', () => {
    console.log(`\n🔒 GhostNet Vault Service running on port ${PORT}`);
    console.log(`   Chain API:  ${CHAIN_URL}`);
    console.log(`   Vault Dir:  ${VAULT_DIR}`);
    console.log(`   Health:     http://localhost:${PORT}/health`);
});
