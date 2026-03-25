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
import jwt from 'jsonwebtoken';
import { fileURLToPath } from 'url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));

const app = express();
const PORT = process.env.GHOSTNET_VAULT_PORT || 4001;
const CHAIN_URL = process.env.GHOSTNET_CHAIN_URL || 'http://127.0.0.1:4000';
const JWT_SECRET = process.env.AUTH_JWT_SECRET;

if (!JWT_SECRET) {
    console.error('FATAL: AUTH_JWT_SECRET not set in environment. Refusing to start.');
    process.exit(1);
}

// ─── Auth Middleware ────────────────────────────────────────
function requireAuth(req, res, next) {
    const authHeader = req.headers.authorization || '';
    const xAuthToken = req.headers['x-auth-token'] || req.headers['X-Auth-Token'] || '';
    const token = authHeader.startsWith('Bearer ') ? authHeader.slice(7) : (xAuthToken || null);
    if (!token) return res.status(401).json({ error: 'Authentication required' });
    try {
        const decoded = jwt.verify(token, JWT_SECRET);
        // Normalize JWT field: email-auth uses `userId`, node-auth uses `id`
        decoded.id = decoded.id || decoded.userId;
        if (!decoded.id) return res.status(401).json({ error: 'Invalid token: missing user identifier' });
        req.user = decoded;
        next();
    } catch (_) {
        res.status(401).json({ error: 'Invalid or expired token' });
    }
}

// ─── Owner Hashing (SHA-256) ────────────────────────────────
function hashOwner(owner) {
    return crypto.createHash('sha256').update(String(owner)).digest('hex');
}

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
    storage: multer.diskStorage({
        destination: (req, file, cb) => cb(null, VAULT_DIR),
        filename: (req, file, cb) => cb(null, `tmp_${Date.now()}_${crypto.randomBytes(16).toString('hex')}`)
    }),
    limits: { fileSize: 3 * 1024 * 1024 * 1024 } // 3GB max
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
app.post('/vault/upload', requireAuth, upload.single('file'), async (req, res) => {
    if (!req.file) return res.status(400).json({ error: 'No file uploaded' });

    const { fileName, iv, authTag, originalSize } = req.body;
    const owner = req.user.id;

    try {
        const fileId = crypto.randomUUID();
        const tmpPath = req.file.path;
        const fileSize = req.file.size;

        // Hash file using streams to support 3GB without crashing RAM
        const fileHash = await new Promise((resolve, reject) => {
            const hash = crypto.createHash('sha256');
            const stream = fs.createReadStream(tmpPath);
            stream.on('data', chunk => hash.update(chunk));
            stream.on('end', () => resolve(hash.digest('hex')));
            stream.on('error', reject);
        });

        // Store encrypted file to disk
        const filePath = path.join(VAULT_DIR, `${fileId}.enc`);
        fs.renameSync(tmpPath, filePath);

        // Build metadata record — store owner as SHA-256 hash
        const ownerHash = hashOwner(owner);
        const record = {
            fileId,
            fileName: fileName || req.file.originalname || 'encrypted_file',
            fileSize: fileSize,
            originalSize: parseInt(originalSize) || fileSize,
            fileHash,
            owner: ownerHash,
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
app.get('/vault/files/:owner', requireAuth, (req, res) => {
    // Verify authenticated user matches the requested owner
    const authenticatedId = req.user.id || req.user.sub;
    if (String(authenticatedId) !== String(req.params.owner)) {
        return res.status(403).json({ error: 'Access denied: you can only list your own files' });
    }
    const ownerHash = hashOwner(req.params.owner);
    const ownerFiles = fileMeta.filter(f => f.owner === ownerHash && !f.deleted);
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
app.get('/vault/download/:fileId', requireAuth, (req, res) => {
    const record = fileMeta.find(f => f.fileId === req.params.fileId && !f.deleted);
    if (!record) return res.status(404).json({ error: 'File not found' });

    // Verify authenticated user owns this file
    const ownerHash = hashOwner(req.user.id || req.user.sub);
    if (record.owner !== ownerHash) return res.status(403).json({ error: 'Access denied' });

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
app.delete('/vault/file/:fileId', requireAuth, async (req, res) => {
    // Use the authenticated user's identity, not the request body
    const authenticatedId = req.user.id || req.user.sub;
    const ownerHash = hashOwner(authenticatedId);

    const record = fileMeta.find(f => f.fileId === req.params.fileId);
    if (!record) return res.status(404).json({ error: 'File not found' });
    if (record.owner !== ownerHash) return res.status(403).json({ error: 'Unauthorized' });

    // Delete the encrypted file from disk
    const filePath = path.join(VAULT_DIR, `${record.fileId}.enc`);
    if (fs.existsSync(filePath)) fs.unlinkSync(filePath);

    // Mark as deleted in metadata
    record.deleted = true;
    record.deletedAt = Date.now();
    saveMeta();

    // Anchor deletion on chain
    await chainAPI('DELETE', `/chain/file/${record.fileId}`, { owner: ownerHash });

    console.log(`🗑️  Vault: File deleted — ${record.fileName} (${record.fileId})`);
    res.json({ success: true, deleted: record.fileId });
});

// ─── API: Verify File Against Blockchain ────────────────────
app.get('/vault/verify/:fileId', requireAuth, async (req, res) => {
    const record = fileMeta.find(f => f.fileId === req.params.fileId && !f.deleted);
    if (!record) return res.status(404).json({ error: 'File not found' });

    // Verify authenticated user owns this file
    const ownerHash = hashOwner(req.user.id || req.user.sub);
    if (record.owner !== ownerHash) return res.status(403).json({ error: 'Access denied' });

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
app.listen(PORT, process.env.VAULT_HOST || '127.0.0.1', () => {
    console.log(`\n🔒 GhostNet Vault Service running on port ${PORT}`);
    console.log(`   Chain API:  ${CHAIN_URL}`);
    console.log(`   Vault Dir:  ${VAULT_DIR}`);
    console.log(`   Health:     http://localhost:${PORT}/health`);
});
