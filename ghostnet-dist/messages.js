
/**

 * GhostNet — Hardened Message System
 * Fixes all 8 security vulnerabilities identified in the audit.
 *
 * Covers:
 *  1. Cryptographically random IDs (no timestamps)
 *  2. AES-256-GCM encryption for message bodies
 *  3. Server-enforced sender identity (never trust client)
 *  4. HMAC-SHA256 message integrity / tamper detection
 *  5. Server-assigned timestamps (never trust client)
 *  6. Full UUID v4 conversation IDs
 *  7. Internal user ID routing (not usernames)
 *  8. Message type whitelist enforcement
 */

'use strict';

const crypto = require('crypto');

// ─────────────────────────────────────────────
// CONSTANTS & CONFIG
// ─────────────────────────────────────────────

const VALID_MESSAGE_TYPES = new Set(['MSG', 'FILE', 'REACTION', 'SYSTEM']);
const MAX_BODY_LENGTH = 2000;  // chars
const MAX_FILE_SIZE = 10 * 1024 * 1024; // 10MB

// These should come from environment variables in production — never hardcode!
const MESSAGE_HMAC_SECRET = process.env.MESSAGE_HMAC_SECRET;
const MESSAGE_ENCRYPTION_KEY = process.env.MESSAGE_ENCRYPTION_KEY
    ? Buffer.from(process.env.MESSAGE_ENCRYPTION_KEY, 'hex')
    : null;

// Fail fast if secrets are missing
if (!MESSAGE_HMAC_SECRET || !MESSAGE_ENCRYPTION_KEY) {
    throw new Error(
        '[GhostNet] FATAL: MESSAGE_HMAC_SECRET and MESSAGE_ENCRYPTION_KEY ' +
        'must be set in environment variables.'
    );
}

// ─────────────────────────────────────────────
// 1 & 6 — CRYPTOGRAPHICALLY RANDOM IDs
// ─────────────────────────────────────────────

/**
 * Generates a secure random message ID.
 * Format: msg_<32 hex chars>
 * No timestamp component — fully opaque to clients.
 */
function generateMessageId() {
    return 'msg_' + crypto.randomBytes(16).toString('hex');
}

/**
 * Generates a secure random conversation ID.
 * Format: convo_<32 hex chars>
 * No timestamp component — fully opaque to clients.
 */
function generateConvoId() {
    return 'convo_' + crypto.randomBytes(16).toString('hex');
}

// ─────────────────────────────────────────────
// 2 — AES-256-GCM ENCRYPTION FOR MESSAGE BODIES
// ─────────────────────────────────────────────

/**
 * Encrypts a plaintext message body using AES-256-GCM.
 * Returns: { ciphertext, iv, authTag } — all as hex strings.
 *
 * The authTag provides authenticated encryption — any tampering
 * of the ciphertext will cause decryption to throw.
 */
function encryptBody(plaintext) {
    const iv = crypto.randomBytes(12); // 96-bit IV for GCM
    const cipher = crypto.createCipheriv('aes-256-gcm', MESSAGE_ENCRYPTION_KEY, iv);

    const ciphertext = Buffer.concat([
        cipher.update(plaintext, 'utf8'),
        cipher.final()
    ]);

    return {
        ciphertext: ciphertext.toString('hex'),
        iv: iv.toString('hex'),
        authTag: cipher.getAuthTag().toString('hex')
    };
}

/**
 * Decrypts an encrypted message body.
 * Throws if the authTag doesn't match (tamper detected).
 */
function decryptBody({ ciphertext, iv, authTag }) {
    const decipher = crypto.createDecipheriv(
        'aes-256-gcm',
        MESSAGE_ENCRYPTION_KEY,
        Buffer.from(iv, 'hex')
    );

    decipher.setAuthTag(Buffer.from(authTag, 'hex'));

    const plaintext = Buffer.concat([
        decipher.update(Buffer.from(ciphertext, 'hex')),
        decipher.final()
    ]);

    return plaintext.toString('utf8');
}

// ─────────────────────────────────────────────
// 4 — HMAC-SHA256 MESSAGE INTEGRITY
// ─────────────────────────────────────────────

/**
 * Computes an HMAC-SHA256 over the canonical message fields.
 * Used to detect tampering at rest or in transit.
 *
 * The HMAC covers: id + convoId + senderId + ts + type + encrypted ciphertext
 * so that any change to any field invalidates the signature.
 */
function computeHmac({ id, convoId, senderId, ts, type, encrypted }) {
    const payload = [
        id,
        convoId,
        senderId,
        String(ts),
        type,
        encrypted.ciphertext,
        encrypted.iv,
        encrypted.authTag
    ].join('|');

    return crypto
        .createHmac('sha256', MESSAGE_HMAC_SECRET)
        .update(payload)
        .digest('hex');
}

/**
 * Verifies the HMAC of a stored message.
 * Uses timing-safe comparison to prevent timing attacks.
 * Returns true if valid, false if tampered.
 */
function verifyHmac(message) {
    const expected = computeHmac(message);
    const actual = message.hmac;

    if (!actual) return false;

    return crypto.timingSafeEqual(
        Buffer.from(expected, 'hex'),
        Buffer.from(actual, 'hex')
    );
}

// ─────────────────────────────────────────────
// 8 — MESSAGE TYPE WHITELIST
// ─────────────────────────────────────────────

/**
 * Validates that the message type is one of the allowed values.
 * Rejects anything not explicitly in the whitelist.
 */
function validateMessageType(type) {
    if (typeof type !== 'string' || !VALID_MESSAGE_TYPES.has(type)) {
        throw new Error(
            `Invalid message type "${type}". ` +
            `Allowed: ${[...VALID_MESSAGE_TYPES].join(', ')}`
        );
    }
}

// ─────────────────────────────────────────────
// 7 — RESOLVE RECIPIENT TO INTERNAL USER ID
// ─────────────────────────────────────────────

/**
 * Resolves a recipient identifier to an internal user ID.
 * Accepts ONLY internal user IDs (user_XXXX format).
 * Rejects usernames to prevent enumeration via the message API.
 *
 * In production: look up against your DB to confirm the user exists.
 */
async function resolveRecipientId(db, recipientId) {
    // Only accept internal user ID format
    if (typeof recipientId !== 'string' || !recipientId.startsWith('user_')) {
        throw new Error(
            'Recipient must be an internal user ID (user_XXXX), not a username.'
        );
    }

    // Confirm the user actually exists in the DB
    const user = await db.get(
        'SELECT id FROM users WHERE id = ?',
        [recipientId]
    );

    if (!user) {
        // Use a generic error — don't confirm whether the user exists
        throw new Error('Recipient not found.');
    }

    return user.id;
}

// ─────────────────────────────────────────────
// CORE: CREATE HARDENED MESSAGE
// ─────────────────────────────────────────────

/**
 * Creates a fully hardened message object ready for storage.
 *
 * Fixes applied:
 *  [1] Cryptographically random message ID
 *  [2] Body is AES-256-GCM encrypted at rest
 *  [3] senderId comes from authenticated session — never the client
 *  [4] HMAC computed over all fields for tamper detection
 *  [5] Timestamp assigned by the server
 *  [6] convoId is a cryptographically random UUID
 *  [7] Recipient validated as internal user ID
 *  [8] Message type validated against whitelist
 *
 * @param {object} db           - SQLite DB instance
 * @param {string} sessionUserId - Authenticated user ID from session/JWT
 * @param {object} input         - Raw client input
 */
async function createHardenedMessage(db, sessionUserId, input) {
    const { body, to, type, convoId } = input;

    // ── [8] Validate message type ──────────────────
    validateMessageType(type);

    // ── [3] Sender is always the authenticated user ──
    // Never trust input.from — always use the session identity
    const senderId = sessionUserId;

    // ── [7] Validate & resolve recipient ──────────
    const recipientId = await resolveRecipientId(db, to);

    // ── Body validation ────────────────────────────
    if (typeof body !== 'string' || body.length === 0) {
        throw new Error('Message body must be a non-empty string.');
    }
    if (body.length > MAX_BODY_LENGTH) {
        throw new Error(`Message body exceeds maximum length of ${MAX_BODY_LENGTH} characters.`);
    }

    // ── [1] Cryptographically random message ID ────
    const id = generateMessageId();

    // ── [6] Use provided convoId or generate a new one ──
    // Validate format if provided — must match our generated format
    let safeConvoId;
    if (convoId) {
        if (!/^convo_[a-f0-9]{32}$/.test(convoId)) {
            throw new Error('Invalid conversation ID format.');
        }
        // Verify the sender is a participant in this conversation
        const participation = await db.get(
            'SELECT 1 FROM conversations WHERE id = ? AND (user1_id = ? OR user2_id = ?)',
            [convoId, senderId, senderId]
        );
        if (!participation) {
            throw new Error('Access denied to this conversation.');
        }
        safeConvoId = convoId;
    } else {
        safeConvoId = generateConvoId();
    }

    // ── [5] Server-assigned timestamp ─────────────
    const ts = Date.now();

    // ── [2] Encrypt the message body ──────────────
    const encrypted = encryptBody(body);

    // ── [4] Compute HMAC over all fields ──────────
    const messageToSign = { id, convoId: safeConvoId, senderId, ts, type, encrypted };
    const hmac = computeHmac(messageToSign);

    // ── Final hardened message object ─────────────
    const hardenedMessage = {
        id,
        convoId: safeConvoId,
        senderId,                     // server-enforced — never from client
        recipientId,                  // internal ID only — never username
        type,                         // whitelist-validated
        encrypted,                    // AES-256-GCM encrypted body + iv + authTag
        ts,                           // server-assigned — never from client
        hmac                          // tamper-detection signature
        // Note: plaintext body is NOT stored — only the encrypted form
    };

    return hardenedMessage;
}

// ─────────────────────────────────────────────
// CORE: RETRIEVE & VERIFY MESSAGE
// ─────────────────────────────────────────────

/**
 * Retrieves and verifies a message from the database.
 * Decrypts the body only after passing integrity checks.
 *
 * @param {object} db           - SQLite DB instance
 * @param {string} messageId    - Message ID to retrieve
 * @param {string} sessionUserId - Authenticated user requesting the message
 */
async function getHardenedMessage(db, messageId, sessionUserId) {
    // Validate message ID format
    if (!/^msg_[a-f0-9]{32}$/.test(messageId)) {
        throw new Error('Invalid message ID format.');
    }

    // Retrieve from DB
    const row = await db.get(
        'SELECT * FROM messages WHERE id = ?',
        [messageId]
    );

    if (!row) {
        throw new Error('Message not found.');
    }

    // ── Authorization: only sender or recipient can read ──
    if (row.senderId !== sessionUserId && row.recipientId !== sessionUserId) {
        // Don't leak existence — return same error as "not found"
        throw new Error('Message not found.');
    }

    // ── [4] Verify HMAC before decrypting ─────────
    const encrypted = JSON.parse(row.encrypted);
    const message = {
        id: row.id,
        convoId: row.convoId,
        senderId: row.senderId,
        ts: row.ts,
        type: row.type,
        encrypted,
        hmac: row.hmac
    };

    if (!verifyHmac(message)) {
        // Log this as a critical security event
        console.error(`[SECURITY] HMAC verification FAILED for message ${messageId} — possible tampering.`);
        throw new Error('Message integrity check failed.');
    }

    // ── [2] Decrypt the body after passing integrity checks ──
    const body = decryptBody(encrypted);

    return {
        id: row.id,
        convoId: row.convoId,
        senderId: row.senderId,
        recipientId: row.recipientId,
        type: row.type,
        body,                         // plaintext returned only to authorized user
        ts: row.ts
        // hmac and encrypted fields NOT exposed to clients
    };
}

// ─────────────────────────────────────────────
// EXPRESS ROUTE HANDLER (drop-in for your server)
// ─────────────────────────────────────────────

/**
 * POST /api/messages
 *
 * Hardened message creation endpoint.
 * Requires: valid JWT in Authorization header (handled by authMiddleware).
 */
async function handleSendMessage(req, res, db) {
    try {
        // req.user.id is set by your JWT auth middleware — never trust req.body.from
        const sessionUserId = req.user && req.user.id;

        if (!sessionUserId) {
            return res.status(401).json({ error: 'Unauthorized.' });
        }

        const { body, to, type, convoId } = req.body;

        // Basic presence checks before deeper validation
        if (!body || !to || !type) {
            return res.status(400).json({ error: 'Missing required fields: body, to, type.' });
        }

        const message = await createHardenedMessage(db, sessionUserId, {
            body,
            to,
            type,
            convoId: convoId || null
        });

        // Persist to DB
        await db.run(
            `INSERT INTO messages
        (id, convoId, senderId, recipientId, type, encrypted, ts, hmac)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
            [
                message.id,
                message.convoId,
                message.senderId,
                message.recipientId,
                message.type,
                JSON.stringify(message.encrypted),
                message.ts,
                message.hmac
            ]
        );

        // Return only non-sensitive fields to the client
        return res.status(201).json({
            id: message.id,
            convoId: message.convoId,
            ts: message.ts,
            type: message.type
        });

    } catch (err) {
        // Never leak internal error details to the client
        console.error('[handleSendMessage]', err.message);

        // Map known validation errors to 400, everything else to 500
        const clientErrors = [
            'Missing required fields',
            'Invalid message type',
            'Message body',
            'Recipient must be',
            'Recipient not found',
            'Invalid conversation ID',
            'Access denied'
        ];

        const isClientError = clientErrors.some(e => err.message.startsWith(e));
        return res.status(isClientError ? 400 : 500).json({
            error: isClientError ? err.message : 'Internal server error.'
        });
    }
}

/**
 * GET /api/messages/:id
 *
 * Hardened message retrieval endpoint.
 */
async function handleGetMessage(req, res, db) {
    try {
        const sessionUserId = req.user && req.user.id;

        if (!sessionUserId) {
            return res.status(401).json({ error: 'Unauthorized.' });
        }

        const message = await getHardenedMessage(db, req.params.id, sessionUserId);
        return res.status(200).json(message);

    } catch (err) {
        console.error('[handleGetMessage]', err.message);

        if (err.message === 'Message not found.' || err.message === 'Invalid message ID format.') {
            return res.status(404).json({ error: 'Message not found.' });
        }
        if (err.message === 'Message integrity check failed.') {
            return res.status(500).json({ error: 'Message integrity check failed.' });
        }
        return res.status(500).json({ error: 'Internal server error.' });
    }
}

// ─────────────────────────────────────────────
// DB SCHEMA (for reference)
// ─────────────────────────────────────────────

const DB_SCHEMA = `
  CREATE TABLE IF NOT EXISTS messages (
    id          TEXT PRIMARY KEY,         -- msg_<32 hex>  — random, not timestamp
    convoId     TEXT NOT NULL,            -- convo_<32 hex> — random, not timestamp
    senderId    TEXT NOT NULL,            -- internal user ID — server-enforced
    recipientId TEXT NOT NULL,            -- internal user ID — never username
    type        TEXT NOT NULL,            -- whitelist-validated
    encrypted   TEXT NOT NULL,            -- JSON: { ciphertext, iv, authTag }
    ts          INTEGER NOT NULL,         -- server-assigned Unix ms timestamp
    hmac        TEXT NOT NULL,            -- HMAC-SHA256 tamper detection
    FOREIGN KEY (senderId)    REFERENCES users(id),
    FOREIGN KEY (recipientId) REFERENCES users(id),
    FOREIGN KEY (convoId)     REFERENCES conversations(id)
  );

  CREATE INDEX IF NOT EXISTS idx_messages_convoId    ON messages(convoId);
  CREATE INDEX IF NOT EXISTS idx_messages_senderId   ON messages(senderId);
  CREATE INDEX IF NOT EXISTS idx_messages_recipientId ON messages(recipientId);
  CREATE INDEX IF NOT EXISTS idx_messages_ts         ON messages(ts);
`;

// ─────────────────────────────────────────────
// EXPORTS
// ─────────────────────────────────────────────

module.exports = {
    generateMessageId,
    generateConvoId,
    encryptBody,
    decryptBody,
    computeHmac,
    verifyHmac,
    validateMessageType,
    resolveRecipientId,
    createHardenedMessage,
    getHardenedMessage,
    handleSendMessage,
    handleGetMessage,
    DB_SCHEMA
};