const crypto = require('crypto');
const fs = require('fs');

/**
 * GhostNet Decentralized Storage
 * Secure, Sharded, Erasure-Coded Storage Protocol
 * 
 * Features:
 * - AES-256-GCM Encryption
 * - File Sharding
 * - Erasure Coding (Simulated / Interface)
 * - Metadata Management
 */

class GhostStorage {
    constructor(nodeId = "local-node") {
        this.nodeId = nodeId;
        this.chunkStore = new Map(); // Local chunk storage simulation
    }

    // --- 1. ENCRYPTION ---

    /**
     * Encrypts a file buffer with AES-256-GCM
     * @param {Buffer} fileBuffer 
     * @returns {Object} { encryptedBuffer, key, iv, authTag }
     */
    encryptFile(fileBuffer) {
        // Generate ephemeral key for this file
        const key = crypto.randomBytes(32);
        const iv = crypto.randomBytes(12);

        const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
        const encrypted = Buffer.concat([cipher.update(fileBuffer), cipher.final()]);
        const authTag = cipher.getAuthTag();

        return {
            encryptedBuffer: encrypted,
            key: key.toString('hex'), // In a real app, this key is encrypted with the user's master key
            iv: iv.toString('hex'),
            authTag: authTag.toString('hex')
        };
    }

    /**
     * Decrypts a file buffer
     */
    decryptFile(encryptedBuffer, keyHex, ivHex, authTagHex) {
        const key = Buffer.from(keyHex, 'hex');
        const iv = Buffer.from(ivHex, 'hex');
        const authTag = Buffer.from(authTagHex, 'hex');

        const decipher = crypto.createDecipheriv('aes-256-gcm', key, iv);
        decipher.setAuthTag(authTag);

        return Buffer.concat([decipher.update(encryptedBuffer), decipher.final()]);
    }

    // --- 2. SHARDING & ERASURE CODING ---

    /**
     * Splits data into N chunks with optional Parity (Erasure Coding)
     * For this demo, we implement simple RAID-5 style XOR parity (N+1)
     * Real implementation would use Reed-Solomon for (N+M)
     */
    splitChunks(buffer, dataShards = 4, parityShards = 1) {
        const totalSize = buffer.length;
        const shardSize = Math.ceil(totalSize / dataShards);
        const chunks = [];

        // 1. Create Data Shards
        for (let i = 0; i < dataShards; i++) {
            const start = i * shardSize;
            const end = Math.min(start + shardSize, totalSize);
            const chunk = Buffer.alloc(shardSize); // Pad last chunk with zeros if needed
            buffer.copy(chunk, 0, start, end);

            chunks.push({
                index: i,
                type: 'data',
                data: chunk.toString('base64'),
                hash: this._hash(chunk)
            });
        }

        // 2. Create Parity Shard (Simple XOR of all data shards)
        // Note: Real RS coding allows reconstructing ANY missing shard. 
        // XOR only recovers ONE missing shard.
        if (parityShards > 0) {
            const parityBuffer = Buffer.alloc(shardSize);
            for (let i = 0; i < shardSize; i++) {
                let byte = 0;
                for (let j = 0; j < dataShards; j++) {
                    const chunkBuffer = Buffer.from(chunks[j].data, 'base64');
                    byte ^= chunkBuffer[i];
                }
                parityBuffer[i] = byte;
            }
            chunks.push({
                index: dataShards,
                type: 'parity',
                data: parityBuffer.toString('base64'),
                hash: this._hash(parityBuffer)
            });
        }

        return chunks;
    }

    // --- 3. DISTRIBUTION (GOSSIP SIMULATION) ---

    /**
     * Simulates distributing chunks to peers
     */
    async distributeChunks(chunks, peers = []) {
        // In a real P2P net, we'd use Kademlia DHT or GossipSub
        const distributionMap = {};

        chunks.forEach((chunk, i) => {
            // Round-robin distribution for demo
            const targetPeer = peers.length > 0 ? peers[i % peers.length] : "local-storage";

            // "Send" the chunk
            if (!distributionMap[targetPeer]) distributionMap[targetPeer] = [];
            distributionMap[targetPeer].push(chunk.hash);

            // Store locally for simulation
            this.chunkStore.set(chunk.hash, chunk);
            console.log(`[GhostStore] Chunk ${chunk.index} (${chunk.type}) -> ${targetPeer}`);
        });

        return distributionMap;
    }

    // --- 4. RECONSTRUCTION ---

    /**
     * Reconstructs file from chunks
     */
    async reconstructFile(metadata, availableChunks) {
        // 1. Sort chunks by index
        const shards = [];
        const requiredCount = metadata.requiredChunks || 4;

        // Map available chunks
        const chunkMap = new Map();
        availableChunks.forEach(c => chunkMap.set(c.index, c));

        // 2. Check Data Shards
        let missingDataIndices = [];
        let parityShard = null;

        for (let i = 0; i < requiredCount; i++) {
            if (chunkMap.has(i)) {
                shards.push(Buffer.from(chunkMap.get(i).data, 'base64'));
            } else {
                shards.push(null); // Missing
                missingDataIndices.push(i);
            }
        }

        // 3. Erasure Coding Recovery (XOR Logic)
        if (missingDataIndices.length > 0) {
            console.log(`[GhostStore] Missing ${missingDataIndices.length} shards. Attempting recovery...`);

            // Check for parity shard (index = requiredCount in our N+1 scheme)
            const parityIndex = requiredCount;
            if (chunkMap.has(parityIndex)) {
                parityShard = Buffer.from(chunkMap.get(parityIndex).data, 'base64');
            }

            if (missingDataIndices.length === 1 && parityShard) {
                // Recover single missing shard using XOR
                const missingIdx = missingDataIndices[0];
                const recovered = Buffer.alloc(parityShard.length);

                for (let i = 0; i < parityShard.length; i++) {
                    let byte = parityShard[i]; // Start with parity
                    for (let j = 0; j < requiredCount; j++) {
                        if (j !== missingIdx) {
                            // XOR with existing data shards
                            byte ^= shards[j][i];
                        }
                    }
                    recovered[i] = byte;
                }
                shards[missingIdx] = recovered;
                console.log(`[GhostStore] Recovered shard ${missingIdx} using parity.`);
            } else if (missingDataIndices.length > 0) {
                throw new Error("Too many missing shards or no parity data available.");
            }
        }

        // 4. Concatenate
        const joined = Buffer.concat(shards);

        // Remove padding? (We rely on decrypt to handle standard padding, 
        // but simple concatenating holds the extra zeros from the last shard.
        // For AES-GCM, the auth tag validation will fail if we include extra bytes 
        // unless we recorded original length.
        // For this demo, we assume the original length is in metadata or handled by padding.)

        // Better: Trim to original size if metadata has it.
        if (metadata.originalSize) {
            return joined.subarray(0, metadata.originalSize);
        }

        return joined;
    }

    // --- HELPER ---

    _hash(buffer) {
        return crypto.createHash('sha256').update(buffer).digest('hex');
    }

    /**
     * Main Workflow: Store File
     */
    async storeFileBuffer(fileBuffer, ttlSeconds = 3600) {
        const fileId = crypto.randomUUID();

        // 1. Encrypt
        const { encryptedBuffer, key, iv, authTag } = this.encryptFile(fileBuffer);

        // 2. Shard
        const DATA_SHARDS = 4;
        const chunks = this.splitChunks(encryptedBuffer, DATA_SHARDS, 1);

        // 3. Distribute
        const locations = await this.distributeChunks(chunks, ["node-A", "node-B", "node-C", "node-D"]);

        // 4. Metadata
        const metadata = {
            fileId,
            originalSize: encryptedBuffer.length,
            requiredChunks: DATA_SHARDS,
            chunkHashes: chunks.map(c => c.hash),
            locations: locations,
            encryption: {
                algo: "AES-256-GCM",
                iv: iv,
                authTag: authTag,
                // Key is NOT stored here in a real system. Returned to user.
            },
            expiryTime: Date.now() + (ttlSeconds * 1000)
        };

        return { metadata, key }; // User must keep 'key' safe!
    }

    /**
     * Main Workflow: Retrieve File
     */
    async retrieveFile(metadata, keyHex) {
        if (Date.now() > metadata.expiryTime) throw new Error("File expired and self-destructed.");

        // 1. Gather Chunks (Simulation: Fetch from store)
        const availableChunks = [];
        for (const hash of metadata.chunkHashes) { // In real app, iterate known hashes
            if (this.chunkStore.has(hash)) {
                availableChunks.push(this.chunkStore.get(hash));
            }
            // If checking parity
        }

        // Also check if we have the parity chunk (which isn't in chunkHashes usually? 
        // Wait, splitChunks returns it. Metadata should track all chunks or derivation logic.)
        // For simplicity, let's assume `chunkHashes` includes ALL generated chunks (data + parity).

        // 2. Reconstruct
        const encryptedBuffer = await this.reconstructFile(metadata, availableChunks);

        // 3. Decrypt
        const decrypted = this.decryptFile(
            encryptedBuffer,
            keyHex,
            metadata.encryption.iv,
            metadata.encryption.authTag
        );

        return decrypted;
    }
}

// --- EXAMPLE USAGE ---
if (require.main === module) {
    (async () => {
        const storage = new GhostStorage();
        const secretData = Buffer.from("Sensitive GhostNet Launch Codes: 123456");

        console.log("Original:", secretData.toString());

        // Store
        const { metadata, key } = await storage.storeFileBuffer(secretData);
        console.log("Stored! Metadata:", JSON.stringify(metadata, null, 2));
        console.log("Secret Key (User held):", key);

        // Simulate Loosing a Shard (Simulating network failure)
        const lostShardHash = metadata.chunkHashes[1]; // Lose index 1
        storage.chunkStore.delete(lostShardHash);
        console.log(`\n[Sim] Lost shard: ${lostShardHash}`);

        // Retrieve
        try {
            const recovered = await storage.retrieveFile(metadata, key);
            console.log("\nDecrypted & Recovered:", recovered.toString());
            console.log("Success! Erasure coding worked.");
        } catch (e) {
            console.error("Recovery Failed:", e.message);
        }
    })();
}

module.exports = GhostStorage;
