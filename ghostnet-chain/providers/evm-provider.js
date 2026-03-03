/**
 * GhostNet EVM Chain Provider (Polygon / Hardhat / Custom EVM)
 * =============================================================
 * Implements BaseChainProvider for any EVM-compatible chain.
 * Uses a lightweight on-chain key-value store via raw transactions
 * for anchoring file hashes. Falls back to an in-memory store
 * when no EVM RPC is available (dev mode).
 * 
 * To switch from Polygon to a custom EVM chain, you only need to
 * change the RPC_URL and PRIVATE_KEY in .env — zero app changes.
 */

import { ethers } from 'ethers';
import { BaseChainProvider } from './base-provider.js';

export class EVMProvider extends BaseChainProvider {
    constructor(config = {}) {
        super(config);
        this.name = 'evm';
        this.provider = null;
        this.wallet = null;
        // In-memory store for dev/fallback (persistent in production via chain)
        this.localStore = new Map();
        this.rpcUrl = config.rpcUrl || process.env.ETH_RPC_URL || 'http://127.0.0.1:8545';
        this.privateKey = config.privateKey || process.env.ETH_PRIVATE_KEY;
    }

    async connect() {
        try {
            this.provider = new ethers.JsonRpcProvider(this.rpcUrl);
            const network = await this.provider.getNetwork();
            console.log(`⛓️  EVM Provider connected — chainId: ${network.chainId}, rpc: ${this.rpcUrl}`);

            if (this.privateKey) {
                this.wallet = new ethers.Wallet(this.privateKey, this.provider);
                console.log(`🔑 Wallet: ${this.wallet.address}`);
            }

            this.connected = true;
        } catch (err) {
            console.warn(`⚠️  EVM RPC unreachable (${this.rpcUrl}). Running in local-fallback mode.`);
            this.connected = false;
            // Still functional — uses localStore
        }
    }

    async disconnect() {
        this.provider = null;
        this.wallet = null;
        this.connected = false;
    }

    /**
     * Anchor file hash on-chain using a self-transfer with data payload.
     * This is the cheapest way to store data on any EVM chain — no smart
     * contract deployment needed. The file hash lives in tx calldata forever.
     */
    async anchorFileHash(fileId, fileHash, metadata = {}) {
        const record = {
            fileId,
            fileHash,
            owner: metadata.owner || 'anonymous',
            fileName: metadata.fileName || 'unknown',
            fileSize: metadata.fileSize || 0,
            timestamp: Date.now(),
            deleted: false,
            txHash: null,
            blockNumber: null
        };

        // Try on-chain anchoring
        if (this.connected && this.wallet) {
            try {
                const payload = JSON.stringify({
                    protocol: 'ghostnet-vault',
                    version: 1,
                    action: 'anchor',
                    fileId,
                    fileHash,
                    owner: record.owner,
                    fileName: record.fileName,
                    fileSize: record.fileSize,
                    ts: record.timestamp
                });

                const tx = await this.wallet.sendTransaction({
                    to: this.wallet.address, // Self-transfer
                    value: 0,
                    data: ethers.hexlify(ethers.toUtf8Bytes(payload))
                });

                const receipt = await tx.wait();
                record.txHash = receipt.hash;
                record.blockNumber = receipt.blockNumber;

                console.log(`✅ File hash anchored on-chain — tx: ${receipt.hash}`);
            } catch (err) {
                console.warn('⚠️  On-chain anchor failed, using local store:', err.message);
                record.txHash = `local_${Date.now().toString(36)}`;
            }
        } else {
            record.txHash = `local_${Date.now().toString(36)}`;
        }

        // Always store locally too (fast reads)
        this.localStore.set(fileId, record);
        return record;
    }

    async verifyFileHash(fileId) {
        return this.localStore.get(fileId) || null;
    }

    async getFilesByOwner(owner) {
        const files = [];
        for (const [, record] of this.localStore) {
            if (record.owner === owner && !record.deleted) {
                files.push(record);
            }
        }
        return files;
    }

    async deleteFileRecord(fileId, owner) {
        const record = this.localStore.get(fileId);
        if (!record) throw new Error('File not found');
        if (record.owner !== owner) throw new Error('Unauthorized — owner mismatch');

        // On-chain: anchor a deletion marker
        if (this.connected && this.wallet) {
            try {
                const payload = JSON.stringify({
                    protocol: 'ghostnet-vault',
                    version: 1,
                    action: 'delete',
                    fileId,
                    ts: Date.now()
                });

                const tx = await this.wallet.sendTransaction({
                    to: this.wallet.address,
                    value: 0,
                    data: ethers.hexlify(ethers.toUtf8Bytes(payload))
                });
                await tx.wait();
            } catch (err) {
                console.warn('⚠️  On-chain delete marker failed:', err.message);
            }
        }

        record.deleted = true;
        this.localStore.set(fileId, record);
        return { txHash: record.txHash, deleted: true };
    }

    async getChainInfo() {
        if (!this.connected || !this.provider) {
            return { chainId: null, blockNumber: null, provider: 'local-fallback', wallet: null };
        }
        try {
            const network = await this.provider.getNetwork();
            const block = await this.provider.getBlockNumber();
            return {
                chainId: Number(network.chainId),
                blockNumber: block,
                provider: this.rpcUrl,
                wallet: this.wallet?.address || null
            };
        } catch {
            return { chainId: null, blockNumber: null, provider: 'error', wallet: null };
        }
    }
}
