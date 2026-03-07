/**
 * GhostNet Blockchain Abstraction Layer — Provider Interface
 * ===========================================================
 * Abstract base class that all chain providers must implement.
 * 
 * To switch chains (e.g. Polygon → custom EVM), create a new
 * provider class implementing this interface and change the
 * GHOSTNET_CHAIN_PROVIDER env var. The rest of the app never
 * touches blockchain code directly.
 */

export class BaseChainProvider {
    constructor(config = {}) {
        this.name = 'base';
        this.config = config;
        this.connected = false;
    }

    /** Connect to the chain RPC */
    async connect() {
        throw new Error('connect() not implemented');
    }

    /** Disconnect cleanly */
    async disconnect() {
        throw new Error('disconnect() not implemented');
    }

    /** Check if connected */
    isConnected() {
        return this.connected;
    }

    /**
     * Anchor a file hash on-chain.
     * @param {string} fileId    — unique file identifier
     * @param {string} fileHash  — SHA-256 hash of the encrypted file
     * @param {object} metadata  — { fileName, fileSize, owner, timestamp }
     * @returns {object} { txHash, blockNumber, gasUsed }
     */
    async anchorFileHash(fileId, fileHash, metadata) {
        throw new Error('anchorFileHash() not implemented');
    }

    /**
     * Verify a file hash on-chain.
     * @param {string} fileId
     * @returns {object|null} { fileHash, owner, timestamp, txHash } or null
     */
    async verifyFileHash(fileId) {
        throw new Error('verifyFileHash() not implemented');
    }

    /**
     * Get all file records for an owner.
     * @param {string} owner — owner address or userId
     * @returns {Array} list of file records
     */
    async getFilesByOwner(owner) {
        throw new Error('getFilesByOwner() not implemented');
    }

    /**
     * Delete a file hash record from chain (mark as deleted).
     * @param {string} fileId
     * @param {string} owner — must match the original uploader
     * @returns {object} { txHash }
     */
    async deleteFileRecord(fileId, owner) {
        throw new Error('deleteFileRecord() not implemented');
    }

    /**
     * Get chain info (for health checks).
     * @returns {object} { chainId, blockNumber, provider }
     */
    async getChainInfo() {
        throw new Error('getChainInfo() not implemented');
    }
}
