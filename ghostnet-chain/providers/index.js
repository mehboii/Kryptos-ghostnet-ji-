/**
 * GhostNet Chain Provider Factory
 * ================================
 * Single import point. Reads GHOSTNET_CHAIN_PROVIDER env var
 * to decide which chain backend to use. Defaults to 'evm'.
 * 
 * To add a new chain: 
 *   1. Create providers/my-chain-provider.js extending BaseChainProvider
 *   2. Add a case in getProvider() below
 *   3. Set GHOSTNET_CHAIN_PROVIDER=my-chain in .env
 *   Done — zero changes in app code.
 */

import { EVMProvider } from './evm-provider.js';

let _instance = null;

/**
 * Get the configured chain provider (singleton).
 * @param {object} config — override config
 * @returns {BaseChainProvider}
 */
export function getProvider(config = {}) {
    if (_instance) return _instance;

    const providerType = (config.type || process.env.GHOSTNET_CHAIN_PROVIDER || 'evm').toLowerCase();

    switch (providerType) {
        case 'evm':
        case 'polygon':
        case 'hardhat':
        case 'custom-evm':
            _instance = new EVMProvider(config);
            break;

        // Future: case 'solana': ...
        // Future: case 'custom': ...

        default:
            console.warn(`Unknown chain provider "${providerType}", falling back to EVM`);
            _instance = new EVMProvider(config);
    }

    return _instance;
}

/**
 * Reset the singleton (useful for tests or hot-swapping).
 */
export function resetProvider() {
    if (_instance) {
        _instance.disconnect().catch(() => { });
    }
    _instance = null;
}
