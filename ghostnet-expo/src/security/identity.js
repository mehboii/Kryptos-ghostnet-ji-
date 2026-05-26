import { mnemonicToSeedSync, generateMnemonic, validateMnemonic } from '@scure/bip39';
import { wordlist } from '@scure/bip39/wordlists/english.js';
import { HDKey } from '@scure/bip32';
import { p256 } from '@noble/curves/nist.js';
import * as SecureStore from 'expo-secure-store';
import { bytesToHex, hexToBytes } from './ecdsa';

const DERIVATION_PATH = "m/44'/60'/0'/0/0";
const STORE_KEY_MNEMONIC = 'ghostnet_mnemonic';
const STORE_KEY_PRIVKEY = 'ghostnet_privkey';
const STORE_KEY_PUBKEY = 'ghostnet_pubkey';

/**
 * Generate a new 12-word BIP39 mnemonic.
 * @returns {string} 12-word space-separated mnemonic
 */
export function createMnemonic() {
  return generateMnemonic(wordlist, 128);
}

/**
 * Validate a mnemonic phrase.
 * @param {string} mnemonic - space-separated word list
 * @returns {boolean}
 */
export function isValidMnemonic(mnemonic) {
  return validateMnemonic(mnemonic, wordlist);
}

/**
 * Derive a deterministic ECDSA keypair from a BIP39 mnemonic.
 * Uses BIP32 at m/44'/60'/0'/0/0 for the private key scalar,
 * then derives the P-256 public key (not secp256k1).
 * @param {string} mnemonic - 12-word BIP39 mnemonic
 * @returns {{ privateKey: string, publicKey: string }} hex-encoded keys
 * @throws {Error} if mnemonic is invalid
 */
export function deriveKeypair(mnemonic) {
  if (!isValidMnemonic(mnemonic)) {
    throw new Error('Invalid mnemonic phrase');
  }
  const seed = mnemonicToSeedSync(mnemonic);
  const master = HDKey.fromMasterSeed(seed);
  const child = master.derive(DERIVATION_PATH);
  if (!child.privateKey) {
    throw new Error('Key derivation failed');
  }
  const privateKey = bytesToHex(child.privateKey);
  const publicKey = bytesToHex(p256.getPublicKey(child.privateKey));
  return { privateKey, publicKey };
}

/**
 * Initialize identity on first launch: generate mnemonic, derive keys,
 * persist everything in SecureStore.
 * If keys already exist, returns the stored identity.
 * No server calls — fully offline.
 * @returns {Promise<{ mnemonic: string, privateKey: string, publicKey: string, isNew: boolean }>}
 */
export async function initializeIdentity() {
  const existingPub = await SecureStore.getItemAsync(STORE_KEY_PUBKEY);
  const existingPriv = await SecureStore.getItemAsync(STORE_KEY_PRIVKEY);
  const existingMnemonic = await SecureStore.getItemAsync(STORE_KEY_MNEMONIC);

  if (existingPub && existingPriv && existingMnemonic) {
    return {
      mnemonic: existingMnemonic,
      privateKey: existingPriv,
      publicKey: existingPub,
      isNew: false,
    };
  }

  const mnemonic = createMnemonic();
  const { privateKey, publicKey } = deriveKeypair(mnemonic);

  await SecureStore.setItemAsync(STORE_KEY_MNEMONIC, mnemonic);
  await SecureStore.setItemAsync(STORE_KEY_PRIVKEY, privateKey);
  await SecureStore.setItemAsync(STORE_KEY_PUBKEY, publicKey);

  return { mnemonic, privateKey, publicKey, isNew: true };
}

/**
 * Restore identity from a seed phrase (reinstall / new device).
 * Derives the same keypair and overwrites SecureStore.
 * @param {string} mnemonic - 12-word BIP39 mnemonic
 * @returns {Promise<{ privateKey: string, publicKey: string }>}
 * @throws {Error} if mnemonic is invalid
 */
export async function restoreIdentity(mnemonic) {
  const trimmed = mnemonic.trim().toLowerCase();
  const { privateKey, publicKey } = deriveKeypair(trimmed);

  await SecureStore.setItemAsync(STORE_KEY_MNEMONIC, trimmed);
  await SecureStore.setItemAsync(STORE_KEY_PRIVKEY, privateKey);
  await SecureStore.setItemAsync(STORE_KEY_PUBKEY, publicKey);

  return { privateKey, publicKey };
}

/**
 * Get the stored public key without exposing the private key.
 * @returns {Promise<string|null>} hex-encoded compressed public key, or null
 */
export async function getPublicKey() {
  return SecureStore.getItemAsync(STORE_KEY_PUBKEY);
}

/**
 * Get the stored private key. Handle with care — never log or transmit.
 * @returns {Promise<string|null>} hex-encoded private key, or null
 */
export async function getPrivateKey() {
  return SecureStore.getItemAsync(STORE_KEY_PRIVKEY);
}

/**
 * Check whether an identity has been initialized.
 * @returns {Promise<boolean>}
 */
export async function hasIdentity() {
  const pub = await SecureStore.getItemAsync(STORE_KEY_PUBKEY);
  return pub !== null;
}

/**
 * Wipe all identity material from SecureStore.
 * Destructive — the seed phrase is the only recovery path.
 * @returns {Promise<void>}
 */
export async function clearIdentity() {
  await SecureStore.deleteItemAsync(STORE_KEY_MNEMONIC);
  await SecureStore.deleteItemAsync(STORE_KEY_PRIVKEY);
  await SecureStore.deleteItemAsync(STORE_KEY_PUBKEY);
}
