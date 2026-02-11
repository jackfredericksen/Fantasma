/**
 * Secure storage utilities for Fantasma Wallet
 * Uses chrome.storage.local with encryption for sensitive data
 */

import { encrypt, decrypt, deriveKey, generateSalt, bytesToBase64, base64ToBytes } from './crypto.js';

// Storage keys
const KEYS = {
  MASTER_KEY_SALT: 'master_key_salt',
  ENCRYPTED_MASTER_SECRET: 'encrypted_master_secret',
  CREDENTIALS: 'credentials',
  ISSUERS: 'issuers',
  SETTINGS: 'settings',
  PENDING_PROOFS: 'pending_proofs',
  USED_NULLIFIERS: 'used_nullifiers'
};

/**
 * Wallet storage manager
 */
class WalletStorage {
  constructor() {
    this.encryptionKey = null;
    this.masterSecret = null;
    this.isUnlocked = false;
  }

  /**
   * Initialize wallet with a password (first time setup)
   */
  async initialize(password) {
    // Generate salt and master secret
    const salt = generateSalt();
    const masterSecret = crypto.getRandomValues(new Uint8Array(32));

    // Derive encryption key
    this.encryptionKey = await deriveKey(password, salt);

    // Encrypt and store master secret
    const encryptedSecret = await encrypt(this.encryptionKey, masterSecret);

    await chrome.storage.local.set({
      [KEYS.MASTER_KEY_SALT]: bytesToBase64(salt),
      [KEYS.ENCRYPTED_MASTER_SECRET]: bytesToBase64(encryptedSecret),
      [KEYS.CREDENTIALS]: [],
      [KEYS.ISSUERS]: [],
      [KEYS.SETTINGS]: { autoLockMinutes: 15 },
      [KEYS.USED_NULLIFIERS]: []
    });

    this.masterSecret = masterSecret;
    this.isUnlocked = true;

    return true;
  }

  /**
   * Unlock wallet with password
   */
  async unlock(password) {
    const data = await chrome.storage.local.get([
      KEYS.MASTER_KEY_SALT,
      KEYS.ENCRYPTED_MASTER_SECRET
    ]);

    if (!data[KEYS.MASTER_KEY_SALT] || !data[KEYS.ENCRYPTED_MASTER_SECRET]) {
      throw new Error('Wallet not initialized');
    }

    const salt = base64ToBytes(data[KEYS.MASTER_KEY_SALT]);
    const encryptedSecret = base64ToBytes(data[KEYS.ENCRYPTED_MASTER_SECRET]);

    // Derive key and attempt decryption
    this.encryptionKey = await deriveKey(password, salt);

    try {
      this.masterSecret = await decrypt(this.encryptionKey, encryptedSecret);
      this.isUnlocked = true;
      return true;
    } catch (e) {
      this.encryptionKey = null;
      throw new Error('Invalid password');
    }
  }

  /**
   * Lock the wallet
   */
  lock() {
    this.encryptionKey = null;
    this.masterSecret = null;
    this.isUnlocked = false;
  }

  /**
   * Check if wallet is initialized
   */
  async isInitialized() {
    const data = await chrome.storage.local.get([KEYS.ENCRYPTED_MASTER_SECRET]);
    return !!data[KEYS.ENCRYPTED_MASTER_SECRET];
  }

  /**
   * Get credentials (decrypted)
   */
  async getCredentials() {
    this.requireUnlocked();

    const data = await chrome.storage.local.get([KEYS.CREDENTIALS]);
    const credentials = data[KEYS.CREDENTIALS] || [];

    // Decrypt each credential
    const decrypted = [];
    for (const cred of credentials) {
      try {
        const encryptedData = base64ToBytes(cred.encryptedData);
        const decryptedBytes = await decrypt(this.encryptionKey, encryptedData);
        const decoder = new TextDecoder();
        const credentialData = JSON.parse(decoder.decode(decryptedBytes));
        decrypted.push({
          id: cred.id,
          issuer: cred.issuer,
          schema: cred.schema,
          type: cred.type,
          issuedAt: cred.issuedAt,
          expiresAt: cred.expiresAt,
          ...credentialData
        });
      } catch (e) {
        console.error('Failed to decrypt credential:', e);
      }
    }

    return decrypted;
  }

  /**
   * Store a new credential
   */
  async storeCredential(credential) {
    this.requireUnlocked();

    const encoder = new TextEncoder();
    const credentialJson = JSON.stringify({
      birthdate: credential.birthdate,
      attributes: credential.attributes,
      commitment: credential.commitment,
      signature: credential.signature
    });

    const encryptedData = await encrypt(
      this.encryptionKey,
      encoder.encode(credentialJson)
    );

    const storedCredential = {
      id: credential.id,
      issuer: credential.issuer,
      schema: credential.schema,
      type: credential.type,
      issuedAt: credential.issuedAt,
      expiresAt: credential.expiresAt,
      encryptedData: bytesToBase64(encryptedData)
    };

    const data = await chrome.storage.local.get([KEYS.CREDENTIALS]);
    const credentials = data[KEYS.CREDENTIALS] || [];
    credentials.push(storedCredential);

    await chrome.storage.local.set({ [KEYS.CREDENTIALS]: credentials });

    return storedCredential.id;
  }

  /**
   * Delete a credential
   */
  async deleteCredential(credentialId) {
    const data = await chrome.storage.local.get([KEYS.CREDENTIALS]);
    const credentials = data[KEYS.CREDENTIALS] || [];
    const filtered = credentials.filter(c => c.id !== credentialId);

    await chrome.storage.local.set({ [KEYS.CREDENTIALS]: filtered });
  }

  /**
   * Get trusted issuers
   */
  async getIssuers() {
    const data = await chrome.storage.local.get([KEYS.ISSUERS]);
    return data[KEYS.ISSUERS] || [];
  }

  /**
   * Add a trusted issuer
   */
  async addIssuer(issuer) {
    const data = await chrome.storage.local.get([KEYS.ISSUERS]);
    const issuers = data[KEYS.ISSUERS] || [];
    issuers.push(issuer);

    await chrome.storage.local.set({ [KEYS.ISSUERS]: issuers });
  }

  /**
   * Get wallet settings
   */
  async getSettings() {
    const data = await chrome.storage.local.get([KEYS.SETTINGS]);
    return data[KEYS.SETTINGS] || { autoLockMinutes: 15 };
  }

  /**
   * Update wallet settings
   */
  async updateSettings(settings) {
    const current = await this.getSettings();
    const updated = { ...current, ...settings };

    await chrome.storage.local.set({ [KEYS.SETTINGS]: updated });
  }

  /**
   * Record a used nullifier
   */
  async recordNullifier(nullifier, domain) {
    const data = await chrome.storage.local.get([KEYS.USED_NULLIFIERS]);
    const nullifiers = data[KEYS.USED_NULLIFIERS] || [];

    nullifiers.push({
      nullifier: bytesToBase64(nullifier),
      domain,
      usedAt: Date.now()
    });

    await chrome.storage.local.set({ [KEYS.USED_NULLIFIERS]: nullifiers });
  }

  /**
   * Check if a nullifier has been used for a domain
   */
  async isNullifierUsed(nullifier, domain) {
    const data = await chrome.storage.local.get([KEYS.USED_NULLIFIERS]);
    const nullifiers = data[KEYS.USED_NULLIFIERS] || [];

    const nullifierB64 = bytesToBase64(nullifier);
    return nullifiers.some(n => n.nullifier === nullifierB64 && n.domain === domain);
  }

  /**
   * Get master secret (for proof generation)
   */
  getMasterSecret() {
    this.requireUnlocked();
    return this.masterSecret;
  }

  /**
   * Require wallet to be unlocked
   */
  requireUnlocked() {
    if (!this.isUnlocked) {
      throw new Error('Wallet is locked');
    }
  }
}

// Export singleton instance
export const walletStorage = new WalletStorage();
export { KEYS };
