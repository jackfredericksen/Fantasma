/**
 * Encrypted credential storage for Fantasma Wallet.
 * Uses chrome.storage.local with AES-GCM encryption via Web Crypto.
 */

import browser from 'webextension-polyfill';
import {
  deriveKey,
  encrypt,
  decrypt,
  generateSalt,
  bytesToBase64,
  base64ToBytes
} from './crypto';
import type {
  StoredCredential,
  DecryptedCredential,
  CredentialImportData,
  WalletSettings
} from './types';

// ─── Storage Keys ────────────────────────────────────────────────────────────

const KEYS = {
  MASTER_KEY_SALT: 'fantasma_master_key_salt',
  ENCRYPTED_MASTER_SECRET: 'fantasma_encrypted_master_secret',
  CREDENTIALS: 'fantasma_credentials',
  SETTINGS: 'fantasma_settings'
} as const;

const DEFAULT_SETTINGS: WalletSettings = {
  serverUrl: 'http://localhost:3000',
  autoLockMinutes: 15
};

// ─── Module State ────────────────────────────────────────────────────────────

let encryptionKey: CryptoKey | null = null;
let masterSecret: Uint8Array | null = null;
let locked = true;

// ─── Initialization & Locking ────────────────────────────────────────────────

/**
 * Check whether the wallet has been set up (a master secret exists).
 */
export async function isInitialized(): Promise<boolean> {
  const data = await browser.storage.local.get(KEYS.ENCRYPTED_MASTER_SECRET);
  return !!data[KEYS.ENCRYPTED_MASTER_SECRET];
}

/**
 * First-time wallet setup. Generates a master secret, encrypts it with
 * a key derived from the user's password, and stores everything.
 */
export async function initialize(password: string): Promise<void> {
  const salt = generateSalt();
  const secret = crypto.getRandomValues(new Uint8Array(32));

  encryptionKey = await deriveKey(password, salt);
  const encryptedSecret = await encrypt(encryptionKey, secret);

  await browser.storage.local.set({
    [KEYS.MASTER_KEY_SALT]: bytesToBase64(salt),
    [KEYS.ENCRYPTED_MASTER_SECRET]: bytesToBase64(encryptedSecret),
    [KEYS.CREDENTIALS]: [],
    [KEYS.SETTINGS]: DEFAULT_SETTINGS
  });

  masterSecret = secret;
  locked = false;
}

/**
 * Unlock the wallet by deriving the encryption key from the password
 * and decrypting the master secret.
 */
export async function unlock(password: string): Promise<void> {
  const data = await browser.storage.local.get([
    KEYS.MASTER_KEY_SALT,
    KEYS.ENCRYPTED_MASTER_SECRET
  ]);

  const saltB64 = data[KEYS.MASTER_KEY_SALT] as string | undefined;
  const encSecretB64 = data[KEYS.ENCRYPTED_MASTER_SECRET] as string | undefined;

  if (!saltB64 || !encSecretB64) {
    throw new Error('Wallet not initialized');
  }

  const salt = base64ToBytes(saltB64);
  const encryptedSecret = base64ToBytes(encSecretB64);
  const derivedKey = await deriveKey(password, salt);

  try {
    masterSecret = await decrypt(derivedKey, encryptedSecret);
    encryptionKey = derivedKey;
    locked = false;
  } catch {
    encryptionKey = null;
    masterSecret = null;
    throw new Error('Invalid password');
  }
}

/**
 * Lock the wallet, clearing all in-memory secrets.
 */
export function lock(): void {
  encryptionKey = null;
  masterSecret = null;
  locked = true;
}

export function isLocked(): boolean {
  return locked;
}

export function getMasterSecret(): Uint8Array {
  requireUnlocked();
  return masterSecret!;
}

// ─── Credential CRUD ─────────────────────────────────────────────────────────

/**
 * Save (import) a new credential. The sensitive attributes are encrypted
 * before being persisted.
 */
export async function saveCredential(
  importData: CredentialImportData
): Promise<string> {
  requireUnlocked();

  const id = crypto.randomUUID();
  const now = new Date().toISOString();

  const sensitivePayload = JSON.stringify({
    attributes: importData.attributes,
    birthdate: importData.birthdate,
    signature: importData.signature
  });

  const ciphertext = await encrypt(encryptionKey!, sensitivePayload);

  const stored: StoredCredential = {
    id,
    type: importData.type,
    issuerName: importData.issuerName,
    issuedAt: now,
    expiresAt: importData.expiresAt,
    encryptedData: bytesToBase64(ciphertext),
    commitment: importData.commitment
  };

  const data = await browser.storage.local.get(KEYS.CREDENTIALS);
  const credentials = (data[KEYS.CREDENTIALS] as StoredCredential[]) || [];
  credentials.push(stored);
  await browser.storage.local.set({ [KEYS.CREDENTIALS]: credentials });

  return id;
}

/**
 * Retrieve all credentials, decrypting the sensitive payload of each.
 */
export async function getCredentials(): Promise<DecryptedCredential[]> {
  requireUnlocked();

  const data = await browser.storage.local.get(KEYS.CREDENTIALS);
  const credentials = (data[KEYS.CREDENTIALS] as StoredCredential[]) || [];

  const decrypted: DecryptedCredential[] = [];

  for (const cred of credentials) {
    try {
      const cipherBytes = base64ToBytes(cred.encryptedData);
      const plainBytes = await decrypt(encryptionKey!, cipherBytes);
      const decoder = new TextDecoder();
      const sensitive = JSON.parse(decoder.decode(plainBytes)) as {
        attributes: Record<string, unknown>;
        birthdate?: string;
        signature?: string;
      };

      decrypted.push({
        id: cred.id,
        type: cred.type,
        issuerName: cred.issuerName,
        issuedAt: cred.issuedAt,
        expiresAt: cred.expiresAt,
        commitment: cred.commitment,
        attributes: sensitive.attributes,
        birthdate: sensitive.birthdate,
        signature: sensitive.signature
      });
    } catch (err) {
      console.error(`Failed to decrypt credential ${cred.id}:`, err);
    }
  }

  return decrypted;
}

/**
 * Retrieve stored (still-encrypted) credential metadata.
 */
export async function getStoredCredentials(): Promise<StoredCredential[]> {
  const data = await browser.storage.local.get(KEYS.CREDENTIALS);
  return (data[KEYS.CREDENTIALS] as StoredCredential[]) || [];
}

/**
 * Delete a credential by id.
 */
export async function deleteCredential(credentialId: string): Promise<void> {
  const data = await browser.storage.local.get(KEYS.CREDENTIALS);
  const credentials = (data[KEYS.CREDENTIALS] as StoredCredential[]) || [];
  const filtered = credentials.filter((c) => c.id !== credentialId);
  await browser.storage.local.set({ [KEYS.CREDENTIALS]: filtered });
}

// ─── Settings ────────────────────────────────────────────────────────────────

export async function getSettings(): Promise<WalletSettings> {
  const data = await browser.storage.local.get(KEYS.SETTINGS);
  return (data[KEYS.SETTINGS] as WalletSettings) ?? DEFAULT_SETTINGS;
}

export async function updateSettings(
  partial: Partial<WalletSettings>
): Promise<void> {
  const current = await getSettings();
  const updated = { ...current, ...partial };
  await browser.storage.local.set({ [KEYS.SETTINGS]: updated });
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

function requireUnlocked(): void {
  if (locked || !encryptionKey) {
    throw new Error('Wallet is locked');
  }
}
