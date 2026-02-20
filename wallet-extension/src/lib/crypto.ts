/**
 * Cryptographic utilities for Fantasma Wallet
 * Uses the Web Crypto API for browser-native crypto operations.
 */

const AES_KEY_LENGTH = 256;
const AES_IV_LENGTH = 12;       // 96-bit IV for AES-GCM
const AES_TAG_LENGTH = 128;     // 128-bit authentication tag
const PBKDF2_ITERATIONS = 600_000; // OWASP recommendation

// ─── Key Derivation ──────────────────────────────────────────────────────────

/**
 * Derive an AES-GCM encryption key from a password via PBKDF2.
 */
export async function deriveKey(
  password: string,
  salt: Uint8Array
): Promise<CryptoKey> {
  const encoder = new TextEncoder();
  const keyMaterial = await crypto.subtle.importKey(
    'raw',
    encoder.encode(password),
    'PBKDF2',
    false,
    ['deriveKey']
  );

  return crypto.subtle.deriveKey(
    {
      name: 'PBKDF2',
      salt,
      iterations: PBKDF2_ITERATIONS,
      hash: 'SHA-256'
    },
    keyMaterial,
    { name: 'AES-GCM', length: AES_KEY_LENGTH },
    false,
    ['encrypt', 'decrypt']
  );
}

// ─── Encryption ──────────────────────────────────────────────────────────────

/**
 * Encrypt plaintext with AES-GCM. Returns IV || ciphertext.
 */
export async function encrypt(
  key: CryptoKey,
  data: string | Uint8Array
): Promise<Uint8Array> {
  const iv = crypto.getRandomValues(new Uint8Array(AES_IV_LENGTH));
  const encoder = new TextEncoder();
  const plaintext = typeof data === 'string' ? encoder.encode(data) : data;

  const ciphertext = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv, tagLength: AES_TAG_LENGTH },
    key,
    plaintext
  );

  const result = new Uint8Array(iv.length + ciphertext.byteLength);
  result.set(iv);
  result.set(new Uint8Array(ciphertext), iv.length);
  return result;
}

/**
 * Decrypt AES-GCM ciphertext (IV || ciphertext).
 */
export async function decrypt(
  key: CryptoKey,
  encryptedData: Uint8Array
): Promise<Uint8Array> {
  const iv = encryptedData.slice(0, AES_IV_LENGTH);
  const ciphertext = encryptedData.slice(AES_IV_LENGTH);

  const plaintext = await crypto.subtle.decrypt(
    { name: 'AES-GCM', iv, tagLength: AES_TAG_LENGTH },
    key,
    ciphertext
  );

  return new Uint8Array(plaintext);
}

// ─── Hashing ─────────────────────────────────────────────────────────────────

/**
 * Compute SHA-256 digest.
 */
export async function sha256(data: string | Uint8Array): Promise<Uint8Array> {
  const encoder = new TextEncoder();
  const buffer = typeof data === 'string' ? encoder.encode(data) : data;
  const hash = await crypto.subtle.digest('SHA-256', buffer);
  return new Uint8Array(hash);
}

// ─── Salt / Random ───────────────────────────────────────────────────────────

/**
 * Generate a 32-byte random salt.
 */
export function generateSalt(): Uint8Array {
  return crypto.getRandomValues(new Uint8Array(32));
}

/**
 * Generate a 32-byte random nullifier.
 */
export function generateNullifier(): Uint8Array {
  return crypto.getRandomValues(new Uint8Array(32));
}

// ─── Encoding Helpers ────────────────────────────────────────────────────────

export function bytesToBase64(bytes: Uint8Array): string {
  return btoa(String.fromCharCode(...bytes));
}

export function base64ToBytes(base64: string): Uint8Array {
  const binary = atob(base64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes;
}

export function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');
}

export function hexToBytes(hex: string): Uint8Array {
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < hex.length; i += 2) {
    bytes[i / 2] = parseInt(hex.slice(i, i + 2), 16);
  }
  return bytes;
}

/**
 * Generate a domain-specific pseudonym from a master secret.
 */
export async function generatePseudonym(
  masterSecret: Uint8Array,
  domain: string
): Promise<Uint8Array> {
  const encoder = new TextEncoder();
  const data = new Uint8Array([
    ...masterSecret,
    ...encoder.encode(domain)
  ]);
  return sha256(data);
}
