/**
 * Cryptographic utilities for Fantasma Wallet
 * Uses Web Crypto API for browser-native crypto operations
 */

// AES-GCM parameters
const AES_KEY_LENGTH = 256;
const AES_IV_LENGTH = 12;
const AES_TAG_LENGTH = 128;

/**
 * Derive an encryption key from a password using PBKDF2
 */
export async function deriveKey(password, salt) {
  const encoder = new TextEncoder();
  const passwordBuffer = encoder.encode(password);

  // Import password as raw key material
  const keyMaterial = await crypto.subtle.importKey(
    'raw',
    passwordBuffer,
    'PBKDF2',
    false,
    ['deriveKey']
  );

  // Derive AES-GCM key
  return crypto.subtle.deriveKey(
    {
      name: 'PBKDF2',
      salt: salt,
      iterations: 600000, // OWASP recommendation
      hash: 'SHA-256'
    },
    keyMaterial,
    {
      name: 'AES-GCM',
      length: AES_KEY_LENGTH
    },
    false,
    ['encrypt', 'decrypt']
  );
}

/**
 * Generate a random salt for key derivation
 */
export function generateSalt() {
  return crypto.getRandomValues(new Uint8Array(32));
}

/**
 * Encrypt data with AES-GCM
 */
export async function encrypt(key, data) {
  const iv = crypto.getRandomValues(new Uint8Array(AES_IV_LENGTH));
  const encoder = new TextEncoder();
  const dataBuffer = typeof data === 'string' ? encoder.encode(data) : data;

  const ciphertext = await crypto.subtle.encrypt(
    {
      name: 'AES-GCM',
      iv: iv,
      tagLength: AES_TAG_LENGTH
    },
    key,
    dataBuffer
  );

  // Combine IV + ciphertext
  const result = new Uint8Array(iv.length + ciphertext.byteLength);
  result.set(iv);
  result.set(new Uint8Array(ciphertext), iv.length);

  return result;
}

/**
 * Decrypt data with AES-GCM
 */
export async function decrypt(key, encryptedData) {
  const iv = encryptedData.slice(0, AES_IV_LENGTH);
  const ciphertext = encryptedData.slice(AES_IV_LENGTH);

  const plaintext = await crypto.subtle.decrypt(
    {
      name: 'AES-GCM',
      iv: iv,
      tagLength: AES_TAG_LENGTH
    },
    key,
    ciphertext
  );

  return new Uint8Array(plaintext);
}

/**
 * Hash data using SHA-256
 */
export async function sha256(data) {
  const encoder = new TextEncoder();
  const dataBuffer = typeof data === 'string' ? encoder.encode(data) : data;
  const hashBuffer = await crypto.subtle.digest('SHA-256', dataBuffer);
  return new Uint8Array(hashBuffer);
}

/**
 * Generate a random nullifier
 */
export function generateNullifier() {
  return crypto.getRandomValues(new Uint8Array(32));
}

/**
 * Generate a pseudonymous user ID for a specific domain
 */
export async function generatePseudonym(masterSecret, domain) {
  const encoder = new TextEncoder();
  const data = new Uint8Array([
    ...masterSecret,
    ...encoder.encode(domain)
  ]);
  return sha256(data);
}

/**
 * Convert bytes to hex string
 */
export function bytesToHex(bytes) {
  return Array.from(bytes)
    .map(b => b.toString(16).padStart(2, '0'))
    .join('');
}

/**
 * Convert hex string to bytes
 */
export function hexToBytes(hex) {
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < hex.length; i += 2) {
    bytes[i / 2] = parseInt(hex.slice(i, i + 2), 16);
  }
  return bytes;
}

/**
 * Convert bytes to base64
 */
export function bytesToBase64(bytes) {
  return btoa(String.fromCharCode(...bytes));
}

/**
 * Convert base64 to bytes
 */
export function base64ToBytes(base64) {
  const binary = atob(base64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes;
}
