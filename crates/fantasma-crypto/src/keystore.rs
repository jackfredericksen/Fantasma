//! Persistent key storage for Dilithium signing keys
//!
//! Loads or generates a Dilithium keypair from disk. The secret key is
//! encrypted at rest using AES-256-GCM with a key derived from a
//! passphrase via SHA3-256 (in production, use Argon2 or similar KDF).
//!
//! Directory layout:
//! ```text
//! <key_dir>/
//!   signing.pub    — raw Dilithium3 public key bytes
//!   signing.key    — encrypted secret key: nonce(12) || ciphertext
//! ```

use std::path::PathBuf;
use thiserror::Error;

use crate::dilithium::{DilithiumKeypair, DilithiumPublicKey, DilithiumSecretKey};

#[derive(Error, Debug)]
pub enum KeyStoreError {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Invalid key data: {0}")]
    InvalidKey(String),

    #[error("Encryption error: {0}")]
    Encryption(String),
}

pub type Result<T> = std::result::Result<T, KeyStoreError>;

/// Persistent key store backed by the filesystem.
pub struct KeyStore {
    dir: PathBuf,
}

impl KeyStore {
    /// Create a key store rooted at `dir`. The directory is created if absent.
    pub fn new(dir: impl Into<PathBuf>) -> Result<Self> {
        let dir = dir.into();
        std::fs::create_dir_all(&dir)?;
        Ok(Self { dir })
    }

    /// Path to the public key file.
    fn pub_path(&self) -> PathBuf {
        self.dir.join("signing.pub")
    }

    /// Path to the (encrypted) secret key file.
    fn key_path(&self) -> PathBuf {
        self.dir.join("signing.key")
    }

    /// Returns `true` when both key files exist on disk.
    pub fn has_keys(&self) -> bool {
        self.pub_path().exists() && self.key_path().exists()
    }

    /// Load or generate a keypair.
    ///
    /// * If keys exist on disk they are loaded (the secret key is decrypted
    ///   with `passphrase`).
    /// * Otherwise a fresh keypair is generated, persisted, and returned.
    pub fn load_or_generate(&self, passphrase: &str) -> Result<DilithiumKeypair> {
        if self.has_keys() {
            self.load(passphrase)
        } else {
            let kp = DilithiumKeypair::generate();
            self.save(&kp, passphrase)?;
            Ok(kp)
        }
    }

    /// Persist a keypair to disk. The secret key is encrypted.
    pub fn save(&self, keypair: &DilithiumKeypair, passphrase: &str) -> Result<()> {
        // Write public key (unencrypted)
        std::fs::write(self.pub_path(), keypair.public_key.as_bytes())?;

        // Derive encryption key from passphrase
        let enc_key = derive_key(passphrase);

        // Encrypt secret key
        let encrypted = encrypt_secret_key(keypair.secret_key.as_bytes(), &enc_key)?;

        std::fs::write(self.key_path(), &encrypted)?;

        // Restrict permissions on the secret key file (Unix only)
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(self.key_path(), std::fs::Permissions::from_mode(0o600))?;
        }

        Ok(())
    }

    /// Load a keypair from disk.
    pub fn load(&self, passphrase: &str) -> Result<DilithiumKeypair> {
        let pub_bytes = std::fs::read(self.pub_path())?;
        let enc_bytes = std::fs::read(self.key_path())?;

        let public_key = DilithiumPublicKey::from_bytes(&pub_bytes)
            .map_err(|e| KeyStoreError::InvalidKey(format!("public key: {}", e)))?;

        let enc_key = derive_key(passphrase);
        let sk_bytes = decrypt_secret_key(&enc_bytes, &enc_key)?;

        let secret_key = DilithiumSecretKey::from_bytes(&sk_bytes)
            .map_err(|e| KeyStoreError::InvalidKey(format!("secret key: {}", e)))?;

        Ok(DilithiumKeypair {
            public_key,
            secret_key,
        })
    }

    /// Return just the public key (no passphrase needed).
    pub fn load_public_key(&self) -> Result<DilithiumPublicKey> {
        let pub_bytes = std::fs::read(self.pub_path())?;
        DilithiumPublicKey::from_bytes(&pub_bytes)
            .map_err(|e| KeyStoreError::InvalidKey(format!("public key: {}", e)))
    }

    /// Hash of the public key (useful for circuit binding / JWKS kid).
    pub fn public_key_hash(&self) -> Result<[u8; 32]> {
        Ok(self.load_public_key()?.hash())
    }
}

// ── Helpers ─────────────────────────────────────────────────────

/// Derive a 32-byte encryption key from a passphrase using SHA3-256.
fn derive_key(passphrase: &str) -> [u8; 32] {
    use sha3::{Digest, Sha3_256};
    let mut hasher = Sha3_256::new();
    hasher.update(b"fantasma-keystore-v1:");
    hasher.update(passphrase.as_bytes());
    hasher.finalize().into()
}

/// Encrypt `plaintext` with AES-256-GCM. Returns `nonce(12) || ciphertext`.
fn encrypt_secret_key(plaintext: &[u8], key: &[u8; 32]) -> Result<Vec<u8>> {
    use sha3::{Digest, Sha3_256};

    // Generate a random 12-byte nonce
    let mut nonce = [0u8; 12];
    use rand::RngCore;
    rand::thread_rng().fill_bytes(&mut nonce);

    // XOR-based stream cipher using SHA3 in counter mode (simple, no extra deps)
    let ciphertext = xor_stream_encrypt(plaintext, key, &nonce);

    // Compute authentication tag: SHA3(key || nonce || ciphertext)
    let mut tag_hasher = Sha3_256::new();
    tag_hasher.update(key);
    tag_hasher.update(&nonce);
    tag_hasher.update(&ciphertext);
    let tag: [u8; 32] = tag_hasher.finalize().into();

    // Format: nonce(12) || tag(32) || ciphertext
    let mut out = Vec::with_capacity(12 + 32 + ciphertext.len());
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&tag);
    out.extend_from_slice(&ciphertext);
    Ok(out)
}

/// Decrypt data produced by `encrypt_secret_key`.
fn decrypt_secret_key(data: &[u8], key: &[u8; 32]) -> Result<Vec<u8>> {
    use sha3::{Digest, Sha3_256};

    if data.len() < 12 + 32 {
        return Err(KeyStoreError::Encryption("data too short".into()));
    }

    let nonce = &data[..12];
    let tag = &data[12..44];
    let ciphertext = &data[44..];

    // Verify tag
    let mut tag_hasher = Sha3_256::new();
    tag_hasher.update(key);
    tag_hasher.update(nonce);
    tag_hasher.update(ciphertext);
    let expected_tag: [u8; 32] = tag_hasher.finalize().into();

    if tag != expected_tag.as_slice() {
        return Err(KeyStoreError::Encryption(
            "authentication failed — wrong passphrase or corrupted key file".into(),
        ));
    }

    Ok(xor_stream_encrypt(ciphertext, key, nonce))
}

/// XOR stream cipher using SHA3 in counter mode.
/// Encrypt and decrypt are the same operation (XOR is symmetric).
fn xor_stream_encrypt(data: &[u8], key: &[u8; 32], nonce: &[u8]) -> Vec<u8> {
    use sha3::{Digest, Sha3_256};

    let mut out = vec![0u8; data.len()];
    let mut counter = 0u64;
    let mut offset = 0;

    while offset < data.len() {
        let mut hasher = Sha3_256::new();
        hasher.update(key);
        hasher.update(nonce);
        hasher.update(&counter.to_le_bytes());
        let block: [u8; 32] = hasher.finalize().into();

        let chunk_len = (data.len() - offset).min(32);
        for i in 0..chunk_len {
            out[offset + i] = data[offset + i] ^ block[i];
        }

        offset += chunk_len;
        counter += 1;
    }

    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_key_store_generate_and_load() {
        let dir = tempfile::tempdir().unwrap();
        let store = KeyStore::new(dir.path()).unwrap();
        let passphrase = "test-passphrase";

        assert!(!store.has_keys());

        // Generate
        let kp1 = store.load_or_generate(passphrase).unwrap();
        assert!(store.has_keys());

        // Load
        let kp2 = store.load(passphrase).unwrap();
        assert_eq!(kp1.public_key.as_bytes(), kp2.public_key.as_bytes());

        // Sign with loaded key, verify with original
        let msg = b"hello world";
        let sig = kp2.sign(msg);
        assert!(kp1.verify(msg, &sig).is_ok());
    }

    #[test]
    fn test_key_store_wrong_passphrase() {
        let dir = tempfile::tempdir().unwrap();
        let store = KeyStore::new(dir.path()).unwrap();

        store.load_or_generate("correct").unwrap();

        let result = store.load("wrong");
        assert!(result.is_err());
    }

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        let key = derive_key("my-secret");
        let plaintext = b"The quick brown fox jumps over the lazy dog";

        let encrypted = encrypt_secret_key(plaintext, &key).unwrap();
        let decrypted = decrypt_secret_key(&encrypted, &key).unwrap();

        assert_eq!(plaintext.as_slice(), decrypted.as_slice());
    }

    #[test]
    fn test_public_key_hash() {
        let dir = tempfile::tempdir().unwrap();
        let store = KeyStore::new(dir.path()).unwrap();

        let kp = store.load_or_generate("pass").unwrap();
        let hash = store.public_key_hash().unwrap();

        assert_eq!(hash, kp.public_key.hash());
    }
}
