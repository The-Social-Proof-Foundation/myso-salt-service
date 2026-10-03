pub mod access_token;
pub mod jwt;
pub mod session_token;
pub mod wallet_signature;

use anyhow::Result;
use chacha20poly1305::{
    aead::{Aead, KeyInit, OsRng},
    ChaCha20Poly1305, Key, Nonce,
};
use rand::RngCore;
use sha2::{Digest, Sha256};
use base64::{Engine as _, engine::general_purpose};

const NONCE_SIZE: usize = 12;

#[derive(Clone)]
pub struct SaltManager {
    encryption_key: Key,
}

impl SaltManager {
    /// Create a new SaltManager with the provided master seed
    pub fn new(master_seed: Vec<u8>) -> Result<Self> {
        if master_seed.len() < 32 {
            anyhow::bail!("Master seed must be at least 32 bytes");
        }

        // Derive encryption key from master seed
        let mut hasher = <Sha256 as Digest>::new();
        hasher.update(b"MYSOCIAL_ENCRYPTION_KEY_V1");
        hasher.update(&master_seed);
        let key_bytes = hasher.finalize();
        let encryption_key = Key::from_slice(&key_bytes);

        Ok(Self {
            encryption_key: *encryption_key,
        })
    }

    /// Encrypt salt for storage
    pub fn encrypt_salt(&self, salt: &[u8]) -> Result<Vec<u8>> {
        let cipher = ChaCha20Poly1305::new(&self.encryption_key);
        
        // Generate random nonce
        let mut nonce_bytes = [0u8; NONCE_SIZE];
        OsRng.fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);
        
        // Encrypt the salt
        let ciphertext = cipher
            .encrypt(nonce, salt)
            .map_err(|e| anyhow::anyhow!("Encryption failed: {:?}", e))?;
        
        // Prepend nonce to ciphertext
        let mut result = nonce_bytes.to_vec();
        result.extend_from_slice(&ciphertext);
        
        Ok(result)
    }

    /// Decrypt salt from storage
    pub fn decrypt_salt(&self, encrypted: &[u8]) -> Result<Vec<u8>> {
        if encrypted.len() < NONCE_SIZE {
            anyhow::bail!("Encrypted data too short");
        }

        let cipher = ChaCha20Poly1305::new(&self.encryption_key);
        
        // Extract nonce and ciphertext
        let (nonce_bytes, ciphertext) = encrypted.split_at(NONCE_SIZE);
        let nonce = Nonce::from_slice(nonce_bytes);
        
        // Decrypt
        let salt = cipher
            .decrypt(nonce, ciphertext)
            .map_err(|e| anyhow::anyhow!("Decryption failed: {:?}", e))?;
        
        Ok(salt)
    }
}

/// Generate a secure random master seed
#[allow(dead_code)]
pub fn generate_master_seed() -> Vec<u8> {
    let mut seed = vec![0u8; 64]; // 512 bits
    OsRng.fill_bytes(&mut seed);
    seed
}

/// Hash a token (JWT or access token) for audit logging
pub fn hash_token_for_audit(token: &str) -> String {
    let mut hasher = <Sha256 as Digest>::new();
    hasher.update(token.as_bytes());
    general_purpose::STANDARD.encode(hasher.finalize())
}

/// Hash a JWT for audit logging (backward compatibility)
#[deprecated(note = "Use hash_token_for_audit instead")]
pub fn hash_jwt_for_audit(jwt: &str) -> String {
    hash_token_for_audit(jwt)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_salt_encryption_decryption() {
        let seed = generate_master_seed();
        let manager = SaltManager::new(seed).unwrap();
        
        let salt = b"test-salt-value";
        let encrypted = manager.encrypt_salt(salt).unwrap();
        let decrypted = manager.decrypt_salt(&encrypted).unwrap();
        
        assert_eq!(salt.to_vec(), decrypted, "Encryption/decryption roundtrip should work");
    }
}
