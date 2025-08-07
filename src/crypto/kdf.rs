use anyhow::Result;
use argon2::{
    password_hash::{PasswordHasher, SaltString},
    Argon2, ParamsBuilder, Version,
};
use zeroize::Zeroizing;

use crate::error::VaultError;

/// Derive encryption key from password using Argon2id
pub fn derive_key(
    password: &Zeroizing<String>,
    salt: &[u8],
    iterations: u32,
) -> Result<Zeroizing<Vec<u8>>> {
    // Configure Argon2id parameters
    let params = ParamsBuilder::new()
        .m_cost(65536) // 64 MB memory
        .t_cost(iterations) // iterations
        .p_cost(4) // 4 parallel threads
        .output_len(32) // 32 bytes = 256 bits
        .build()
        .map_err(|e| VaultError::KdfError(e.to_string()))?;
    
    let argon2 = Argon2::new(
        argon2::Algorithm::Argon2id,
        Version::V0x13,
        params,
    );
    
    // Create salt string from bytes
    let salt_string = SaltString::encode_b64(salt)
        .map_err(|e| VaultError::KdfError(e.to_string()))?;
    
    // Derive key
    let password_hash = argon2
        .hash_password(password.as_bytes(), &salt_string)
        .map_err(|e| VaultError::KdfError(e.to_string()))?;
    
    // Extract the hash bytes
    let hash = password_hash
        .hash
        .ok_or_else(|| VaultError::KdfError("No hash produced".to_string()))?;
    
    Ok(Zeroizing::new(hash.as_bytes().to_vec()))
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_derive_key() {
        let password = Zeroizing::new("test_password".to_string());
        let salt = b"test_salt_32_bytes_long_exactly!";
        
        let key = derive_key(&password, salt, 1).unwrap();
        
        assert_eq!(key.len(), 32);
    }
    
    #[test]
    fn test_derive_key_deterministic() {
        let password = Zeroizing::new("test_password".to_string());
        let salt = b"test_salt_32_bytes_long_exactly!";
        
        let key1 = derive_key(&password, salt, 1).unwrap();
        let key2 = derive_key(&password, salt, 1).unwrap();
        
        assert_eq!(*key1, *key2);
    }
    
    #[test]
    fn test_derive_key_different_passwords() {
        let password1 = Zeroizing::new("password1".to_string());
        let password2 = Zeroizing::new("password2".to_string());
        let salt = b"test_salt_32_bytes_long_exactly!";
        
        let key1 = derive_key(&password1, salt, 1).unwrap();
        let key2 = derive_key(&password2, salt, 1).unwrap();
        
        assert_ne!(*key1, *key2);
    }
}
