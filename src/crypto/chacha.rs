use anyhow::Result;
use rand::RngCore;
use ring::aead::{Aad, BoundKey, Nonce, NonceSequence, OpeningKey, SealingKey, UnboundKey, CHACHA20_POLY1305};
use ring::error::Unspecified;
use std::path::Path;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use zeroize::Zeroizing;

use super::{kdf, CHUNK_SIZE, SALT_SIZE, VERSION};
use crate::crypto::Algorithm;
use crate::error::VaultError;

/// Custom nonce sequence for ChaCha20
struct CounterNonceSequence {
    counter: u64,
}

impl CounterNonceSequence {
    fn new() -> Self {
        Self { counter: 0 }
    }
}

impl NonceSequence for CounterNonceSequence {
    fn advance(&mut self) -> Result<Nonce, Unspecified> {
        let mut nonce_bytes = [0u8; 12];
        nonce_bytes[4..].copy_from_slice(&self.counter.to_le_bytes());
        self.counter += 1;
        Nonce::try_assume_unique_for_key(&nonce_bytes)
    }
}

/// Encrypt a file using ChaCha20-Poly1305
pub async fn encrypt_file(
    input: &Path,
    output: &Path,
    password: &Zeroizing<String>,
    iterations: u32,
) -> Result<()> {
    // Generate random salt
    let mut salt = vec![0u8; SALT_SIZE];
    rand::thread_rng().fill_bytes(&mut salt);
    
    // Derive key from password
    let key = kdf::derive_key(password, &salt, iterations)?;
    
    // Generate random nonce (ChaCha20 uses 12 bytes with ring)
    let mut nonce = [0u8; 12];
    rand::thread_rng().fill_bytes(&mut nonce);
    
    // Open input file
    let mut input_file = tokio::fs::File::open(input).await?;
    
    // Create output file
    let mut output_file = tokio::fs::File::create(output).await?;
    
    // Write header: version (1 byte) + algorithm (1 byte) + salt + nonce
    output_file.write_u8(VERSION).await?;
    output_file.write_u8(Algorithm::ChaCha20Poly1305.to_byte()).await?;
    output_file.write_all(&salt).await?;
    output_file.write_all(&nonce).await?;
    
    // Create sealing key
    let unbound_key = UnboundKey::new(&CHACHA20_POLY1305, &key)
        .map_err(|_| VaultError::EncryptionError("Failed to create key".to_string()))?;
    
    let nonce_sequence = CounterNonceSequence::new();
    let mut sealing_key = SealingKey::new(unbound_key, nonce_sequence);
    
    // Encrypt file in chunks
    let mut buffer = vec![0u8; CHUNK_SIZE];
    
    loop {
        let bytes_read = input_file.read(&mut buffer).await?;
        if bytes_read == 0 {
            break;
        }
        
        let mut in_out = buffer[..bytes_read].to_vec();
        
        sealing_key
            .seal_in_place_append_tag(Aad::empty(), &mut in_out)
            .map_err(|_| VaultError::EncryptionError("Encryption failed".to_string()))?;
        
        // Write chunk size (4 bytes) + encrypted chunk
        output_file.write_u32(in_out.len() as u32).await?;
        output_file.write_all(&in_out).await?;
    }
    
    output_file.flush().await?;
    
    Ok(())
}

/// Decrypt a file using ChaCha20-Poly1305
pub async fn decrypt_file(
    input: &Path,
    output: &Path,
    password: &Zeroizing<String>,
) -> Result<()> {
    // Open input file
    let mut input_file = tokio::fs::File::open(input).await?;
    
    // Read header
    let version = input_file.read_u8().await?;
    if version != VERSION {
        return Err(VaultError::UnsupportedVersion(version).into());
    }
    
    let algorithm_byte = input_file.read_u8().await?;
    if algorithm_byte != Algorithm::ChaCha20Poly1305.to_byte() {
        return Err(VaultError::InvalidFormat("Wrong algorithm".to_string()).into());
    }
    
    // Read salt
    let mut salt = vec![0u8; SALT_SIZE];
    input_file.read_exact(&mut salt).await?;
    
    // Read nonce
    let mut nonce = [0u8; 12];
    input_file.read_exact(&mut nonce).await?;
    
    // Derive key from password
    let key = kdf::derive_key(password, &salt, 3)?; // Use default iterations for decryption
    
    // Create opening key
    let unbound_key = UnboundKey::new(&CHACHA20_POLY1305, &key)
        .map_err(|_| VaultError::DecryptionError("Failed to create key".to_string()))?;
    
    let nonce_sequence = CounterNonceSequence::new();
    let mut opening_key = OpeningKey::new(unbound_key, nonce_sequence);
    
    // Create output file
    let mut output_file = tokio::fs::File::create(output).await?;
    
    // Decrypt file in chunks
    loop {
        // Read chunk size
        let chunk_size = match input_file.read_u32().await {
            Ok(size) => size as usize,
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => break,
            Err(e) => return Err(e.into()),
        };
        
        // Read encrypted chunk
        let mut encrypted_chunk = vec![0u8; chunk_size];
        input_file.read_exact(&mut encrypted_chunk).await?;
        
        // Decrypt chunk
        let decrypted = opening_key
            .open_in_place(Aad::empty(), &mut encrypted_chunk)
            .map_err(|_| VaultError::AuthenticationFailed)?;
        
        // Write decrypted data
        output_file.write_all(decrypted).await?;
    }
    
    output_file.flush().await?;
    
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::NamedTempFile;
    use tokio::io::AsyncWriteExt;
    
    #[tokio::test]
    async fn test_encrypt_decrypt_round_trip() {
        let password = Zeroizing::new("test_password".to_string());
        
        // Create temp input file
        let input_file = NamedTempFile::new().unwrap();
        let input_path = input_file.path();
        
        let test_data = b"Hello, World! This is a test with ChaCha20.";
        let mut file = tokio::fs::File::create(input_path).await.unwrap();
        file.write_all(test_data).await.unwrap();
        file.flush().await.unwrap();
        drop(file);
        
        // Create temp output files
        let encrypted_file = NamedTempFile::new().unwrap();
        let encrypted_path = encrypted_file.path();
        
        let decrypted_file = NamedTempFile::new().unwrap();
        let decrypted_path = decrypted_file.path();
        
        // Encrypt
        encrypt_file(input_path, encrypted_path, &password, 1)
            .await
            .unwrap();
        
        // Decrypt
        decrypt_file(encrypted_path, decrypted_path, &password)
            .await
            .unwrap();
        
        // Verify
        let decrypted_data = tokio::fs::read(decrypted_path).await.unwrap();
        assert_eq!(test_data, &decrypted_data[..]);
    }
}
