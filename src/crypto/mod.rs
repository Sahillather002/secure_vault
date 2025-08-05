mod aes;
mod chacha;
mod kdf;
mod types;

pub use types::{Algorithm, CryptoEngine};

use anyhow::Result;
use std::path::Path;
use zeroize::Zeroizing;

use crate::error::VaultError;

/// File format version
pub const VERSION: u8 = 1;

/// Salt size for key derivation
pub const SALT_SIZE: usize = 32;

/// Chunk size for streaming encryption (1 MB)
pub const CHUNK_SIZE: usize = 1024 * 1024;

impl CryptoEngine {
    /// Create a new crypto engine
    pub fn new(algorithm: Algorithm, iterations: u32) -> Self {
        Self {
            algorithm,
            iterations,
        }
    }
    
    /// Encrypt a file
    pub async fn encrypt_file(
        &self,
        input: &Path,
        output: &Path,
        password: &Zeroizing<String>,
    ) -> Result<()> {
        if !input.exists() {
            return Err(VaultError::InputNotFound(input.to_path_buf()).into());
        }
        
        match self.algorithm {
            Algorithm::Aes256Gcm => {
                aes::encrypt_file(input, output, password, self.iterations).await
            }
            Algorithm::ChaCha20Poly1305 => {
                chacha::encrypt_file(input, output, password, self.iterations).await
            }
        }
    }
    
    /// Decrypt a file
    pub async fn decrypt_file(
        input: &Path,
        output: &Path,
        password: &Zeroizing<String>,
    ) -> Result<()> {
        if !input.exists() {
            return Err(VaultError::InputNotFound(input.to_path_buf()).into());
        }
        
        // Read header to determine algorithm
        let mut file = tokio::fs::File::open(input).await?;
        use tokio::io::AsyncReadExt;
        
        let mut header = [0u8; 2];
        file.read_exact(&mut header).await?;
        
        let version = header[0];
        let algorithm_byte = header[1];
        
        if version != VERSION {
            return Err(VaultError::UnsupportedVersion(version).into());
        }
        
        let algorithm = Algorithm::from_byte(algorithm_byte)
            .ok_or(VaultError::UnsupportedAlgorithm(algorithm_byte))?;
        
        drop(file);
        
        match algorithm {
            Algorithm::Aes256Gcm => {
                aes::decrypt_file(input, output, password).await
            }
            Algorithm::ChaCha20Poly1305 => {
                chacha::decrypt_file(input, output, password).await
            }
        }
    }
}
