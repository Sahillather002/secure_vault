use clap::ValueEnum;
use serde::{Deserialize, Serialize};

/// Supported encryption algorithms
#[derive(Debug, Clone, Copy, ValueEnum, Serialize, Deserialize)]
pub enum Algorithm {
    /// AES-256-GCM (default)
    #[value(name = "aes256gcm")]
    Aes256Gcm,
    
    /// ChaCha20-Poly1305
    #[value(name = "chacha20")]
    ChaCha20Poly1305,
}

impl Algorithm {
    /// Convert algorithm to byte representation
    pub fn to_byte(&self) -> u8 {
        match self {
            Algorithm::Aes256Gcm => 1,
            Algorithm::ChaCha20Poly1305 => 2,
        }
    }
    
    /// Convert byte to algorithm
    pub fn from_byte(byte: u8) -> Option<Self> {
        match byte {
            1 => Some(Algorithm::Aes256Gcm),
            2 => Some(Algorithm::ChaCha20Poly1305),
            _ => None,
        }
    }
    
    /// Get nonce size for algorithm
    pub fn nonce_size(&self) -> usize {
        match self {
            Algorithm::Aes256Gcm => 12,
            Algorithm::ChaCha20Poly1305 => 24,
        }
    }
    
    /// Get tag size for algorithm
    pub fn tag_size(&self) -> usize {
        16 // Both algorithms use 16-byte tags
    }
}

/// Crypto engine configuration
pub struct CryptoEngine {
    pub algorithm: Algorithm,
    pub iterations: u32,
}

/// Key material (will be zeroized on drop)
pub struct KeyMaterial {
    pub key: Vec<u8>,
}

impl Drop for KeyMaterial {
    fn drop(&mut self) {
        use zeroize::Zeroize;
        self.key.zeroize();
    }
}
