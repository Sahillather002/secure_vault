use std::path::PathBuf;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum VaultError {
    #[error("Output file already exists: {0}. Use --force to overwrite")]
    OutputExists(PathBuf),
    
    #[error("Input file not found: {0}")]
    InputNotFound(PathBuf),
    
    #[error("Failed to read file: {0}")]
    FileReadError(String),
    
    #[error("Failed to write file: {0}")]
    FileWriteError(String),
    
    #[error("Encryption failed: {0}")]
    EncryptionError(String),
    
    #[error("Decryption failed: {0}")]
    DecryptionError(String),
    
    #[error("Invalid file format: {0}")]
    InvalidFormat(String),
    
    #[error("Unsupported version: {0}")]
    UnsupportedVersion(u8),
    
    #[error("Unsupported algorithm: {0}")]
    UnsupportedAlgorithm(u8),
    
    #[error("Password required")]
    PasswordRequired,
    
    #[error("Invalid password or corrupted file")]
    AuthenticationFailed,
    
    #[error("Key derivation failed: {0}")]
    KdfError(String),
    
    #[error("IO error: {0}")]
    IoError(#[from] std::io::Error),
}
