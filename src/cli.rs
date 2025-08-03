use clap::{Parser, Subcommand};
use std::path::PathBuf;

use crate::crypto::Algorithm;

#[derive(Parser)]
#[command(name = "secure-vault")]
#[command(author = "Your Name <your.email@example.com>")]
#[command(version = "0.1.0")]
#[command(about = "A secure file encryption/decryption tool", long_about = None)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand)]
pub enum Commands {
    /// Encrypt a file
    Encrypt {
        /// Input file to encrypt
        #[arg(value_name = "FILE")]
        input: PathBuf,
        
        /// Output file path
        #[arg(short, long, value_name = "FILE")]
        output: PathBuf,
        
        /// Encryption algorithm to use
        #[arg(short, long, default_value = "aes256gcm")]
        algorithm: Algorithm,
        
        /// KDF iterations (higher = more secure but slower)
        #[arg(short, long, default_value = "3")]
        iterations: u32,
        
        /// Force overwrite if output file exists
        #[arg(short, long)]
        force: bool,
        
        /// Verbose output
        #[arg(short, long)]
        verbose: bool,
    },
    
    /// Decrypt a file
    Decrypt {
        /// Input file to decrypt
        #[arg(value_name = "FILE")]
        input: PathBuf,
        
        /// Output file path
        #[arg(short, long, value_name = "FILE")]
        output: PathBuf,
        
        /// Force overwrite if output file exists
        #[arg(short, long)]
        force: bool,
        
        /// Verbose output
        #[arg(short, long)]
        verbose: bool,
    },
}
