use anyhow::Result;
use clap::Parser;

mod cli;
mod crypto;
mod error;
mod utils;

use cli::{Cli, Commands};
use crypto::CryptoEngine;
use error::VaultError;

#[tokio::main]
async fn main() -> Result<()> {
    env_logger::init();
    
    let cli = Cli::parse();
    
    match cli.command {
        Commands::Encrypt {
            input,
            output,
            algorithm,
            iterations,
            force,
            verbose,
        } => {
            if verbose {
                println!("🔐 SecureVault - File Encryption");
                println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
                println!("Input:     {}", input.display());
                println!("Output:    {}", output.display());
                println!("Algorithm: {:?}", algorithm);
                println!("KDF Iterations: {}", iterations);
                println!();
            }
            
            // Check if output exists
            if output.exists() && !force {
                return Err(VaultError::OutputExists(output).into());
            }
            
            // Get password
            let password = utils::get_password("Enter encryption password: ")?;
            
            // Create crypto engine
            let engine = CryptoEngine::new(algorithm, iterations);
            
            // Encrypt file
            if verbose {
                println!("⏳ Encrypting...");
            }
            
            engine.encrypt_file(&input, &output, &password).await?;
            
            if verbose {
                println!("✅ Encryption complete!");
                println!("📁 Encrypted file: {}", output.display());
            } else {
                println!("✅ File encrypted successfully");
            }
        }
        
        Commands::Decrypt {
            input,
            output,
            force,
            verbose,
        } => {
            if verbose {
                println!("🔓 SecureVault - File Decryption");
                println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
                println!("Input:  {}", input.display());
                println!("Output: {}", output.display());
                println!();
            }
            
            // Check if output exists
            if output.exists() && !force {
                return Err(VaultError::OutputExists(output).into());
            }
            
            // Get password
            let password = utils::get_password("Enter decryption password: ")?;
            
            if verbose {
                println!("⏳ Decrypting...");
            }
            
            // Decrypt file
            CryptoEngine::decrypt_file(&input, &output, &password).await?;
            
            if verbose {
                println!("✅ Decryption complete!");
                println!("📁 Decrypted file: {}", output.display());
            } else {
                println!("✅ File decrypted successfully");
            }
        }
    }
    
    Ok(())
}
