use anyhow::Result;
use std::io::{self, Write};
use zeroize::Zeroizing;

use crate::error::VaultError;

/// Get password from user or environment variable
pub fn get_password(prompt: &str) -> Result<Zeroizing<String>> {
    // Try environment variable first (more secure for scripts)
    if let Ok(password) = std::env::var("VAULT_PASSWORD") {
        return Ok(Zeroizing::new(password));
    }
    
    // Prompt user
    print!("{}", prompt);
    io::stdout().flush()?;
    
    let password = rpassword::read_password()?;
    
    if password.is_empty() {
        return Err(VaultError::PasswordRequired.into());
    }
    
    Ok(Zeroizing::new(password))
}

/// Securely compare two byte slices in constant time
pub fn constant_time_compare(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    
    let mut result = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        result |= x ^ y;
    }
    
    result == 0
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_constant_time_compare() {
        let a = b"hello";
        let b = b"hello";
        let c = b"world";
        
        assert!(constant_time_compare(a, b));
        assert!(!constant_time_compare(a, c));
    }
    
    #[test]
    fn test_constant_time_compare_different_lengths() {
        let a = b"hello";
        let b = b"hello world";
        
        assert!(!constant_time_compare(a, b));
    }
}
