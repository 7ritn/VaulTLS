use crate::data::token::{ApiToken, Scope};
use crate::ApiError;
use anyhow::{anyhow, Result};
use hmac::{Hmac, Mac};
use sha2::Sha256;
use rand::{thread_rng, Rng};
use base64::{Engine as _, engine::general_purpose};
use std::time::SystemTime;

type HmacSha256 = Hmac<Sha256>;

/// Token hasher for HMAC-SHA256 authentication
pub struct TokenHasher {
    server_secret: Vec<u8>,
}

impl TokenHasher {
    /// Create a new token hasher with server secret
    pub fn new(server_secret: &[u8]) -> Self {
        Self {
            server_secret: server_secret.to_vec(),
        }
    }

    /// Hash a token with salt using HMAC-SHA256
    pub fn hash_token(&self, token: &str, salt: &[u8]) -> Result<String> {
        let mut mac = HmacSha256::new_from_slice(&self.server_secret)
            .map_err(|e| anyhow!("Invalid server secret: {}", e))?;
        
        mac.update(salt);
        mac.update(token.as_bytes());
        
        let result = mac.finalize();
        Ok(hex::encode(result.into_bytes()))
    }

    /// Generate a random salt for token hashing
    pub fn generate_salt() -> [u8; 32] {
        let mut salt = [0u8; 32];
        thread_rng().fill(&mut salt);
        salt
    }

    /// Verify a token against its hash using constant-time comparison
    pub fn verify_token(&self, token: &str, salt: &[u8], hash: &str) -> bool {
        match self.hash_token(token, salt) {
            Ok(computed_hash) => {
                // Use constant-time comparison to prevent timing attacks
                use subtle::ConstantTimeEq;
                computed_hash.as_bytes().ct_eq(hash.as_bytes()).into()
            }
            Err(_) => false,
        }
    }

    /// Hash a new token and return the hash and salt
    pub fn hash_new_token(&self, token: &str) -> Result<(String, String)> {
        let salt = Self::generate_salt();
        let hash = self.hash_token(token, &salt)?;
        let salt_hex = hex::encode(salt);
        Ok((hash, salt_hex))
    }
}

/// Bearer authentication context
#[derive(Debug, Clone)]
pub struct BearerAuth {
    pub token: ApiToken,
    pub tenant_id: String,
    pub scopes: Vec<Scope>,
    pub user_id: Option<i64>,
}

impl BearerAuth {
    /// Create a new bearer auth context
    pub fn new(token: ApiToken, user_id: Option<i64>) -> Result<Self> {
        let scopes = token.scopes.iter()
            .filter_map(|s| Scope::from_str(s))
            .collect();

        Ok(Self {
            tenant_id: token.tenant_id.clone(),
            scopes,
            user_id,
            token,
        })
    }

    /// Check if the auth context has a specific scope
    pub fn has_scope(&self, scope: &Scope) -> bool {
        self.scopes.contains(scope)
    }

    /// Check if the auth context has any of the specified scopes
    pub fn has_any_scope(&self, scopes: &[Scope]) -> bool {
        scopes.iter().any(|scope| self.has_scope(scope))
    }

    /// Check if the auth context has all of the specified scopes
    pub fn has_all_scopes(&self, scopes: &[Scope]) -> bool {
        scopes.iter().all(|scope| self.has_scope(scope))
    }

    /// Update the token's last used timestamp
    pub fn update_last_used(&mut self) {
        self.token.last_used_at = Some(chrono::Utc::now().timestamp());
    }
}

/// Scope guard for endpoint protection
pub struct ScopeGuard {
    pub required_scopes: Vec<Scope>,
}

impl ScopeGuard {
    /// Create a new scope guard with required scopes
    pub fn new(scopes: Vec<Scope>) -> Self {
        Self { required_scopes: scopes }
    }

    /// Check if the bearer auth has the required scopes
    pub fn check_scopes(&self, auth: &BearerAuth) -> bool {
        auth.has_all_scopes(&self.required_scopes)
    }

    /// Get a descriptive error message for missing scopes
    pub fn get_missing_scopes_error(&self, auth: &BearerAuth) -> String {
        let missing: Vec<String> = self.required_scopes
            .iter()
            .filter(|scope| !auth.has_scope(scope))
            .map(|scope| scope.as_str().to_string())
            .collect();

        if missing.is_empty() {
            "Access granted".to_string()
        } else {
            format!("Missing required scopes: {}", missing.join(", "))
        }
    }
}

/// Rate limiter for token-based requests
pub struct TokenRateLimiter {
    // In-memory rate limiting (could be extended with Redis)
    // For now, we'll implement a simple leaky bucket
}

impl TokenRateLimiter {
    /// Check if a token is within its rate limit
    pub fn check_rate_limit(&self, token: &ApiToken) -> bool {
        // TODO: Implement proper rate limiting
        // For now, always allow (will be implemented in later iterations)
        true
    }

    /// Record a request for rate limiting
    pub fn record_request(&mut self, token: &ApiToken) {
        // TODO: Implement request recording
    }
}

/// Utility functions for token operations
pub mod token_utils {
    use super::*;

    /// Extract bearer token from Authorization header
    pub fn extract_bearer_token(auth_header: &str) -> Option<&str> {
        auth_header.strip_prefix("Bearer ")
    }

    /// Parse a full token into prefix and token value
    pub fn parse_full_token(full_token: &str) -> Option<(String, String)> {
        ApiToken::parse_token(full_token)
    }

    /// Generate a secure random token value
    pub fn generate_token_value() -> String {
        ApiToken::generate_token_value()
    }

    /// Validate token format
    pub fn validate_token_format(token: &str) -> bool {
        // Check if token matches expected format: vlt_xxxxxx_<base64url>
        if let Some((prefix, _)) = parse_full_token(token) {
            prefix.starts_with("vlt_") && prefix.len() == 10
        } else {
            false
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_token_hashing() {
        let secret = b"test_secret_key_32_bytes_long!!!";
        let hasher = TokenHasher::new(secret);
        
        let token = "test_token_value";
        let salt = TokenHasher::generate_salt();
        
        let hash = hasher.hash_token(token, &salt).unwrap();
        assert!(hasher.verify_token(token, &salt, &hash));
        assert!(!hasher.verify_token("wrong_token", &salt, &hash));
    }

    #[test]
    fn test_scope_guard() {
        let required_scopes = vec![Scope::CertRead, Scope::CertWrite];
        let guard = ScopeGuard::new(required_scopes);
        
        // Create a mock token with scopes
        let mut token = ApiToken::new(
            "Test token".to_string(),
            vec!["cert.read".to_string(), "cert.write".to_string()],
            1,
            "tenant-id".to_string(),
            None,
            None,
        );
        
        let auth = BearerAuth::new(token, Some(1)).unwrap();
        assert!(guard.check_scopes(&auth));
    }

    #[test]
    fn test_token_format_validation() {
        assert!(token_utils::validate_token_format("vlt_abc123_dGVzdF90b2tlbl92YWx1ZQ"));
        assert!(!token_utils::validate_token_format("invalid_token"));
        assert!(!token_utils::validate_token_format("vlt_abc_short"));
    }
}
