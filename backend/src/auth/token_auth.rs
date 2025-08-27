use crate::data::token::{ApiToken, Scope};
use crate::data::objects::AppState;
use crate::auth::permissions::PermissionSystem;
use crate::ApiError;
use anyhow::{anyhow, Result};
use hmac::{Hmac, Mac};
use sha2::Sha256;
use rand::{thread_rng, Rng};
use base64::{Engine as _, engine::general_purpose};
use std::time::SystemTime;
use rocket::{Request, State, http::Status, request::{FromRequest, Outcome}};
use tracing::{debug, warn};

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

// ===== ROCKET REQUEST GUARDS =====

/// Bearer token authentication request guard
#[derive(Debug, Clone)]
pub struct BearerAuthenticated {
    pub auth: BearerAuth,
}

/// Bearer token authentication with specific scope requirements
#[derive(Debug, Clone)]
pub struct BearerAuthenticatedWithScopes {
    pub auth: BearerAuth,
    pub required_scopes: Vec<Scope>,
}

impl BearerAuthenticated {
    /// Extract and validate bearer token from request
    async fn authenticate_bearer_token(request: &Request<'_>) -> Option<BearerAuth> {
        // Get Authorization header
        let auth_header = request.headers().get_one("Authorization")?;
        let token_str = token_utils::extract_bearer_token(auth_header)?;

        // Validate token format
        if !token_utils::validate_token_format(token_str) {
            debug!("Invalid token format: {}", token_str);
            return None;
        }

        // Parse token
        let (prefix, token_value) = token_utils::parse_full_token(token_str)?;

        // Get app state
        let state = request.guard::<&State<AppState>>().await.succeeded()?;

        // Look up token in database
        let token = match state.db.get_api_token_by_prefix(&prefix).await {
            Ok(token) => token,
            Err(e) => {
                debug!("Token lookup failed for prefix {}: {}", prefix, e);
                return None;
            }
        };

        // Verify token hash
        let hasher = match TokenHasher::new(&state.settings.get_secret().into_bytes()) {
            Ok(hasher) => hasher,
            Err(e) => {
                warn!("Failed to create token hasher: {}", e);
                return None;
            }
        };

        let salt_bytes = match hex::decode(&token.salt) {
            Ok(bytes) => bytes,
            Err(e) => {
                warn!("Invalid salt format for token {}: {}", prefix, e);
                return None;
            }
        };

        if !hasher.verify_token(&token_value, &salt_bytes, &token.hash) {
            debug!("Token verification failed for prefix: {}", prefix);
            return None;
        }

        // Check token constraints
        if !token.is_usable() {
            debug!("Token {} is not usable (disabled, expired, or revoked)", prefix);
            return None;
        }

        // Update last used timestamp (async operation, don't wait)
        let _ = state.db.update_token_last_used(&token.id).await;

        // Create bearer auth context
        match BearerAuth::new(token, None) {
            Ok(auth) => Some(auth),
            Err(e) => {
                warn!("Failed to create bearer auth context: {}", e);
                None
            }
        }
    }
}

#[rocket::async_trait]
impl<'r> FromRequest<'r> for BearerAuthenticated {
    type Error = ApiError;

    async fn from_request(request: &'r Request<'_>) -> Outcome<Self, Self::Error> {
        match Self::authenticate_bearer_token(request).await {
            Some(auth) => Outcome::Success(BearerAuthenticated { auth }),
            None => Outcome::Error((Status::Unauthorized, ApiError::missing_bearer_token())),
        }
    }
}

/// Bearer authentication with automatic scope checking
pub struct BearerAuthenticatedWithEndpointScopes {
    pub auth: BearerAuth,
}

#[rocket::async_trait]
impl<'r> FromRequest<'r> for BearerAuthenticatedWithEndpointScopes {
    type Error = ApiError;

    async fn from_request(request: &'r Request<'_>) -> Outcome<Self, Self::Error> {
        // First authenticate the token
        let auth = match BearerAuthenticated::authenticate_bearer_token(request).await {
            Some(auth) => auth,
            None => return Outcome::Error((Status::Unauthorized, ApiError::missing_bearer_token())),
        };

        // Get app state for permission checking
        let state = match request.guard::<&State<AppState>>().await {
            Outcome::Success(state) => state,
            _ => return Outcome::Error((Status::InternalServerError, ApiError::InternalServerError)),
        };

        // Create permission system
        let mut permission_system = PermissionSystem::new(state.db.clone());

        // Get endpoint and method
        let endpoint = request.uri().path().as_str();
        let method = request.method().as_str();

        // Check if token has required scopes for this endpoint
        match permission_system.check_token_access(&auth.token.scopes, endpoint, method).await {
            Ok(true) => Outcome::Success(BearerAuthenticatedWithEndpointScopes { auth }),
            Ok(false) => {
                debug!("Token {} lacks required scopes for {} {}", auth.token.prefix, method, endpoint);
                Outcome::Error((Status::Forbidden, ApiError::insufficient_scope("required for this endpoint")))
            },
            Err(e) => {
                warn!("Permission check failed: {}", e);
                Outcome::Error((Status::InternalServerError, ApiError::InternalServerError))
            }
        }
    }
}

/// Macro to create scope-specific authentication guards
macro_rules! bearer_auth_with_scopes {
    ($name:ident, $($scope:expr),+) => {
        pub struct $name {
            pub auth: BearerAuth,
        }

        #[rocket::async_trait]
        impl<'r> FromRequest<'r> for $name {
            type Error = ApiError;

            async fn from_request(request: &'r Request<'_>) -> Outcome<Self, Self::Error> {
                let required_scopes = vec![$($scope),+];

                match BearerAuthenticated::authenticate_bearer_token(request).await {
                    Some(auth) => {
                        // Check if token has all required scopes
                        let has_scopes = required_scopes.iter().all(|scope| auth.has_scope(scope));

                        if has_scopes {
                            Outcome::Success($name { auth })
                        } else {
                            debug!("Token {} missing required scopes", auth.token.prefix);
                            Outcome::Error((Status::Forbidden, ApiError::insufficient_scope("required for this operation")))
                        }
                    },
                    None => Outcome::Error((Status::Unauthorized, ApiError::missing_bearer_token())),
                }
            }
        }
    };
}

// Create specific authentication guards for common scope combinations
bearer_auth_with_scopes!(BearerCertRead, &Scope::CertRead);
bearer_auth_with_scopes!(BearerCertWrite, &Scope::CertWrite);
bearer_auth_with_scopes!(BearerCertRevoke, &Scope::CertRevoke);
bearer_auth_with_scopes!(BearerCaRead, &Scope::CaRead);
bearer_auth_with_scopes!(BearerCaWrite, &Scope::CaWrite);
bearer_auth_with_scopes!(BearerCaKeyop, &Scope::CaKeyop);
bearer_auth_with_scopes!(BearerTokenAdmin, &Scope::TokenAdmin);
bearer_auth_with_scopes!(BearerAdminTenant, &Scope::AdminTenant);

// Combined scope guards
bearer_auth_with_scopes!(BearerCertReadWrite, &Scope::CertRead, &Scope::CertWrite);
bearer_auth_with_scopes!(BearerCaReadWrite, &Scope::CaRead, &Scope::CaWrite);

// Profile scope guards
bearer_auth_with_scopes!(BearerProfileRead, &Scope::ProfileRead);
bearer_auth_with_scopes!(BearerProfileWrite, &Scope::ProfileWrite);

// Audit scope guards
bearer_auth_with_scopes!(BearerAuditRead, &Scope::AuditRead);
