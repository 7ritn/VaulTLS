use rocket::serde::{Deserialize, Serialize};
use rocket_okapi::JsonSchema;
use uuid::Uuid;
use rand::{thread_rng, Rng};
use base64::{Engine as _, engine::general_purpose};

/// Scopes define fine-grained permissions for API operations
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Scope {
    // Certificate operations
    CertRead,
    CertWrite,
    CertRevoke,
    CertDownload,
    
    // CA operations
    CaRead,
    CaWrite,
    CaKeyop,
    
    // Profile operations
    ProfileRead,
    ProfileWrite,
    
    // Token operations
    TokenRead,
    TokenWrite,
    TokenAdmin,  // Cross-tenant token management
    
    // Audit and metrics
    AuditRead,
    MetricsRead,
    
    // Admin operations
    AdminTenant,
}

impl Scope {
    /// Convert scope to string representation
    pub fn as_str(&self) -> &'static str {
        match self {
            Scope::CertRead => "cert.read",
            Scope::CertWrite => "cert.write",
            Scope::CertRevoke => "cert.revoke",
            Scope::CertDownload => "cert.download",
            Scope::CaRead => "ca.read",
            Scope::CaWrite => "ca.write",
            Scope::CaKeyop => "ca.keyop",
            Scope::ProfileRead => "profile.read",
            Scope::ProfileWrite => "profile.write",
            Scope::TokenRead => "token.read",
            Scope::TokenWrite => "token.write",
            Scope::TokenAdmin => "token.admin",
            Scope::AuditRead => "audit.read",
            Scope::MetricsRead => "metrics.read",
            Scope::AdminTenant => "admin.tenant",
        }
    }

    /// Parse scope from string representation
    pub fn from_str(s: &str) -> Option<Self> {
        match s {
            "cert.read" => Some(Scope::CertRead),
            "cert.write" => Some(Scope::CertWrite),
            "cert.revoke" => Some(Scope::CertRevoke),
            "cert.download" => Some(Scope::CertDownload),
            "ca.read" => Some(Scope::CaRead),
            "ca.write" => Some(Scope::CaWrite),
            "ca.keyop" => Some(Scope::CaKeyop),
            "profile.read" => Some(Scope::ProfileRead),
            "profile.write" => Some(Scope::ProfileWrite),
            "token.read" => Some(Scope::TokenRead),
            "token.write" => Some(Scope::TokenWrite),
            "token.admin" => Some(Scope::TokenAdmin),
            "audit.read" => Some(Scope::AuditRead),
            "metrics.read" => Some(Scope::MetricsRead),
            "admin.tenant" => Some(Scope::AdminTenant),
            _ => None,
        }
    }

    /// Get all available scopes
    pub fn all() -> Vec<Self> {
        vec![
            Scope::CertRead, Scope::CertWrite, Scope::CertRevoke, Scope::CertDownload,
            Scope::CaRead, Scope::CaWrite, Scope::CaKeyop,
            Scope::ProfileRead, Scope::ProfileWrite,
            Scope::TokenRead, Scope::TokenWrite, Scope::TokenAdmin,
            Scope::AuditRead, Scope::MetricsRead,
            Scope::AdminTenant,
        ]
    }
}

/// API Token for Bearer authentication
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct ApiToken {
    pub id: String,  // UUID v4
    pub prefix: String,  // Short display ID (e.g., "vlt_abc123")
    #[serde(skip)]
    pub hash: String,  // HMAC-SHA256 hash (never serialized)
    #[serde(skip)]
    pub salt: String,  // Per-token salt (never serialized)
    pub scopes: Vec<String>,  // Array of scope strings
    pub description: String,
    pub is_enabled: bool,
    pub revoked_at: Option<i64>,
    pub last_used_at: Option<i64>,
    pub expires_at: Option<i64>,
    pub created_at: i64,
    pub created_by_user_id: i64,
    pub tenant_id: String,
    pub rate_limit_per_minute: Option<i32>,
}

impl ApiToken {
    /// Create a new API token with generated values
    pub fn new(
        description: String,
        scopes: Vec<String>,
        created_by_user_id: i64,
        tenant_id: String,
        expires_at: Option<i64>,
        rate_limit_per_minute: Option<i32>,
    ) -> Self {
        let prefix = Self::generate_prefix();
        
        Self {
            id: Uuid::new_v4().to_string(),
            prefix,
            hash: String::new(),  // Will be set when token is hashed
            salt: String::new(),  // Will be set when token is hashed
            scopes,
            description,
            is_enabled: true,
            revoked_at: None,
            last_used_at: None,
            expires_at,
            created_at: chrono::Utc::now().timestamp(),
            created_by_user_id,
            tenant_id,
            rate_limit_per_minute,
        }
    }

    /// Generate a token prefix (vlt_ + 6 random alphanumeric characters)
    fn generate_prefix() -> String {
        let chars: Vec<char> = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
            .chars()
            .collect();
        let mut rng = thread_rng();
        let suffix: String = (0..6)
            .map(|_| chars[rng.gen_range(0..chars.len())])
            .collect();
        format!("vlt_{}", suffix)
    }

    /// Generate a random token value (32 bytes, base64url encoded)
    pub fn generate_token_value() -> String {
        let mut token_bytes = [0u8; 32];
        thread_rng().fill(&mut token_bytes);
        general_purpose::URL_SAFE_NO_PAD.encode(token_bytes)
    }

    /// Get the full token format: prefix_tokenvalue
    pub fn full_token_format(prefix: &str, token_value: &str) -> String {
        format!("{}_{}", prefix, token_value)
    }

    /// Parse a full token into prefix and token value
    pub fn parse_token(full_token: &str) -> Option<(String, String)> {
        if let Some(underscore_pos) = full_token.rfind('_') {
            let prefix = full_token[..underscore_pos].to_string();
            let token_value = full_token[underscore_pos + 1..].to_string();
            if prefix.starts_with("vlt_") && prefix.len() == 10 {
                return Some((prefix, token_value));
            }
        }
        None
    }

    /// Check if token is expired
    pub fn is_expired(&self) -> bool {
        if let Some(expires_at) = self.expires_at {
            chrono::Utc::now().timestamp() > expires_at
        } else {
            false
        }
    }

    /// Check if token is revoked
    pub fn is_revoked(&self) -> bool {
        self.revoked_at.is_some()
    }

    /// Check if token is usable (enabled, not expired, not revoked)
    pub fn is_usable(&self) -> bool {
        self.is_enabled && !self.is_expired() && !self.is_revoked()
    }
}

/// Request to create a new API token
#[derive(Debug, Serialize, Deserialize, JsonSchema)]
pub struct CreateTokenRequest {
    pub description: String,
    pub scopes: Vec<String>,
    pub expires_at: Option<i64>,
    pub rate_limit_per_minute: Option<i32>,
    pub tenant_id: Option<String>,  // Admin can specify tenant
}

/// Response when creating a token (includes one-time plaintext)
#[derive(Debug, Serialize, Deserialize, JsonSchema)]
pub struct CreateTokenResponse {
    pub token: ApiToken,
    pub token_plaintext_once: String,  // Full token value, shown only once
}

/// Request to update an API token
#[derive(Debug, Serialize, Deserialize, JsonSchema)]
pub struct UpdateTokenRequest {
    pub description: Option<String>,
    pub scopes: Option<Vec<String>>,
    pub is_enabled: Option<bool>,
    pub expires_at: Option<i64>,
    pub rate_limit_per_minute: Option<i32>,
}

/// Token rotation response
#[derive(Debug, Serialize, Deserialize, JsonSchema)]
pub struct RotateTokenResponse {
    pub token_plaintext_once: String,  // New token value, shown only once
}

/// Token information response (without sensitive data)
#[derive(Debug, Serialize, Deserialize, JsonSchema)]
pub struct TokenResponse {
    pub id: String,
    pub prefix: String,
    pub description: String,
    pub scopes: Vec<String>,
    pub is_enabled: bool,
    pub revoked_at: Option<i64>,
    pub last_used_at: Option<i64>,
    pub expires_at: Option<i64>,
    pub created_at: i64,
    pub created_by_user_id: i64,
    pub tenant_id: String,
    pub rate_limit_per_minute: Option<i32>,
}

impl From<ApiToken> for TokenResponse {
    fn from(token: ApiToken) -> Self {
        Self {
            id: token.id,
            prefix: token.prefix,
            description: token.description,
            scopes: token.scopes,
            is_enabled: token.is_enabled,
            revoked_at: token.revoked_at,
            last_used_at: token.last_used_at,
            expires_at: token.expires_at,
            created_at: token.created_at,
            created_by_user_id: token.created_by_user_id,
            tenant_id: token.tenant_id,
            rate_limit_per_minute: token.rate_limit_per_minute,
        }
    }
}

/// Token list response with pagination
#[derive(Debug, Serialize, Deserialize, JsonSchema)]
pub struct TokenListResponse {
    pub tokens: Vec<TokenResponse>,
    pub total: i64,
    pub page: i32,
    pub per_page: i32,
    pub has_more: bool,
}

/// Token usage statistics
#[derive(Debug, Serialize, Deserialize, JsonSchema)]
pub struct TokenUsageStats {
    pub token_id: String,
    pub requests_last_hour: i32,
    pub requests_last_day: i32,
    pub requests_last_week: i32,
    pub last_used_at: Option<i64>,
    pub last_used_endpoint: Option<String>,
    pub last_used_ip: Option<String>,
}
