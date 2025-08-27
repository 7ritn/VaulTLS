use rocket::serde::{Deserialize, Serialize};
use rocket_okapi::JsonSchema;

/// Audit event for tracking all operations in VaulTLS
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct AuditEvent {
    pub id: i64,
    pub event_type: String,
    pub resource_type: String,
    pub resource_id: Option<String>,
    pub user_id: Option<i64>,
    pub token_prefix: Option<String>,
    pub tenant_id: Option<String>,
    pub endpoint: String,
    pub method: String,
    pub status_code: i32,
    pub duration_ms: Option<i64>,
    pub ip_address: Option<String>,
    pub user_agent: Option<String>,
    pub request_body: Option<String>,   // Sanitized
    pub response_body: Option<String>,  // Sanitized
    pub created_at: i64,
}

impl AuditEvent {
    /// Create a new audit event
    pub fn new(
        event_type: String,
        resource_type: String,
        resource_id: Option<String>,
        user_id: Option<i64>,
        token_prefix: Option<String>,
        tenant_id: Option<String>,
        endpoint: String,
        method: String,
        status_code: i32,
    ) -> Self {
        Self {
            id: -1,  // Will be set by database
            event_type,
            resource_type,
            resource_id,
            user_id,
            token_prefix,
            tenant_id,
            endpoint,
            method,
            status_code,
            duration_ms: None,
            ip_address: None,
            user_agent: None,
            request_body: None,
            response_body: None,
            created_at: chrono::Utc::now().timestamp(),
        }
    }

    /// Set optional fields
    pub fn with_duration(mut self, duration_ms: i64) -> Self {
        self.duration_ms = Some(duration_ms);
        self
    }

    pub fn with_ip_address(mut self, ip_address: String) -> Self {
        self.ip_address = Some(ip_address);
        self
    }

    pub fn with_user_agent(mut self, user_agent: String) -> Self {
        self.user_agent = Some(user_agent);
        self
    }

    pub fn with_request_body(mut self, request_body: String) -> Self {
        self.request_body = Some(Self::sanitize_body(request_body));
        self
    }

    pub fn with_response_body(mut self, response_body: String) -> Self {
        self.response_body = Some(Self::sanitize_body(response_body));
        self
    }

    /// Sanitize request/response bodies to remove sensitive information
    fn sanitize_body(body: String) -> String {
        // Remove sensitive fields like passwords, tokens, keys
        let sensitive_fields = [
            "password", "token", "key", "secret", "hash", "salt",
            "pkcs12", "private_key", "certificate", "pkcs12_password"
        ];
        
        let mut sanitized = body;
        for field in &sensitive_fields {
            // Simple regex replacement for JSON fields
            let pattern = format!(r#""{}":\s*"[^"]*""#, field);
            sanitized = regex::Regex::new(&pattern)
                .unwrap_or_else(|_| regex::Regex::new("").unwrap())
                .replace_all(&sanitized, &format!(r#""{}":"[REDACTED]""#, field))
                .to_string();
        }
        
        // Limit body size to prevent excessive storage
        if sanitized.len() > 1000 {
            format!("{}...[TRUNCATED]", &sanitized[..1000])
        } else {
            sanitized
        }
    }
}

/// Event types for audit logging
pub struct AuditEventType;

impl AuditEventType {
    pub const AUTH_SUCCESS: &'static str = "auth.success";
    pub const AUTH_FAILURE: &'static str = "auth.failure";
    pub const TOKEN_CREATED: &'static str = "token.created";
    pub const TOKEN_REVOKED: &'static str = "token.revoked";
    pub const TOKEN_ROTATED: &'static str = "token.rotated";
    pub const CERT_ISSUED: &'static str = "cert.issued";
    pub const CERT_REVOKED: &'static str = "cert.revoked";
    pub const CERT_RENEWED: &'static str = "cert.renewed";
    pub const CERT_DOWNLOADED: &'static str = "cert.downloaded";
    pub const CA_CREATED: &'static str = "ca.created";
    pub const CA_ROTATED: &'static str = "ca.rotated";
    pub const PROFILE_CREATED: &'static str = "profile.created";
    pub const PROFILE_UPDATED: &'static str = "profile.updated";
    pub const USER_CREATED: &'static str = "user.created";
    pub const USER_UPDATED: &'static str = "user.updated";
    pub const TENANT_CREATED: &'static str = "tenant.created";
    pub const TENANT_UPDATED: &'static str = "tenant.updated";
}

/// Resource types for audit logging
pub struct AuditResourceType;

impl AuditResourceType {
    pub const TOKEN: &'static str = "token";
    pub const CERTIFICATE: &'static str = "certificate";
    pub const CA: &'static str = "ca";
    pub const PROFILE: &'static str = "profile";
    pub const USER: &'static str = "user";
    pub const TENANT: &'static str = "tenant";
    pub const AUTH: &'static str = "auth";
}

/// Query parameters for audit event filtering
#[derive(Debug, Serialize, Deserialize, JsonSchema)]
pub struct AuditEventQuery {
    pub event_type: Option<String>,
    pub resource_type: Option<String>,
    pub resource_id: Option<String>,
    pub user_id: Option<i64>,
    pub token_prefix: Option<String>,
    pub tenant_id: Option<String>,
    pub start_date: Option<i64>,
    pub end_date: Option<i64>,
    pub page: Option<i32>,
    pub page_size: Option<i32>,
}
