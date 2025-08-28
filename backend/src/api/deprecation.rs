/// API Deprecation Management System
/// 
/// This module handles the deprecation of legacy API endpoints
/// and provides migration guidance to users.

use rocket::serde::json::Json;
use serde_json::Value;
use crate::data::error::ApiError;

/// Deprecation warning header
pub const DEPRECATION_HEADER: &str = "X-VaulTLS-Deprecation-Warning";

/// Deprecation notice structure
#[derive(serde::Serialize)]
pub struct DeprecationNotice {
    pub deprecated: bool,
    pub endpoint: String,
    pub deprecation_date: String,
    pub removal_date: String,
    pub replacement: String,
    pub migration_guide: String,
    pub breaking_changes: Vec<String>,
}

/// Legacy endpoint deprecation information
pub fn get_deprecation_info(endpoint: &str) -> Option<DeprecationNotice> {
    match endpoint {
        "/certificates" => Some(DeprecationNotice {
            deprecated: true,
            endpoint: "GET /certificates".to_string(),
            deprecation_date: "2024-01-01".to_string(),
            removal_date: "2024-06-01".to_string(),
            replacement: "POST /certificates/search".to_string(),
            migration_guide: "https://github.com/7ritn/VaulTLS/blob/main/docs/api/migration.md#certificate-search".to_string(),
            breaking_changes: vec![
                "Requires Bearer token authentication".to_string(),
                "Response format includes pagination".to_string(),
                "Advanced filtering capabilities".to_string(),
            ],
        }),
        
        "POST /certificates" => Some(DeprecationNotice {
            deprecated: true,
            endpoint: "POST /certificates (legacy)".to_string(),
            deprecation_date: "2024-01-01".to_string(),
            removal_date: "2024-06-01".to_string(),
            replacement: "POST /certificates (modern)".to_string(),
            migration_guide: "https://github.com/7ritn/VaulTLS/blob/main/docs/api/migration.md#certificate-creation".to_string(),
            breaking_changes: vec![
                "Requires Bearer token authentication".to_string(),
                "Enhanced request format with CA selection".to_string(),
                "Profile-based certificate creation".to_string(),
            ],
        }),
        
        "/certificates/<id>/download" => Some(DeprecationNotice {
            deprecated: true,
            endpoint: "GET /certificates/<id>/download".to_string(),
            deprecation_date: "2024-01-01".to_string(),
            removal_date: "2024-06-01".to_string(),
            replacement: "POST /certificates/bulk-download".to_string(),
            migration_guide: "https://github.com/7ritn/VaulTLS/blob/main/docs/api/migration.md#certificate-download".to_string(),
            breaking_changes: vec![
                "Requires Bearer token authentication".to_string(),
                "Bulk download format with multiple certificates".to_string(),
                "Enhanced metadata in response".to_string(),
            ],
        }),
        
        "/certificates/<id>" => Some(DeprecationNotice {
            deprecated: true,
            endpoint: "DELETE /certificates/<id>".to_string(),
            deprecation_date: "2024-01-01".to_string(),
            removal_date: "2024-06-01".to_string(),
            replacement: "POST /certificates/batch".to_string(),
            migration_guide: "https://github.com/7ritn/VaulTLS/blob/main/docs/api/migration.md#certificate-deletion".to_string(),
            breaking_changes: vec![
                "Requires Bearer token authentication".to_string(),
                "Batch operation format".to_string(),
                "Enhanced audit logging".to_string(),
            ],
        }),
        
        "/certificates/<id>/password" => Some(DeprecationNotice {
            deprecated: true,
            endpoint: "GET /certificates/<id>/password".to_string(),
            deprecation_date: "2024-01-01".to_string(),
            removal_date: "2024-06-01".to_string(),
            replacement: "POST /certificates/search with metadata".to_string(),
            migration_guide: "https://github.com/7ritn/VaulTLS/blob/main/docs/api/migration.md#certificate-passwords".to_string(),
            breaking_changes: vec![
                "Requires Bearer token authentication".to_string(),
                "Password information included in certificate metadata".to_string(),
                "Enhanced security controls".to_string(),
            ],
        }),
        
        "/certificates/ca/download" => Some(DeprecationNotice {
            deprecated: true,
            endpoint: "GET /certificates/ca/download".to_string(),
            deprecation_date: "2024-01-01".to_string(),
            removal_date: "2024-06-01".to_string(),
            replacement: "GET /cas/<ca_id>/certificate".to_string(),
            migration_guide: "https://github.com/7ritn/VaulTLS/blob/main/docs/api/migration.md#ca-download".to_string(),
            breaking_changes: vec![
                "Requires Bearer token authentication".to_string(),
                "CA-specific endpoints with proper identification".to_string(),
                "Enhanced CA management capabilities".to_string(),
            ],
        }),
        
        _ => None,
    }
}

/// Add deprecation warning to response headers
pub fn add_deprecation_warning(endpoint: &str) -> Option<(String, String)> {
    if let Some(notice) = get_deprecation_info(endpoint) {
        let warning = format!(
            "Endpoint deprecated. Use {} instead. Removal date: {}",
            notice.replacement,
            notice.removal_date
        );
        Some((DEPRECATION_HEADER.to_string(), warning))
    } else {
        None
    }
}

/// Generate deprecation response for completely removed endpoints
pub fn generate_deprecation_response(endpoint: &str) -> Result<Json<Value>, ApiError> {
    if let Some(notice) = get_deprecation_info(endpoint) {
        Err(ApiError::Gone(format!(
            "Endpoint {} has been removed. Use {} instead. Migration guide: {}",
            notice.endpoint,
            notice.replacement,
            notice.migration_guide
        )))
    } else {
        Err(ApiError::NotFound("Endpoint not found".to_string()))
    }
}

/// Legacy endpoint wrapper that adds deprecation warnings
pub fn legacy_endpoint_response<T>(endpoint: &str, response: T) -> (Option<(String, String)>, T) {
    let warning = add_deprecation_warning(endpoint);
    (warning, response)
}

/// Check if legacy endpoints should be disabled
pub fn legacy_endpoints_enabled() -> bool {
    std::env::var("VAULTLS_LEGACY_API_ENABLED")
        .unwrap_or_else(|_| "true".to_string())
        .parse::<bool>()
        .unwrap_or(true)
}

/// Environment variable configuration for API deprecation
pub mod config {
    /// Enable/disable legacy API endpoints
    pub const LEGACY_API_ENABLED: &str = "VAULTLS_LEGACY_API_ENABLED";
    
    /// Show deprecation warnings in responses
    pub const SHOW_DEPRECATION_WARNINGS: &str = "VAULTLS_SHOW_DEPRECATION_WARNINGS";
    
    /// Strict mode - return errors for deprecated endpoints
    pub const STRICT_DEPRECATION_MODE: &str = "VAULTLS_STRICT_DEPRECATION_MODE";
}

/// Deprecation middleware for legacy endpoints
pub fn check_deprecation_policy(endpoint: &str) -> Result<(), ApiError> {
    // Check if legacy endpoints are disabled
    if !legacy_endpoints_enabled() {
        return generate_deprecation_response(endpoint).map(|_| ());
    }
    
    // Check if strict deprecation mode is enabled
    let strict_mode = std::env::var(config::STRICT_DEPRECATION_MODE)
        .unwrap_or_else(|_| "false".to_string())
        .parse::<bool>()
        .unwrap_or(false);
    
    if strict_mode && get_deprecation_info(endpoint).is_some() {
        return generate_deprecation_response(endpoint).map(|_| ());
    }
    
    Ok(())
}

/// Generate migration guide response
pub fn get_migration_guide() -> Json<Value> {
    Json(serde_json::json!({
        "title": "VaulTLS API Migration Guide",
        "version": "2.0",
        "description": "Guide for migrating from legacy session-based API to modern Bearer token API",
        "migration_steps": [
            {
                "step": 1,
                "title": "Create API Token",
                "description": "Create a Bearer token with appropriate scopes",
                "endpoint": "POST /api/tokens",
                "example": {
                    "description": "Migration Token",
                    "scopes": ["cert.read", "cert.write", "ca.read"],
                    "expires_at": null
                }
            },
            {
                "step": 2,
                "title": "Update Authentication",
                "description": "Replace session cookies with Bearer token headers",
                "old_format": "Cookie: session=...",
                "new_format": "Authorization: Bearer vlt_abc123_..."
            },
            {
                "step": 3,
                "title": "Update Endpoints",
                "description": "Replace legacy endpoints with modern equivalents",
                "migrations": [
                    {
                        "old": "GET /certificates",
                        "new": "POST /certificates/search",
                        "changes": ["Pagination support", "Advanced filtering", "Bearer auth required"]
                    },
                    {
                        "old": "POST /certificates",
                        "new": "POST /certificates",
                        "changes": ["Enhanced request format", "CA selection", "Profile support"]
                    },
                    {
                        "old": "GET /certificates/<id>/download",
                        "new": "POST /certificates/bulk-download",
                        "changes": ["Bulk download support", "Multiple formats", "Enhanced metadata"]
                    }
                ]
            }
        ],
        "deprecated_endpoints": get_all_deprecated_endpoints(),
        "support": {
            "documentation": "https://github.com/7ritn/VaulTLS/blob/main/docs/api/migration.md",
            "examples": "https://github.com/7ritn/VaulTLS/blob/main/examples/api-migration/",
            "support_email": "support@vaultls.com"
        }
    }))
}

/// Get all deprecated endpoints for documentation
fn get_all_deprecated_endpoints() -> Vec<DeprecationNotice> {
    vec![
        "/certificates",
        "POST /certificates",
        "/certificates/<id>/download",
        "/certificates/<id>",
        "/certificates/<id>/password",
        "/certificates/ca/download",
    ]
    .into_iter()
    .filter_map(|endpoint| get_deprecation_info(endpoint))
    .collect()
}
