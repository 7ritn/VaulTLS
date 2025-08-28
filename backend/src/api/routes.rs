/// Central API Route Registry for VaulTLS
/// 
/// This module defines all API endpoints in a centralized location
/// to ensure consistency and prevent duplication across the codebase.

use rocket::Route;
use rocket_okapi::openapi_get_routes;

// Import all endpoint handlers
use crate::api::{
    // Server & Documentation
    version, api_docs,
    
    // Authentication & Setup
    is_setup, setup, login, logout, change_password,
    oidc_login, oidc_callback, get_current_user,
    
    // User Management
    get_users, create_user, delete_user, update_user,
    
    // Legacy Certificate Management (to be deprecated)
    get_certificates as legacy_get_certificates,
    create_user_certificate as legacy_create_certificate,
    download_certificate as legacy_download_certificate,
    delete_user_cert as legacy_delete_certificate,
    fetch_certificate_password as legacy_fetch_password,
    
    // Modern Certificate Management
    create_certificate_with_ca, search_certificates,
    batch_certificate_operation, get_certificate_chain,
    validate_certificate_chain, get_expiring_certificates,
    get_certificate_statistics, bulk_download_certificates,
    
    // Certificate Authority Management
    create_ca, list_cas, get_ca, update_ca, delete_ca,
    download_ca_certificate, download_ca_chain, rotate_ca_key,
    get_available_cas, download_ca,
    
    // Certificate Profiles
    create_profile, list_profiles, get_profile,
    update_profile, delete_profile,
    
    // Certificate Templates
    create_certificate_template, list_certificate_templates,
    get_certificate_template, update_certificate_template,
    delete_certificate_template, create_certificate_from_template,
    
    // API Token Management
    create_api_token, list_api_tokens, get_api_token,
    update_api_token, rotate_api_token, revoke_api_token,
    delete_api_token,
    
    // Certificate Revocation Lists
    revoke_certificate, restore_certificate, download_crl,
    get_crl_info, check_certificate_status,
    get_revocation_statistics, generate_crl,
    
    // Audit & Compliance
    get_audit_events, search_audit_events, get_audit_statistics,
    get_audit_activity, export_audit_events, generate_compliance_report,
    
    // Webhook Management
    create_webhook, list_webhooks, get_webhook,
    update_webhook, delete_webhook, test_webhook,
    
    // Settings Management
    fetch_settings, update_settings,
    
    // Protected Documentation
    protected_redoc, protected_openapi_spec,
};

/// API Version and Endpoint Organization
pub const API_VERSION: &str = "v1";
pub const API_BASE_PATH: &str = "/api";

/// Modern API Routes (Bearer Token Authentication)
/// These are the primary endpoints for API automation and integration
pub fn modern_api_routes() -> Vec<Route> {
    openapi_get_routes![
        // ===== SERVER & DOCUMENTATION =====
        version,
        api_docs,
        
        // ===== AUTHENTICATION & SETUP =====
        is_setup,
        setup,
        login,
        logout,
        change_password,
        oidc_login,
        oidc_callback,
        get_current_user,
        
        // ===== USER MANAGEMENT =====
        get_users,
        create_user,
        delete_user,
        update_user,
        
        // ===== MODERN CERTIFICATE MANAGEMENT =====
        create_certificate_with_ca,
        search_certificates,
        batch_certificate_operation,
        get_certificate_chain,
        validate_certificate_chain,
        get_expiring_certificates,
        get_certificate_statistics,
        bulk_download_certificates,
        
        // ===== CERTIFICATE AUTHORITY MANAGEMENT =====
        create_ca,
        list_cas,
        get_ca,
        update_ca,
        delete_ca,
        download_ca_certificate,
        download_ca_chain,
        rotate_ca_key,
        get_available_cas,
        download_ca,
        
        // ===== CERTIFICATE PROFILES =====
        create_profile,
        list_profiles,
        get_profile,
        update_profile,
        delete_profile,
        
        // ===== CERTIFICATE TEMPLATES =====
        create_certificate_template,
        list_certificate_templates,
        get_certificate_template,
        update_certificate_template,
        delete_certificate_template,
        create_certificate_from_template,
        
        // ===== API TOKEN MANAGEMENT =====
        create_api_token,
        list_api_tokens,
        get_api_token,
        update_api_token,
        rotate_api_token,
        revoke_api_token,
        delete_api_token,
        
        // ===== CERTIFICATE REVOCATION LISTS =====
        revoke_certificate,
        restore_certificate,
        download_crl,
        get_crl_info,
        check_certificate_status,
        get_revocation_statistics,
        generate_crl,
        
        // ===== AUDIT & COMPLIANCE =====
        get_audit_events,
        search_audit_events,
        get_audit_statistics,
        get_audit_activity,
        export_audit_events,
        generate_compliance_report,
        
        // ===== WEBHOOK MANAGEMENT =====
        create_webhook,
        list_webhooks,
        get_webhook,
        update_webhook,
        delete_webhook,
        test_webhook,
        
        // ===== SETTINGS MANAGEMENT =====
        fetch_settings,
        update_settings,
    ]
}

/// Legacy API Routes (Session Authentication)
/// These endpoints are maintained for backward compatibility
/// and will be deprecated in favor of Bearer token endpoints
pub fn legacy_api_routes() -> Vec<Route> {
    openapi_get_routes![
        // Legacy certificate management (session-based)
        get_certificates_legacy,
        create_user_certificate_legacy,
        download_certificate_legacy,
        delete_user_cert_legacy,
        fetch_certificate_password_legacy,
        download_ca_legacy,
    ]
}

/// Protected Documentation Routes
/// These require authentication when VAULTLS_API_DOCS_REQUIRE_AUTH=true
pub fn protected_docs_routes() -> Vec<Route> {
    openapi_get_routes![
        protected_redoc,
        protected_openapi_spec,
    ]
}

/// API Endpoint Categories for Documentation
pub mod categories {
    pub const SERVER: &str = "Server";
    pub const AUTHENTICATION: &str = "Authentication";
    pub const USERS: &str = "Users";
    pub const CERTIFICATES: &str = "Certificates";
    pub const CERTIFICATE_AUTHORITIES: &str = "Certificate Authorities";
    pub const PROFILES: &str = "Certificate Profiles";
    pub const TEMPLATES: &str = "Certificate Templates";
    pub const TOKENS: &str = "API Tokens";
    pub const REVOCATION: &str = "Certificate Revocation";
    pub const AUDIT: &str = "Audit & Compliance";
    pub const WEBHOOKS: &str = "Webhooks";
    pub const SETTINGS: &str = "Settings";
    pub const DOCUMENTATION: &str = "Documentation";
}

/// API Endpoint Paths Registry
/// Central registry of all API endpoint paths for consistency
pub mod paths {
    // Server & Documentation
    pub const VERSION: &str = "/server/version";
    pub const DOCS: &str = "/docs";
    
    // Authentication & Setup
    pub const SETUP: &str = "/server/setup";
    pub const LOGIN: &str = "/auth/login";
    pub const LOGOUT: &str = "/auth/logout";
    pub const CHANGE_PASSWORD: &str = "/auth/password";
    pub const OIDC_LOGIN: &str = "/auth/oidc/login";
    pub const OIDC_CALLBACK: &str = "/auth/oidc/callback";
    pub const CURRENT_USER: &str = "/auth/user";
    
    // User Management
    pub const USERS: &str = "/users";
    pub const USER_BY_ID: &str = "/users/<user_id>";
    
    // Modern Certificate Management
    pub const CERTIFICATES: &str = "/certificates";
    pub const CERTIFICATE_SEARCH: &str = "/certificates/search";
    pub const CERTIFICATE_BATCH: &str = "/certificates/batch";
    pub const CERTIFICATE_CHAIN: &str = "/certificates/<cert_id>/chain";
    pub const CERTIFICATE_VALIDATE: &str = "/certificates/validate-chain";
    pub const CERTIFICATES_EXPIRING: &str = "/certificates/expiring";
    pub const CERTIFICATES_STATISTICS: &str = "/certificates/statistics";
    pub const CERTIFICATES_BULK_DOWNLOAD: &str = "/certificates/bulk-download";
    
    // Certificate Authority Management
    pub const CAS: &str = "/cas";
    pub const CA_BY_ID: &str = "/cas/<ca_id>";
    pub const CA_CERTIFICATE: &str = "/cas/<ca_id>/certificate";
    pub const CA_CHAIN: &str = "/cas/<ca_id>/chain";
    pub const CA_ROTATE: &str = "/cas/<ca_id>/rotate";
    pub const CA_AVAILABLE: &str = "/cas/available";
    
    // Certificate Profiles
    pub const PROFILES: &str = "/profiles";
    pub const PROFILE_BY_ID: &str = "/profiles/<profile_id>";
    
    // Certificate Templates
    pub const TEMPLATES: &str = "/templates";
    pub const TEMPLATE_BY_ID: &str = "/templates/<template_id>";
    pub const TEMPLATE_CERTIFICATES: &str = "/templates/<template_id>/certificates";
    
    // API Token Management
    pub const TOKENS: &str = "/tokens";
    pub const TOKEN_BY_ID: &str = "/tokens/<token_id>";
    pub const TOKEN_ROTATE: &str = "/tokens/<token_id>/rotate";
    pub const TOKEN_REVOKE: &str = "/tokens/<token_id>/revoke";
    
    // Certificate Revocation Lists
    pub const CERTIFICATE_REVOKE: &str = "/certificates/<cert_id>/revoke";
    pub const CERTIFICATE_RESTORE: &str = "/certificates/<cert_id>/restore";
    pub const CRL_DOWNLOAD: &str = "/crl";
    pub const CRL_INFO: &str = "/crl/info";
    pub const CERTIFICATE_STATUS: &str = "/certificates/<cert_id>/status";
    pub const REVOCATION_STATISTICS: &str = "/revocation/statistics";
    pub const CRL_GENERATE: &str = "/crl/generate";
    
    // Audit & Compliance
    pub const AUDIT_EVENTS: &str = "/audit/events";
    pub const AUDIT_SEARCH: &str = "/audit/events/search";
    pub const AUDIT_STATISTICS: &str = "/audit/statistics";
    pub const AUDIT_ACTIVITY: &str = "/audit/activity";
    pub const AUDIT_EXPORT: &str = "/audit/export";
    pub const COMPLIANCE_REPORT: &str = "/audit/compliance-report";
    
    // Webhook Management
    pub const WEBHOOKS: &str = "/webhooks";
    pub const WEBHOOK_BY_ID: &str = "/webhooks/<webhook_id>";
    pub const WEBHOOK_TEST: &str = "/webhooks/<webhook_id>/test";
    
    // Settings Management
    pub const SETTINGS: &str = "/settings";
    
    // Legacy Endpoints (to be deprecated)
    pub mod legacy {
        pub const CERTIFICATES: &str = "/certificates";
        pub const CERTIFICATE_CREATE: &str = "/certificates";
        pub const CERTIFICATE_DOWNLOAD: &str = "/certificates/<cert_id>/download";
        pub const CERTIFICATE_DELETE: &str = "/certificates/<cert_id>";
        pub const CERTIFICATE_PASSWORD: &str = "/certificates/<cert_id>/password";
        pub const CA_DOWNLOAD: &str = "/certificates/ca/download";
    }
}

/// Migration Guide for Legacy Endpoints
pub mod migration {
    use super::paths;
    
    pub struct EndpointMigration {
        pub legacy_path: &'static str,
        pub modern_path: &'static str,
        pub auth_change: &'static str,
        pub breaking_changes: Vec<&'static str>,
    }
    
    pub const MIGRATIONS: &[EndpointMigration] = &[
        EndpointMigration {
            legacy_path: "/certificates",
            modern_path: "/certificates/search",
            auth_change: "Session → Bearer Token",
            breaking_changes: vec![
                "Requires Bearer token with cert.read scope",
                "Response format changed to include pagination",
                "Advanced filtering capabilities added"
            ],
        },
        EndpointMigration {
            legacy_path: "/certificates (POST)",
            modern_path: "/certificates",
            auth_change: "Session → Bearer Token",
            breaking_changes: vec![
                "Requires Bearer token with cert.write scope",
                "Enhanced request format with CA selection",
                "Profile-based certificate creation"
            ],
        },
        EndpointMigration {
            legacy_path: "/certificates/<id>/download",
            modern_path: "/certificates/bulk-download",
            auth_change: "Session → Bearer Token",
            breaking_changes: vec![
                "Requires Bearer token with cert.read scope",
                "Supports bulk download with multiple formats",
                "Enhanced metadata in response"
            ],
        },
    ];
}
