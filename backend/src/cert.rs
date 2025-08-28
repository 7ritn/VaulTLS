use std::fs;
use std::time::{SystemTime, UNIX_EPOCH};
use anyhow::anyhow;
use anyhow::Result;
use openssl::asn1::{Asn1Integer, Asn1Time};
use openssl::bn::BigNum;
use openssl::ec::{EcGroup, EcKey};
use openssl::error::ErrorStack;
use openssl::hash::MessageDigest;
use openssl::nid::Nid;
use openssl::pkcs12::Pkcs12;
use openssl::pkey::{PKey, Private};
use openssl::stack::Stack;
use openssl::x509::{X509Name, X509NameBuilder, X509};
use openssl::x509::extension::{AuthorityKeyIdentifier, BasicConstraints, ExtendedKeyUsage, KeyUsage, SubjectAlternativeName, SubjectKeyIdentifier};
use openssl::x509::X509Builder;
use passwords::PasswordGenerator;
use rocket_okapi::JsonSchema;
use serde::{Deserialize, Serialize};
use crate::constants::CA_FILE_PATH;
use crate::data::enums::{CertificateRenewMethod, CertificateType};
use crate::data::enums::CertificateType::{Client, Server};
use crate::ApiError;

#[derive(Default, Clone, Serialize, Deserialize, JsonSchema, Debug)]
/// Certificate can be either CA or user certificate.
pub struct Certificate {
    pub id: i64,
    pub name: String,
    pub created_on: i64,
    pub valid_until: i64,
    pub certificate_type: CertificateType,
    pub user_id: i64,
    pub renew_method: CertificateRenewMethod,
    pub tenant_id: String,
    pub profile_id: Option<String>,
    pub serial_number: Option<String>,
    pub issuer: Option<String>,
    pub subject: Option<String>,
    pub algorithm: Option<String>,
    pub key_size: Option<i32>,
    pub sans: Option<String>,  // JSON string
    pub metadata: Option<String>,  // JSON string
    pub status: String,
    pub revoked_at: Option<i64>,
    pub revoked_by_user_id: Option<i64>,
    pub revocation_reason: Option<i32>,
    #[serde(skip)]
    pub pkcs12: Vec<u8>,
    #[serde(skip)]
    pub pkcs12_password: String,
    #[serde(skip)]
    pub ca_id: i64,
}

#[derive(Clone, Serialize, Deserialize, JsonSchema, Debug)]
pub struct CA {
    pub id: i64,
    pub created_on: i64,
    pub valid_until: i64,
    pub tenant_id: String,
    pub name: Option<String>,
    pub description: Option<String>,
    pub key_algorithm: String,
    pub key_size: Option<i32>,
    pub path_len: Option<i32>,
    pub basic_constraints: Option<String>,
    pub crl_distribution_points: Option<String>,  // JSON string
    pub authority_info_access: Option<String>,    // JSON string
    pub is_active: bool,
    pub is_root_ca: bool,
    pub parent_ca_id: Option<i64>,
    pub serial_number: Option<String>,
    pub issuer: Option<String>,
    pub subject: Option<String>,
    pub key_usage: Option<String>,           // JSON array of key usage flags
    pub extended_key_usage: Option<String>,  // JSON array of EKU OIDs
    pub certificate_policies: Option<String>, // JSON array of policy OIDs
    pub policy_constraints: Option<String>,   // JSON object with policy constraints
    pub name_constraints: Option<String>,     // JSON object with name constraints
    pub created_by_user_id: i64,
    pub metadata: Option<String>,            // JSON object for additional metadata
    #[serde(skip)]
    pub cert: Vec<u8>,
    #[serde(skip)]
    pub key: Vec<u8>,
}

/// Key algorithm options for CA creation
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum KeyAlgorithm {
    #[serde(rename = "rsa-2048")]
    Rsa2048,
    #[serde(rename = "rsa-3072")]
    Rsa3072,
    #[serde(rename = "rsa-4096")]
    Rsa4096,
    #[serde(rename = "ecdsa-p256")]
    EcdsaP256,
    #[serde(rename = "ecdsa-p384")]
    EcdsaP384,
    #[serde(rename = "ecdsa-p521")]
    EcdsaP521,
    #[serde(rename = "ed25519")]
    Ed25519,
}

impl KeyAlgorithm {
    pub fn as_str(&self) -> &'static str {
        match self {
            KeyAlgorithm::Rsa2048 => "rsa-2048",
            KeyAlgorithm::Rsa3072 => "rsa-3072",
            KeyAlgorithm::Rsa4096 => "rsa-4096",
            KeyAlgorithm::EcdsaP256 => "ecdsa-p256",
            KeyAlgorithm::EcdsaP384 => "ecdsa-p384",
            KeyAlgorithm::EcdsaP521 => "ecdsa-p521",
            KeyAlgorithm::Ed25519 => "ed25519",
        }
    }

    pub fn from_str(s: &str) -> Option<Self> {
        match s {
            "rsa-2048" => Some(KeyAlgorithm::Rsa2048),
            "rsa-3072" => Some(KeyAlgorithm::Rsa3072),
            "rsa-4096" => Some(KeyAlgorithm::Rsa4096),
            "ecdsa-p256" => Some(KeyAlgorithm::EcdsaP256),
            "ecdsa-p384" => Some(KeyAlgorithm::EcdsaP384),
            "ecdsa-p521" => Some(KeyAlgorithm::EcdsaP521),
            "ed25519" => Some(KeyAlgorithm::Ed25519),
            _ => None,
        }
    }

    pub fn key_size(&self) -> i32 {
        match self {
            KeyAlgorithm::Rsa2048 => 2048,
            KeyAlgorithm::Rsa3072 => 3072,
            KeyAlgorithm::Rsa4096 => 4096,
            KeyAlgorithm::EcdsaP256 => 256,
            KeyAlgorithm::EcdsaP384 => 384,
            KeyAlgorithm::EcdsaP521 => 521,
            KeyAlgorithm::Ed25519 => 255,
        }
    }

    pub fn is_rsa(&self) -> bool {
        matches!(self, KeyAlgorithm::Rsa2048 | KeyAlgorithm::Rsa3072 | KeyAlgorithm::Rsa4096)
    }

    pub fn is_ecdsa(&self) -> bool {
        matches!(self, KeyAlgorithm::EcdsaP256 | KeyAlgorithm::EcdsaP384 | KeyAlgorithm::EcdsaP521)
    }

    pub fn is_ed25519(&self) -> bool {
        matches!(self, KeyAlgorithm::Ed25519)
    }
}

impl Default for KeyAlgorithm {
    fn default() -> Self {
        KeyAlgorithm::EcdsaP256
    }
}

/// CA creation request
#[derive(Debug, Serialize, Deserialize, JsonSchema)]
pub struct CreateCaRequest {
    pub name: String,
    pub description: Option<String>,
    pub key_algorithm: Option<KeyAlgorithm>,
    pub validity_years: Option<i32>,
    pub is_root_ca: Option<bool>,
    pub parent_ca_id: Option<i64>,
    pub path_len: Option<i32>,
    pub key_usage: Option<Vec<String>>,
    pub extended_key_usage: Option<Vec<String>>,
    pub certificate_policies: Option<Vec<String>>,
    pub name_constraints: Option<NameConstraints>,
    pub crl_distribution_points: Option<Vec<String>>,
    pub authority_info_access: Option<AuthorityInfoAccess>,
}

/// CA update request
#[derive(Debug, Serialize, Deserialize, JsonSchema)]
pub struct UpdateCaRequest {
    pub name: Option<String>,
    pub description: Option<String>,
    pub is_active: Option<bool>,
    pub crl_distribution_points: Option<Vec<String>>,
    pub authority_info_access: Option<AuthorityInfoAccess>,
}

/// Name constraints for CA certificates
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct NameConstraints {
    pub permitted_dns: Option<Vec<String>>,
    pub excluded_dns: Option<Vec<String>>,
    pub permitted_email: Option<Vec<String>>,
    pub excluded_email: Option<Vec<String>>,
    pub permitted_uri: Option<Vec<String>>,
    pub excluded_uri: Option<Vec<String>>,
    pub permitted_ip: Option<Vec<String>>,
    pub excluded_ip: Option<Vec<String>>,
}

/// Authority Information Access extension
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct AuthorityInfoAccess {
    pub ca_issuers: Option<Vec<String>>,
    pub ocsp_responders: Option<Vec<String>>,
}

/// CA response (without sensitive data)
#[derive(Debug, Serialize, Deserialize, JsonSchema)]
pub struct CaResponse {
    pub id: i64,
    pub created_on: i64,
    pub valid_until: i64,
    pub tenant_id: String,
    pub name: Option<String>,
    pub description: Option<String>,
    pub key_algorithm: String,
    pub key_size: Option<i32>,
    pub path_len: Option<i32>,
    pub is_active: bool,
    pub is_root_ca: bool,
    pub parent_ca_id: Option<i64>,
    pub serial_number: Option<String>,
    pub issuer: Option<String>,
    pub subject: Option<String>,
    pub key_usage: Option<Vec<String>>,
    pub extended_key_usage: Option<Vec<String>>,
    pub certificate_policies: Option<Vec<String>>,
    pub crl_distribution_points: Option<Vec<String>>,
    pub authority_info_access: Option<AuthorityInfoAccess>,
    pub created_by_user_id: i64,
    pub certificate_count: Option<i64>,
    pub last_crl_update: Option<i64>,
}

impl From<CA> for CaResponse {
    fn from(ca: CA) -> Self {
        Self {
            id: ca.id,
            created_on: ca.created_on,
            valid_until: ca.valid_until,
            tenant_id: ca.tenant_id,
            name: ca.name,
            description: ca.description,
            key_algorithm: ca.key_algorithm,
            key_size: ca.key_size,
            path_len: ca.path_len,
            is_active: ca.is_active,
            is_root_ca: ca.is_root_ca,
            parent_ca_id: ca.parent_ca_id,
            serial_number: ca.serial_number,
            issuer: ca.issuer,
            subject: ca.subject,
            key_usage: ca.key_usage.and_then(|s| serde_json::from_str(&s).ok()),
            extended_key_usage: ca.extended_key_usage.and_then(|s| serde_json::from_str(&s).ok()),
            certificate_policies: ca.certificate_policies.and_then(|s| serde_json::from_str(&s).ok()),
            crl_distribution_points: ca.crl_distribution_points.and_then(|s| serde_json::from_str(&s).ok()),
            authority_info_access: ca.authority_info_access.and_then(|s| serde_json::from_str(&s).ok()),
            created_by_user_id: ca.created_by_user_id,
            certificate_count: None, // Will be populated by the API layer
            last_crl_update: None,   // Will be populated by the API layer
        }
    }
}

/// CA list response with pagination
#[derive(Debug, Serialize, Deserialize, JsonSchema)]
pub struct CaListResponse {
    pub cas: Vec<CaResponse>,
    pub total: i64,
    pub page: i32,
    pub per_page: i32,
    pub has_more: bool,
}

/// CA hierarchy information
#[derive(Debug, Serialize, Deserialize, JsonSchema)]
pub struct CaHierarchy {
    pub ca: CaResponse,
    pub children: Vec<CaHierarchy>,
    pub depth: i32,
}

/// CA statistics
#[derive(Debug, Serialize, Deserialize, JsonSchema)]
pub struct CaStatistics {
    pub ca_id: i64,
    pub tenant_id: String,
    pub total_certificates: i64,
    pub active_certificates: i64,
    pub revoked_certificates: i64,
    pub expired_certificates: i64,
    pub certificates_issued_last_30_days: i64,
    pub last_certificate_issued: Option<i64>,
    pub last_crl_generated: Option<i64>,
    pub crl_size_bytes: Option<i64>,
}

/// CA key rotation request
#[derive(Debug, Serialize, Deserialize, JsonSchema)]
pub struct RotateCaRequest {
    pub new_key_algorithm: Option<KeyAlgorithm>,
    pub validity_years: Option<i32>,
    pub new_description: Option<String>,
    pub preserve_chain: Option<bool>,
    pub force_rotation: Option<bool>,
    pub certificate_action: Option<CertificateAction>,
}

/// Actions to take with existing certificates during CA rotation
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum CertificateAction {
    /// Revoke all existing certificates
    Revoke,
    /// Migrate certificates to new CA (update ca_id)
    Migrate,
    /// Keep certificates as-is (they will reference old CA)
    Keep,
}

/// CA key rotation response
#[derive(Debug, Serialize, Deserialize, JsonSchema)]
pub struct CaRotationResponse {
    pub old_ca_id: i64,
    pub new_ca_id: i64,
    pub new_ca: CaResponse,
    pub certificates_affected: i64,
    pub rotation_timestamp: i64,
    pub chain_preserved: bool,
}

/// Certificate creation request with CA selection
#[derive(Debug, Serialize, Deserialize, JsonSchema)]
pub struct CreateCertificateWithCaRequest {
    pub cert_name: String,
    pub cert_type: Option<CertificateType>,
    pub user_id: i64,
    pub validity_in_years: Option<u64>,
    pub dns_names: Option<Vec<String>>,
    pub pkcs12_password: Option<String>,
    pub renew_method: Option<CertificateRenewMethod>,
    pub ca_selection: CaSelection,
}

/// CA selection criteria for certificate issuance
#[derive(Debug, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "type", content = "value")]
pub enum CaSelection {
    /// Select CA by ID
    #[serde(rename = "by_id")]
    ById(i64),
    /// Select CA by name
    #[serde(rename = "by_name")]
    ByName(String),
    /// Automatically select the best CA
    #[serde(rename = "auto")]
    Auto,
}

// ===== ENHANCED CERTIFICATE SEARCH =====

/// Advanced certificate search request
#[derive(Debug, Serialize, Deserialize, JsonSchema)]
pub struct CertificateSearchRequest {
    /// Search filters
    pub filters: Option<Vec<SearchFilter>>,
    /// Sorting options
    pub sort: Option<Vec<SortOption>>,
    /// Pagination
    pub page: Option<i32>,
    pub per_page: Option<i32>,
    /// Include revoked certificates
    pub include_revoked: Option<bool>,
    /// Include expired certificates
    pub include_expired: Option<bool>,
}

/// Search filter for certificate queries
#[derive(Debug, Serialize, Deserialize, JsonSchema)]
pub struct SearchFilter {
    /// Field to filter on
    pub field: SearchField,
    /// Operator to use
    pub operator: SearchOperator,
    /// Value to compare against
    pub value: SearchValue,
}

/// Fields that can be searched
#[derive(Debug, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum SearchField {
    Name,
    CommonName,
    SerialNumber,
    Issuer,
    Subject,
    Status,
    CertificateType,
    Algorithm,
    KeySize,
    CreatedAt,
    ValidUntil,
    RevokedAt,
    Sans,
    ProfileId,
    CaId,
    UserId,
    Metadata,
}

/// Search operators
#[derive(Debug, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum SearchOperator {
    /// Equals
    Eq,
    /// Not equals
    Ne,
    /// Less than
    Lt,
    /// Less than or equal
    Lte,
    /// Greater than
    Gt,
    /// Greater than or equal
    Gte,
    /// Like (SQL LIKE with wildcards)
    Like,
    /// In (value in list)
    In,
    /// Not in (value not in list)
    Nin,
    /// Between (for ranges)
    Between,
    /// Contains (for JSON fields)
    Contains,
    /// Starts with
    StartsWith,
    /// Ends with
    EndsWith,
}

/// Search value (can be different types)
#[derive(Debug, Serialize, Deserialize, JsonSchema)]
#[serde(untagged)]
pub enum SearchValue {
    String(String),
    Number(i64),
    Float(f64),
    Boolean(bool),
    Array(Vec<String>),
    Range { start: i64, end: i64 },
}

/// Sort option for search results
#[derive(Debug, Serialize, Deserialize, JsonSchema)]
pub struct SortOption {
    pub field: SearchField,
    pub direction: SortDirection,
}

/// Sort direction
#[derive(Debug, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum SortDirection {
    Asc,
    Desc,
}

/// Certificate search response
#[derive(Debug, Serialize, Deserialize, JsonSchema)]
pub struct CertificateSearchResponse {
    pub certificates: Vec<Certificate>,
    pub total: i64,
    pub page: i32,
    pub per_page: i32,
    pub has_more: bool,
    pub filters_applied: Vec<SearchFilter>,
    pub sort_applied: Vec<SortOption>,
}

// ===== BATCH OPERATIONS =====

/// Batch operation request
#[derive(Debug, Serialize, Deserialize, JsonSchema)]
pub struct BatchOperationRequest {
    /// Certificate IDs to operate on
    pub certificate_ids: Vec<i64>,
    /// Operation to perform
    pub operation: BatchOperation,
    /// Operation-specific parameters
    pub parameters: Option<BatchOperationParameters>,
}

/// Batch operations
#[derive(Debug, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum BatchOperation {
    /// Revoke certificates
    Revoke,
    /// Restore certificates
    Restore,
    /// Delete certificates
    Delete,
    /// Download certificates
    Download,
    /// Renew certificates
    Renew,
    /// Update metadata
    UpdateMetadata,
}

/// Parameters for batch operations
#[derive(Debug, Serialize, Deserialize, JsonSchema)]
pub struct BatchOperationParameters {
    /// For revoke operation
    pub revocation_reason: Option<i32>,
    pub revocation_note: Option<String>,
    /// For download operation
    pub format: Option<String>,
    pub include_chain: Option<bool>,
    /// For renew operation
    pub validity_years: Option<i32>,
    /// For metadata update
    pub metadata: Option<serde_json::Value>,
}

/// Batch operation response
#[derive(Debug, Serialize, Deserialize, JsonSchema)]
pub struct BatchOperationResponse {
    pub operation: BatchOperation,
    pub total_requested: i32,
    pub successful: i32,
    pub failed: i32,
    pub results: Vec<BatchOperationResult>,
    pub download_url: Option<String>, // For download operations
}

/// Individual result in batch operation
#[derive(Debug, Serialize, Deserialize, JsonSchema)]
pub struct BatchOperationResult {
    pub certificate_id: i64,
    pub success: bool,
    pub error: Option<String>,
    pub details: Option<String>,
}

// ===== CERTIFICATE CHAIN MANAGEMENT =====

/// Certificate chain information
#[derive(Debug, Serialize, Deserialize, JsonSchema)]
pub struct CertificateChain {
    pub certificate: Certificate,
    pub issuer_chain: Vec<Certificate>,
    pub root_ca: Option<Certificate>,
    pub chain_valid: bool,
    pub validation_errors: Vec<String>,
}

/// Chain validation request
#[derive(Debug, Serialize, Deserialize, JsonSchema)]
pub struct ChainValidationRequest {
    pub certificate_id: i64,
    pub validate_expiry: Option<bool>,
    pub validate_revocation: Option<bool>,
}

/// Chain validation response
#[derive(Debug, Serialize, Deserialize, JsonSchema)]
pub struct ChainValidationResponse {
    pub certificate_id: i64,
    pub chain_valid: bool,
    pub validation_results: Vec<ValidationResult>,
    pub chain_length: i32,
    pub expires_at: i64,
}

/// Individual validation result
#[derive(Debug, Serialize, Deserialize, JsonSchema)]
pub struct ValidationResult {
    pub check_type: String,
    pub passed: bool,
    pub message: String,
    pub details: Option<String>,
}

// ===== CERTIFICATE STATISTICS =====

/// Certificate statistics for a tenant
#[derive(Debug, Serialize, Deserialize, JsonSchema)]
pub struct CertificateStatistics {
    pub total_certificates: i64,
    pub active_certificates: i64,
    pub revoked_certificates: i64,
    pub expired_certificates: i64,
    pub expiring_soon: i64, // Within 30 days
    pub by_type: CertificateTypeStats,
    pub by_algorithm: Vec<AlgorithmStats>,
    pub by_ca: Vec<CaStats>,
    pub by_profile: Vec<ProfileStats>,
    pub recent_activity: RecentActivity,
}

/// Certificate statistics by type
#[derive(Debug, Serialize, Deserialize, JsonSchema)]
pub struct CertificateTypeStats {
    pub server: i64,
    pub client: i64,
}

/// Algorithm usage statistics
#[derive(Debug, Serialize, Deserialize, JsonSchema)]
pub struct AlgorithmStats {
    pub algorithm: String,
    pub count: i64,
    pub percentage: f64,
}

/// CA usage statistics
#[derive(Debug, Serialize, Deserialize, JsonSchema)]
pub struct CaStats {
    pub ca_id: i64,
    pub ca_name: String,
    pub count: i64,
    pub percentage: f64,
}

/// Profile usage statistics
#[derive(Debug, Serialize, Deserialize, JsonSchema)]
pub struct ProfileStats {
    pub profile_id: String,
    pub profile_name: String,
    pub count: i64,
    pub percentage: f64,
}

/// Recent activity statistics
#[derive(Debug, Serialize, Deserialize, JsonSchema)]
pub struct RecentActivity {
    pub certificates_issued_last_7_days: i64,
    pub certificates_issued_last_30_days: i64,
    pub certificates_revoked_last_7_days: i64,
    pub certificates_revoked_last_30_days: i64,
}

// ===== BULK DOWNLOAD =====

/// Bulk download request
#[derive(Debug, Serialize, Deserialize, JsonSchema)]
pub struct BulkDownloadRequest {
    pub certificate_ids: Vec<i64>,
    pub format: Option<String>, // pem, der, p12, etc.
    pub include_chain: Option<bool>,
    pub include_private_key: Option<bool>,
    pub password: Option<String>, // For P12 format
}

// ===== CERTIFICATE RENEWAL =====

/// Certificate renewal request
#[derive(Debug, Serialize, Deserialize, JsonSchema)]
pub struct CertificateRenewalRequest {
    pub certificate_id: i64,
    pub validity_years: Option<i32>,
    pub use_same_key: Option<bool>,
    pub update_sans: Option<Vec<String>>,
}

/// Certificate renewal response
#[derive(Debug, Serialize, Deserialize, JsonSchema)]
pub struct CertificateRenewalResponse {
    pub old_certificate_id: i64,
    pub new_certificate_id: i64,
    pub new_certificate: Certificate,
    pub renewal_timestamp: i64,
}

// ===== CERTIFICATE TEMPLATES =====

/// Certificate template for quick issuance
#[derive(Debug, Serialize, Deserialize, JsonSchema)]
pub struct CertificateTemplate {
    pub id: String,
    pub name: String,
    pub description: String,
    pub certificate_type: CertificateType,
    pub profile_id: String,
    pub default_validity_years: i32,
    pub default_key_algorithm: String,
    pub san_template: Option<String>, // Template with placeholders
    pub metadata_template: Option<serde_json::Value>,
    pub tenant_id: String,
    pub created_at: i64,
}

/// Template-based certificate creation request
#[derive(Debug, Serialize, Deserialize, JsonSchema)]
pub struct CreateCertificateFromTemplateRequest {
    pub template_id: String,
    pub name: String,
    pub user_id: i64,
    pub template_variables: Option<serde_json::Value>, // For SAN template substitution
    pub validity_years: Option<i32>, // Override template default
    pub ca_selection: Option<CaSelection>, // Override template CA
}

/// Certificate template creation request
#[derive(Debug, Serialize, Deserialize, JsonSchema)]
pub struct CreateCertificateTemplateRequest {
    pub name: String,
    pub description: String,
    pub certificate_type: CertificateType,
    pub profile_id: String,
    pub default_validity_years: i32,
    pub default_key_algorithm: String,
    pub san_template: Option<String>, // Template with placeholders like {{hostname}}.{{domain}}
    pub metadata_template: Option<serde_json::Value>,
    pub ca_selection: Option<CaSelection>,
    pub auto_renewal: Option<bool>,
    pub notification_settings: Option<TemplateNotificationSettings>,
}

/// Update certificate template request
#[derive(Debug, Serialize, Deserialize, JsonSchema)]
pub struct UpdateCertificateTemplateRequest {
    pub name: Option<String>,
    pub description: Option<String>,
    pub certificate_type: Option<CertificateType>,
    pub profile_id: Option<String>,
    pub default_validity_years: Option<i32>,
    pub default_key_algorithm: Option<String>,
    pub san_template: Option<String>,
    pub metadata_template: Option<serde_json::Value>,
    pub ca_selection: Option<CaSelection>,
    pub auto_renewal: Option<bool>,
    pub notification_settings: Option<TemplateNotificationSettings>,
}

/// Template notification settings
#[derive(Debug, Serialize, Deserialize, JsonSchema)]
pub struct TemplateNotificationSettings {
    pub notify_on_creation: bool,
    pub notify_on_expiration: bool,
    pub notify_on_renewal: bool,
    pub notification_days_before_expiry: i32,
    pub webhook_urls: Vec<String>,
    pub email_recipients: Vec<String>,
}

/// Certificate template list response
#[derive(Debug, Serialize, Deserialize, JsonSchema)]
pub struct CertificateTemplateListResponse {
    pub templates: Vec<CertificateTemplate>,
    pub total: i64,
    pub page: i32,
    pub per_page: i32,
    pub has_more: bool,
}

/// Template variable definition
#[derive(Debug, Serialize, Deserialize, JsonSchema)]
pub struct TemplateVariable {
    pub name: String,
    pub description: String,
    pub required: bool,
    pub default_value: Option<String>,
    pub validation_regex: Option<String>,
    pub example: Option<String>,
}

/// Certificate template for standardized certificate creation
#[derive(Debug, Serialize, Deserialize, JsonSchema)]
pub struct CertificateTemplate {
    pub id: String,
    pub name: String,
    pub description: String,
    pub certificate_type: CertificateType,
    pub profile_id: String,
    pub default_validity_years: i32,
    pub default_key_algorithm: String,
    pub san_template: Option<String>,
    pub metadata_template: Option<serde_json::Value>,
    pub tenant_id: String,
    pub created_at: i64,
}

// ===== WEBHOOK NOTIFICATIONS =====

/// Webhook configuration
#[derive(Debug, Serialize, Deserialize, JsonSchema)]
pub struct WebhookConfig {
    pub id: String,
    pub name: String,
    pub url: String,
    pub events: Vec<WebhookEvent>,
    pub secret: Option<String>, // For HMAC signature verification
    pub headers: Option<serde_json::Value>, // Custom headers
    pub timeout_seconds: i32,
    pub retry_attempts: i32,
    pub is_active: bool,
    pub tenant_id: String,
    pub created_at: i64,
    pub last_triggered: Option<i64>,
    pub success_count: i64,
    pub failure_count: i64,
}

/// Webhook event types
#[derive(Debug, Serialize, Deserialize, JsonSchema, Clone)]
#[serde(rename_all = "snake_case")]
pub enum WebhookEvent {
    CertificateCreated,
    CertificateRevoked,
    CertificateExpiring,
    CertificateRenewed,
    CertificateDeleted,
    CaCreated,
    CaRotated,
    CaRevoked,
    ProfileCreated,
    ProfileUpdated,
    ProfileDeleted,
    AuditThreshold,
    SystemAlert,
}

/// Webhook payload for certificate events
#[derive(Debug, Serialize, Deserialize, JsonSchema)]
pub struct WebhookPayload {
    pub event: WebhookEvent,
    pub timestamp: i64,
    pub tenant_id: String,
    pub webhook_id: String,
    pub data: WebhookEventData,
    pub signature: Option<String>, // HMAC signature if secret is configured
}

/// Webhook event data
#[derive(Debug, Serialize, Deserialize, JsonSchema)]
#[serde(untagged)]
pub enum WebhookEventData {
    Certificate(CertificateEventData),
    Ca(CaEventData),
    Profile(ProfileEventData),
    Audit(AuditEventData),
    System(SystemEventData),
}

/// Certificate event data for webhooks
#[derive(Debug, Serialize, Deserialize, JsonSchema)]
pub struct CertificateEventData {
    pub certificate_id: i64,
    pub certificate_name: String,
    pub certificate_type: String,
    pub serial_number: String,
    pub subject: String,
    pub issuer: String,
    pub valid_until: i64,
    pub status: String,
    pub user_id: i64,
    pub ca_id: i64,
    pub profile_id: Option<String>,
    pub metadata: Option<serde_json::Value>,
}

/// CA event data for webhooks
#[derive(Debug, Serialize, Deserialize, JsonSchema)]
pub struct CaEventData {
    pub ca_id: i64,
    pub ca_name: String,
    pub subject: String,
    pub valid_until: i64,
    pub is_root_ca: bool,
    pub parent_ca_id: Option<i64>,
    pub key_algorithm: String,
    pub created_by_user_id: i64,
}

/// Profile event data for webhooks
#[derive(Debug, Serialize, Deserialize, JsonSchema)]
pub struct ProfileEventData {
    pub profile_id: String,
    pub profile_name: String,
    pub certificate_type: String,
    pub default_days: i32,
    pub max_days: i32,
    pub eku: Vec<String>,
    pub key_usage: Vec<String>,
}

/// Audit event data for webhooks
#[derive(Debug, Serialize, Deserialize, JsonSchema)]
pub struct AuditEventData {
    pub threshold_type: String,
    pub threshold_value: i64,
    pub current_value: i64,
    pub time_period: String,
    pub description: String,
}

/// System event data for webhooks
#[derive(Debug, Serialize, Deserialize, JsonSchema)]
pub struct SystemEventData {
    pub alert_type: String,
    pub severity: String,
    pub message: String,
    pub details: Option<serde_json::Value>,
}

/// Webhook creation request
#[derive(Debug, Serialize, Deserialize, JsonSchema)]
pub struct CreateWebhookRequest {
    pub name: String,
    pub url: String,
    pub events: Vec<WebhookEvent>,
    pub secret: Option<String>,
    pub headers: Option<serde_json::Value>,
    pub timeout_seconds: Option<i32>,
    pub retry_attempts: Option<i32>,
}

/// Webhook update request
#[derive(Debug, Serialize, Deserialize, JsonSchema)]
pub struct UpdateWebhookRequest {
    pub name: Option<String>,
    pub url: Option<String>,
    pub events: Option<Vec<WebhookEvent>>,
    pub secret: Option<String>,
    pub headers: Option<serde_json::Value>,
    pub timeout_seconds: Option<i32>,
    pub retry_attempts: Option<i32>,
    pub is_active: Option<bool>,
}

/// Webhook list response
#[derive(Debug, Serialize, Deserialize, JsonSchema)]
pub struct WebhookListResponse {
    pub webhooks: Vec<WebhookConfig>,
    pub total: i64,
    pub page: i32,
    pub per_page: i32,
    pub has_more: bool,
}

/// Webhook delivery log
#[derive(Debug, Serialize, Deserialize, JsonSchema)]
pub struct WebhookDelivery {
    pub id: String,
    pub webhook_id: String,
    pub event: WebhookEvent,
    pub payload: WebhookPayload,
    pub response_status: Option<i32>,
    pub response_body: Option<String>,
    pub error_message: Option<String>,
    pub attempt_number: i32,
    pub delivered_at: i64,
    pub duration_ms: i64,
    pub success: bool,
}

pub struct CertificateBuilder {
    x509: X509Builder,
    private_key: PKey<Private>,
    created_on: i64,
    valid_until: Option<i64>,
    name: Option<String>,
    pkcs12_password: String,
    ca: Option<(i64, X509, PKey<Private>)>,
    user_id: Option<i64>,
    renew_method: CertificateRenewMethod
}
impl CertificateBuilder {
    pub fn new() -> Result<Self> {
        let private_key = generate_private_key()?;
        let asn1_serial = generate_serial_number()?;
        let (created_on_unix, created_on_openssl) = get_timestamp(0)?;

        let mut x509 = X509Builder::new()?;
        x509.set_version(2)?;
        x509.set_serial_number(&asn1_serial)?;
        x509.set_not_before(&created_on_openssl)?;
        x509.set_pubkey(&private_key)?;

        Ok(Self {
            x509,
            private_key,
            created_on: created_on_unix,
            valid_until: None,
            name: None,
            pkcs12_password: String::new(),
            ca: None,
            user_id: None,
            renew_method: Default::default()
        })
    }

    /// Copy information over from an existing certificate
    /// Fields set are:\
    ///     - Name\
    ///     - Validity\
    ///     - PKCS#12 Password\
    ///     - Renew Method\
    ///     - User ID\
    pub fn try_from(old_cert: &Certificate) -> Result<Self> {
        let validity_in_years = ((old_cert.valid_until - old_cert.created_on) / 1000 / 60 / 60 / 24 / 365).max(1);

        Self::new()?
            .set_name(&old_cert.name)?
            .set_valid_until(validity_in_years as u64)?
            .set_pkcs12_password(&old_cert.pkcs12_password)?
            .set_renew_method(old_cert.renew_method)?
            .set_user_id(old_cert.user_id)

    }

    pub fn set_name(mut self, name: &str) -> Result<Self, anyhow::Error> {
        self.name = Some(name.to_string());
        let common_name = create_cn(name)?;
        self.x509.set_subject_name(&common_name)?;
        Ok(self)
    }

    pub fn set_valid_until(mut self, years: u64) -> Result<Self, anyhow::Error> {
        let (valid_until_unix, valid_until_openssl) = if years != 0 {
            get_timestamp(years)?
        } else {
            get_short_lifetime()?
        };
        self.valid_until = Some(valid_until_unix);
        self.x509.set_not_after(&valid_until_openssl)?;
        Ok(self)
    }

    pub fn set_pkcs12_password(mut self, password: &str) -> Result<Self, anyhow::Error> {
        self.pkcs12_password = password.to_string();
        Ok(self)
    }

    pub fn set_dns_san(mut self, dns_names: &Vec<String>) -> Result<Self, anyhow::Error> {
        let mut san_builder = SubjectAlternativeName::new();
        for dns in dns_names {
            san_builder.dns(dns);
        }
        let san = san_builder.build(&self.x509.x509v3_context(None, None))?;
        self.x509.append_extension(san)?;

        Ok(self)
    }

    pub fn set_email_san(mut self, email: &str) -> Result<Self, anyhow::Error> {
        let san = SubjectAlternativeName::new()
            .email(email)
            .build(&self.x509.x509v3_context(None, None))?;
        self.x509.append_extension(san)?;

        Ok(self)
    }

    pub fn set_ca(mut self, ca: &CA) -> Result<Self, anyhow::Error> {
        let ca_cert = X509::from_der(&ca.cert)?;
        let ca_key = PKey::private_key_from_der(&ca.key)?;
        self.ca = Some((ca.id, ca_cert, ca_key));
        Ok(self)
    }

    /// Set CA by ID (for multi-CA environments)
    pub async fn set_ca_by_id(mut self, ca_id: i64, db: &crate::db::VaulTLSDB) -> Result<Self, anyhow::Error> {
        let ca = db.get_ca_by_id(ca_id).await?;
        self.set_ca(&ca)
    }

    /// Set CA by name and tenant (for multi-CA environments)
    pub async fn set_ca_by_name(mut self, ca_name: &str, tenant_id: &str, db: &crate::db::VaulTLSDB) -> Result<Self, anyhow::Error> {
        let ca = db.get_ca_by_name(ca_name, tenant_id).await?;
        self.set_ca(&ca)
    }

    /// Get the best CA for certificate issuance based on criteria
    pub async fn select_best_ca(
        mut self,
        tenant_id: &str,
        cert_type: &CertificateType,
        db: &crate::db::VaulTLSDB
    ) -> Result<Self, anyhow::Error> {
        let ca = db.get_best_ca_for_issuance(tenant_id, cert_type).await?;
        self.set_ca(&ca)
    }

    /// Set CA with validation for certificate type compatibility
    pub fn set_ca_with_validation(mut self, ca: &CA, cert_type: &CertificateType) -> Result<Self, anyhow::Error> {
        // Validate CA is active
        if !ca.is_active {
            return Err(anyhow!("Cannot use inactive CA for certificate issuance"));
        }

        // Check if CA is suitable for the certificate type
        if let Some(key_usage) = &ca.key_usage {
            let key_usage_vec: Vec<String> = serde_json::from_str(key_usage)
                .unwrap_or_default();

            if !key_usage_vec.contains(&"keyCertSign".to_string()) {
                return Err(anyhow!("CA does not have keyCertSign usage"));
            }
        }

        // Additional validation based on certificate type
        match cert_type {
            CertificateType::Server => {
                // Server certificates can be issued by any CA
            },
            CertificateType::Client => {
                // Client certificates can be issued by any CA
                // Could add specific validation here if needed
            }
        }

        self.set_ca(ca)
    }

    pub fn set_user_id(mut self, user_id: i64) -> Result<Self, anyhow::Error> {
        self.user_id = Some(user_id);
        Ok(self)
    }

    pub fn set_renew_method(mut self, renew_method: CertificateRenewMethod) -> Result<Self, anyhow::Error> {
        self.renew_method = renew_method;
        Ok(self)
    }

    pub fn build_ca(mut self) -> Result<CA, anyhow::Error> {
        let name = self.name.ok_or(anyhow!("X509: name not set"))?;
        let valid_until = self.valid_until.ok_or(anyhow!("X509: valid_until not set"))?;

        let cn = create_cn(&name)?;
        self.x509.set_issuer_name(&cn)?;

        let basic_constraints = BasicConstraints::new().ca().build()?;
        self.x509.append_extension(basic_constraints)?;

        let key_usage = KeyUsage::new()
            .key_cert_sign()
            .crl_sign()
            .build()?;
        self.x509.append_extension(key_usage)?;

        let subject_key_identifier = SubjectKeyIdentifier::new().build(&self.x509.x509v3_context(None, None))?;
        self.x509.append_extension(subject_key_identifier)?;
        let authority_key_identifier = AuthorityKeyIdentifier::new().keyid(true).build(&self.x509.x509v3_context(None, None))?;
        self.x509.append_extension(authority_key_identifier)?;

        self.x509.sign(&self.private_key, MessageDigest::sha256())?;
        let cert = self.x509.build();

        Ok(CA{
            id: -1,
            created_on: self.created_on,
            valid_until,
            cert: cert.to_der()?,
            key: self.private_key.private_key_to_der()?,
            tenant_id: "00000000-0000-0000-0000-000000000000".to_string(), // Default tenant
            name: None,
            description: None,
            key_algorithm: "ecdsa-p256".to_string(),
            key_size: Some(256),
            path_len: None,
            basic_constraints: None,
            crl_distribution_points: None,
            authority_info_access: None,
            is_active: true,
            is_root_ca: true,
            parent_ca_id: None,
            serial_number: None,
            issuer: None,
            subject: None,
            key_usage: None,
            extended_key_usage: None,
            certificate_policies: None,
            policy_constraints: None,
            name_constraints: None,
            created_by_user_id: 1, // Default admin user
            metadata: None,
        })
    }

    pub fn build_client(mut self) -> Result<Certificate, anyhow::Error> {
        let ext_key_usage = ExtendedKeyUsage::new()
            .client_auth()
            .build()?;
        self.x509.append_extension(ext_key_usage)?;

        self.build_common(Client)
    }

    pub fn build_server(mut self) -> Result<Certificate, anyhow::Error> {
        let ext_key_usage = ExtendedKeyUsage::new()
            .server_auth()
            .build()?;
        self.x509.append_extension(ext_key_usage)?;

        self.build_common(Server)
    }

    pub fn build_common(mut self, certificate_type: CertificateType) -> Result<Certificate, anyhow::Error> {
        let name = self.name.ok_or(anyhow!("X509: name not set"))?;
        let valid_until = self.valid_until.ok_or(anyhow!("X509: valid_until not set"))?;
        let user_id = self.user_id.ok_or(anyhow!("X509: user_id not set"))?;
        let (ca_id, ca_cert, ca_key) = self.ca.ok_or(anyhow!("X509: CA not set"))?;

        let basic_constraints = BasicConstraints::new().build()?;
        self.x509.append_extension(basic_constraints)?;

        let key_usage = KeyUsage::new()
            .digital_signature()
            .key_encipherment()
            .build()?;
        self.x509.append_extension(key_usage)?;

        self.x509.set_issuer_name(ca_cert.subject_name())?;

        self.x509.sign(&ca_key, MessageDigest::sha256())?;
        let cert = self.x509.build();

        let mut ca_stack = Stack::new()?;
        ca_stack.push(ca_cert.clone())?;

        let pkcs12 = Pkcs12::builder()
            .name(&name)
            .ca(ca_stack)
            .cert(&cert)
            .pkey(&self.private_key)
            .build2(&self.pkcs12_password)?;

        Ok(Certificate{
            id: -1,
            name,
            created_on: self.created_on,
            valid_until,
            certificate_type,
            pkcs12: pkcs12.to_der()?,
            pkcs12_password: self.pkcs12_password,
            ca_id,
            user_id,
            renew_method: self.renew_method,
            tenant_id: "00000000-0000-0000-0000-000000000000".to_string(), // Default tenant
            profile_id: None,
            serial_number: None,
            issuer: None,
            subject: None,
            algorithm: Some("ecdsa-p256".to_string()),
            key_size: Some(256),
            sans: None,
            metadata: None,
            status: "active".to_string(),
            revoked_at: None,
            revoked_by_user_id: None,
            revocation_reason: None,
        })
    }
}

/// Generates a new private key.
fn generate_private_key() -> Result<PKey<Private>, ErrorStack> {
    let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1)?;
    let ec_key = EcKey::generate(&group)?;
    let server_key = PKey::from_ec_key(ec_key)?;
    Ok(server_key)
}

fn create_cn(ca_name: &str) -> Result<X509Name, ErrorStack> {
    let mut name_builder = X509NameBuilder::new()?;
    name_builder.append_entry_by_text("CN", ca_name)?;
    let name = name_builder.build();
    Ok(name)
}

/// Returns the password for the PKCS#12.
pub(crate) fn get_password(system_generated_password: bool, pkcs12_password: &Option<String>) -> String {
    if system_generated_password {
        // Create password for the PKCS#12
        let pg = PasswordGenerator {
            length: 20,
            numbers: true,
            lowercase_letters: true,
            uppercase_letters: true,
            symbols: true,
            spaces: false,
            exclude_similar_characters: false,
            strict: true,
        };
        pg.generate_one().unwrap()
    } else {
        match pkcs12_password {
            Some(p) => p.clone(),
            None => "".to_string(),
        }
    }
}

/// Generates a random serial number.
fn generate_serial_number() -> Result<Asn1Integer, ErrorStack> {
    let mut big_serial = BigNum::new()?;
    big_serial.rand(64, openssl::bn::MsbOption::MAYBE_ZERO, false)?;
    let asn1_serial = big_serial.to_asn1_integer()?;
    Ok(asn1_serial)
}

/// Returns the current UNIX timestamp in milliseconds and an OpenSSL Asn1Time object.
fn get_timestamp(from_now_in_years: u64) -> Result<(i64, Asn1Time), ErrorStack> {
    let time = SystemTime::now() + std::time::Duration::from_secs(60 * 60 * 24 * 365 * from_now_in_years);
    let time_unix = time.duration_since(UNIX_EPOCH).unwrap().as_millis() as i64;
    let time_openssl = Asn1Time::days_from_now(365 * from_now_in_years as u32)?;

    Ok((time_unix, time_openssl))
}

/// For E2E testing generate a short lifetime certificate.
fn get_short_lifetime() -> Result<(i64, Asn1Time), ErrorStack> {
    let time = SystemTime::now() + std::time::Duration::from_secs(60 * 60 * 24);
    let time_unix = time.duration_since(UNIX_EPOCH).unwrap().as_millis() as i64;
    let time_openssl = Asn1Time::days_from_now(1)?;

    Ok((time_unix, time_openssl))
}

/// Convert a CA certificate to PEM format.
pub(crate) fn get_pem(ca: &CA) -> Result<Vec<u8>, ErrorStack> {
    let cert = X509::from_der(&ca.cert)?;
    cert.to_pem()
}

/// Saves the CA certificate to a file for filesystem access.
pub(crate) fn save_ca(ca: &CA) -> Result<(), ApiError> {
    let pem = get_pem(ca)?;
    fs::write(CA_FILE_PATH, pem).map_err(|e| ApiError::Other(e.to_string()))?;
    Ok(())
}

pub(crate) fn get_dns_names(cert: &Certificate) -> Result<Vec<String>, anyhow::Error> {
    let encrypted_p12 = Pkcs12::from_der(&cert.pkcs12)?;
    let Some(cert) = encrypted_p12.parse2(&cert.pkcs12_password)?.cert else { return Err(anyhow::anyhow!("No certificate found in PKCS#12"))};
    let Some(san) = cert.subject_alt_names() else { return Err(anyhow::anyhow!("No certificate found in PKCS#12"))};
    Ok(san.iter().filter_map(|name| name.dnsname().map(|s| s.to_string())).collect())
}