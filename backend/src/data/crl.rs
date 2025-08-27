use rocket::serde::{Deserialize, Serialize};
use rocket_okapi::JsonSchema;

/// Certificate Revocation List entry
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct RevokedCertificate {
    pub id: i64,
    pub certificate_id: i64,
    pub serial_number: String,
    pub revocation_date: i64,
    pub revocation_reason: RevocationReason,
    pub ca_id: i64,
    pub tenant_id: String,
    pub revoked_by_user_id: Option<i64>,
    pub created_at: i64,
}

/// CRL metadata for tracking CRL generation
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct CrlMetadata {
    pub id: i64,
    pub ca_id: i64,
    pub tenant_id: String,
    pub crl_number: i64,
    pub this_update: i64,
    pub next_update: i64,
    pub revoked_count: i64,
    pub created_at: i64,
}

/// Revocation reasons as defined in RFC 5280
#[derive(Debug, Clone, Copy, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
#[repr(u8)]
pub enum RevocationReason {
    Unspecified = 0,
    KeyCompromise = 1,
    CaCompromise = 2,
    AffiliationChanged = 3,
    Superseded = 4,
    CessationOfOperation = 5,
    CertificateHold = 6,
    // 7 is unused
    RemoveFromCrl = 8,
    PrivilegeWithdrawn = 9,
    AaCompromise = 10,
}

impl RevocationReason {
    /// Convert from u8 to RevocationReason
    pub fn from_u8(value: u8) -> Option<Self> {
        match value {
            0 => Some(RevocationReason::Unspecified),
            1 => Some(RevocationReason::KeyCompromise),
            2 => Some(RevocationReason::CaCompromise),
            3 => Some(RevocationReason::AffiliationChanged),
            4 => Some(RevocationReason::Superseded),
            5 => Some(RevocationReason::CessationOfOperation),
            6 => Some(RevocationReason::CertificateHold),
            8 => Some(RevocationReason::RemoveFromCrl),
            9 => Some(RevocationReason::PrivilegeWithdrawn),
            10 => Some(RevocationReason::AaCompromise),
            _ => None,
        }
    }

    /// Get human-readable description
    pub fn description(&self) -> &'static str {
        match self {
            RevocationReason::Unspecified => "Unspecified",
            RevocationReason::KeyCompromise => "Key Compromise",
            RevocationReason::CaCompromise => "CA Compromise",
            RevocationReason::AffiliationChanged => "Affiliation Changed",
            RevocationReason::Superseded => "Superseded",
            RevocationReason::CessationOfOperation => "Cessation of Operation",
            RevocationReason::CertificateHold => "Certificate Hold",
            RevocationReason::RemoveFromCrl => "Remove from CRL",
            RevocationReason::PrivilegeWithdrawn => "Privilege Withdrawn",
            RevocationReason::AaCompromise => "AA Compromise",
        }
    }
}

impl Default for RevocationReason {
    fn default() -> Self {
        RevocationReason::Unspecified
    }
}

/// Certificate revocation status
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum RevocationStatus {
    Active,
    Revoked,
    Expired,
    Hold,
}

impl RevocationStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            RevocationStatus::Active => "active",
            RevocationStatus::Revoked => "revoked",
            RevocationStatus::Expired => "expired",
            RevocationStatus::Hold => "hold",
        }
    }

    pub fn from_str(s: &str) -> Option<Self> {
        match s {
            "active" => Some(RevocationStatus::Active),
            "revoked" => Some(RevocationStatus::Revoked),
            "expired" => Some(RevocationStatus::Expired),
            "hold" => Some(RevocationStatus::Hold),
            _ => None,
        }
    }
}

impl Default for RevocationStatus {
    fn default() -> Self {
        RevocationStatus::Active
    }
}

/// Request to revoke a certificate
#[derive(Debug, Serialize, Deserialize, JsonSchema)]
pub struct RevokeCertificateRequest {
    pub reason: Option<RevocationReason>,
    pub effective_date: Option<i64>, // Unix timestamp, defaults to now
}

/// Response when revoking a certificate
#[derive(Debug, Serialize, Deserialize, JsonSchema)]
pub struct RevokeCertificateResponse {
    pub certificate_id: i64,
    pub serial_number: String,
    pub revocation_date: i64,
    pub reason: RevocationReason,
    pub crl_updated: bool,
}

/// CRL download format options
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "lowercase")]
pub enum CrlFormat {
    Der,
    Pem,
}

impl CrlFormat {
    pub fn from_str(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "der" => Some(CrlFormat::Der),
            "pem" => Some(CrlFormat::Pem),
            _ => None,
        }
    }

    pub fn content_type(&self) -> &'static str {
        match self {
            CrlFormat::Der => "application/pkix-crl",
            CrlFormat::Pem => "application/x-pem-file",
        }
    }

    pub fn file_extension(&self) -> &'static str {
        match self {
            CrlFormat::Der => "crl",
            CrlFormat::Pem => "pem",
        }
    }
}

impl Default for CrlFormat {
    fn default() -> Self {
        CrlFormat::Der
    }
}

/// CRL information response
#[derive(Debug, Serialize, Deserialize, JsonSchema)]
pub struct CrlInfo {
    pub ca_id: i64,
    pub tenant_id: String,
    pub crl_number: i64,
    pub this_update: i64,
    pub next_update: i64,
    pub revoked_count: i64,
    pub total_certificates: i64,
    pub last_generated: i64,
}

/// OCSP request information (for future OCSP support)
#[derive(Debug, Serialize, Deserialize, JsonSchema)]
pub struct OcspRequest {
    pub serial_number: String,
    pub ca_id: i64,
    pub tenant_id: String,
}

/// OCSP response information (for future OCSP support)
#[derive(Debug, Serialize, Deserialize, JsonSchema)]
pub struct OcspResponse {
    pub serial_number: String,
    pub status: OcspStatus,
    pub this_update: i64,
    pub next_update: Option<i64>,
    pub revocation_time: Option<i64>,
    pub revocation_reason: Option<RevocationReason>,
}

/// OCSP certificate status
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum OcspStatus {
    Good,
    Revoked,
    Unknown,
}

/// Certificate status check request
#[derive(Debug, Serialize, Deserialize, JsonSchema)]
pub struct CertificateStatusRequest {
    pub serial_number: String,
    pub ca_id: Option<i64>,
}

/// Certificate status check response
#[derive(Debug, Serialize, Deserialize, JsonSchema)]
pub struct CertificateStatusResponse {
    pub serial_number: String,
    pub status: RevocationStatus,
    pub revocation_date: Option<i64>,
    pub revocation_reason: Option<RevocationReason>,
    pub valid_until: i64,
    pub ca_id: i64,
    pub tenant_id: String,
}

/// CRL generation options
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct CrlGenerationOptions {
    pub validity_hours: Option<i32>, // How long the CRL is valid (default: 168 hours = 7 days)
    pub include_expired: Option<bool>, // Include expired certificates in CRL (default: false)
    pub crl_extensions: Option<bool>, // Include CRL extensions (default: true)
}

impl Default for CrlGenerationOptions {
    fn default() -> Self {
        Self {
            validity_hours: Some(168), // 7 days
            include_expired: Some(false),
            crl_extensions: Some(true),
        }
    }
}

/// Statistics about certificate revocations
#[derive(Debug, Serialize, Deserialize, JsonSchema)]
pub struct RevocationStatistics {
    pub total_certificates: i64,
    pub active_certificates: i64,
    pub revoked_certificates: i64,
    pub expired_certificates: i64,
    pub revocations_by_reason: std::collections::HashMap<String, i64>,
    pub revocations_last_30_days: i64,
    pub tenant_id: String,
    pub ca_id: i64,
}
