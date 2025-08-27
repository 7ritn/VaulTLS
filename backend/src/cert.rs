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