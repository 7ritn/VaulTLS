use rocket::serde::{Deserialize, Serialize};
use rocket_okapi::JsonSchema;
use uuid::Uuid;
use std::collections::HashMap;

/// Certificate profile for defining certificate policies and constraints
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct Profile {
    pub id: String,  // UUID v4
    pub name: String,
    pub eku: Vec<String>,  // Extended Key Usage values
    pub key_usage: Vec<String>,  // Key Usage values
    pub san_rules: Option<SanRules>,  // SAN validation rules
    pub default_days: i32,
    pub max_days: i32,
    pub renewal_window_pct: i32,  // Percentage of validity period when renewal is allowed
    pub key_alg_options: Vec<String>,  // Allowed key algorithms
    pub tenant_id: String,
    pub created_at: i64,
}

impl Profile {
    /// Create a new profile
    pub fn new(
        name: String,
        eku: Vec<String>,
        key_usage: Vec<String>,
        default_days: i32,
        max_days: i32,
        key_alg_options: Vec<String>,
        tenant_id: String,
    ) -> Self {
        Self {
            id: Uuid::new_v4().to_string(),
            name,
            eku,
            key_usage,
            san_rules: None,
            default_days,
            max_days,
            renewal_window_pct: 30,  // Default 30%
            key_alg_options,
            tenant_id,
            created_at: chrono::Utc::now().timestamp(),
        }
    }

    /// Create a server certificate profile
    pub fn server_profile(tenant_id: String) -> Self {
        Self::new(
            "Server Certificate".to_string(),
            vec!["serverAuth".to_string()],
            vec!["digitalSignature".to_string(), "keyEncipherment".to_string()],
            365,  // 1 year default
            1095, // 3 years max
            vec!["rsa-2048".to_string(), "rsa-3072".to_string(), "ecdsa-p256".to_string()],
            tenant_id,
        )
    }

    /// Create a client certificate profile
    pub fn client_profile(tenant_id: String) -> Self {
        Self::new(
            "Client Certificate".to_string(),
            vec!["clientAuth".to_string()],
            vec!["digitalSignature".to_string()],
            365,  // 1 year default
            730,  // 2 years max
            vec!["rsa-2048".to_string(), "ecdsa-p256".to_string()],
            tenant_id,
        )
    }

    /// Validate if a certificate request matches this profile
    pub fn validate_request(&self, request: &CertificateRequest) -> Result<(), String> {
        // Validate validity period
        if request.validity_days > self.max_days {
            return Err(format!("Validity period {} days exceeds maximum {} days", 
                request.validity_days, self.max_days));
        }

        // Validate key algorithm
        if !self.key_alg_options.contains(&request.key_algorithm) {
            return Err(format!("Key algorithm {} not allowed by profile", request.key_algorithm));
        }

        // Validate SANs if rules are defined
        if let Some(ref san_rules) = self.san_rules {
            san_rules.validate(&request.sans)?;
        }

        Ok(())
    }
}

/// SAN (Subject Alternative Name) validation rules
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct SanRules {
    pub dns_pattern: Option<String>,     // Regex pattern for DNS names
    pub ip_pattern: Option<String>,      // Regex pattern for IP addresses
    pub email_pattern: Option<String>,   // Regex pattern for email addresses
    pub uri_pattern: Option<String>,     // Regex pattern for URIs
    pub max_dns_names: Option<i32>,      // Maximum number of DNS names
    pub max_ip_addresses: Option<i32>,   // Maximum number of IP addresses
    pub max_email_addresses: Option<i32>, // Maximum number of email addresses
    pub max_uris: Option<i32>,           // Maximum number of URIs
}

impl SanRules {
    /// Validate SANs against the rules
    pub fn validate(&self, sans: &SubjectAlternativeNames) -> Result<(), String> {
        // Validate DNS names
        if let Some(ref dns_names) = sans.dns_names {
            if let Some(max) = self.max_dns_names {
                if dns_names.len() > max as usize {
                    return Err(format!("Too many DNS names: {} > {}", dns_names.len(), max));
                }
            }
            
            if let Some(ref pattern) = self.dns_pattern {
                let regex = regex::Regex::new(pattern)
                    .map_err(|_| "Invalid DNS pattern in profile")?;
                for dns_name in dns_names {
                    if !regex.is_match(dns_name) {
                        return Err(format!("DNS name '{}' doesn't match pattern", dns_name));
                    }
                }
            }
        }

        // Validate IP addresses
        if let Some(ref ip_addresses) = sans.ip_addresses {
            if let Some(max) = self.max_ip_addresses {
                if ip_addresses.len() > max as usize {
                    return Err(format!("Too many IP addresses: {} > {}", ip_addresses.len(), max));
                }
            }
            
            if let Some(ref pattern) = self.ip_pattern {
                let regex = regex::Regex::new(pattern)
                    .map_err(|_| "Invalid IP pattern in profile")?;
                for ip_addr in ip_addresses {
                    if !regex.is_match(ip_addr) {
                        return Err(format!("IP address '{}' doesn't match pattern", ip_addr));
                    }
                }
            }
        }

        // Similar validation for email and URI...
        
        Ok(())
    }
}

/// Subject Alternative Names for certificate requests
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct SubjectAlternativeNames {
    pub dns_names: Option<Vec<String>>,
    pub ip_addresses: Option<Vec<String>>,
    pub email_addresses: Option<Vec<String>>,
    pub uris: Option<Vec<String>>,
}

/// Certificate request for validation against profiles
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct CertificateRequest {
    pub validity_days: i32,
    pub key_algorithm: String,
    pub sans: SubjectAlternativeNames,
}

/// Request to create a new profile
#[derive(Debug, Serialize, Deserialize, JsonSchema)]
pub struct CreateProfileRequest {
    pub name: String,
    pub eku: Vec<String>,
    pub key_usage: Vec<String>,
    pub san_rules: Option<SanRules>,
    pub default_days: i32,
    pub max_days: i32,
    pub renewal_window_pct: Option<i32>,
    pub key_alg_options: Vec<String>,
}

/// Request to update a profile
#[derive(Debug, Serialize, Deserialize, JsonSchema)]
pub struct UpdateProfileRequest {
    pub name: Option<String>,
    pub eku: Option<Vec<String>>,
    pub key_usage: Option<Vec<String>>,
    pub san_rules: Option<SanRules>,
    pub default_days: Option<i32>,
    pub max_days: Option<i32>,
    pub renewal_window_pct: Option<i32>,
    pub key_alg_options: Option<Vec<String>>,
}

/// Extended Key Usage values
pub struct ExtendedKeyUsage;

impl ExtendedKeyUsage {
    pub const SERVER_AUTH: &'static str = "serverAuth";
    pub const CLIENT_AUTH: &'static str = "clientAuth";
    pub const CODE_SIGNING: &'static str = "codeSigning";
    pub const EMAIL_PROTECTION: &'static str = "emailProtection";
    pub const TIME_STAMPING: &'static str = "timeStamping";
    pub const OCSP_SIGNING: &'static str = "OCSPSigning";
    
    pub fn all() -> Vec<&'static str> {
        vec![
            Self::SERVER_AUTH,
            Self::CLIENT_AUTH,
            Self::CODE_SIGNING,
            Self::EMAIL_PROTECTION,
            Self::TIME_STAMPING,
            Self::OCSP_SIGNING,
        ]
    }
}

/// Key Usage values
pub struct KeyUsage;

impl KeyUsage {
    pub const DIGITAL_SIGNATURE: &'static str = "digitalSignature";
    pub const KEY_ENCIPHERMENT: &'static str = "keyEncipherment";
    pub const KEY_AGREEMENT: &'static str = "keyAgreement";
    pub const KEY_CERT_SIGN: &'static str = "keyCertSign";
    pub const CRL_SIGN: &'static str = "cRLSign";
    pub const DATA_ENCIPHERMENT: &'static str = "dataEncipherment";
    pub const NON_REPUDIATION: &'static str = "nonRepudiation";
    
    pub fn all() -> Vec<&'static str> {
        vec![
            Self::DIGITAL_SIGNATURE,
            Self::KEY_ENCIPHERMENT,
            Self::KEY_AGREEMENT,
            Self::KEY_CERT_SIGN,
            Self::CRL_SIGN,
            Self::DATA_ENCIPHERMENT,
            Self::NON_REPUDIATION,
        ]
    }
}
