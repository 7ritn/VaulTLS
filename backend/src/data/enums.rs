use num_enum::TryFromPrimitive;
use rocket_okapi::JsonSchema;
use rusqlite::types::{FromSql, FromSqlError, FromSqlResult, ValueRef};
use serde_repr::{Deserialize_repr, Serialize_repr};

#[derive(Serialize_repr, Deserialize_repr, JsonSchema, Clone, Debug, TryFromPrimitive, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum UserRole {
    User = 0,
    Admin = 1
}

impl FromSql for UserRole {
    fn column_result(value: ValueRef<'_>) -> FromSqlResult<Self> {
        match value {
            ValueRef::Integer(i) => {
                let value = i as u8;
                UserRole::try_from(value)
                    .map_err(|_| FromSqlError::InvalidType)
            },
            _ => Err(FromSqlError::InvalidType),
        }
    }
}

#[derive(Serialize_repr, Deserialize_repr, JsonSchema, Clone, Debug, Copy, PartialEq, Eq, Default)]
#[repr(u8)]
#[allow(clippy::upper_case_acronyms)]
pub(crate) enum MailEncryption {
    #[default]
    None = 0,
    TLS = 1,
    STARTTLS = 2
}

impl From<String> for MailEncryption {
    fn from(value: String) -> Self {
        match value.to_uppercase().as_str()
        {
            "TLS" => MailEncryption::TLS,
            "STARTTLS" => MailEncryption::STARTTLS,
            _ => MailEncryption::None
        }
    }
}

#[derive(Serialize_repr, Deserialize_repr, JsonSchema, Clone, Debug, Copy, PartialEq, Eq, Default)]
#[repr(u8)]
pub(crate) enum PasswordRule {
    #[default]
    Optional = 0,
    Required = 1,
    System = 2
}

#[derive(Debug, Clone)]
pub enum CertData {
    Pkcs12(Vec<u8>),
    Pem(Vec<u8>),
    SshBundle(Vec<u8>),
}

impl CertData {
    pub fn into_bytes(self) -> Vec<u8> {
        match self { CertData::Pkcs12(b) | CertData::Pem(b) | CertData::SshBundle(b) => b }
    }
    pub fn as_bytes(&self) -> &[u8] {
        match self { CertData::Pkcs12(b) | CertData::Pem(b) | CertData::SshBundle(b) => b }
    }
}

impl Default for CertData {
    fn default() -> Self {
        CertData::Pkcs12(Vec::new())
    }
}

#[derive(Serialize_repr, Deserialize_repr, JsonSchema, TryFromPrimitive, Clone, Debug, Copy, PartialEq, Eq, Default)]
#[repr(u8)]
pub enum CertificateType {
    #[default]
    TLSClient = 0,
    TLSServer = 1,
    SSHClient = 10,
    SSHServer = 11,
}

impl FromSql for CertificateType {
    fn column_result(value: ValueRef<'_>) -> FromSqlResult<Self> {
        match value {
            ValueRef::Integer(i) => {
                let value = i as u8;
                CertificateType::try_from(value)
                    .map_err(|_| FromSqlError::InvalidType)
            },
            _ => Err(FromSqlError::InvalidType),
        }
    }
}

#[derive(Serialize_repr, Deserialize_repr, JsonSchema, TryFromPrimitive, Clone, Debug, Copy, PartialEq, Eq, Default)]
#[repr(u8)]
pub enum CAType {
    #[default]
    TLS = 0,
    SSH = 1
}

impl FromSql for CAType {
    fn column_result(value: ValueRef<'_>) -> FromSqlResult<Self> {
        match value {
            ValueRef::Integer(i) => {
                let value = i as u8;
                CAType::try_from(value)
                    .map_err(|_| FromSqlError::InvalidType)
            },
            _ => Err(FromSqlError::InvalidType),
        }
    }
}

#[derive(Serialize_repr, Deserialize_repr, JsonSchema, TryFromPrimitive, Clone, Debug, Copy, PartialEq, Eq, Default)]
#[repr(u8)]
pub enum CertificateRenewMethod {
    #[default]
    None = 0,
    Notify = 1,
    Renew = 2,
    RenewAndNotify = 3
}

impl FromSql for CertificateRenewMethod {
    fn column_result(value: ValueRef<'_>) -> FromSqlResult<Self> {
        match value {
            ValueRef::Integer(i) => {
                let value = i as u8;
                CertificateRenewMethod::try_from(value)
                    .map_err(|_| FromSqlError::InvalidType)
            },
            _ => Err(FromSqlError::InvalidType),
        }
    }
}

#[derive(Serialize_repr, Deserialize_repr, JsonSchema, TryFromPrimitive, Clone, Debug, Copy, PartialEq, Eq, Default)]
#[repr(u8)]
pub enum TimespanUnit {
    #[default]
    Year = 0,
    Month = 1,
    Day = 2,
    Hour = 3
}

#[derive(serde::Deserialize, serde::Serialize, rocket::form::FromFormField, rocket_okapi::JsonSchema, Clone, Debug, Copy, PartialEq, Eq, Default)]
#[serde(rename_all = "lowercase")]
pub enum DataFormat {
    #[default]
    DER,
    PEM,
}

impl From<String> for DataFormat {
    fn from(value: String) -> Self {
        match value.to_lowercase().as_str() {
            "pem" => DataFormat::PEM,
            _ => DataFormat::DER,
        }
    }
}
/// Key algorithm used for newly generated TLS keys (CA, intermediate CA and leaf certificates).
#[derive(Serialize_repr, Deserialize_repr, JsonSchema, TryFromPrimitive, Clone, Debug, Copy, PartialEq, Eq, Default)]
#[repr(u8)]
pub enum KeyAlgorithm {
    #[default]
    EcdsaP256 = 0,
    EcdsaP384 = 1,
}

impl KeyAlgorithm {
    /// Returns the rcgen algorithm used to generate a key pair of this type.
    pub(crate) fn rcgen_algorithm(self) -> &'static rcgen::SignatureAlgorithm {
        match self {
            KeyAlgorithm::EcdsaP256 => &rcgen::PKCS_ECDSA_P256_SHA256,
            KeyAlgorithm::EcdsaP384 => &rcgen::PKCS_ECDSA_P384_SHA384,
        }
    }

    /// Detects the algorithm of the public key in a DER certificate. Fails for keys that are not P-256 or P-384.
    pub(crate) fn from_cert_der(der: &[u8]) -> anyhow::Result<Self> {
        let key = openssl::x509::X509::from_der(der)?.public_key()?;
        match key.ec_key().ok().and_then(|ec| ec.group().curve_name()) {
            Some(openssl::nid::Nid::X9_62_PRIME256V1) => Ok(KeyAlgorithm::EcdsaP256),
            Some(openssl::nid::Nid::SECP384R1) => Ok(KeyAlgorithm::EcdsaP384),
            _ => Err(anyhow::anyhow!("Unsupported key algorithm")),
        }
    }
}
