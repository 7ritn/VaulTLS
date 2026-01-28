use rocket::serde::{Deserialize, Serialize};
use rocket_okapi::JsonSchema;
use passwords::PasswordGenerator;
use crate::data::enums::{CAType, CertificateRenewMethod, CertificateType};
use crate::data::objects::Name;

#[derive(Debug, Clone, Default, Serialize, Deserialize, JsonSchema)]
/// Certificate can be either SSH or TLS certificate.
pub struct Certificate {
    pub id: i64,
    pub name: Name,
    pub created_on: i64,
    pub valid_until: i64,
    pub certificate_type: CertificateType,
    pub user_id: i64,
    pub renew_method: CertificateRenewMethod,
    pub ca_id: i64,
    #[serde(skip)]
    pub data: Vec<u8>,
    #[serde(skip)]
    pub password: String
}

#[derive(Clone, Serialize, Deserialize, JsonSchema, Debug)]
pub struct CA {
    pub id: i64,
    pub name: Name,
    pub created_on: i64,
    pub valid_until: i64,
    pub ca_type: CAType,
    #[serde(skip)]
    pub cert: Vec<u8>,
    #[serde(skip)]
    pub key: Vec<u8>,
}

/// Saves the CA certificate to a file for filesystem access.
#[cfg(not(feature = "test-mode"))]
pub(crate) fn save_ca(ca: &CA) -> anyhow::Result<()> {
    use std::fs;
    use crate::ApiError;
    use crate::certs::tls_cert::get_tls_pem;
    use crate::certs::ssh_cert::get_ssh_pem;
    use crate::constants::{CA_DIR_PATH, CA_FILE_PATTERN, CA_SSH_FILE_PATH, CA_TLS_FILE_PATH};
    let pem = match ca.ca_type {
        CAType::TLS => get_tls_pem(ca)?,
        CAType::SSH => get_ssh_pem(ca)?,
    };
    let ca_id_file_path = CA_FILE_PATTERN.replace("{}", &ca.id.to_string());
    fs::create_dir_all(CA_DIR_PATH)?;
    fs::write(ca_id_file_path, pem.clone()).map_err(|e| ApiError::Other(e.to_string()))?;
    match ca.ca_type {
        CAType::SSH => fs::write(CA_SSH_FILE_PATH, pem).map_err(|e| ApiError::Other(e.to_string()))?,
        CAType::TLS => fs::write(CA_TLS_FILE_PATH, pem).map_err(|e| ApiError::Other(e.to_string()))?,
    }
    Ok(())
}

#[cfg(feature = "test-mode")]
pub(crate) fn save_ca(_ca: &CA) -> anyhow::Result<()> {
    Ok(())
}

/// Returns the password for the certificate. If none provided returns empty string.
pub fn get_password(system_generated_password: bool, cert_password: &Option<String>) -> String {
    if system_generated_password {
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
        match cert_password {
            Some(p) => p.clone(),
            None => String::new(),
        }
    }
}