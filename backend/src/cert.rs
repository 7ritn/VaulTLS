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
use tracing::info;
use crate::constants::{CA_DIR_PATH, CA_FILE_PATTERN, CA_TLS_FILE_PATH};
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
    pub name: String,
    pub created_on: i64,
    pub valid_until: i64,
    #[serde(skip)]
    pub cert: Vec<u8>,
    #[serde(skip)]
    pub key: Vec<u8>,
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
            name,
            created_on: self.created_on,
            valid_until,
            cert: cert.to_der()?,
            key: self.private_key.private_key_to_der()?,
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
            renew_method: self.renew_method
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
pub(crate) fn save_ca(ca: &CA) -> Result<()> {
    let pem = get_pem(ca)?;
    let ca_id_file_path = CA_FILE_PATTERN.replace("{}", &ca.id.to_string());
    fs::create_dir_all(CA_DIR_PATH)?;
    fs::write(ca_id_file_path, pem.clone()).map_err(|e| ApiError::Other(e.to_string()))?;
    fs::write(CA_TLS_FILE_PATH, pem).map_err(|e| ApiError::Other(e.to_string()))?;
    Ok(())
}

pub(crate) fn migrate_ca_storage() -> Result<()> {
    if fs::exists("ca.cert").is_ok() {
        info!("Migrating CA storage to separate directory");
        fs::create_dir(CA_DIR_PATH)?;
        fs::rename("ca.cert", CA_TLS_FILE_PATH)?;
        fs::copy(CA_TLS_FILE_PATH, CA_FILE_PATTERN.replace("{}", "0"))?;
    }
    Ok(())
}

pub(crate) fn get_dns_names(cert: &Certificate) -> Result<Vec<String>, anyhow::Error> {
    let encrypted_p12 = Pkcs12::from_der(&cert.pkcs12)?;
    let Some(cert) = encrypted_p12.parse2(&cert.pkcs12_password)?.cert else { return Err(anyhow::anyhow!("No certificate found in PKCS#12"))};
    let Some(san) = cert.subject_alt_names() else { return Err(anyhow::anyhow!("No certificate found in PKCS#12"))};
    Ok(san.iter().filter_map(|name| name.dnsname().map(|s| s.to_string())).collect())
}