use std::fs;
use std::time::{SystemTime, UNIX_EPOCH};

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
use crate::data::enums::CertificateType;
use crate::data::enums::CertificateType::{Client, Server, CA};
use crate::ApiError;

#[derive(Default, Clone, Serialize, Deserialize, JsonSchema)]
/// Certificate can be either CA or user certificate.
/// Iff CA, cert and key must be set.
/// Iff user cert, pkcs12 must be set.
pub struct Certificate {
    pub id: i64,
    pub name: String,
    pub created_on: i64,
    pub valid_until: i64,
    pub certificate_type: CertificateType,
    pub user_id: i64,
    #[serde(skip)]
    pub pkcs12: Vec<u8>,
    #[serde(skip)]
    pub pkcs12_password: String,
    #[serde(skip)]
    pub cert: Vec<u8>,
    #[serde(skip)]
    pub key: Vec<u8>,
    #[serde(skip)]
    pub ca_id: i64,
}

/// Creates a new CA certificate.
pub(crate) fn create_ca(
    ca_name: &str,
    ca_validity_in_years: u64
) -> Result<Certificate, ErrorStack> {
    let private_key = generate_private_key()?;
    let subject_name = create_cn(ca_name)?;
    let asn1_serial = generate_serial_number()?;

    let (created_on_unix, created_on_openssl) = get_timestamp(0)?;
    let (valid_until_unix, valid_until_openssl) = get_timestamp(ca_validity_in_years)?;

    let basic_constraints = BasicConstraints::new().ca().build()?;

    let key_usage = KeyUsage::new()
        .key_cert_sign()
        .crl_sign()
        .build()?;

    let mut ca_builder = X509Builder::new()?;
    ca_builder.set_version(2)?; // X509 v3
    ca_builder.set_subject_name(&subject_name)?;
    ca_builder.set_issuer_name(&subject_name)?;
    ca_builder.set_serial_number(&asn1_serial)?;
    ca_builder.set_pubkey(&private_key)?;
    ca_builder.set_not_before(&created_on_openssl)?;
    ca_builder.set_not_after(&valid_until_openssl)?;
    ca_builder.append_extension(basic_constraints)?;
    ca_builder.append_extension(key_usage)?;

    let subject_key_identifier = SubjectKeyIdentifier::new().build(&ca_builder.x509v3_context(None, None))?;
    ca_builder.append_extension(subject_key_identifier)?;
    let authority_key_identifier = AuthorityKeyIdentifier::new().keyid(true).build(&ca_builder.x509v3_context(None, None))?;
    ca_builder.append_extension(authority_key_identifier)?;

    ca_builder.sign(&private_key, MessageDigest::sha256())?;

    let certificate = ca_builder.build();
    
    Ok(Certificate{
        created_on: created_on_unix,
        valid_until: valid_until_unix,
        certificate_type: CA,
        cert: certificate.to_der()?,
        key: private_key.private_key_to_der()?,
        ..Default::default()
    })
}

/// Creates a new user certificate.
pub(crate) fn create_user_cert(
    ca: &Certificate,
    name: &str,
    validity_in_years: u64,
    user_id: i64,
    user_email: &str,
    system_generated_password: bool,
    pkcs12_password: &Option<String>
) -> Result<Certificate, ErrorStack> {
    let ca_cert = X509::from_der(&ca.cert)?;
    let ca_key = PKey::private_key_from_der(&ca.key)?;

    let user_key = generate_private_key()?;
    let subject_name = create_cn(name)?;

    let key_usage = KeyUsage::new()
        .digital_signature()
        .key_encipherment()
        .build()?;

    let ext_key_usage = ExtendedKeyUsage::new()
        .client_auth()
        .build()?;

    let basic_constraints = BasicConstraints::new().build()?;

    let (created_on_unix, created_on_openssl) = get_timestamp(0)?;
    let (valid_until_unix, valid_until_openssl) = get_timestamp(validity_in_years)?;

    let serial = generate_serial_number()?;

    let mut user_cert_builder = X509Builder::new()?;
    user_cert_builder.set_version(2)?; // X509 v3
    user_cert_builder.set_subject_name(&subject_name)?;
    user_cert_builder.set_issuer_name(ca_cert.subject_name())?;
    user_cert_builder.set_serial_number(&serial)?;
    user_cert_builder.set_pubkey(&user_key)?;
    user_cert_builder.set_not_before(created_on_openssl.as_ref())?;
    user_cert_builder.set_not_after(valid_until_openssl.as_ref())?;
    user_cert_builder.append_extension(key_usage)?;
    user_cert_builder.append_extension(ext_key_usage)?;
    user_cert_builder.append_extension(basic_constraints)?;

    let san = SubjectAlternativeName::new()
        .email(user_email)
        .build(&user_cert_builder.x509v3_context(None, None))?;
    user_cert_builder.append_extension(san)?;
    
    user_cert_builder.sign(&ca_key, MessageDigest::sha256())?;

    let user_cert = user_cert_builder.build();

    let mut ca_stack = Stack::new()?;
    ca_stack.push(ca_cert.clone())?;
    
    let password = get_password(system_generated_password, pkcs12_password);

    // Create the PKCS#12 structure
    let pkcs12 = Pkcs12::builder()
        .name(&name)
        .ca(ca_stack)
        .cert(&user_cert)
        .pkey(&user_key)
        .build2(&password)?;

    Ok(Certificate{
        name: name.to_string(),
        created_on: created_on_unix,
        valid_until: valid_until_unix,
        certificate_type: Client,
        pkcs12: pkcs12.to_der()?,
        pkcs12_password: password.to_string(),
        ca_id: ca.id,
        user_id,
        ..Default::default()
    })
}

/// Creates a new server certificate.
pub(crate) fn create_server_cert(
    ca: &Certificate,
    common_name: &str,
    dns_names: &Vec<String>,
    validity_in_years: u64,
    system_generated_password: bool,
    pkcs12_password: &Option<String>,
    user_id: i64
) -> Result<Certificate, ErrorStack> {
    let ca_cert = X509::from_der(&ca.cert)?;
    let ca_key = PKey::private_key_from_der(&ca.key)?;

    let server_key = generate_private_key()?;
    let subject_name = create_cn(common_name)?;
    let serial = generate_serial_number()?;
    
    let (created_on_unix, not_before) = get_timestamp(0)?;
    let (valid_until_unix, not_after) = get_timestamp(validity_in_years)?;

    let key_usage = KeyUsage::new()
        .digital_signature()
        .key_encipherment()
        .build()?;

    let ext_key_usage = ExtendedKeyUsage::new()
        .server_auth()
        .build()?;

    let basic_constraints = BasicConstraints::new().critical().build()?;

    let mut cert_builder = X509Builder::new()?;
    cert_builder.set_version(2)?;
    cert_builder.set_subject_name(&subject_name)?;
    cert_builder.set_issuer_name(ca_cert.subject_name())?;
    cert_builder.set_serial_number(&serial)?;
    cert_builder.set_pubkey(&server_key)?;
    cert_builder.set_not_before(not_before.as_ref())?;
    cert_builder.set_not_after(not_after.as_ref())?;
    cert_builder.append_extension(basic_constraints)?;
    cert_builder.append_extension(key_usage)?;
    cert_builder.append_extension(ext_key_usage)?;

    let mut san_builder = SubjectAlternativeName::new();
    for dns in dns_names {
        san_builder.dns(dns);
    }
    let san = san_builder.build(&cert_builder.x509v3_context(Some(&ca_cert), None))?;
    cert_builder.append_extension(san)?;

    cert_builder.sign(&ca_key, MessageDigest::sha256())?;
    let server_cert = cert_builder.build();

    let mut ca_stack = Stack::new()?;
    ca_stack.push(ca_cert.clone())?;
    let password = get_password(system_generated_password, pkcs12_password);
    let pkcs12 = Pkcs12::builder()
        .name(common_name)
        .ca(ca_stack)
        .cert(&server_cert)
        .pkey(&server_key)
        .build2(password.as_ref())?;

    Ok(Certificate {
        name: common_name.to_string(),
        created_on: created_on_unix,
        valid_until: valid_until_unix,
        certificate_type: Server,
        pkcs12: pkcs12.to_der()?,
        pkcs12_password: password.to_string(),
        ca_id: ca.id,
        user_id,
        ..Default::default()
    })
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
fn get_password(system_generated_password: bool, pkcs12_password: &Option<String>) -> String {
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

/// Convert a CA certificate to PEM format.
pub(crate) fn get_pem(ca: &Certificate) -> Result<Vec<u8>, ErrorStack> {
    let cert = X509::from_der(&ca.cert)?;
    cert.to_pem()
}

/// Saves the CA certificate to a file for filesystem access.
pub(crate) fn save_ca(ca: &Certificate) -> Result<(), ApiError> {
    let pem = get_pem(ca)?;
    fs::write(CA_FILE_PATH, pem).map_err(|e| ApiError::Other(e.to_string()))?;
    Ok(())
}