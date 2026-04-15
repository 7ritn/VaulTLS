#[cfg(feature = "test-mode")]
use std::env::temp_dir;
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
use openssl::x509::{X509Name, X509NameBuilder, X509Ref, X509};
use openssl::x509::extension::{AuthorityKeyIdentifier, BasicConstraints, ExtendedKeyUsage, KeyUsage, SubjectAlternativeName, SubjectKeyIdentifier};
use openssl::x509::{X509Builder};
use openssl::x509::X509Req;
use rcgen::{CertificateRevocationListParams, Issuer, KeyIdMethod, KeyPair, RevocationReason, RevokedCertParams, SerialNumber};
use rustls_pki_types::CertificateDer;
use time::{OffsetDateTime, Duration};
use tracing::info;
use crate::ApiError;
#[cfg(not(feature = "test-mode"))]
use crate::constants::{CA_DIR_PATH, CA_FILE_PATTERN, CA_TLS_FILE_PATH, CRL_DIR_PATH, CRL_FILE_PATTERN};
#[cfg(feature = "test-mode")]
use crate::constants::{CA_DIR_PATH, CA_FILE_PATTERN, CA_TLS_FILE_PATH};
use crate::data::enums::{CertificateRenewMethod, CertificateType, TimespanUnit};
use crate::data::enums::CertificateType::{TLSClient, TLSServer};
use crate::certs::common::{Certificate, CA};
use crate::data::enums::CAType::TLS;
use crate::data::objects::Name;

pub struct TLSCertificateBuilder {
    x509: X509Builder,
    private_key: Option<PKey<Private>>,
    created_on: i64,
    valid_until: Option<i64>,
    name: Option<Name>,
    pkcs12_password: String,
    ca: Option<(i64, X509, PKey<Private>)>,
    user_id: Option<i64>,
    renew_method: CertificateRenewMethod
}
impl TLSCertificateBuilder {
    pub fn new() -> Result<Self> {
        let private_key = generate_private_key()?;
        let asn1_serial = generate_serial_number()?;
        let (created_on_unix, created_on_openssl) = get_timestamp(0, TimespanUnit::Hour)?;

        let mut x509 = X509Builder::new()?;
        x509.set_version(2)?;
        x509.set_serial_number(&asn1_serial)?;
        x509.set_not_before(&created_on_openssl)?;
        x509.set_pubkey(&private_key)?;

        Ok(Self {
            x509,
            private_key: Some(private_key),
            created_on: created_on_unix,
            valid_until: None,
            name: None,
            pkcs12_password: String::new(),
            ca: None,
            user_id: None,
            renew_method: Default::default()
        })
    }

    /// Build a certificate from a CSR (the CSR's public key is used; no private key is held).
    /// The CSR signature is verified to prove the requester holds the private key.
    pub fn from_csr(csr_der: &[u8]) -> Result<Self> {
        let csr = X509Req::from_der(csr_der)?;
        let csr_pubkey = csr.public_key()?;
        if !csr.verify(&csr_pubkey)? {
            return Err(anyhow!("CSR signature verification failed"));
        }

        let asn1_serial = generate_serial_number()?;
        let (created_on_unix, created_on_openssl) = get_timestamp(0, TimespanUnit::Hour)?;

        let mut x509 = X509Builder::new()?;
        x509.set_version(2)?;
        x509.set_serial_number(&asn1_serial)?;
        x509.set_not_before(&created_on_openssl)?;
        x509.set_pubkey(&csr_pubkey)?;

        Ok(Self {
            x509,
            private_key: None,
            created_on: created_on_unix,
            valid_until: None,
            name: None,
            pkcs12_password: String::new(),
            ca: None,
            user_id: None,
            renew_method: Default::default(),
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
        let validity_d = ((old_cert.valid_until - old_cert.created_on) / 1000 / 60 / 60 / 24).max(14);

        Self::new()?
            .set_name(old_cert.name.clone())?
            .set_valid_until(validity_d as u64, TimespanUnit::Day)?
            .set_password(&old_cert.password)?
            .set_renew_method(old_cert.renew_method)?
            .set_user_id(old_cert.user_id)
    }

    pub fn try_from_ca(old_ca: &CA) -> Result<CA> {
        if old_ca.ca_type != TLS {
            return Err(anyhow!("CA is not of type SSH"));
        }
        let validity_h = ((old_ca.valid_until - old_ca.created_on) / 1000 / 60 / 60 / 24).max(14);

        Self::new()?
            .set_name(old_ca.name.clone())?
            .set_valid_until(validity_h as u64, TimespanUnit::Day)?
            .build_ca()

    }

    pub fn set_name(mut self, name: Name) -> Result<Self, anyhow::Error> {
        let common_name = create_cn(&name)?;
        self.x509.set_subject_name(&common_name)?;
        self.name = Some(name);
        Ok(self)
    }

    pub fn set_valid_until(mut self, duration: u64, unit: TimespanUnit) -> Result<Self, anyhow::Error> {
        let (valid_until_unix, valid_until_openssl) = if duration != 0 {
            get_timestamp(duration, unit)?
        } else {
            get_short_lifetime()?
        };
        self.valid_until = Some(valid_until_unix);
        self.x509.set_not_after(&valid_until_openssl)?;
        Ok(self)
    }

    pub fn set_password(mut self, password: &str) -> Result<Self, anyhow::Error> {
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
        if ca.ca_type != TLS {
            return Err(anyhow!("CA is not of type SSH"));
        }
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

        let basic_constraints = BasicConstraints::new().critical().ca().build()?;
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

        let private_key = self.private_key.ok_or(anyhow!("X509: no private key for CA build"))?;
        self.x509.sign(&private_key, MessageDigest::sha256())?;
        let cert = self.x509.build();

        Ok(CA{
            id: -1,
            name,
            created_on: self.created_on,
            valid_until,
            ca_type: TLS,
            cert: cert.to_der()?,
            key: private_key.private_key_to_der()?,
            crl_number: 0,
        })
    }

    pub fn build_client(mut self) -> Result<Certificate, anyhow::Error> {
        let ext_key_usage = ExtendedKeyUsage::new()
            .client_auth()
            .build()?;
        self.x509.append_extension(ext_key_usage)?;

        self.build_common(TLSClient)
    }

    pub fn build_server(mut self) -> Result<Certificate, anyhow::Error> {
        let ext_key_usage = ExtendedKeyUsage::new()
            .server_auth()
            .build()?;
        self.x509.append_extension(ext_key_usage)?;

        self.build_common(TLSServer)
    }

    /// Build a server certificate and return PEM output `(cert_pem, chain_pem, serial_bytes)`.
    /// For use with CSR-based issuance (e.g. ACME) where no private key is held by this builder.
    pub fn build_server_pem(mut self) -> Result<(Vec<u8>, Vec<u8>, Vec<u8>)> {
        let ext_key_usage = ExtendedKeyUsage::new()
            .server_auth()
            .build()?;
        self.x509.append_extension(ext_key_usage)?;

        let (_, ca_cert, ca_key) = self.ca.ok_or(anyhow!("X509: CA not set"))?;
        apply_end_entity_extensions(&mut self.x509, &ca_cert, &ca_key)?;
        let cert = self.x509.build();

        let serial_bytes = cert.serial_number().to_bn()?.to_vec();
        let cert_pem = cert.to_pem()?;
        let ca_pem = ca_cert.to_pem()?;

        let mut chain_pem = cert_pem.clone();
        chain_pem.extend_from_slice(&ca_pem);

        Ok((cert_pem, chain_pem, serial_bytes))
    }

    pub fn build_common(mut self, certificate_type: CertificateType) -> Result<Certificate, anyhow::Error> {
        let name = self.name.ok_or(anyhow!("X509: name not set"))?;
        let valid_until = self.valid_until.ok_or(anyhow!("X509: valid_until not set"))?;
        let user_id = self.user_id.ok_or(anyhow!("X509: user_id not set"))?;
        let (ca_id, ca_cert, ca_key) = self.ca.ok_or(anyhow!("X509: CA not set"))?;
        let private_key = self.private_key.ok_or(anyhow!("X509: no private key (use build_server_pem for CSR-based certs)"))?;

        apply_end_entity_extensions(&mut self.x509, &ca_cert, &ca_key)?;
        let cert = self.x509.build();

        let mut ca_stack = Stack::new()?;
        ca_stack.push(ca_cert.clone())?;

        let pkcs12 = Pkcs12::builder()
            .name(&name.cn)
            .ca(ca_stack)
            .cert(&cert)
            .pkey(&private_key)
            .build2(&self.pkcs12_password)?;

        Ok(Certificate {
            id: -1,
            name,
            created_on: self.created_on,
            valid_until,
            certificate_type,
            data: pkcs12.to_der()?,
            password: self.pkcs12_password,
            ca_id,
            user_id,
            renew_method: self.renew_method,
            revoked_at: None
        })
    }
}

/// Applies the standard end-entity X509 extensions and signs the certificate.
/// Used by both `build_common` (PKCS#12 output) and `build_server_pem` (PEM output).
fn apply_end_entity_extensions(x509: &mut X509Builder, ca_cert: &X509, ca_key: &PKey<Private>) -> Result<()> {
    let basic_constraints = BasicConstraints::new().build()?;
    x509.append_extension(basic_constraints)?;

    let key_usage = KeyUsage::new()
        .digital_signature()
        .key_encipherment()
        .build()?;
    x509.append_extension(key_usage)?;

    x509.set_issuer_name(ca_cert.subject_name())?;

    let subject_key_identifier = SubjectKeyIdentifier::new()
        .build(&x509.x509v3_context(None, None))?;
    x509.append_extension(subject_key_identifier)?;

    let authority_key_identifier = AuthorityKeyIdentifier::new()
        .keyid(true)
        .build(&x509.x509v3_context(Some(ca_cert), None))?;
    x509.append_extension(authority_key_identifier)?;

    x509.sign(ca_key, MessageDigest::sha256())?;
    Ok(())
}

/// Generates a new private key.
fn generate_private_key() -> Result<PKey<Private>, ErrorStack> {
    let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1)?;
    let ec_key = EcKey::generate(&group)?;
    let server_key = PKey::from_ec_key(ec_key)?;
    Ok(server_key)
}

fn create_cn(name: &Name) -> Result<X509Name, ErrorStack> {
    let mut name_builder = X509NameBuilder::new()?;
    name_builder.append_entry_by_text("CN", &name.cn)?;
    if let Some(ref ou) = name.ou {
        name_builder.append_entry_by_text("OU", ou)?;
    }
    let name = name_builder.build();
    Ok(name)
}

/// Generates a random serial number.
fn generate_serial_number() -> Result<Asn1Integer, ErrorStack> {
    let mut big_serial = BigNum::new()?;
    big_serial.rand(64, openssl::bn::MsbOption::MAYBE_ZERO, false)?;
    let asn1_serial = big_serial.to_asn1_integer()?;
    Ok(asn1_serial)
}

/// Returns the current UNIX timestamp in milliseconds and an OpenSSL Asn1Time object.
pub(crate) fn get_timestamp(duration: u64, unit: TimespanUnit) -> Result<(i64, Asn1Time), ErrorStack> {
    let duration_per_unit_h = match unit {
        TimespanUnit::Year => 365*24,
        TimespanUnit::Month => 30*24,
        TimespanUnit::Day => 24,
        TimespanUnit::Hour => 1,
    };
    let duration_s = 60 * 60 * duration * duration_per_unit_h;
    let time = SystemTime::now() + std::time::Duration::from_secs(duration_s);
    let time_unix_ms = time.duration_since(UNIX_EPOCH).unwrap().as_millis() as i64;
    let time_openssl = Asn1Time::from_unix(time_unix_ms / 1000)?;

    Ok((time_unix_ms, time_openssl))
}

/// For E2E testing generate a short lifetime certificate.
fn get_short_lifetime() -> Result<(i64, Asn1Time), ErrorStack> {
    let time = SystemTime::now() + std::time::Duration::from_secs(60 * 60 * 24);
    let time_unix = time.duration_since(UNIX_EPOCH).unwrap().as_millis() as i64;
    let time_openssl = Asn1Time::days_from_now(1)?;

    Ok((time_unix, time_openssl))
}

/// Convert a CA certificate to PEM format.
pub(crate) fn get_tls_pem(ca: &CA) -> Result<Vec<u8>, ErrorStack> {
    let cert = X509::from_der(&ca.cert)?;
    cert.to_pem()
}

pub fn extract_serial_number(cert: &Certificate) -> Result<Vec<u8>> {
    if cert.data.starts_with(b"-----BEGIN CERTIFICATE-----") {
        let x509 = X509::from_pem(&cert.data)?;
        return Ok(x509.serial_number().to_bn()?.to_vec());
    }
    let encrypted_p12 = Pkcs12::from_der(&cert.data)?;
    let Some(cert) = encrypted_p12.parse2(&cert.password)?.cert else { return Err(anyhow::anyhow!("No certificate found in PKCS#12"))};
    Ok(cert.serial_number().to_bn()?.to_vec())
}

#[cfg(not(feature = "test-mode"))]
pub(crate) fn retrieve_crl(ca_id: i64) -> Result<Vec<u8>> {
    let ca_id_file_path = CRL_FILE_PATTERN.replace("{}", &ca_id.to_string());
    Ok(fs::read(ca_id_file_path)?)
}

#[cfg(feature = "test-mode")]
pub(crate) fn retrieve_crl(ca_id: i64) -> Result<Vec<u8>> {
    let mut path = temp_dir();
    path.push(format!("crl-{}.crl", ca_id));
    Ok(fs::read(path)?)
}

pub(crate) fn create_and_save_crl(ca: &mut CA, revoked_certs: Vec<(Vec<u8>, i64)>, crl_next_update_hours: i64) -> Result<()> {
    let crl_der = create_crl(ca, revoked_certs, crl_next_update_hours)?;
    save_crl(crl_der, ca.id)
}

fn extract_ski(cert: &X509Ref) -> Result<Vec<u8>, ErrorStack> {
    let ext = cert.subject_key_id()
        .ok_or_else(|| ErrorStack::get())?;
    Ok(ext.as_slice().to_vec())
}

pub(crate) fn create_crl(ca: &mut CA, revoked_certs: Vec<(Vec<u8>, i64)>, crl_next_update_hours: i64) -> Result<Vec<u8>> {
    let ca_key_pair = KeyPair::try_from(ca.key.clone())?;
    let cert_der = CertificateDer::from(ca.cert.clone());
    let issuer = Issuer::from_ca_cert_der(&cert_der, ca_key_pair)?;

    let now = OffsetDateTime::now_utc();
    let next_update = now + Duration::hours(crl_next_update_hours);
    ca.crl_number += 1;
    let crl_number = ca.crl_number;

    let ca_cert = X509::from_der(&ca.cert)?;
    let ski = extract_ski(&ca_cert)?;

    let revoked_params = revoked_certs.into_iter().map(|(serial, revoked_at)| {
        RevokedCertParams {
            serial_number: SerialNumber::from(serial),
            revocation_time: OffsetDateTime::from_unix_timestamp(revoked_at).unwrap_or(now),
            reason_code: Some(RevocationReason::Unspecified),
            invalidity_date: None,
        }
    }).collect();

    let crl_params = CertificateRevocationListParams {
        this_update: now,
        next_update,
        crl_number: SerialNumber::from(crl_number.unsigned_abs()),
        issuing_distribution_point: None,
        revoked_certs: revoked_params,
        key_identifier_method: KeyIdMethod::PreSpecified(ski),
    };

    let crl = crl_params.signed_by(&issuer)?;
    Ok(crl.der().to_vec())
}

#[cfg(not(feature = "test-mode"))]
pub(crate) fn save_crl(crl_der: Vec<u8>, ca_id: i64) -> Result<()> {
    let ca_id_file_path = CRL_FILE_PATTERN.replace("{}", &ca_id.to_string());
    fs::create_dir_all(CRL_DIR_PATH)?;
    fs::write(ca_id_file_path, crl_der).map_err(|e| ApiError::Other(e.to_string()))?;
    Ok(())
}

#[cfg(feature = "test-mode")]
pub(crate) fn save_crl(crl_der: Vec<u8>, ca_id: i64) -> Result<()> {
    let mut path = temp_dir();
    path.push(format!("crl-{}.crl", ca_id));
    fs::write(path, crl_der).map_err(|e| ApiError::Other(e.to_string()))?;
    Ok(())
}

/// Migrates the Certificate Authority (CA) storage to a separate directory.
pub(crate) fn migrate_ca_storage() -> Result<()> {
    if fs::exists("./ca.cert").is_ok_and(|exists| exists) {
        info!("Migrating CA storage to separate directory");
        fs::create_dir(CA_DIR_PATH)?;
        fs::rename("./ca.cert", CA_TLS_FILE_PATH)?;
        fs::copy(CA_TLS_FILE_PATH, CA_FILE_PATTERN.replace("{}", "1"))?;
    }
    Ok(())
}

/// Extract DNS names stored in X509 certificate
pub(crate) fn get_dns_names(cert: &Certificate) -> Result<Vec<String>, anyhow::Error> {
    if cert.data.starts_with(b"-----BEGIN CERTIFICATE-----") {
        let x509 = X509::from_pem(&cert.data)?;
        let Some(san) = x509.subject_alt_names() else { return Ok(vec![]) };
        return Ok(san.iter().filter_map(|name| name.dnsname().map(|s| s.to_string())).collect());
    }
    let encrypted_p12 = Pkcs12::from_der(&cert.data)?;
    let Some(cert) = encrypted_p12.parse2(&cert.password)?.cert else { return Err(anyhow::anyhow!("No certificate found in PKCS#12"))};
    let Some(san) = cert.subject_alt_names() else { return Err(anyhow::anyhow!("No certificate found in PKCS#12"))};
    Ok(san.iter().filter_map(|name| name.dnsname().map(|s| s.to_string())).collect())
}
