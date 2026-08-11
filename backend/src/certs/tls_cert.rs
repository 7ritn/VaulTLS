use std::{cmp, env, fs};
use std::borrow::Cow;
use anyhow::anyhow;
use anyhow::Result;
use openssl::asn1::{Asn1Integer, Asn1Time};
use openssl::bn::BigNum;
use openssl::hash::MessageDigest;
use openssl::pkcs12::Pkcs12;
use openssl::pkey::PKey;
use openssl::stack::Stack;
use openssl::x509::{X509, X509Builder, X509NameBuilder, X509Req};
use openssl::x509::extension::{BasicConstraints as OpensslBasicConstraints, ExtendedKeyUsage as OpensslExtendedKeyUsage, SubjectAlternativeName as OpensslSubjectAlternativeName};
use rcgen::{CertificateParams, CertificateRevocationListParams, DistinguishedName, DnType, Issuer, IsCa, KeyIdMethod, KeyPair, KeyUsagePurpose, RevocationReason, RevokedCertParams, SerialNumber, SanType, BasicConstraints, CrlDistributionPoint};
use rustls_pki_types::CertificateDer;
use time::{OffsetDateTime, Duration};
use tracing::info;
use crate::ApiError;
#[cfg(not(feature = "test-mode"))]
use crate::constants::{CA_DIR_PATH, CA_FILE_PATTERN, CA_TLS_FILE_PATH, CRL_DIR_PATH, CRL_FILE_PATTERN};
#[cfg(feature = "test-mode")]
use crate::constants::{CA_DIR_PATH, CA_FILE_PATTERN, CA_TLS_FILE_PATH};
#[cfg(feature = "test-mode")]
use std::env::temp_dir;
use openssl::nid::Nid;
use rcgen::string::Ia5String;
use x509_parser::prelude::{parse_x509_pem, CertificateRevocationList, FromDer, ParsedExtension, X509Certificate};
use crate::data::enums::{CertData, CertificateRenewMethod, CertificateType, DataFormat, TimespanUnit};
use crate::data::enums::CertificateType::{TLSClient, TLSServer};
use crate::certs::common::{Certificate, CA};
use crate::data::enums::CAType::TLS;
use crate::data::objects::Name;

pub struct TLSCertificateBuilder {
    params: CertificateParams,
    key_pair: KeyPair,
    created_on: i64,
    valid_until: Option<i64>,
    name: Option<Name>,
    pkcs12_password: String,
    ca: Option<(i64, Vec<u8>, Vec<u8>)>,
    user_id: Option<i64>,
    renew_method: CertificateRenewMethod
}
impl TLSCertificateBuilder {
    pub fn new() -> Result<Self> {
        let key_pair = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256)?;
        let mut params = CertificateParams::default();
        params.not_before = OffsetDateTime::now_utc();
        params.serial_number = Some(SerialNumber::from(rand::random::<u64>()));

        let created_on_unix = params.not_before.unix_timestamp_nanos() / 1_000_000;

        Ok(Self {
            params,
            key_pair,
            created_on: created_on_unix as i64,
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
        let validity_d = ((old_cert.valid_until - old_cert.created_on) / 1000 / 60 / 60 / 24).max(14);

        Self::new()?
            .set_name(old_cert.name.clone())?
            .set_valid_until(validity_d as u64, TimespanUnit::Day)?
            .set_password(&old_cert.password)?
            .set_renew_method(old_cert.renew_method)?
            .set_user_id(old_cert.user_id)
    }

    pub fn set_name(mut self, name: Name) -> Result<Self, anyhow::Error> {
        let mut dn = DistinguishedName::new();
        dn.push(DnType::CommonName, &name.cn);
        if let Some(ref ou) = name.ou {
            dn.push(DnType::OrganizationalUnitName, ou);
        }
        self.params.distinguished_name = dn;
        self.name = Some(name);
        Ok(self)
    }

    pub fn set_valid_until(mut self, duration: u64, unit: TimespanUnit) -> Result<Self, anyhow::Error> {
        let valid_until_time = get_timestamp(duration, unit);
        self.valid_until = Some(valid_until_time.unix_timestamp() * 1000);
        self.params.not_after = valid_until_time;
        Ok(self)
    }

    pub fn set_password(mut self, password: &str) -> Result<Self> {
        self.pkcs12_password = password.to_string();
        Ok(self)
    }

    pub fn set_dns_san(mut self, dns_names: &Vec<String>) -> Result<Self> {
        for dns in dns_names {
            self.params.subject_alt_names.push(SanType::DnsName(Ia5String::try_from(dns.clone())?));
        }
        Ok(self)
    }

    pub fn set_email_san(mut self, email: &str) -> Result<Self> {
        self.params.subject_alt_names.push(SanType::Rfc822Name(Ia5String::try_from(email.to_string())?));
        Ok(self)
    }

    pub fn set_ca(mut self, ca: &CA) -> Result<Self, anyhow::Error> {
        if ca.ca_type != TLS {
            return Err(anyhow!("CA is not of type SSH"));
        }
        self.ca = Some((ca.id, ca.cert.clone(), ca.key.clone()));
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

        self.params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        self.params.key_usages = vec![
            KeyUsagePurpose::KeyCertSign,
            KeyUsagePurpose::CrlSign,
        ];

        let cert = self.params.self_signed(&self.key_pair)?;

        Ok(CA{
            id: -1,
            name,
            created_on: self.created_on,
            valid_until,
            ca_type: TLS,
            cert: cert.der().to_vec(),
            key: self.key_pair.serialize_der(),
            crl_number: 0,
        })
    }

    pub fn build_client(mut self) -> Result<Certificate, anyhow::Error> {
        self.params.extended_key_usages = vec![rcgen::ExtendedKeyUsagePurpose::ClientAuth];
        self.build_common(TLSClient)
    }

    pub fn build_server(mut self) -> Result<Certificate, anyhow::Error> {
        self.params.extended_key_usages = vec![rcgen::ExtendedKeyUsagePurpose::ServerAuth];
        self.build_common(TLSServer)
    }

    pub fn build_common(mut self, certificate_type: CertificateType) -> Result<Certificate, anyhow::Error> {
        let name = self.name.ok_or(anyhow!("X509: name not set"))?;
        let valid_until = self.valid_until.ok_or(anyhow!("X509: valid_until not set"))?;
        let user_id = self.user_id.ok_or(anyhow!("X509: user_id not set"))?;
        let (ca_id, ca_cert_der, ca_key_der) = self.ca.ok_or(anyhow!("X509: CA not set"))?;

        self.params.key_usages = vec![
            KeyUsagePurpose::DigitalSignature,
            KeyUsagePurpose::KeyEncipherment,
        ];
        self.params.is_ca = IsCa::ExplicitNoCa;

        if let Ok(crl_uri_base) = env::var("VAULTLS_CRL_DP_URL") {
            let crl_uri = format!("{}/crl/crl-{}.crl", crl_uri_base, ca_id);
            self.params.crl_distribution_points = vec![
                CrlDistributionPoint {
                    uris: vec![ crl_uri ],
                }
            ];
        }

        let ca_key_pair = KeyPair::try_from(ca_key_der.clone())?;
        let ca_cert_der_obj = CertificateDer::from(ca_cert_der.clone());
        let issuer = Issuer::from_ca_cert_der(&ca_cert_der_obj, ca_key_pair)?;

        let cert = self.params.signed_by(&self.key_pair, &issuer)?;
        let cert_der = cert.der().to_vec();

        // PKCS#12 creation using openssl (as rcgen doesn't support it)
        let openssl_cert = X509::from_der(&cert_der)?;
        let openssl_ca_cert = X509::from_der(&ca_cert_der)?;
        let openssl_pkey = PKey::private_key_from_der(&self.key_pair.serialize_der())?;

        let mut ca_stack = Stack::new()?;
        ca_stack.push(openssl_ca_cert)?;

        let pkcs12 = Pkcs12::builder()
            .name(&name.cn)
            .ca(ca_stack)
            .cert(&openssl_cert)
            .pkey(&openssl_pkey)
            .build2(&self.pkcs12_password)?;

        Ok(Certificate {
            id: -1,
            name,
            created_on: self.created_on,
            valid_until,
            certificate_type,
            data: CertData::Pkcs12(pkcs12.to_der()?),
            password: self.pkcs12_password,
            ca_id,
            user_id,
            renew_method: self.renew_method,
            revoked_at: None
        })
    }
}

/// Issues a server certificate from a CSR and returns `(cert_pem, chain_pem, serial_bytes)`.
/// The CSR signature is verified before issuance. The subject CN is derived from the first DNS name.
pub fn issue_cert_from_csr(
    csr_der: &[u8],
    ca: &CA,
    validity_days: u64,
    dns_names: &[String],
) -> Result<(Vec<u8>, Vec<u8>, Vec<u8>)> {
    let csr = X509Req::from_der(csr_der)?;
    let csr_pubkey = csr.public_key()?;
    if !csr.verify(&csr_pubkey)? {
        return Err(anyhow!("CSR signature verification failed"));
    }

    let ca_cert = X509::from_der(&ca.cert)?;
    let ca_key = PKey::private_key_from_der(&ca.key)?;

    let asn1_serial = generate_asn1_serial_number()?;
    let (_, not_before) = get_asn1_timestamp(0, TimespanUnit::Hour)?;
    let (_, not_after) = get_asn1_timestamp(validity_days, TimespanUnit::Day)?;

    let mut x509 = X509Builder::new()?;
    x509.set_version(2)?;
    x509.set_serial_number(&asn1_serial)?;
    x509.set_not_before(&not_before)?;
    x509.set_not_after(&not_after)?;
    x509.set_pubkey(&csr_pubkey)?;

    let cn = dns_names.first().map(|s| s.as_str()).unwrap_or("acme");
    let mut name_builder = X509NameBuilder::new()?;
    name_builder.append_entry_by_text("CN", cn)?;
    name_builder.append_entry_by_text("OU", "ACME")?;
    x509.set_subject_name(&name_builder.build())?;

    if !dns_names.is_empty() {
        let mut san_builder = OpensslSubjectAlternativeName::new();
        for dns in dns_names {
            san_builder.dns(dns);
        }
        let san = san_builder.build(&x509.x509v3_context(None, None))?;
        x509.append_extension(san)?;
    }

    let ext_key_usage = OpensslExtendedKeyUsage::new().server_auth().build()?;
    x509.append_extension(ext_key_usage)?;

    let basic_constraints = OpensslBasicConstraints::new().build()?;
    x509.append_extension(basic_constraints)?;

    let key_usage = openssl::x509::extension::KeyUsage::new()
        .digital_signature()
        .key_encipherment()
        .build()?;
    x509.append_extension(key_usage)?;

    x509.set_issuer_name(ca_cert.subject_name())?;

    let subject_key_identifier = openssl::x509::extension::SubjectKeyIdentifier::new().build(&x509.x509v3_context(None, None))?;
    x509.append_extension(subject_key_identifier)?;

    let authority_key_identifier = openssl::x509::extension::AuthorityKeyIdentifier::new().keyid(true).build(&x509.x509v3_context(Some(&ca_cert), None))?;
    x509.append_extension(authority_key_identifier)?;

    x509.sign(&ca_key, MessageDigest::sha256())?;

    let cert = x509.build();

    let serial_bytes = cert.serial_number().to_bn()?.to_vec();
    let cert_pem = cert.to_pem()?;
    let ca_pem = ca_cert.to_pem()?;

    let mut chain_pem = cert_pem.clone();
    chain_pem.extend_from_slice(&ca_pem);

    Ok((cert_pem, chain_pem, serial_bytes))
}

fn generate_asn1_serial_number() -> Result<Asn1Integer> {
    let mut big_serial = BigNum::new()?;
    big_serial.rand(64, openssl::bn::MsbOption::MAYBE_ZERO, false)?;
    let asn1_serial = big_serial.to_asn1_integer()?;
    Ok(asn1_serial)
}

fn get_asn1_timestamp(duration: u64, unit: TimespanUnit) -> Result<(i64, Asn1Time)> {
    let duration_per_unit_h = match unit {
        TimespanUnit::Year => 365*24,
        TimespanUnit::Month => 30*24,
        TimespanUnit::Day => 24,
        TimespanUnit::Hour => 1,
    };
    let duration_s = 60 * 60 * duration * duration_per_unit_h;
    let time = std::time::SystemTime::now() + std::time::Duration::from_secs(duration_s);
    let time_unix_ms = time.duration_since(std::time::UNIX_EPOCH)?.as_millis() as i64;
    let time_openssl = Asn1Time::from_unix(time_unix_ms / 1000)?;

    Ok((time_unix_ms, time_openssl))
}

pub(crate) fn get_timestamp(duration: u64, unit: TimespanUnit) -> OffsetDateTime {
    let duration_per_unit_h = match unit {
        TimespanUnit::Year => 365*24,
        TimespanUnit::Month => 30*24,
        TimespanUnit::Day => 24,
        TimespanUnit::Hour => 1,
    };
    let duration_s = cmp::max(duration * duration_per_unit_h, 1) * 60 * 60;
    OffsetDateTime::now_utc() + Duration::seconds(duration_s as i64)
}

/// Convert a CA certificate to PEM format.
pub(crate) fn get_tls_pem(ca: &CA) -> Result<Vec<u8>> {
    let cert = X509::from_der(&ca.cert)?;
    Ok(cert.to_pem()?)
}

pub(crate) fn extract_pem_serial_number(pem: &[u8]) -> Result<Vec<u8>> {
    let pem = parse_x509_pem(pem)
        .map_err(|e| anyhow!("Failed to parse PEM: {}", e))?;
    let (_, cert) = X509Certificate::from_der(&pem.1.contents)
        .map_err(|e| anyhow!("Failed to parse DER: {}", e))?;
    Ok(cert.tbs_certificate.serial.to_bytes_be())
}

pub(crate) fn extract_pkcs12_serial_number(pkcs12: &[u8], password: &str) -> Result<Vec<u8>> {
    let encrypted_p12 = Pkcs12::from_der(pkcs12)?;
    let parsed = encrypted_p12.parse2(password)?;
    let Some(inner) = parsed.cert else {
        return Err(anyhow!("No certificate found in PKCS#12"));
    };
    Ok(inner.serial_number().to_bn()?.to_vec())
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

fn extract_ski(cert: &X509Certificate) -> Result<Vec<u8>> {
    cert.extensions()
        .iter()
        .find_map(|ext| match ext.parsed_extension() {
            ParsedExtension::SubjectKeyIdentifier(ski) => Some(ski.0.to_vec()),
            _ => None,
        })
        .ok_or_else(|| anyhow!("No SKI extension found"))
}

pub fn create_crl(ca: &mut CA, revoked_certs: Vec<(Vec<u8>, i64)>, crl_next_update_hours: i64) -> Result<Vec<u8>> {
    let ca_key_pair = KeyPair::try_from(ca.key.clone())?;
    let issuer = Issuer::from_ca_cert_der(&ca.cert.clone().into(), ca_key_pair)?;

    let now = OffsetDateTime::now_utc();
    let next_update = now + Duration::hours(crl_next_update_hours);
    ca.crl_number += 1;
    let crl_number = ca.crl_number;

    let (_, cert) = X509Certificate::from_der(&ca.cert)
        .map_err(|e| anyhow!("Failed to parse certificate for SKI: {}", e))?;
    let ski = extract_ski(&cert)?;

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
    match &cert.data {
        CertData::Pem(bytes) => {
            let x509 = X509::from_pem(bytes)?;
            let Some(san) = x509.subject_alt_names() else { return Ok(vec![]) };
            Ok(san.iter().filter_map(|name| name.dnsname().map(|s| s.to_string())).collect())
        }
        CertData::Pkcs12(bytes) => {
            let encrypted_p12 = Pkcs12::from_der(bytes)?;
            let Some(inner) = encrypted_p12.parse2(&cert.password)?.cert else {
                return Err(anyhow!("No certificate found in PKCS#12"));
            };
            let Some(san) = inner.subject_alt_names() else {
                return Err(anyhow!("No SAN found in PKCS#12 certificate"));
            };
            Ok(san.iter().filter_map(|name| name.dnsname().map(|s| s.to_string())).collect())
        }
        CertData::SshBundle(_) => Ok(vec![]),
    }
}

pub fn parse_ca(cert_bytes: &[u8], key_bytes: &[u8], data_format: DataFormat, crl_number: i64) -> Result<CA> {
    use x509_parser::prelude::FromDer;
    let cert_der = match data_format {
        DataFormat::DER => cert_bytes.to_vec(),
        DataFormat::PEM => {
            let pem = parse_x509_pem(cert_bytes)
                .map_err(|e| anyhow!("Failed to parse CA PEM: {}", e))?;
            pem.1.contents
        }
    };

    let (_, cert) = X509Certificate::from_der(&cert_der)
        .map_err(|e| anyhow!("Failed to parse CA DER: {}", e))?;

    let subject = &cert.tbs_certificate.subject;
    let cn = subject.iter_common_name()
        .next()
        .and_then(|attr| attr.as_str().ok())
        .ok_or_else(|| anyhow!("No CN in CA certificate"))?
        .to_string();

    let ou = subject.iter_organizational_unit()
        .next()
        .and_then(|attr| attr.as_str().ok())
        .map(|s| s.to_string());
    
    let created_on_unix = cert.tbs_certificate.validity.not_before.timestamp() * 1000;
    let valid_until_unix = cert.tbs_certificate.validity.not_after.timestamp() * 1000;

    Ok(CA {
        id: -1,
        name: Name { cn, ou },
        created_on: created_on_unix,
        valid_until: valid_until_unix,
        ca_type: TLS,
        cert: cert_der,
        key: key_bytes.to_vec(),
        crl_number,
    })
}

pub fn parse_p12_metadata(p12_bytes: &[u8], password: &str) -> Result<(Name, i64, i64)> {
    let p12 = Pkcs12::from_der(p12_bytes)?;
    let parsed = p12.parse2(password)?;
    let cert = parsed.cert.ok_or_else(|| anyhow!("No certificate in PKCS#12"))?;
    
    let subject = cert.subject_name();
    let cn = subject.entries_by_nid(Nid::COMMONNAME)
        .next()
        .ok_or_else(|| anyhow!("No CN in certificate"))?
        .data()
        .to_string()?;

    let ou = subject.entries_by_nid(Nid::ORGANIZATIONALUNITNAME)
        .next()
        .and_then(|e| e.data().to_string().ok());

    let created_on_unix = asn1_time_to_unix(cert.not_before())?;
    let valid_until_unix = asn1_time_to_unix(cert.not_after())?;

    Ok((Name { cn, ou }, created_on_unix, valid_until_unix))
}

pub fn extract_crl_number(crl_bytes: &[u8], format: DataFormat) -> Result<i64> {
    let crl_der = match format {
        DataFormat::DER => Cow::Borrowed(crl_bytes),
        DataFormat::PEM => {
            let (_, pem) = parse_x509_pem(crl_bytes)
                .map_err(|e| anyhow!("Failed to parse CRL PEM: {e}"))?;
            Cow::Owned(pem.contents)
        }
    };

    let (_, crl) = CertificateRevocationList::from_der(&crl_der)
        .map_err(|e| anyhow!("Failed to parse CRL with x509-parser: {}", e))?;

    Ok(crl.extensions()
        .iter()
        .find_map(|ext| match ext.parsed_extension() {
            ParsedExtension::CRLNumber(num) => Some(num),
            _ => None,
        })
        .ok_or_else(|| anyhow!("No CRL number extension found in CRL"))?
        .to_string()
        .parse::<i64>()?)
}

fn asn1_time_to_unix(time: &openssl::asn1::Asn1TimeRef) -> Result<i64> {
    let epoch = Asn1Time::from_unix(0)?;
    let diff = epoch.diff(time)?;
    Ok((diff.days as i64 * 24 * 3600 + diff.secs as i64) * 1000)
}
