use std::borrow::Cow;
#[cfg(feature = "test-mode")]
use std::env::temp_dir;
use std::fs;
use anyhow::anyhow;
use rcgen::{CertificateRevocationListParams, Issuer, KeyIdMethod, KeyPair, RevocationReason, RevokedCertParams, SerialNumber};
use time::{Duration, OffsetDateTime};
use x509_parser::certificate::X509Certificate;
use x509_parser::extensions::ParsedExtension;
use x509_parser::pem::parse_x509_pem;
use x509_parser::prelude::{CertificateRevocationList, FromDer};
use crate::certs::common::CA;
use crate::data::enums::{CAType, DataFormat};
use crate::data::error::ApiError;
use crate::db::VaulTLSDB;
use crate::settings::Settings;

pub(crate) async fn create_new_crl(db: &VaulTLSDB, settings: &Settings, ca: &mut CA) -> Result<Vec<u8>, ApiError> {
    let (revoked_params, crl_next_update_hours) = create_crl_params(db, settings, ca).await?;
    let crl_der = create_crl(ca, revoked_params, crl_next_update_hours)?;
    db.increase_ca_crl_number(ca.id, ca.crl_number).await?;
    let _ = save_crl(crl_der.clone(), ca.id); // Ignore errors
    Ok(crl_der)
}

pub(crate) async fn create_crl_params(db: &VaulTLSDB, settings: &Settings, ca: &CA) -> Result<(Vec<(Vec<u8>, i64)>, i64), ApiError>{
    assert_eq!(ca.ca_type, CAType::TLS);

    let revoked_certs = db.get_user_certs(None, Some(ca.id), Some(true)).await.map_err(|e| ApiError::Other(e.to_string()))?;

    let mut revoked_params = Vec::new();
    for cert in revoked_certs {
        let serial = cert.get_serial()
            .map_err(|_| ApiError::Other("Could not retrieve serial number from certificate to create CRL".to_string()))?;

        revoked_params.push((serial, cert.revoked_at.unwrap_or(0)));
    }

    let crl_next_update_hours = settings.get_crl_next_update_hours();

    Ok((revoked_params, crl_next_update_hours))
}

#[cfg(not(feature = "test-mode"))]
pub(crate) fn retrieve_crl(ca_id: i64) -> anyhow::Result<Vec<u8>> {
    let ca_id_file_path = crate::constants::CRL_FILE_PATTERN.replace("{}", &ca_id.to_string());
    Ok(fs::read(ca_id_file_path)?)
}

#[cfg(feature = "test-mode")]
pub(crate) fn retrieve_crl(ca_id: i64) -> anyhow::Result<Vec<u8>> {
    let mut path = temp_dir();
    path.push(format!("crl-{}.crl", ca_id));
    Ok(fs::read(path)?)
}

pub(crate) fn create_and_save_crl(ca: &mut CA, revoked_certs: Vec<(Vec<u8>, i64)>, crl_next_update_hours: i64) -> anyhow::Result<()> {
    let crl_der = create_crl(ca, revoked_certs, crl_next_update_hours)?;
    save_crl(crl_der, ca.id)
}

fn extract_ski(cert: &X509Certificate) -> anyhow::Result<Vec<u8>> {
    cert.extensions()
        .iter()
        .find_map(|ext| match ext.parsed_extension() {
            ParsedExtension::SubjectKeyIdentifier(ski) => Some(ski.0.to_vec()),
            _ => None,
        })
        .ok_or_else(|| anyhow!("No SKI extension found"))
}

pub fn create_crl(ca: &mut CA, revoked_certs: Vec<(Vec<u8>, i64)>, crl_next_update_hours: i64) -> anyhow::Result<Vec<u8>> {
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
pub(crate) fn save_crl(crl_der: Vec<u8>, ca_id: i64) -> anyhow::Result<()> {
    let ca_id_file_path = crate::constants::CRL_FILE_PATTERN.replace("{}", &ca_id.to_string());
    fs::create_dir_all(crate::constants::CRL_DIR_PATH)?;
    fs::write(ca_id_file_path, crl_der).map_err(|e| crate::ApiError::Other(e.to_string()))?;
    Ok(())
}

#[cfg(feature = "test-mode")]
pub(crate) fn save_crl(crl_der: Vec<u8>, ca_id: i64) -> anyhow::Result<()> {
    let mut path = temp_dir();
    path.push(format!("crl-{}.crl", ca_id));
    fs::write(path, crl_der).map_err(|e| ApiError::Other(e.to_string()))?;
    Ok(())
}

pub fn extract_crl_number(crl_bytes: &[u8], format: DataFormat) -> anyhow::Result<i64> {
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