use crate::certs::common::{Certificate, CA};
use crate::data::enums::{CertificateRenewMethod, CertificateType};
use anyhow::anyhow;
use anyhow::Result;
use rand::prelude::*;
use rand::rng;
use ssh_key::rand_core::OsRng;
use ssh_key::{certificate, Algorithm, PrivateKey};
use std::io::{Cursor, Write};
use std::time::{SystemTime, UNIX_EPOCH};
use zip::write::SimpleFileOptions;
use zip::{ZipArchive, ZipWriter};

pub struct SSHCertificateBuilder {
    created_on: i64,
    valid_until: Option<i64>,
    name: Option<String>,
    ca: Option<(i64, PrivateKey)>,
    user_id: Option<i64>,
    renew_method: CertificateRenewMethod,
    principals: Vec<String>,
    password: Option<String>,
}

impl SSHCertificateBuilder {
    pub fn new() -> Result<Self> {
        let created_on = SystemTime::now()
            .duration_since(UNIX_EPOCH)?
            .as_secs() as i64;
        Ok(Self {
            created_on,
            valid_until: None,
            name: None,
            ca: None,
            user_id: None,
            renew_method: Default::default(),
            principals: Vec::new(),
            password: None,
        })
    }

    pub fn set_name(mut self, name: &str) -> Result<Self> {
        self.name = Some(name.to_string());
        Ok(self)
    }

    pub fn set_valid_until(mut self, years: u64) -> Result<Self> {
        let valid_until = self.created_on + (365 * 86400) * years as i64;
        self.valid_until = Some(valid_until);
        Ok(self)
    }

    pub fn set_principals(mut self, principals: &[String]) -> Result<Self> {
        self.principals = principals.to_vec();
        Ok(self)
    }

    pub fn set_ca(mut self, ca: &CA) -> Result<Self> {
        let ca_key = PrivateKey::from_bytes(ca.key.as_slice())?;
        self.ca = Some((ca.id, ca_key));
        Ok(self)
    }

    pub fn set_user_id(mut self, user_id: i64) -> Result<Self> {
        self.user_id = Some(user_id);
        Ok(self)
    }

    pub fn set_renew_method(mut self, renew_method: CertificateRenewMethod) -> Result<Self> {
        self.renew_method = renew_method;
        Ok(self)
    }

    pub fn set_password(mut self, password: &str) -> Result<Self> {
        self.password = Some(password.to_string());
        Ok(self)
    }

    pub fn build_ca(self) -> Result<CA> {
        let ca_key = PrivateKey::random(&mut OsRng, Algorithm::Ed25519)?;
        let key = ca_key.to_bytes()?.to_vec();

        Ok(CA{
            id: -1,
            name: self.name.unwrap_or_else(|| "CA".to_string()),
            created_on: self.created_on,
            valid_until: -1,
            cert: Vec::new(),
            key,
        })
    }

    pub fn build_user(self) -> Result<Certificate> {
        let name = self.name.ok_or(anyhow!("SSH: name not set"))?;
        let valid_until = self.valid_until.ok_or(anyhow!("SSH: valid_until not set"))?;
        let user_id = self.user_id.ok_or(anyhow!("SSH: user_id not set"))?;
        let (ca_id, ca_key) = self.ca.ok_or(anyhow!("SSH: CA not set"))?;

        let mut user_private_key= PrivateKey::random(&mut OsRng, Algorithm::Ed25519)?;
        if let Some(password) = self.password.clone() {
            user_private_key = user_private_key.encrypt(&mut OsRng, password.as_bytes())?;
        }
        let user_public_key = user_private_key.public_key();

        let serial = rng().random();

        let mut cert_builder = certificate::Builder::new_with_random_nonce(
            &mut OsRng,
            user_public_key,
            self.created_on as u64,
            valid_until as u64,
        )?;
        cert_builder.serial(serial)?;
        cert_builder.key_id(name.clone())?;
        cert_builder.cert_type(certificate::CertType::User)?;
        for principal in self.principals {
            cert_builder.valid_principal(principal)?;
        }

        let cert = cert_builder.sign(&ca_key)?;
        let cert_bytes = cert.to_bytes()?;
        let key_bytes = user_private_key.to_bytes()?.to_vec();

        let data = create_cert_key_bundle(&name, cert_bytes, key_bytes)?;

        Ok(Certificate {
            id: -1,
            name,
            created_on: self.created_on,
            valid_until,
            certificate_type: CertificateType::SSHClient,
            user_id,
            renew_method: self.renew_method,
            ca_id,
            data,
            password: self.password.unwrap_or_default(),
        })
    }
}

pub fn create_cert_key_bundle(name: &str, cert_bytes: Vec<u8>, key_bytes: Vec<u8>) -> Result<Vec<u8>> {
    let mut buffer = Cursor::new(Vec::with_capacity(cert_bytes.len() + key_bytes.len()));
    let mut zip = ZipWriter::new(&mut buffer);

    let options = SimpleFileOptions::default().compression_method(zip::CompressionMethod::Stored);
    zip.start_file(format!("{}.pub", name), options)?;
    zip.write_all(cert_bytes.as_slice())?;

    zip.start_file(format!("{}.key", name), options)?;
    zip.write_all(key_bytes.as_slice())?;

    zip.finish()?;

    Ok(buffer.into_inner())
}

pub fn extract_cert_key_bundle(zip_bytes: Vec<u8>, name: &str) -> Result<(Vec<u8>, Vec<u8>)> {
    let cursor = Cursor::new(zip_bytes);
    let mut archive = ZipArchive::new(cursor)?;

    let mut cert_bytes = Vec::new();
    let mut key_bytes = Vec::new();

    for i in 0..archive.len() {
        let mut file = archive.by_index(i)?;
        let file_name = file.name();

        if file_name == format!("{}.pub", name) {
            std::io::Read::read_to_end(&mut file, &mut cert_bytes)?;
        } else if file_name == format!("{}.key", name) {
            std::io::Read::read_to_end(&mut file, &mut key_bytes)?;
        }
    }

    if cert_bytes.is_empty() || key_bytes.is_empty() {
        return Err(anyhow!("Certificate or key not found in ZIP"));
    }

    Ok((cert_bytes, key_bytes))
}
