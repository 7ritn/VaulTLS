use crate::certs::common::{Certificate, CA};
use crate::data::enums::{CertificateRenewMethod, CertificateType};
use anyhow::anyhow;
use anyhow::Result;
use rand::prelude::*;
use rand::rng;
use ssh_key::rand_core::OsRng;
use ssh_key::{certificate, Algorithm, LineEnding, PrivateKey};
use std::io::{Cursor, Write};
use std::time::{SystemTime, UNIX_EPOCH};
use tracing::trace;
use zip::write::SimpleFileOptions;
use zip::ZipWriter;
use crate::data::enums::CAType::SSH;

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
            .as_millis() as i64;
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
        let valid_until = self.created_on + (365 * 86400 * 1000) * years as i64;
        self.valid_until = Some(valid_until);
        Ok(self)
    }

    pub fn set_principals(mut self, principals: &[String]) -> Result<Self> {
        self.principals = principals
            .iter()
            .filter(|principal| !principal.is_empty())
            .map(|principal| principal.clone())
            .collect();
        Ok(self)
    }

    pub fn set_ca(mut self, ca: &CA) -> Result<Self> {
        if ca.ca_type != SSH {
            return Err(anyhow!("CA is not of type SSH"));
        }
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
            ca_type: SSH,
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
            self.created_on as u64 / 1000,
            valid_until as u64 / 1000,
        )?;
        cert_builder.serial(serial)?;
        cert_builder.key_id(name.clone())?;
        cert_builder.cert_type(certificate::CertType::User)?;

        if self.principals.is_empty() {
            cert_builder.all_principals_valid()?;
        }

        for principal in self.principals {
            cert_builder.valid_principal(principal)?;
        }

        let cert = cert_builder.sign(&ca_key)?;
        trace!("SSH certificate signed with: {}", ca_key.fingerprint(Default::default()));

        let data = create_cert_key_bundle(&name, cert, user_private_key)?;

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

    pub fn build_host(self) -> Result<Certificate> {
        let name = self.name.ok_or(anyhow!("SSH: name not set"))?;
        let valid_until = self.valid_until.ok_or(anyhow!("SSH: valid_until not set"))?;
        let (ca_id, ca_key) = self.ca.ok_or(anyhow!("SSH: CA not set"))?;
        let user_id = self.user_id.ok_or(anyhow!("SSH: user_id not set"))?;

        let host_private_key = PrivateKey::random(&mut OsRng, Algorithm::Ed25519)?;
        let host_public_key = host_private_key.public_key();

        let serial = rng().random();

        let mut cert_builder = certificate::Builder::new_with_random_nonce(
            &mut OsRng,
            host_public_key,
            self.created_on as u64 / 1000,
            valid_until as u64 / 1000,
        )?;
        cert_builder.serial(serial)?;
        cert_builder.key_id(name.clone())?;
        cert_builder.cert_type(certificate::CertType::Host)?;
        for principal in self.principals {
            cert_builder.valid_principal(principal)?;
        }

        let cert = cert_builder.sign(&ca_key)?;
        trace!("SSH certificate signed with: {}", ca_key.fingerprint(Default::default()));

        let data = create_cert_key_bundle(&name, cert, host_private_key)?;

        Ok(Certificate {
            id: -1,
            name,
            created_on: self.created_on,
            valid_until,
            certificate_type: CertificateType::SSHServer,
            user_id,
            renew_method: self.renew_method,
            ca_id,
            data,
            password: self.password.unwrap_or_default(),
        })
    }

}

pub fn create_cert_key_bundle(name: &str, cert: ssh_key::Certificate, key: PrivateKey) -> Result<Vec<u8>> {
    let cert_bytes = cert.to_openssh()?.into_bytes();
    let key_str = key.to_openssh(LineEnding::LF)?;
    let key_bytes = key_str.to_string().into_bytes();

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

pub fn get_ssh_pem(ca: &CA) -> Result<Vec<u8>> {
    let private_key = PrivateKey::from_bytes(&ca.key)?;
    let public_key = private_key.public_key();
    Ok(public_key.to_openssh()?.as_bytes().to_vec())
}