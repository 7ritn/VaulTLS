use crate::certs::common::{Certificate, CA};
use crate::data::enums::{CertData, CertificateRenewMethod, CertificateType, TimespanUnit};
use anyhow::anyhow;
use anyhow::Result;
use rand::prelude::*;
use rand::rng;
use ssh_key::rand_core::OsRng;
use ssh_key::{certificate, Algorithm, LineEnding, PrivateKey};
use std::io::{Cursor, Read, Write};
use std::time::{SystemTime, UNIX_EPOCH};
use tracing::trace;
use zip::write::SimpleFileOptions;
use zip::ZipWriter;
use crate::data::enums::CAType::SSH;
#[cfg(not(feature = "test-mode"))]
use crate::constants::{KRL_DIR_PATH, KRL_FILE_PATTERN};
use std::fs;
#[cfg(feature = "test-mode")]
use std::env::temp_dir;
use crate::data::error::ApiError;

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

    pub fn set_valid_until(mut self, duration: u64, unit: TimespanUnit) -> Result<Self> {
        let duration_per_unit_h = match unit {
            TimespanUnit::Year => 365*24,
            TimespanUnit::Month => 30*24,
            TimespanUnit::Day => 24,
            TimespanUnit::Hour => 1,
        };
        let duration_s = 60 * 60 * duration as i64 * duration_per_unit_h;
        let valid_until = self.created_on + (duration_s * 1000);
        self.valid_until = Some(valid_until);
        Ok(self)
    }

    pub fn set_principals(mut self, principals: &[String]) -> Result<Self> {
        self.principals = principals
            .iter()
            .filter(|principal| !principal.is_empty())
            .cloned()
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

        let name = self.name.unwrap_or_else(|| "CA".to_string()).into();

        Ok(CA{
            id: -1,
            name,
            created_on: self.created_on,
            valid_until: -1,
            ca_type: SSH,
            cert: Vec::new(),
            key,
            crl_number: 0,
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

        // Attach some standard cert extensions that are normal for home lab usage
        cert_builder.extension("permit-pty", "")?;
        cert_builder.extension("permit-port-forwarding", "")?;
        cert_builder.extension("permit-user-rc", "")?;

        let cert = cert_builder.sign(&ca_key)?;
        trace!("SSH certificate signed with: {}", ca_key.fingerprint(Default::default()));

        let data = CertData::SshBundle(create_cert_key_bundle(&name, cert, user_private_key)?);

        Ok(Certificate {
            id: -1,
            name: name.into(),
            created_on: self.created_on,
            valid_until,
            certificate_type: CertificateType::SSHClient,
            user_id,
            renew_method: self.renew_method,
            ca_id,
            data,
            password: self.password.unwrap_or_default(),
            revoked_at: None
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

        let data = CertData::SshBundle(create_cert_key_bundle(&name, cert, host_private_key)?);

        Ok(Certificate {
            id: -1,
            name: name.into(),
            created_on: self.created_on,
            valid_until,
            certificate_type: CertificateType::SSHServer,
            user_id,
            renew_method: self.renew_method,
            ca_id,
            data,
            password: self.password.unwrap_or_default(),
            revoked_at: None
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

pub fn extract_ssh_serial_number(data: &Vec<u8>, name: &str) -> Result<Vec<u8>> {
    let reader = Cursor::new(data);
    let mut zip = zip::ZipArchive::new(reader).map_err(|e: zip::result::ZipError| ApiError::Other(e.to_string()))?;
    let mut cert_file = zip.by_name(&format!("{}.pub", name)).map_err(|e: zip::result::ZipError| ApiError::Other(e.to_string()))?;
    let mut cert_bytes = Vec::new();
    cert_file.read_to_end(&mut cert_bytes).map_err(|e: std::io::Error| ApiError::Other(e.to_string()))?;
    let cert_str = String::from_utf8_lossy(&cert_bytes);
    let ssh_cert = ssh_key::Certificate::from_openssh(&cert_str).map_err(|e| ApiError::Other(e.to_string()))?;
    Ok(ssh_cert.serial().to_be_bytes().into())
}

#[cfg(not(feature = "test-mode"))]
pub(crate) fn retrieve_krl(ca_id: i64) -> Result<Vec<u8>> {
    let ca_id_file_path = KRL_FILE_PATTERN.replace("{}", &ca_id.to_string());
    Ok(fs::read(ca_id_file_path)?)
}

#[cfg(feature = "test-mode")]
pub(crate) fn retrieve_krl(ca_id: i64) -> Result<Vec<u8>> {
    let mut path = temp_dir();
    path.push(format!("krl-{}.krl", ca_id));
    Ok(fs::read(path)?)
}

pub(crate) fn create_and_save_krl(ca: &mut CA, revoked_serials: &Vec<Vec<u8>>) -> Result<()> {
    let krl_bytes = create_krl(ca, revoked_serials)?;
    save_krl(krl_bytes, ca.id)
}

pub(crate) fn create_krl(ca: &mut CA, revoked_serials: &Vec<Vec<u8>>) -> Result<Vec<u8>> {
    let mut krl = Vec::new();

    // --- KRL Header ---
    krl.extend_from_slice(b"SSHKRL\n\0"); // Format Identifier
    krl.extend_from_slice(&1u32.to_be_bytes()); // Format Version

    // KRL Version
    ca.crl_number += 1;
    let krl_version = (ca.crl_number as u64).to_be_bytes();
    krl.extend_from_slice(&krl_version);

    // Date
    let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
    krl.extend_from_slice(&now.to_be_bytes());

    krl.extend_from_slice(&0u64.to_be_bytes()); // Flags
    krl.extend_from_slice(&0u32.to_be_bytes()); // Reserved
    krl.extend_from_slice(&0u32.to_be_bytes()); // Comment

    // --- KRL Body ---
    // Consists of one section
    // Section consists of CA information and subsection with all revoked keys
    krl.push(1 /* KRL_SECTION_CERTIFICATES */);

    let mut section_data = Vec::new();

    // Extract the CA pubkey blob from the CA private key bytes
    let ca_private_key = PrivateKey::from_bytes(&ca.key)?;
    let ca_pubkey_blob = ca_private_key.public_key().to_bytes()?;

    // CA Key as String (Length + Bytes)
    section_data.extend_from_slice(&(ca_pubkey_blob.len() as u32).to_be_bytes());
    section_data.extend_from_slice(&ca_pubkey_blob);

    // Reserved
    section_data.extend_from_slice(&0u32.to_be_bytes());

    // SUBSECTION: cert_section_type = 0x20 (KRL_SECTION_CERT_SERIAL_LIST)
    section_data.push(0x20);

    // SUBSECTION: cert_section_data
    // OpenSSH expects pairs of (min, max) u64s.
    // To revoke single serials, the min and max are identical.
    let mut cert_section_data = Vec::new();
    for serial in revoked_serials {
        cert_section_data.extend_from_slice(serial);
    }

    // Write cert_section_data as an SSH string (length + data) into the section_data
    section_data.extend_from_slice(&(cert_section_data.len() as u32).to_be_bytes());
    section_data.extend_from_slice(&cert_section_data);

    // Finally, write section_data as an SSH string into the main KRL buffer
    krl.extend_from_slice(&(section_data.len() as u32).to_be_bytes());
    krl.extend_from_slice(&section_data);

    Ok(krl)
}

#[cfg(not(feature = "test-mode"))]
pub(crate) fn save_krl(krl_bytes: Vec<u8>, ca_id: i64) -> Result<()> {
    let ca_id_file_path = KRL_FILE_PATTERN.replace("{}", &ca_id.to_string());
    fs::create_dir_all(KRL_DIR_PATH)?;
    fs::write(ca_id_file_path, krl_bytes)?;
    Ok(())
}

#[cfg(feature = "test-mode")]
pub(crate) fn save_krl(krl_bytes: Vec<u8>, ca_id: i64) -> Result<()> {
    let mut path = temp_dir();
    path.push(format!("krl-{}.krl", ca_id));
    fs::write(path, krl_bytes)?;
    Ok(())
}