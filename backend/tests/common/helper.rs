use std::io::{Cursor, Read};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use anyhow::Result;
use ssh_key::{Certificate, PrivateKey};
use zip::ZipArchive;

pub(crate) fn get_timestamp_ms(from_now_in_years: u64) -> i64 {
    let time = SystemTime::now() + Duration::from_secs(60 * 60 * 24 * 365 * from_now_in_years);
    time.duration_since(UNIX_EPOCH).unwrap().as_millis() as i64
}

pub(crate) fn get_timestamp_s(from_now_in_years: u64) -> i64 {
    let time = SystemTime::now() + Duration::from_secs(60 * 60 * 24 * 365 * from_now_in_years);
    time.duration_since(UNIX_EPOCH).unwrap().as_secs() as i64
}

pub fn extract_ssh_cert_key_bundle(zip_data: &[u8]) -> Result<(Certificate, PrivateKey)> {
    let cursor = Cursor::new(zip_data);
    let mut archive = ZipArchive::new(cursor)?;

    let mut cert_bytes = Vec::new();
    let mut key_bytes = Vec::new();

    for i in 0..archive.len() {
        let mut file = archive.by_index(i)?;
        let file_name = file.name().to_string();

        if file_name.ends_with(".pub") {
            file.read_to_end(&mut cert_bytes)?;
        } else if file_name.ends_with(".key") {
            file.read_to_end(&mut key_bytes)?;
        }
    }

    let cert_str = String::from_utf8(cert_bytes.clone())?;
    let cert = ssh_key::Certificate::from_openssh(&cert_str)?;

    let key_str = String::from_utf8(key_bytes.clone())?;
    let key = ssh_key::PrivateKey::from_openssh(&key_str)?;

    Ok((cert, key))
}