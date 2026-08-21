use std::fs;
use tracing::info;
use crate::constants::{CA_DIR_PATH, CA_FILE_PATTERN, CA_TLS_FILE_PATH};
use anyhow::Result;
use crate::certs::common::CA;
#[cfg(not(feature = "test-mode"))]
use crate::certs::crl::create_new_crl;
use crate::db::VaulTLSDB;
use crate::settings::Settings;
#[cfg(not(feature = "test-mode"))]
use crate::constants::CRL_FILE_PATTERN;

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

#[cfg(not(feature = "test-mode"))]
pub(crate) async fn migrate_create_all_new_crl(ca_id_list: Vec<CA>, db: &VaulTLSDB, settings: &Settings) -> Result<()> {
    info!("Checking for missing CRLs CA");
    for mut ca in ca_id_list {
        let ca_path = CRL_FILE_PATTERN.replace("{}", &ca.id.to_string());
        if !fs::exists(ca_path).is_ok_and(|exists| exists) {
            info!("Creating empty CRL for CA {} (ID {})", ca.name, ca.id);
            let _ = create_new_crl(db, settings, &mut ca).await;
        }
    }
    Ok(())
}

#[cfg(feature = "test-mode")]
pub(crate) async fn migrate_create_all_new_crl(_ca_id_list: Vec<CA>, _db: &VaulTLSDB, _settings: &Settings) -> Result<()> {
    Ok(())
}