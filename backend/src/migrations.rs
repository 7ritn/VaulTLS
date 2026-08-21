use std::fs;
use tracing::info;
use crate::constants::{CA_DIR_PATH, CA_FILE_PATTERN, CA_TLS_FILE_PATH};
use anyhow::Result;

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
