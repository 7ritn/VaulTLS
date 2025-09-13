use argon2::{Algorithm, Argon2, Params, Version};
use const_format::formatcp;
use once_cell::sync::Lazy;

pub(crate) const SETTINGS_FILE_PATH: &str = "settings.json";
pub(crate) const DB_FILE_PATH: &str = "database.db3";
pub(crate) const TEMP_DB_FILE_PATH: &str = "encrypted.db3";
pub(crate) const CA_DIR_PATH: &str = "./ca";
pub(crate) const CA_FILE_PATTERN: &str = "./ca/ca-{}.pem";
pub(crate) const CA_TLS_FILE_PATH: &str = "./ca/ca-tls.cert";
pub(crate) const API_PORT: u16 = 3737;
pub const VAULTLS_VERSION: &str = formatcp!("v{}", env!("CARGO_PKG_VERSION"));

#[cfg(not(test))]
pub static ARGON2: Lazy<Argon2<'static>> = Lazy::new(|| {
    let params = Params::new(64 * 1024, 3, 4, Some(50))
    .expect("Failed to create Argon2 parameters");

    Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
});

#[cfg(test)]
pub static ARGON2: Lazy<Argon2<'static>> = Lazy::new(|| {
    // Test setup (weaker params for speed)
    let params = Params::new(1024, 1, 1, Some(50)).unwrap();
    Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
});