use argon2::{Algorithm, Argon2, Params, Version};
use once_cell::sync::Lazy;

pub(crate) const SETTINGS_FILE_PATH: &str = "settings.json";
pub(crate) const DB_FILE_PATH: &str = "database.db3";
pub(crate) const TEMP_DB_FILE_PATH: &str = "encrypted.db3";
pub(crate) const CA_FILE_PATH: &str = "ca.cert";
pub(crate) const API_PORT: u16 = 3737;
pub const VAULTLS_VERSION: &str = "v0.8.0";

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