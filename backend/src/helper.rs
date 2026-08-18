use std::{env, fs};
use std::path::Path;
use serde::Serializer;
use crate::auth::password_auth::Password;

/// Serializes a Password to a boolean
pub fn serialize_password_hash<S>(password_hash: &Option<Password>, s: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    s.serialize_bool(password_hash.is_some())
}

/// Get secret
pub fn get_secret(name: &str) -> Option<String> {
    let mut path = "/run/secrets/".to_string() + name;
    if let Ok(env_var) = env::var(name) {
        if !Path::new(&env_var).exists() {
            return Some(env_var)
        }
        path = env_var;
    }

    fs::read_to_string(path)
        .map(|secret| secret.trim().to_string())
        .ok()
}

#[inline(always)]
pub fn env_var_vec(env_name: &str) -> Vec<String> {
    env::var(env_name).map(|env| env.split(',').map(str::to_owned).collect()).unwrap_or_default()
}
