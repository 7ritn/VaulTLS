use crate::constants::ARGON2;
use crate::data::enums::Password;
use crate::ApiError;
use argon2::password_hash::rand_core::OsRng;
use argon2::password_hash::SaltString;
use argon2::PasswordHasher;

/// Hashes a password using Argon2 server-side
pub fn server_hash_password(password: &str) -> Result<Password, ApiError> {
    let salt = SaltString::generate(&mut OsRng);

    let password_hash_string = ARGON2.hash_password(password.as_bytes(), &salt)
        .map_err(|_| ApiError::Other("Failed to hash password".to_string()))?
        .serialize();

    if password.starts_with("$argon2id") {
        Ok(Password::V2(password_hash_string))
    } else {
        Ok(Password::V1(password_hash_string))
    }
}

/// Hashes a password using Argon2 frontend-side
pub fn client_hash_password(password: &str) -> Result<String, ApiError> {
    let salt_str = "VaulTLSVaulTLSVaulTLSVaulTLS";
    let salt = SaltString::encode_b64(salt_str.as_bytes())?;

    let password_hash_string = ARGON2.hash_password(password.as_bytes(), &salt)
        .map_err(|_| ApiError::Other("Failed to hash password".to_string()))?
        .serialize();
    Ok(password_hash_string.to_string())
}

/// Hashes a password using Argon2 performing the steps of both the frontend and backend
pub fn double_hash_password(password: &String) -> Result<Password, ApiError> {
    let first_hash = client_hash_password(password)?;
    server_hash_password(&first_hash)
}