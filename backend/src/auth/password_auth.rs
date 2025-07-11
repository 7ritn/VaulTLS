use argon2::{Argon2, PasswordVerifier};
use argon2::password_hash::PasswordHashString;
use crate::ApiError;

/// Verifies a password against a password hash.
pub(crate) fn verify_password(password_hash_string: &PasswordHashString, password: &str) -> Result<(), ApiError> {
    let password_hash = password_hash_string.password_hash();

    let argon2 = Argon2::default();
    argon2
        .verify_password(password.as_bytes(), &password_hash)
        .map_err(|_| ApiError::BadRequest("Passwords do not match.".to_string()))
}