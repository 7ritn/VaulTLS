use crate::constants::ARGON2;
use crate::ApiError;
use argon2::password_hash::{PasswordHashString, SaltString};
use argon2::{password_hash, PasswordHasher, PasswordVerifier};
use std::fmt::Display;
use argon2::password_hash::rand_core::OsRng;
use rusqlite::types::{FromSql, FromSqlError, FromSqlResult, ValueRef};

#[derive(Clone, Debug)]
pub enum Password {
    V1(PasswordHashString),
    V2(PasswordHashString)
}

impl Display for Password {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Password::V1(p) => write!(f, "v1{p}"),
            Password::V2(p) => write!(f, "v2{p}")
        }
    }
}

impl TryFrom<&str> for Password {
    type Error = password_hash::Error;

    fn try_from(s: &str) -> Result<Self, Self::Error> {
        if let Some(extract) = s.strip_prefix("v1") {
            Ok(Password::V1(PasswordHashString::new(extract)?))
        } else if let Some(extract) = s.strip_prefix("v2") {
            Ok(Password::V2(PasswordHashString::new(extract)?))
        } else {
            Ok(Password::V1(PasswordHashString::new(s)?))
        }
    }
}

impl FromSql for Password {
    fn column_result(value: ValueRef<'_>) -> FromSqlResult<Self> {
        match value {
            ValueRef::Text(s) => {
                let s = String::from_utf8_lossy(s).to_string();
                Password::try_from(s.as_str()).map_err(|_| FromSqlError::InvalidType)
            },
            _ => Err(FromSqlError::InvalidType),
        }
    }
}

impl Password {
    /// Verify password hash with corresponding password
    pub(crate) fn verify(&self, other: &str) -> bool {
        let mut password_to_verify = Some(other.to_string());
        let password_hash = match self {
            Password::V1(inner) => inner.password_hash(),
            Password::V2(inner) => {
                if !other.starts_with("$argon2id") {
                    // Plaintext password needs to be double hashed
                    password_to_verify = Self::client_hash(other).ok()
                }
                inner.password_hash()
            },
        };
        if let Some(password_to_verify) = password_to_verify {
            ARGON2.verify_password(password_to_verify.as_bytes(), &password_hash).is_ok()
        } else {
            false
        }
    }

    /// Hashes a password using Argon2 client-side
    fn client_hash(password: &str) -> Result<String, ApiError> {
        let salt_str = "VaulTLSVaulTLSVaulTLSVaulTLS";
        let salt = SaltString::encode_b64(salt_str.as_bytes())?;

        let password_hash_string = ARGON2.hash_password(password.as_bytes(), &salt)
            .map_err(|_| ApiError::Other("Failed to hash password".to_string()))?
            .serialize();
        Ok(password_hash_string.to_string())
    }
    
    /// Hashes a password using Argon2 server-side
    pub(crate) fn new_server_hash(password: &str) -> Result<Password, ApiError> {
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
    

    /// Hashes a password using Argon2 performing the steps of both the frontend and backend
    pub(crate) fn new_double_hash(password: &str) -> Result<Password, ApiError> {
        let first_hash = Self::client_hash(password)?;
        Self::new_server_hash(&first_hash)
    }
}