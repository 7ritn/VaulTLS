use crate::constants::ARGON2;
use crate::ApiError;
use argon2::password_hash::phc::PasswordHash;
use argon2::{password_hash, PasswordHasher, PasswordVerifier};
use std::fmt::Display;
use rusqlite::types::{FromSql, FromSqlError, FromSqlResult, ValueRef};

#[derive(Clone, Debug)]
pub enum Password {
    V1(String),
    V2(String)
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
            PasswordHash::new(extract)?;
            Ok(Password::V1(extract.to_string()))
        } else if let Some(extract) = s.strip_prefix("v2") {
            PasswordHash::new(extract)?;
            Ok(Password::V2(extract.to_string()))
        } else {
            PasswordHash::new(s)?;
            Ok(Password::V1(s.to_string()))
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
        let (password_hash, password_to_verify) = match self {
            Password::V1(inner) => (inner, Some(other.to_string())),
            Password::V2(inner) => {
                let password_to_verify = if !other.starts_with("$argon2id") {
                    // Plaintext password needs to be double hashed
                    Self::client_hash(other).ok()
                } else {
                    Some(other.to_string())
                };
                (inner, password_to_verify)
            },
        };
        let password_hash = match PasswordHash::new(password_hash) {
            Ok(password_hash) => password_hash,
            Err(_) => return false,
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

        let password_hash_string = ARGON2.hash_password_with_salt(password.as_bytes(), salt_str.as_bytes())
            .map_err(|_| ApiError::Other("Failed to hash password".to_string()))?
            .to_string();
        Ok(password_hash_string.to_string())
    }
    
    /// Hashes a password using Argon2 server-side
    pub(crate) fn new_server_hash(password: &str) -> Result<Password, ApiError> {
        let password_hash_string = ARGON2.hash_password(password.as_bytes())
            .map_err(|_| ApiError::Other("Failed to hash password".to_string()))?
            .to_string();

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