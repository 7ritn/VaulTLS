use std::fmt::Display;
use argon2::{password_hash, PasswordVerifier};
use argon2::password_hash::PasswordHashString;
use num_enum::TryFromPrimitive;
use rocket_okapi::JsonSchema;
use rusqlite::types::{FromSql, FromSqlError, FromSqlResult, ValueRef};
use serde_repr::{Deserialize_repr, Serialize_repr};
use crate::constants::ARGON2;

#[derive(Serialize_repr, Deserialize_repr, JsonSchema, Clone, Debug, TryFromPrimitive, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum UserRole {
    User = 0,
    Admin = 1
}

impl FromSql for UserRole {
    fn column_result(value: ValueRef<'_>) -> FromSqlResult<Self> {
        match value {
            ValueRef::Integer(i) => {
                let value = i as u8;
                UserRole::try_from(value)
                    .map_err(|_| FromSqlError::InvalidType)
            },
            _ => Err(FromSqlError::InvalidType),
        }
    }
}

#[derive(Serialize_repr, Deserialize_repr, JsonSchema, Clone, Debug, Copy, PartialEq, Eq, Default)]
#[repr(u8)]
#[allow(clippy::upper_case_acronyms)]
pub(crate) enum MailEncryption {
    #[default]
    None = 0,
    TLS = 1,
    STARTTLS = 2
}

#[derive(Serialize_repr, Deserialize_repr, JsonSchema, Clone, Debug, Copy, PartialEq, Eq, Default)]
#[repr(u8)]
pub(crate) enum PasswordRule {
    #[default]
    Optional = 0,
    Required = 1,
    System = 2
}

#[derive(Serialize_repr, Deserialize_repr, JsonSchema, TryFromPrimitive, Clone, Debug, Copy, PartialEq, Eq, Default)]
#[repr(u8)]
pub enum CertificateType {
    #[default]
    Client = 0,
    Server = 1,
    CA = 2
}

impl FromSql for CertificateType {
    fn column_result(value: ValueRef<'_>) -> FromSqlResult<Self> {
        match value {
            ValueRef::Integer(i) => {
                let value = i as u8;
                CertificateType::try_from(value)
                    .map_err(|_| FromSqlError::InvalidType)
            },
            _ => Err(FromSqlError::InvalidType),
        }
    }
}

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

impl PartialEq<&str> for Password {
    fn eq(&self, other: &&str) -> bool {
        let password_hash = match self {
            Password::V1(inner) | Password::V2(inner) => inner.password_hash(),
        };

        ARGON2.verify_password(other.as_bytes(), &password_hash).is_ok()
    }
}