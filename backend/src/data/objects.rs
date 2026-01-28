use std::fmt;
use crate::helper;
use std::sync::Arc;
use rocket::serde::{Deserialize, Serialize};
use rocket_okapi::JsonSchema;
use rusqlite::ToSql;
use rusqlite::types::{FromSql, FromSqlError, FromSqlResult, ToSqlOutput, ValueRef};
use tokio::sync::Mutex;
use crate::auth::oidc_auth::OidcAuth;
use crate::auth::password_auth::Password;
use crate::data::enums::UserRole;
use crate::db::VaulTLSDB;
use crate::notification::mail::Mailer;
use crate::settings::Settings;

#[derive(Clone, Debug)]
pub(crate) struct AppState {
    pub(crate) db: VaulTLSDB,
    pub(crate) settings: Settings,
    pub(crate) oidc: Arc<Mutex<Option<OidcAuth>>>,
    pub(crate) mailer: Arc<Mutex<Option<Mailer>>>
}

#[derive(Deserialize, Serialize, JsonSchema, Debug, Clone)]
pub struct User {
    pub id: i64,
    pub name: String,
    pub email: String,
    #[serde(rename = "has_password", serialize_with = "helper::serialize_password_hash", skip_deserializing)]
    #[schemars(skip)]
    pub password_hash: Option<Password>,
    #[serde(skip)]
    pub oidc_id: Option<String>,
    pub role: UserRole
}

#[derive(Default, Deserialize, Serialize, JsonSchema, Debug, Clone, PartialEq)]
pub struct Name {
    pub cn: String,
    pub ou: Option<String>
}

impl ToSql for Name {
    fn to_sql(&self) -> rusqlite::Result<ToSqlOutput<'_>> {
        let mut serialized = self.cn.clone();
        serialized.push('\0');
        if let Some(ou) = &self.ou {
            serialized.push_str(ou);
        }
        Ok(ToSqlOutput::from(serialized))
    }
}

impl FromSql for Name {
    fn column_result(value: ValueRef<'_>) -> FromSqlResult<Self> {
        let bytes = value.as_str()?;
        let parts: Vec<&str> = bytes.split('\0').collect();

        if parts.is_empty() {
            return Err(FromSqlError::InvalidType);
        }

        let cn = parts[0].to_string();
        let ou = parts.get(1).and_then(|s| if s.is_empty() { None } else { Some(s.to_string()) });


        Ok(Name { cn, ou })
    }
}

impl fmt::Display for Name {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.cn)
    }
}

impl From<String> for Name {
    fn from(value: String) -> Self {
        Self{cn: value, ou: None}
    }
}

impl From<&str> for Name {
    fn from(value: &str) -> Self {
        value.to_string().into()
    }
}