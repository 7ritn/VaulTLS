use crate::helper;
use std::sync::Arc;
use rocket::serde::{Deserialize, Serialize};
use rocket_okapi::JsonSchema;
use tokio::sync::Mutex;
use crate::auth::oidc_auth::OidcAuth;
use crate::auth::password_auth::Password;
use crate::data::enums::UserRole;
use crate::db::VaulTLSDB;
use crate::notification::mail::Mailer;
use crate::settings::Settings;

#[derive(Clone, Debug)]
pub(crate) struct AppState {
    pub(crate) db: Arc<Mutex<VaulTLSDB>>,
    pub(crate) settings: Arc<Mutex<Settings>>,
    pub(crate) oidc: Arc<Mutex<Option<OidcAuth>>>,
    pub(crate) mailer: Arc<Mutex<Option<Mailer>>>
}

#[derive(Deserialize, Serialize, JsonSchema, Debug)]
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