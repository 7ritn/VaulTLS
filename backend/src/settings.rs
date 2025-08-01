use std::{env, fs};
use argon2::password_hash::rand_core::{OsRng, RngCore};
use openssl::base64;
use rocket::serde;
use rocket::serde::json::serde_json;
use rocket::serde::{Deserialize, Serialize};
use rocket::serde::ser::SerializeStruct;
use rocket_okapi::JsonSchema;
use schemars::schema::{ObjectValidation, Schema, SchemaObject, SingleOrVec};
use schemars::SchemaGenerator;
use crate::data::enums::{MailEncryption, PasswordRule};
use crate::constants::SETTINGS_FILE_PATH;
use tokio::fs::OpenOptions;
use tokio::io::AsyncWriteExt;
use crate::ApiError;
use crate::helper::get_secret;

/// Settings for the backend.
#[derive(Serialize, Deserialize, JsonSchema, Clone, Default, Debug)]
pub(crate) struct Settings {
    #[serde(default)]
    mail: Mail,
    #[serde(default)]
    common: Common,
    #[serde(default)]
    auth: Auth,
    #[serde(default)]
    oidc: OIDC,
    #[serde(default)]
    logic: Logic
}

/// Wrapper for the settings to make them serializable for the frontend.
#[derive(Deserialize, Default)]
pub(crate) struct FrontendSettings(pub(crate) Settings);

/// Serialize the settings for the frontend.
impl Serialize for FrontendSettings {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let mut state = serializer.serialize_struct("Settings", 1)?;
        state.serialize_field("common", &self.0.common)?;
        state.serialize_field("mail", &self.0.mail)?;
        state.serialize_field("oidc", &self.0.oidc)?;
        state.end()
    }
}


/// Schematize the settings for the API
impl JsonSchema for FrontendSettings {
    fn schema_name() -> String {
        "FrontendSettings".to_string()
    }

    fn json_schema(generator: &mut SchemaGenerator) -> Schema {
        let mut props = schemars::Map::new();

        props.insert(
            "common".to_string(),
            generator.subschema_for::<Common>(),
        );
        props.insert(
            "mail".to_string(),
            generator.subschema_for::<Mail>(),
        );
        props.insert(
            "oidc".to_string(),
            generator.subschema_for::<OIDC>(),
        );

        Schema::Object(SchemaObject {
            instance_type: Some(SingleOrVec::Single(Box::new(schemars::schema::InstanceType::Object))),
            object: Some(Box::new(ObjectValidation {
                properties: props,
                required: schemars::Set::from_iter(vec![
                    "common".to_string(),
                    "mail".to_string(),
                    "oidc".to_string(),
                ]),
                ..Default::default()
            })),
            ..Default::default()
        })
    }
}

/// Common settings for the backend.
#[derive(Serialize, Deserialize, JsonSchema, Clone, Default, Debug)]
pub(crate) struct Common {
    password_enabled: bool,
    vaultls_url: String,
    #[serde(default)]
    password_rule: PasswordRule,
}

impl Common {
    /// Replace common settings with environment variables.
    fn load_from_env(&mut self) {
        if let Ok(password_enabled) = env::var("VAULTLS_PASSWORD_ENABLED") {
            self.password_enabled = password_enabled == "true";
        }
        if let Ok(vaultls_url) = env::var("VAULTLS_URL") {
            self.vaultls_url = vaultls_url;
        }
    }
}

/// Mail settings for the backend.
#[derive(Serialize, Deserialize, JsonSchema, Clone, Default, Debug)]
pub(crate) struct Mail {
    pub(crate) smtp_host: String,
    pub(crate) smtp_port: u16,
    pub(crate) encryption: MailEncryption,
    pub(crate) username: Option<String>,
    pub(crate) password: Option<String>,
    pub(crate) from: String
}

impl Mail {
    /// Check if the mail settings are valid.
    pub(crate) fn is_valid(&self) -> bool {
        !self.smtp_host.is_empty() && self.smtp_port > 0 && !self.from.is_empty()
    }

    /// Replace mail settings with environment variables.
    fn load_from_env(&mut self) {
        let get_env = || -> anyhow::Result<Mail> {
            let host = env::var("VAULTLS_MAIL_HOST")?;
            let port = env::var("VAULTLS_MAIL_PORT")?;
            let encryption = env::var("VAULTLS_MAIL_ENCRYPTION").unwrap_or_default().into();
            let username = env::var("VAULTLS_MAIL_USERNAME").ok();
            let password = get_secret("VAULTLS_OIDC_SECRET_PASSWORD").ok();
            let from = env::var("VAULTLS_MAIL_FROM").unwrap_or_default();

            Ok(Mail{
                smtp_host: host,
                smtp_port: port.parse().expect("Mail port is not a number"),
                encryption,
                username,
                password,
                from,
            })
        };

        if let Ok(oidc_env) = get_env() {
            *self = oidc_env;
        }
    }
}

/// Authentication settings for the backend.
#[derive(Serialize, Deserialize, JsonSchema, Clone, Debug)]
pub(crate) struct Auth {
    jwt_key: String,
}

impl Default for Auth {
    fn default() -> Self {
        Self{ jwt_key: generate_jwt_key(), }
    }
}

/// OpenID Connect settings for the backend.
#[derive(Serialize, Deserialize, JsonSchema, Clone, Default, Debug)]
#[allow(clippy::upper_case_acronyms)]
pub(crate) struct OIDC {
    pub(crate) id: String,
    pub(crate) secret: String,
    pub(crate) auth_url: String,
    pub(crate) callback_url: String
}

impl OIDC {
    /// Check if the OIDC settings are valid.
    pub(crate) fn is_valid(&self) -> bool {
        !(self.id.is_empty() || self.secret.is_empty() || self.auth_url.is_empty() || self.callback_url.is_empty())
    }
    
    /// Replace OIDC settings with environment variables.
    fn load_from_env(&mut self) {
        let get_env = || -> anyhow::Result<OIDC> {
            let id = env::var("VAULTLS_OIDC_ID")?;
            let secret = get_secret("VAULTLS_OIDC_SECRET")?;
            let auth_url = env::var("VAULTLS_OIDC_AUTH_URL")?;
            let callback_url = env::var("VAULTLS_OIDC_CALLBACK_URL")?;
            Ok(OIDC{ id, secret, auth_url, callback_url })
        };

        if let Ok(oidc_env) = get_env() {
            *self = oidc_env;
        }
    }
}

#[derive(Serialize, Deserialize, JsonSchema, Clone, Default, Debug)]
pub(crate) struct Logic {
    pub(crate) db_encrypted: bool,
}


/// Generates a new JWT key.
fn generate_jwt_key() -> String {
    let mut secret = [0u8; 32];
    OsRng.fill_bytes(&mut secret);
    base64::encode_block(&secret)
}

impl Settings {
    /// Load saved settings from a file
    pub(crate) async fn load_from_file(file_path: Option<&str>) -> Result<Self, ApiError> {
        let settings_string = fs::read_to_string(file_path.unwrap_or(SETTINGS_FILE_PATH))
            .unwrap_or("{}".to_string());
        let mut settings: Self = serde_json::from_str(&settings_string).unwrap_or(Default::default());
        settings.common.load_from_env();
        settings.mail.load_from_env();
        settings.oidc.load_from_env();
        settings.save_to_file(None).await?;
        Ok(settings)
    }

    /// Save current settings to a file, can specify a file path otherwise SETTINGS_FILE_PATH is used.
    pub(crate) async fn save_to_file(&self, file_path: Option<&str>) -> Result<(), ApiError> {
        let path = file_path.unwrap_or(SETTINGS_FILE_PATH);
        
        let mut file = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(path)
            .await
            .map_err(|e| ApiError::Other(format!("Failed to open settings file: {e}")))?;

        let contents = serde_json::to_string_pretty(self)
            .map_err(|e| ApiError::Other(format!("Failed to serialize settings: {e}")))?;
        
        file.write_all(contents.as_bytes())
            .await
            .map_err(|e| ApiError::Other(format!("Failed to write settings: {e}")))?;
        
        file.sync_all()
            .await
            .map_err(|e| ApiError::Other(format!("Failed to flush settings to disk: {e}")))?;

        Ok(())
    }
    
    /// Set the settings and save them to the file.
    pub(crate) async fn set_settings(&mut self, settings: &Settings) -> Result<(), ApiError> {
        self.common = settings.common.clone();
        self.mail = settings.mail.clone();
        self.oidc = settings.oidc.clone();

        self.save_to_file(None).await
    }
    
    /// Get the JWT key from the settings.
    pub(crate) fn get_jwt_key(&self) -> Result<Vec<u8>, ApiError> {
        base64::decode_block(self.auth.jwt_key.as_str())
            .map_err(|_| ApiError::Other("Failed to decode jwt key".to_string()))
    }
    
    pub(crate) fn get_mail(&self) -> &Mail { &self.mail }
    pub(crate) fn get_oidc(&self) -> &OIDC { &self.oidc }
    pub(crate) fn get_vaultls_url(&self) -> &str { &self.common.vaultls_url }
    pub(crate) fn get_db_encrypted(&self) -> bool { self.logic.db_encrypted }
    
    pub(crate) async fn set_password_enabled(&mut self, password_enabled: bool) -> Result<(), ApiError>{
        self.common.password_enabled = password_enabled;
        self.save_to_file(None).await
    }

    pub(crate) async fn set_db_encrypted(&mut self) -> Result<(), ApiError>{
        self.logic.db_encrypted = true;
        self.save_to_file(None).await
    }
    
    /// Check if the password is enabled.
    pub(crate) fn password_enabled(&self) -> bool {
        self.common.password_enabled
    }

    pub(crate) fn password_rule(&self) -> PasswordRule {
        self.common.password_rule
    }
}