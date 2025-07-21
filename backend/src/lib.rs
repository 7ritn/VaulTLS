use std::{env, fs};
use std::os::unix::prelude::PermissionsExt;
use std::path::Path;
use std::sync::Arc;
use rocket::{Build, Rocket};
use rocket::fairing::AdHoc;
use rocket::http::Method;
use rocket_cors::{AllowedOrigins, CorsOptions};
use rocket_okapi::openapi_get_routes;
use rocket_okapi::rapidoc::{make_rapidoc, GeneralConfig, HideShowConfig, Layout, LayoutConfig, RapiDocConfig, RenderStyle, SchemaConfig, SchemaStyle};
use rocket_okapi::settings::UrlObject;
use tokio::sync::Mutex;
use crate::api::*;
use crate::auth::oidc_auth::OidcAuth;
use crate::constants::{API_PORT, DB_FILE_PATH, VAULTLS_VERSION};
use crate::data::objects::AppState;
use crate::db::VaulTLSDB;
use crate::helper::get_secret;
use crate::notification::Mailer;
use crate::settings::Settings;

mod db;
pub mod cert;
mod settings;
mod notification;
pub mod data;
mod helper;
mod auth;
pub mod constants;
mod api;

type ApiError = data::error::ApiError;

pub async fn create_rocket() -> Rocket<Build> {
    println!("Starting mTLS Certificates API");
    println!("Version {VAULTLS_VERSION}");

    println!("Loading settings from file");
    let mut settings = Settings::load_from_file(None).await.expect("Failed loading settings");

    println!("Trying to use database at {DB_FILE_PATH}");
    let db_path = Path::new(DB_FILE_PATH);
    let db_initialized = db_path.exists();
    let db = VaulTLSDB::new(settings.get_db_encrypted(), false).expect("Failed opening SQLite database");
    if !settings.get_db_encrypted() && env::var("VAULTLS_DB_SECRET").is_ok() {
        settings.set_db_encrypted().await.unwrap()
    }
    if !db_initialized {
        println!("New database. Set initial database file permissions to 0600");
        // Adjust permissions
        let mut perms = fs::metadata(db_path).unwrap().permissions();
        perms.set_mode(0o600);
        fs::set_permissions(db_path, perms).unwrap();
    }

    let oidc_settings = settings.get_oidc();
    let oidc = match oidc_settings.auth_url.is_empty() {
        true => None,
        false => {
            println!("OIDC enabled. Trying to connect to {}.", oidc_settings.auth_url);
            OidcAuth::new(settings.get_oidc()).await.ok()
        }
    };

    let mail_settings = settings.get_mail();
    let mailer = match mail_settings.is_valid() {
        true => {
            println!("Mail enabled. Trying to connect to {}.", mail_settings.smtp_host);
            Mailer::new(mail_settings, settings.get_vaultls_url()).await.ok()
        },
        false => None
    };
    let rocket_secret = get_secret("VAULTLS_API_SECRET").expect("Failed to get VAULTLS_API_SECRET");
    unsafe { env::set_var("ROCKET_SECRET_KEY", rocket_secret) }

    let app_state = AppState {
        db: Arc::new(Mutex::new(db)),
        settings: Arc::new(Mutex::new(settings)),
        oidc: Arc::new(Mutex::new(oidc)),
        mailer: Arc::new(Mutex::new(mailer))
    };

    let cors = CorsOptions::default()
        .allowed_origins(AllowedOrigins::all())
        .allow_credentials(true)
        .allowed_methods(
            vec![Method::Get, Method::Post, Method::Put, Method::Delete]
                .into_iter()
                .map(From::from)
                .collect(),
        )
        .allow_credentials(true);

    println!("Initialization complete.");

    rocket::build()
        .configure(rocket::Config::figment().merge(("port", API_PORT)))
        .manage(app_state)
        .mount(
            "/api",
            openapi_get_routes![
                version,
                get_certificates,
                create_user_certificate,
                download_ca,
                download_certificate,
                delete_user_cert,
                fetch_certificate_password,
                fetch_settings,
                update_settings,
                is_setup,
                setup,
                login,
                change_password,
                logout,
                oidc_login,
                oidc_callback,
                get_current_user,
                get_users,
                create_user,
                delete_user,
                update_user
            ],
        )
        .mount(
            "/api",
            make_rapidoc(&RapiDocConfig {
                general: GeneralConfig {
                    spec_urls: vec![UrlObject::new("General", "/api/openapi.json")],
                    ..Default::default()
                },
                layout: LayoutConfig {
                    layout: Layout::Row,
                    render_style: RenderStyle::View,
                    response_area_height: "300px".to_string(),
                },
                schema: SchemaConfig {
                    schema_style: SchemaStyle::Table,
                    ..Default::default()
                },
                hide_show: HideShowConfig {
                    allow_spec_url_load: false,
                    allow_spec_file_load: false,
                    ..Default::default()
                },
                ..Default::default()
            }),
        )
        .attach(cors.to_cors().unwrap())
        .attach(AdHoc::config::<Settings>())
}

pub async fn create_test_rocket() -> Rocket<Build> {
    let db = VaulTLSDB::new(false, true).expect("Failed opening SQLite database");
    let settings = Settings::default();
    let oidc = None;
    let mailer = None;

    let app_state = AppState {
        db: Arc::new(Mutex::new(db)),
        settings: Arc::new(Mutex::new(settings)),
        oidc: Arc::new(Mutex::new(oidc)),
        mailer: Arc::new(Mutex::new(mailer))
    };


    rocket::build()
        .manage(app_state)
        .mount(
            "/",
            openapi_get_routes![
                version,
                get_certificates,
                create_user_certificate,
                download_ca,
                download_certificate,
                delete_user_cert,
                fetch_certificate_password,
                fetch_settings,
                update_settings,
                is_setup,
                setup,
                login,
                change_password,
                logout,
                oidc_login,
                oidc_callback,
                get_current_user,
                get_users,
                create_user,
                delete_user,
                update_user
            ],
        )
}