use std::{env, fs};
use std::os::unix::prelude::PermissionsExt;
use std::path::Path;
use std::sync::Arc;
use rocket::{Build, Config, Rocket};
use rocket::fairing::AdHoc;
use rocket_okapi::openapi_get_routes;
use rocket_okapi::rapidoc::{make_rapidoc, GeneralConfig, HideShowConfig, Layout, LayoutConfig, RapiDocConfig, RenderStyle, SchemaConfig, SchemaStyle};
use rocket_okapi::settings::UrlObject;
use tokio::sync::Mutex;
use tracing::{debug, info, trace};
use tracing_subscriber::EnvFilter;
use crate::api::*;
use crate::auth::oidc_auth::OidcAuth;
use crate::auth::password_auth::Password;
use crate::certs::tls_cert::migrate_ca_storage;
use crate::constants::{API_PORT, DB_FILE_PATH, VAULTLS_VERSION};
use crate::data::objects::AppState;
use crate::db::VaulTLSDB;
use crate::helper::get_secret;
use crate::notification::mail::Mailer;
use crate::notification::notifier::watch_expiry;
use crate::settings::Settings;

mod db;
pub mod certs;
mod settings;
pub mod data;
mod helper;
mod auth;
pub mod constants;
mod api;
mod notification;

type ApiError = data::error::ApiError;

pub async fn create_rocket() -> Rocket<Build> {
    let mut filter = EnvFilter::try_from_default_env().unwrap_or_default();


    filter = if let Ok(env_var) = env::var("VAULTLS_LOG_LEVEL") {
        match env_var.as_str() {
            "trace" => {
                filter.add_directive("vaultls=trace".parse().unwrap())
                      .add_directive("rocket=trace".parse().unwrap())
            },
            "debug" => {
                filter.add_directive("vaultls=debug".parse().unwrap())
                      .add_directive("rocket=debug".parse().unwrap())
            },
            "info" => {
                filter.add_directive("vaultls=info".parse().unwrap())
                      .add_directive("rocket=info".parse().unwrap())
            },
            "warn" => filter.add_directive("vaultls=warn".parse().unwrap()),
            "error" => filter.add_directive("vaultls=error".parse().unwrap()),
            _ => filter.add_directive("vaultls=info".parse().unwrap())
        }
    } else { filter.add_directive("vaultls=info".parse().unwrap()) };

    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .init();

    info!("Starting mTLS Certificates API");
    info!("Version {VAULTLS_VERSION}");

    info!("Loading settings from file");
    let settings = Settings::load_from_file(None).expect("Failed loading settings");
    trace!("Settings loaded: {:?}", settings);

    let db_path = Path::new(DB_FILE_PATH);
    let db_initialized = db_path.exists();
    let mut encrypted = settings.get_db_encrypted();

    if !encrypted && let Ok(db_secret) = get_secret("VAULTLS_DB_SECRET") {
        if db_initialized {
            VaulTLSDB::migrate_to_encrypted(&db_secret).expect("Failed to migrate database to encrypted");
        }
        settings.set_db_encrypted().expect("Failed to set database to encrypted in settings");
        encrypted = true;
    }

    let db = VaulTLSDB::new(encrypted, false).expect("Failed opening SQLite database");
    db.fix_password().await.expect("Failed fixing passwords");
    if !db_initialized {
        info!("New database. Set initial database file permissions to 0600");
        // Adjust permissions
        let mut perms = fs::metadata(db_path).unwrap().permissions();
        perms.set_mode(0o600);
        fs::set_permissions(db_path, perms).unwrap();
    }
    info!("Database initialized");

    if let Ok(email) = env::var("VAULTLS_ACCOUNT_EMAIL") && let Ok(password) = get_secret("VAULTLS_ACCOUNT_PASSWORD") {
        info!("Setting password for user {} and exiting", email);
        let user = db.get_user_by_email(email.clone()).await.expect("Failed to find user");
        let password_hash = Password::new_double_hash(&password).expect("Failed to hash password");
        db.set_user_password(user.id, password_hash).await.expect("Failed to set password");
        info!("Password for user {} successfully set. Exiting.", email);
        std::process::exit(0);
    }

    let oidc_settings = settings.get_oidc();
    let oidc = match oidc_settings.auth_url.is_empty() {
        true => None,
        false => {
            debug!("OIDC enabled. Trying to connect to {}.", oidc_settings.auth_url);
            OidcAuth::new(&oidc_settings).await.ok()
        }
    };

    match oidc.is_some() {
        true => info!("OIDC is active."),
        false => info!("OIDC is inactive.")
    }

    let mail_settings = settings.get_mail();
    let mailer = match mail_settings.is_valid() {
        true => {
            debug!("Mail enabled. Trying to connect to {}.", mail_settings.smtp_host);
            Mailer::new(&mail_settings, &settings.get_vaultls_url()).await.ok()
        },
        false => None
    };

    match mailer.is_some() {
        true => info!("Mail notifications are active."),
        false => info!("Mail notifications are inactive.")
    }
    
    // Migrate certs
    migrate_ca_storage().expect("Failed migrating CA storage paths");

    let rocket_secret = get_secret("VAULTLS_API_SECRET").expect("Failed to get VAULTLS_API_SECRET");
    trace!("Rocket secret: {}", rocket_secret);
    
    let mailer = Arc::new(Mutex::new(mailer));

    let app_state = AppState {
        db: db.clone(),
        settings,
        oidc: Arc::new(Mutex::new(oidc)),
        mailer: mailer.clone()
    };

    tokio::spawn(async move {
        watch_expiry(db.clone(), mailer.clone()).await;
    });

    trace!("App State: {:?}", app_state);

    info!("Initialization complete.");

    let figment = Config::figment()
        .merge(("secret_key", rocket_secret))
        .merge(("port", API_PORT));

    rocket::build()
        .configure(figment)
        .manage(app_state)
        .mount(
            "/api",
            openapi_get_routes![
                version,
                get_certificates,
                create_ca,
                create_user_certificate,
                get_all_ca,
                download_current_tls_ca,
                download_current_ssh_ca,
                download_ca,
                download_certificate,
                delete_user_cert,
                revoke_certificate,
                download_crl,
                delete_ca,
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
        .attach(AdHoc::config::<Settings>())
}

pub async fn create_test_rocket() -> Rocket<Build> {
    let db = VaulTLSDB::new(false, true).expect("Failed opening SQLite database");
    let settings = Settings::default();
    let oidc = None;

    let mail_settings = settings.get_mail();
    let mailer = match mail_settings.is_valid() {
        true => {
            Mailer::new(&mail_settings, &settings.get_vaultls_url()).await.ok()
        },
        false => None
    };

    let app_state = AppState {
        db,
        settings,
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
                create_ca,
                get_all_ca,
                download_current_tls_ca,
                download_current_ssh_ca,
                download_ca,
                download_certificate,
                delete_user_cert,
                revoke_certificate,
                download_crl,
                delete_ca,
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