use std::{env, fs};
#[cfg(unix)]
use std::os::unix::prelude::PermissionsExt;
use std::path::Path;
use std::sync::Arc;
use rocket::{Build, Config, Rocket};
use rocket::fairing::AdHoc;
use rocket::http::Method;
use rocket_cors::{AllowedOrigins, CorsOptions};
use rocket_okapi::openapi_get_routes;
use rocket_okapi::rapidoc::{make_rapidoc, GeneralConfig, HideShowConfig, Layout, LayoutConfig, RapiDocConfig, RenderStyle, SchemaConfig, SchemaStyle};
use rocket_okapi::redoc::{make_redoc, RedocConfig};
use rocket_okapi::settings::UrlObject;
use tokio::sync::Mutex;
use tracing::{debug, info, trace};
use tracing_subscriber::EnvFilter;
use crate::api::*;
use crate::auth::oidc_auth::OidcAuth;
use crate::constants::{API_PORT, DB_FILE_PATH, VAULTLS_VERSION};
use crate::data::objects::AppState;
use crate::db::VaulTLSDB;
use crate::helper::get_secret;
use crate::notification::mail::Mailer;
use crate::notification::notifier::watch_expiry;
use crate::settings::Settings;

mod db;
pub mod cert;
pub mod crl;
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
    let encrypted = settings.get_db_encrypted();
    let db = VaulTLSDB::new(encrypted, false).expect("Failed opening SQLite database");
    db.fix_password().await.expect("Failed fixing passwords");
    if !encrypted && env::var("VAULTLS_DB_SECRET").is_ok() {
        settings.set_db_encrypted().unwrap()
    }
    if !db_initialized {
        info!("New database. Set initial database file permissions to 0600");
        // Adjust permissions (Unix only)
        #[cfg(unix)]
        {
            let mut perms = fs::metadata(db_path).unwrap().permissions();
            perms.set_mode(0o600);
            fs::set_permissions(db_path, perms).unwrap();
        }
    }
    info!("Database initialized");

    let oidc_settings = settings.get_oidc();
    let oidc = match oidc_settings.auth_url.is_empty() {
        true => None,
        false => {
            debug!("OIDC enabled. Trying to connect to {}.", oidc_settings.auth_url);
            OidcAuth::new(&settings.get_oidc()).await.ok()
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
                api_docs,
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
                update_user,
                revoke_certificate,
                restore_certificate,
                download_crl,
                get_crl_info,
                check_certificate_status,
                get_revocation_statistics,
                generate_crl,
                create_api_token,
                list_api_tokens,
                get_api_token,
                update_api_token,
                rotate_api_token,
                revoke_api_token,
                delete_api_token,
                create_ca,
                list_cas,
                get_ca,
                update_ca,
                delete_ca,
                download_ca_certificate,
                download_ca_chain,
                rotate_ca_key,
                create_certificate_with_ca,
                get_available_cas,
                create_profile,
                list_profiles,
                get_profile,
                update_profile,
                delete_profile,
                search_certificates,
                batch_certificate_operation,
                get_certificate_chain,
                validate_certificate_chain,
                get_expiring_certificates,
                get_certificate_statistics,
                bulk_download_certificates,
                get_audit_events,
                search_audit_events,
                get_audit_statistics,
                get_audit_activity,
                export_audit_events,
                generate_compliance_report
            ],
        )
        // Conditionally mount API documentation based on environment variables
        .attach(rocket::fairing::AdHoc::on_ignite("API Documentation", |rocket| async {
            let docs_enabled = std::env::var("VAULTLS_API_DOCS_ENABLED")
                .unwrap_or_else(|_| "true".to_string())
                .parse::<bool>()
                .unwrap_or(true);

            let docs_require_auth = std::env::var("VAULTLS_API_DOCS_REQUIRE_AUTH")
                .unwrap_or_else(|_| "false".to_string())
                .parse::<bool>()
                .unwrap_or(false);

            if !docs_enabled {
                println!("📚 API Documentation: DISABLED (VAULTLS_API_DOCS_ENABLED=false)");
                return rocket;
            }

            if docs_require_auth {
                println!("📚 API Documentation: ENABLED with authentication required");
                // Mount protected documentation endpoints
                rocket
                    .mount("/api-docs", routes![protected_rapidoc])
                    .mount("/redoc", routes![protected_redoc])
                    .mount("/api/openapi.json", routes![protected_openapi_spec])
            } else {
                println!("📚 API Documentation: ENABLED (public access)");
                // Mount public documentation endpoints
                rocket
                    .mount(
                        "/api-docs",
                        make_rapidoc(&RapiDocConfig {
                            general: GeneralConfig {
                                spec_urls: vec![UrlObject::new("VaulTLS API", "/api/openapi.json")],
                                ..Default::default()
                            },
                            layout: LayoutConfig {
                                layout: Layout::Column,
                                render_style: RenderStyle::Read,
                                response_area_height: "400px".to_string(),
                            },
                            schema: SchemaConfig {
                                schema_style: SchemaStyle::Tree,
                                ..Default::default()
                            },
                            hide_show: HideShowConfig {
                                allow_spec_url_load: true,
                                allow_spec_file_load: false,
                                allow_search: true,
                                allow_try: true,
                                allow_server_selection: true,
                                show_header: true,
                                show_info: true,
                                show_components: true,
                                ..Default::default()
                            },
                            ..Default::default()
                        }),
                    )
                    .mount(
                        "/redoc",
                        make_redoc(&RedocConfig {
                            spec_url: "/api/openapi.json".to_string(),
                            title: Some("VaulTLS API Documentation".to_string()),
                            ..Default::default()
                        }),
                    )
            }
        }))
        .mount(
            "/redoc",
            make_redoc(&RedocConfig {
                spec_url: "/api/openapi.json".to_string(),
                title: Some("VaulTLS API Documentation".to_string()),
                theme: Some("dark".to_string()),
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
                api_docs,
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
                update_user,
                revoke_certificate,
                restore_certificate,
                download_crl,
                get_crl_info,
                check_certificate_status,
                get_revocation_statistics,
                generate_crl,
                create_api_token,
                list_api_tokens,
                get_api_token,
                update_api_token,
                rotate_api_token,
                revoke_api_token,
                delete_api_token,
                create_ca,
                list_cas,
                get_ca,
                update_ca,
                delete_ca,
                download_ca_certificate,
                download_ca_chain,
                rotate_ca_key,
                create_certificate_with_ca,
                get_available_cas,
                create_profile,
                list_profiles,
                get_profile,
                update_profile,
                delete_profile,
                search_certificates,
                batch_certificate_operation,
                get_certificate_chain,
                validate_certificate_chain,
                get_expiring_certificates,
                get_certificate_statistics,
                bulk_download_certificates,
                get_audit_events,
                search_audit_events,
                get_audit_statistics,
                get_audit_activity,
                export_audit_events,
                generate_compliance_report
            ],
        )
}