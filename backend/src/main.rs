#[macro_use]
extern crate rocket;

use std::env;
use rocket::fairing::AdHoc;
use rocket::http::{Cookie, CookieJar, Method, SameSite};
use rocket::serde::json::Json;
use rocket::State;
use std::sync::Arc;
use argon2::password_hash::PasswordHashString;
use rocket::config::LogLevel;
use rocket::response::Redirect;
use rocket::tokio::sync::Mutex;
use rocket_cors::{AllowedOrigins, CorsOptions};
use serde::{Deserialize, Serialize};
use cert::create_ca;
use db::VaulTLSDB;
use settings::Settings;
use crate::cert::{get_pem, save_ca, Certificate};
use crate::data::api::{CallbackQuery, ChangePasswordRequest, CreateCertificateRequest, CreateUserRequest, DownloadResponse, IsSetupResponse, LoginRequest, SetupRequest};
use crate::data::enums::UserRole;
use crate::data::error::ApiError;
use crate::helper::{hash_password, hash_password_string};
use crate::notification::{MailMessage, Mailer};
use auth::oidc_auth::OidcAuth;
use crate::auth::password_auth::verify_password;
use crate::auth::session_auth::{generate_token, Authenticated};
use crate::constants::{API_PORT, DB_FILE_PATH, VAULTLS_VERSION};
use crate::settings::FrontendSettings;

mod db;
mod cert;
mod settings;
mod notification;
mod data;
mod helper;
mod auth;
mod constants;

#[derive(Clone)]
struct AppState {
    db: Arc<Mutex<VaulTLSDB>>,
    settings: Arc<Mutex<Settings>>,
    oidc: Arc<Mutex<Option<OidcAuth>>>,
    mailer: Arc<Mutex<Option<Mailer>>>
}

#[derive(Deserialize, Serialize, Debug)]
struct User {
    id: i64,
    name: String,
    email: String,
    #[serde(rename = "has_password", serialize_with = "helper::serialize_password_hash", skip_deserializing)]
    password_hash: Option<PasswordHashString>,
    #[serde(skip)]
    oidc_id: Option<String>,
    role: UserRole
}

#[get("/api")]
fn index() -> &'static str {
    "<h1>mTLS Certificates API</h1>"
}

#[get("/api/certificates")]
async fn get_certificates(
    state: &State<AppState>,
    authentication: Authenticated
) -> Result<Json<Vec<Certificate>>, ApiError> {
    let db = state.db.lock().await;
    let user_id= if authentication.claims.role == UserRole::Admin {
            None
        } else {
            Some(authentication.claims.id)
        };
    let certificates = db.get_all_user_cert(user_id)?;
    Ok(Json(certificates))
}

#[post("/api/certificates", format = "json", data = "<payload>")]
async fn create_user_certificate(
    state: &State<AppState>,
    payload: Json<CreateCertificateRequest>,
    authentication: Authenticated
) -> Result<Json<Certificate>, ApiError> {
    if authentication.claims.role != UserRole::Admin { return Err(ApiError::Forbidden(None)) }

    let db = state.db.lock().await;

    let ca = db.get_current_ca()?;
    let mut user_cert = cert::create_user_cert(&ca, &payload.cert_name, payload.subject_alt_name.clone(), payload.validity_in_years.unwrap_or(1), payload.user_id)?;

    db.insert_user_cert(&mut user_cert)?;

    if Some(true) == payload.notify_user {
        let user = db.get_user(payload.user_id)?;
        let mail = MailMessage{
            to: format!("{} <{}>", user.name, user.email),
            subject: "VaulTLS: A new certificate is available".to_string(),
            username: user.name,
            certificate: user_cert.clone()
        };

        let mailer = state.mailer.clone();
        tokio::spawn(async move {
            if let Some(mailer) = &mut *mailer.lock().await {
                let _ = mailer.send_email(mail).await;
            }
        });
    }

    Ok(Json(user_cert))
}

#[get("/api/certificates/ca/download")]
async fn download_ca(
    state: &State<AppState>
) -> Result<DownloadResponse, ApiError> {
    let db = state.db.lock().await;
    let ca = db.get_current_ca()?;
    let pem = get_pem(&ca)?;
    Ok(DownloadResponse::new(pem, "ca_certificate.pem"))
}
#[get("/api/certificates/<id>/download")]
async fn download_certificate(
    state: &State<AppState>,
    id: i64,
    authentication: Authenticated
) -> Result<DownloadResponse, ApiError> {
    let db = state.db.lock().await;
    let (user_id, pkcs12) = db.get_user_cert_pkcs12(id)?;
    if user_id != authentication.claims.id && authentication.claims.role != UserRole::Admin { return Err(ApiError::Forbidden(None)) }
    Ok(DownloadResponse::new(pkcs12, "user_certificate.p12"))
}

#[delete("/api/certificates/<id>")]
async fn delete_user_cert(
    state: &State<AppState>,
    id: i64,
    authentication: Authenticated
) -> Result<(), ApiError> {
    if authentication.claims.role != UserRole::Admin { return Err(ApiError::Forbidden(None)) }
    let db = state.db.lock().await;
    db.delete_user_cert(id)?;
    Ok(())
}

#[get("/api/settings")]
async fn fetch_settings(
    state: &State<AppState>,
    authentication: Authenticated
) -> Result<Json<FrontendSettings>, ApiError> {
    if authentication.claims.role != UserRole::Admin { return Err(ApiError::Forbidden(None)) }
    let settings = state.settings.lock().await;
    let frontend_settings = FrontendSettings(settings.clone());
    Ok(Json(frontend_settings))
}

#[put("/api/settings", format = "json", data = "<payload>")]
async fn update_settings(
    state: &State<AppState>,
    payload: Json<Settings>,
    authentication: Authenticated
) -> Result<(), ApiError> {
    if authentication.claims.role != UserRole::Admin { return Err(ApiError::Forbidden(None)) }
    let mut settings = state.settings.lock().await;
    let mut oidc = state.oidc.lock().await;

    settings.set_settings(&payload).await?;

    if let Some(oidc) = &mut *oidc {
        oidc.update_config(&settings.get_oidc()).await?;
    }

    let mut mailer = state.mailer.lock().await;
    let mail_settings = settings.get_mail();
    if mail_settings.is_valid() {
        *mailer = Mailer::new(mail_settings, settings.get_vaultls_url()).await.ok()
    } else {
        *mailer = None;
    }

    Ok(())
}

#[get("/api/is_setup")]
async fn is_setup(
    state: &State<AppState>
) -> Result<Json<IsSetupResponse>, ApiError> {
    let settings = state.settings.lock().await;
    let db = state.db.lock().await;
    let is_setup = db.is_setup();
    let has_password = settings.password_enabled();
    let oidc_url = settings.get_oidc().auth_url.clone();
    Ok(Json(IsSetupResponse {
        setup: is_setup,
        password: has_password,
        oidc: oidc_url
    }))
}

#[post("/api/setup", format = "json", data = "<setup_req>")]
async fn setup(
    state: &State<AppState>,
    setup_req: Json<SetupRequest>
) -> Result<(), ApiError> {
    let mut settings = state.settings.lock().await;
    let db = state.db.lock().await;

    if db.is_setup() {
        return Err(ApiError::Unauthorized(None))
    }

    if setup_req.password.is_none() && settings.get_oidc().auth_url.is_empty() {
        return Err(ApiError::Other("Password is required".to_string()))
    }

    if setup_req.password.is_some() {
        settings.set_password_enabled(true);
    }

    let mut user = User{
        id: -1,
        name: setup_req.name.clone(),
        email: setup_req.email.clone(),
        password_hash: hash_password_string(&setup_req.password)?,
        oidc_id: None,
        role: UserRole::Admin,
    };

    db.add_user(&mut user)?;

    let mut ca = create_ca(&setup_req.ca_name, setup_req.ca_validity_in_years)?;
    save_ca(&ca)?;
    db.insert_ca(&mut ca)?;

    Ok(())
}

#[post("/api/auth/login", format = "json", data = "<login_req_opt>")]
async fn login(
    state: &State<AppState>,
    jar: &CookieJar<'_>,
    login_req_opt: Json<LoginRequest>
) -> Result<(), ApiError> {
    let settings = state.settings.lock().await;
    let db = state.db.lock().await;
    let user: User = db.get_user_by_email(&*login_req_opt.email).map_err(|_| ApiError::Unauthorized(Some("Invalid credentials".to_string())))?;
    if let Some(password_hash) = user.password_hash {
        verify_password(&password_hash, &*login_req_opt.password)?;
        let jwt_key = settings.get_jwt_key()?;
        let token = generate_token(&jwt_key, user.id, user.role)?;

        let cookie = Cookie::build(("auth_token", token.clone()))
            .secure(true)
            .http_only(true)
            .same_site(SameSite::Lax);
        jar.add_private(cookie);

        return Ok(());
    }
    Err(ApiError::Unauthorized(Some("Invalid credentials".to_string())))
}

#[post("/api/auth/change_password", data = "<change_pass_req>")]
async fn change_password(
    state: &State<AppState>,
    change_pass_req: Json<ChangePasswordRequest>,
    authentication: Authenticated
) -> Result<(), ApiError> {
    let db = state.db.lock().await;
    let user_id = authentication.claims.id;

    let password_hash = db.get_user(user_id)?.password_hash;

    if let Some(password_hash) = password_hash {
        match &change_pass_req.old_password {
            Some(old_password) => verify_password(&password_hash, old_password)?,
            None => return Err(ApiError::BadRequest("Old password is required".to_string()))
        }
    }

    let password_hash = hash_password(&change_pass_req.new_password)?;
    db.set_user_password(user_id, &password_hash)
}

#[get("/api/auth/oidc/login")]
async fn oidc_login(
    state: &State<AppState>,
) -> Result<Redirect, ApiError> {
    let mut oidc_option = state.oidc.lock().await;

    match &mut *oidc_option {
        Some(oidc) => {
            let url = oidc.generate_oidc_url().await?;
            Ok(Redirect::to(url.to_string()))

        }
        None => { Err(ApiError::BadRequest("OIDC not configured".to_string())) },
    }
}

#[get("/api/auth/oidc/callback?<response..>")]
async fn oidc_callback(
    state: &State<AppState>,
    jar: &CookieJar<'_>,
    response: CallbackQuery
) -> Result<Redirect, ApiError> {
    let mut oidc_option = state.oidc.lock().await;
    let settings = state.settings.lock().await;
    let db = state.db.lock().await;

    match &mut *oidc_option {
        Some(oidc) => {
            let mut user = oidc.verify_auth_code(response.code.to_string(), response.state.to_string()).await?;

            db.register_oidc_user(&mut user)?;

            let jwt_key = settings.get_jwt_key()?;
            let token = generate_token(&jwt_key, user.id, user.role)?;

            let auth_cookie = Cookie::build(("auth_token", token))
                .secure(true)
                .http_only(true)
                .same_site(SameSite::Lax);
            jar.add_private(auth_cookie);

            Ok(Redirect::to("/overview?oidc=success"))
        }
        None => { Err(ApiError::BadRequest("OIDC not configured".to_string())) },
    }
}

#[get("/api/auth/me")]
async fn get_current_user(
    state: &State<AppState>,
    authentication: Authenticated
) -> Result<Json<User>, ApiError> {
    let db = state.db.lock().await;
    let user = db.get_user(authentication.claims.id)?;
    Ok(Json(user))
}

#[get("/api/users")]
async fn get_users(
    state: &State<AppState>,
    authentication: Authenticated
) -> Result<Json<Vec<User>>, ApiError> {
    if authentication.claims.role != UserRole::Admin { return Err(ApiError::Forbidden(None)) }
    let db = state.db.lock().await;
    let users = db.get_all_user()?;
    Ok(Json(users))
}

#[post("/api/users", format = "json", data = "<payload>")]
async fn create_user(
    state: &State<AppState>,
    payload: Json<CreateUserRequest>,
    authentication: Authenticated
) -> Result<Json<i64>, ApiError> {
    if authentication.claims.role != UserRole::Admin { return Err(ApiError::Forbidden(None)) }

    let db = state.db.lock().await;

    let mut user = User{
        id: -1,
        name: payload.user_name.to_string(),
        email: payload.user_email.to_string(),
        password_hash: hash_password_string(&payload.password)?,
        oidc_id: None,
        role: payload.role
    };

    db.add_user(&mut user)?;

    Ok(Json(user.id))
}

#[put("/api/users", format = "json", data = "<payload>")]
async fn update_user(
    state: &State<AppState>,
    payload: Json<User>,
    authentication: Authenticated
) -> Result<(), ApiError> {
    if payload.id != authentication.claims.id && authentication.claims.role != UserRole::Admin { return Err(ApiError::Forbidden(None)) }
    let db = state.db.lock().await;
    Ok(db.update_user(&payload)?)
}

#[delete("/api/users/<id>")]
async fn delete_user(
    state: &State<AppState>,
    id: i64,
    authentication: Authenticated
) -> Result<(), ApiError> {
    if authentication.claims.role != UserRole::Admin { return Err(ApiError::Forbidden(None)) }
    let db = state.db.lock().await;
    db.delete_user(id)?;
    Ok(())
}


#[launch]
async fn rocket() -> _ {
    println!("Starting mTLS Certificates API");
    println!("Version {}", VAULTLS_VERSION);

    println!("Trying to use database at {}", DB_FILE_PATH);
    let db_path = std::path::Path::new(DB_FILE_PATH);
    let db_initialized = db_path.exists();
    let db = VaulTLSDB::new(db_path).expect("Failed opening SQLite database.");
    if !db_initialized {
        println!("No database found. Initializing.");
        db.initialize_db().expect("Failed initializing database");
    }

    println!("Loading settings from file");
    let settings = Settings::load_from_file(None).await.expect("Failed loading settings");

    let oidc_settings = settings.get_oidc();
    let oidc = match oidc_settings.auth_url.is_empty() {
        true => None,
        false => {
            println!("OIDC enabled. Trying to connect to {}.", oidc_settings.auth_url);
            OidcAuth::new(&settings.get_oidc()).await.ok()
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
    let rocket_secret = env::var("VAULTLS_API_SECRET").expect("VAULTS_API_SECRET is not set");
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
            "/",
            routes![
                index,
                get_certificates,
                create_user_certificate,
                download_ca,
                download_certificate,
                delete_user_cert,
                fetch_settings,
                update_settings,
                is_setup,
                setup,
                login,
                change_password,
                oidc_login,
                oidc_callback,
                get_current_user,
                get_users,
                create_user,
                delete_user,
                update_user
            ],
        )
        .attach(cors.to_cors().unwrap())
        .attach(AdHoc::config::<Settings>())
}