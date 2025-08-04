use rocket_okapi::openapi;
use rocket::{delete, get, post, put, State};
use rocket::response::Redirect;
use rocket::serde::json::Json;
use rocket::http::{Cookie, CookieJar, SameSite};
use tracing::{trace, debug, info, warn};
use crate::auth::oidc_auth::OidcAuth;
use crate::auth::password_auth::Password;
use crate::auth::session_auth::{generate_token, Authenticated, AuthenticatedPrivileged};
use crate::cert::{get_password, get_pem, save_ca, Certificate, CertificateBuilder};
use crate::constants::VAULTLS_VERSION;
use crate::data::api::{CallbackQuery, ChangePasswordRequest, CreateUserCertificateRequest, CreateUserRequest, DownloadResponse, IsSetupResponse, LoginRequest, SetupRequest};
use crate::data::enums::{CertificateType, PasswordRule, UserRole};
use crate::data::error::ApiError;
use crate::data::objects::{AppState, User};
use crate::notification::mail::{MailMessage, Mailer};
use crate::settings::{FrontendSettings, Settings};

#[openapi(tag = "Setup")]
#[get("/server/version")]
/// Get the current version of the server.
pub(crate) fn version() -> &'static str {
    VAULTLS_VERSION
}

#[openapi(tag = "Setup")]
#[get("/server/setup")]
/// Get server setup parameters.
pub(crate) async fn is_setup(
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

#[openapi(tag = "Setup")]
#[post("/server/setup", format = "json", data = "<setup_req>")]
/// Set up the application. Only possible if DB is not setup.
pub(crate) async fn setup(
    state: &State<AppState>,
    setup_req: Json<SetupRequest>
) -> Result<(), ApiError> {
    let mut settings = state.settings.lock().await;
    let db = state.db.lock().await;

    if db.is_setup() {
        warn!("Server is already setup.");
        return Err(ApiError::Unauthorized(None))
    }

    if setup_req.password.is_none() && settings.get_oidc().auth_url.is_empty() {
        return Err(ApiError::Other("Password is required".to_string()))
    }

    let mut password_hash = None;
    if let Some(ref password) = setup_req.password {
        settings.set_password_enabled(true).await?;
        password_hash = Some(Password::new_server_hash(password)?);
    }

    let mut user = User{
        id: -1,
        name: setup_req.name.clone(),
        email: setup_req.email.clone(),
        password_hash,
        oidc_id: None,
        role: UserRole::Admin,
    };

    db.add_user(&mut user)?;

    let mut ca = CertificateBuilder::new()?
        .set_name(&setup_req.ca_name)?
        .set_valid_until(setup_req.ca_validity_in_years)?
        .build_ca()?;
    save_ca(&ca)?;
    db.insert_ca(&mut ca)?;

    info!("VaulTLS was successfully set up.");

    Ok(())
}

#[openapi(tag = "Authentication")]
#[post("/auth/login", format = "json", data = "<login_req_opt>")]
/// Endpoint to login. Required for most endpoints.
pub(crate) async fn login(
    state: &State<AppState>,
    jar: &CookieJar<'_>,
    login_req_opt: Json<LoginRequest>
) -> Result<(), ApiError> {
    let settings = state.settings.lock().await;
    let db = state.db.lock().await;

    let user: User = db.get_user_by_email(&login_req_opt.email).map_err(|_| {
        warn!(user=login_req_opt.email, "Invalid email");
        ApiError::Unauthorized(Some("Invalid credentials".to_string()))
    })?;
    if let Some(password_hash) = user.password_hash {
        if password_hash.verify(&login_req_opt.password) {
            let jwt_key = settings.get_jwt_key()?;
            let token = generate_token(&jwt_key, user.id, user.role)?;

            let cookie = Cookie::build(("auth_token", token.clone()))
                .http_only(true)
                .same_site(SameSite::Lax);
            jar.add_private(cookie);

            info!(user=user.name, "Successful password-based user login.");

            if let Password::V1(_) = password_hash {
                info!(user=user.name, "Migrating a user' password to V2.");
                let migration_password = Password::new_double_hash(&login_req_opt.password)?;
                db.set_user_password(user.id, &migration_password)?;
            }

            return Ok(());
        } else if let Password::V1(hash_string) = password_hash {
            // User tried to supply a hashed password, but has not been migrated yet
            // Require user to supply plaintext password to log in
            return Err(ApiError::Conflict(hash_string.to_string()))
        }
    }
    warn!(user=user.name, "Invalid password");
    Err(ApiError::Unauthorized(Some("Invalid credentials".to_string())))
}

#[openapi(tag = "Authentication")]
#[post("/auth/change_password", data = "<change_pass_req>")]
/// Endpoint to change password.
pub(crate) async fn change_password(
    state: &State<AppState>,
    change_pass_req: Json<ChangePasswordRequest>,
    authentication: Authenticated
) -> Result<(), ApiError> {
    let db = state.db.lock().await;

    let user_id = authentication.claims.id;
    let user = db.get_user(user_id)?;
    let password_hash = user.password_hash;

    if let Some(password_hash) = password_hash {
        if let Some(ref old_password) = change_pass_req.old_password {
            if !password_hash.verify(old_password) {
                warn!(user=user.name, "Password Change: Old password is incorrect");
                return Err(ApiError::BadRequest("Old password is incorrect".to_string()))
            }
        } else {
            warn!(user=user.name, "Password Change: Old password is required");
            return Err(ApiError::BadRequest("Old password is required".to_string()))
        }
    }

    let password_hash = Password::new_server_hash(&change_pass_req.new_password)?;
    db.set_user_password(user_id, &password_hash)?;

    info!(user=user.name, "Password Change: Success");

    Ok(())
}

#[openapi(tag = "Authentication")]
#[post("/auth/logout")]
/// Endpoint to logout.
pub(crate) async fn logout(
    jar: &CookieJar<'_>
) -> Result<(), ApiError> {
    jar.remove_private(Cookie::build(("name", "auth_token")));
    Ok(())
}

#[openapi(tag = "Authentication")]
#[get("/auth/oidc/login")]
/// Endpoint to initiate OIDC login.
pub(crate) async fn oidc_login(
    state: &State<AppState>,
) -> Result<Redirect, ApiError> {
    let mut oidc_option = state.oidc.lock().await;

    match &mut *oidc_option {
        Some(oidc) => {
            let url = oidc.generate_oidc_url().await?;
            debug!(url=?url, "Redirecting to OIDC login URL");
            Ok(Redirect::to(url.to_string()))

        }
        None => {
            warn!("A user tried to login with OIDC, but OIDC is not configured.");
            Err(ApiError::BadRequest("OIDC not configured".to_string()))
        },
    }
}

#[openapi(tag = "Authentication")]
#[get("/auth/oidc/callback?<response..>")]
/// Endpoint to handle OIDC callback.
pub(crate) async fn oidc_callback(
    state: &State<AppState>,
    jar: &CookieJar<'_>,
    response: CallbackQuery
) -> Result<Redirect, ApiError> {
    let mut oidc_option = state.oidc.lock().await;
    let settings = state.settings.lock().await;
    let db = state.db.lock().await;

    match &mut *oidc_option {
        Some(oidc) => {
            trace!("Verifying OIDC authentication code.");
            let mut user = oidc.verify_auth_code(response.code.to_string(), response.state.to_string()).await?;

            db.register_oidc_user(&mut user)?;

            let jwt_key = settings.get_jwt_key()?;
            let token = generate_token(&jwt_key, user.id, user.role)?;

            let auth_cookie = Cookie::build(("auth_token", token))
                .http_only(true)
                .same_site(SameSite::Lax);
            jar.add_private(auth_cookie);

            info!(user=user.name, "Successful oidc-based user login");

            Ok(Redirect::to("/overview?oidc=success"))
        }
        None => { Err(ApiError::BadRequest("OIDC not configured".to_string())) },
    }
}

#[openapi(tag = "Authentication")]
#[get("/auth/me")]
/// Endpoint to get the current user. Used to know role of user.
pub(crate) async fn get_current_user(
    state: &State<AppState>,
    authentication: Authenticated
) -> Result<Json<User>, ApiError> {
    let db = state.db.lock().await;
    let user = db.get_user(authentication.claims.id)?;
    Ok(Json(user))
}

#[openapi(tag = "Certificates")]
#[get("/certificates")]
/// Get all certificates. If admin all certificates are returned, otherwise only certificates owned by the user. Requires authentication.
pub(crate) async fn get_certificates(
    state: &State<AppState>,
    authentication: Authenticated
) -> Result<Json<Vec<Certificate>>, ApiError> {
    let db = state.db.lock().await;
    let user_id = match authentication.claims.role {
        UserRole::User => Some(authentication.claims.id),
        UserRole::Admin => None
    };
    let certificates = db.get_all_user_cert(user_id)?;
    Ok(Json(certificates))
}

#[openapi(tag = "Certificates")]
#[post("/certificates", format = "json", data = "<payload>")]
/// Create a new certificate. Requires admin role.
pub(crate) async fn create_user_certificate(
    state: &State<AppState>,
    payload: Json<CreateUserCertificateRequest>,
    _authentication: AuthenticatedPrivileged
) -> Result<Json<Certificate>, ApiError> {
    let settings = state.settings.lock().await;
    let db = state.db.lock().await;

    debug!(cert_name=?payload.cert_name, "Creating certificate");

    let use_random_password = if settings.password_rule() == PasswordRule::System
        || (settings.password_rule() == PasswordRule::Required
            && payload.pkcs12_password.as_deref().unwrap_or("").trim().is_empty()) {
        debug!(cert_name=?payload.cert_name, "Using system-supplied password");
        true
    } else {
        debug!(cert_name=?payload.cert_name, "Using user-supplied password");
        payload.system_generated_password
    };

    let ca = db.get_current_ca()?;
    let pkcs12_password = get_password(use_random_password, &payload.pkcs12_password);
    let cert_builder = CertificateBuilder::new()?
        .set_name(&payload.cert_name)?
        .set_valid_until(payload.validity_in_years.unwrap_or(1))?
        .set_renew_method(payload.renew_method.unwrap_or_default())?
        .set_pkcs12_password(&pkcs12_password)?
        .set_ca(&ca)?
        .set_user_id(payload.user_id)?;
    let mut cert = match payload.cert_type.unwrap_or_default() {
        CertificateType::Client => {
            let user = db.get_user(payload.user_id)?;
            cert_builder
                .set_email_san(&user.email)?
                .build_client()?
        }
        CertificateType::Server => {
            let dns = payload.dns_names.clone().unwrap_or_default();
            cert_builder
                .set_dns_san(&dns)?
                .build_server()?
        }
    };

    db.insert_user_cert(&mut cert)?;

    info!(cert=cert.name, "New certificate created.");
    trace!("{:?}", cert);

    if Some(true) == payload.notify_user {
        let user = db.get_user(payload.user_id)?;
        let mail = MailMessage{
            to: format!("{} <{}>", user.name, user.email),
            subject: "VaulTLS: A new certificate is available".to_string(),
            username: user.name,
            certificate: cert.clone()
        };

        debug!(mail=?mail, "Sending mail notification");

        let mailer = state.mailer.clone();
        tokio::spawn(async move {
            if let Some(mailer) = &mut *mailer.lock().await {
                let _ = mailer.notify_new_certificate(mail).await;
            }
        });
    }

    Ok(Json(cert))
}

#[openapi(tag = "Certificates")]
#[get("/certificates/ca/download")]
/// Download the current CA certificate.
pub(crate) async fn download_ca(
    state: &State<AppState>
) -> Result<DownloadResponse, ApiError> {
    let db = state.db.lock().await;
    let ca = db.get_current_ca()?;
    let pem = get_pem(&ca)?;
    Ok(DownloadResponse::new(pem, "ca_certificate.pem"))
}

#[openapi(tag = "Certificates")]
#[get("/certificates/<id>/download")]
/// Download a user-owned certificate. Requires authentication.
pub(crate) async fn download_certificate(
    state: &State<AppState>,
    id: i64,
    authentication: Authenticated
) -> Result<DownloadResponse, ApiError> {
    let db = state.db.lock().await;
    let (user_id, name, pkcs12) = db.get_user_cert_pkcs12(id)?;
    if user_id != authentication.claims.id && authentication.claims.role != UserRole::Admin { return Err(ApiError::Forbidden(None)) }
    Ok(DownloadResponse::new(pkcs12, &format!("{name}.p12")))
}

#[openapi(tag = "Certificates")]
#[get("/certificates/<id>/password")]
/// Fetch the password for a user-owned certificate. Requires authentication.
pub(crate) async fn fetch_certificate_password(
    state: &State<AppState>,
    id: i64,
    authentication: Authenticated
) -> Result<Json<String>, ApiError> {
    let db = state.db.lock().await;
    let (user_id, pkcs12_password) = db.get_user_cert_pkcs12_password(id)?;
    if user_id != authentication.claims.id && authentication.claims.role != UserRole::Admin { return Err(ApiError::Forbidden(None)) }
    Ok(Json(pkcs12_password))
}

#[openapi(tag = "Certificates")]
#[delete("/certificates/<id>")]
/// Delete a user-owned certificate. Requires admin role.
pub(crate) async fn delete_user_cert(
    state: &State<AppState>,
    id: i64,
    _authentication: AuthenticatedPrivileged
) -> Result<(), ApiError> {
    let db = state.db.lock().await;
    db.delete_user_cert(id)?;
    Ok(())
}

#[openapi(tag = "Settings")]
#[get("/settings")]
/// Fetch application settings. Requires admin role.
pub(crate) async fn fetch_settings(
    state: &State<AppState>,
    _authentication: AuthenticatedPrivileged
) -> Result<Json<FrontendSettings>, ApiError> {
    let settings = state.settings.lock().await;
    let frontend_settings = FrontendSettings(settings.clone());
    Ok(Json(frontend_settings))
}

#[openapi(tag = "Settings")]
#[put("/settings", format = "json", data = "<payload>")]
/// Update application settings. Requires admin role.
pub(crate) async fn update_settings(
    state: &State<AppState>,
    payload: Json<Settings>,
    _authentication: AuthenticatedPrivileged
) -> Result<(), ApiError> {
    let mut settings = state.settings.lock().await;
    let mut oidc = state.oidc.lock().await;

    settings.set_settings(&payload).await?;

    let oidc_settings = settings.get_oidc();
    if oidc_settings.is_valid() {
        *oidc = OidcAuth::new(oidc_settings).await.ok()
    } else {
        *oidc = None;
    }

    match oidc.is_some() {
        true => info!("OIDC is active."),
        false => info!("OIDC is inactive.")
    }

    let mut mailer = state.mailer.lock().await;
    let mail_settings = settings.get_mail();
    if mail_settings.is_valid() {
        *mailer = Mailer::new(mail_settings, settings.get_vaultls_url()).await.ok()
    } else {
        *mailer = None;
    }

    match mailer.is_some() {
        true => info!("Mail notifications are active."),
        false => info!("Mail notifications are inactive.")
    }

    info!("Settings updated.");

    Ok(())
}

#[openapi(tag = "Users")]
#[get("/users")]
/// Returns a list of all users. Requires admin role.
pub(crate) async fn get_users(
    state: &State<AppState>,
    _authentication: AuthenticatedPrivileged
) -> Result<Json<Vec<User>>, ApiError> {
    let db = state.db.lock().await;
    let users = db.get_all_user()?;
    Ok(Json(users))
}

#[openapi(tag = "Users")]
#[post("/users", format = "json", data = "<payload>")]
/// Create a new user. Requires admin role.
pub(crate) async fn create_user(
    state: &State<AppState>,
    payload: Json<CreateUserRequest>,
    _authentication: AuthenticatedPrivileged
) -> Result<Json<i64>, ApiError> {
    let db = state.db.lock().await;

    let password_hash = match payload.password {
        Some(ref p) => Some(Password::new_server_hash(p)?),
        None => None,
    };

    let mut user = User{
        id: -1,
        name: payload.user_name.to_string(),
        email: payload.user_email.to_string(),
        password_hash,
        oidc_id: None,
        role: payload.role
    };

    db.add_user(&mut user)?;

    info!(user=?user, "User created.");
    trace!("{:?}", user);

    Ok(Json(user.id))
}

#[openapi(tag = "Users")]
#[put("/users/<id>", format = "json", data = "<payload>")]
/// Update a user. Requires admin role.
pub(crate) async fn update_user(
    state: &State<AppState>,
    id: i64,
    payload: Json<User>,
    authentication: Authenticated
) -> Result<(), ApiError> {
    if authentication.claims.id != id && authentication.claims.role != UserRole::Admin {
        return Err(ApiError::Forbidden(None))
    }
    if authentication.claims.role == UserRole::User
        && payload.role == UserRole::Admin {
        return Err(ApiError::Forbidden(None))
    }

    let user = User {
        id,
        ..payload.into_inner()
    };
    let db = state.db.lock().await;
    db.update_user(&user)?;

    info!(user=?user, "User updated.");
    trace!("{:?}", user);

    Ok(())
}

#[openapi(tag = "Users")]
#[delete("/users/<id>")]
/// Delete a user. Requires admin role.
pub(crate) async fn delete_user(
    state: &State<AppState>,
    id: i64,
    _authentication: AuthenticatedPrivileged
) -> Result<(), ApiError> {
    let db = state.db.lock().await;
    db.delete_user(id)?;

    info!(user=?id, "User deleted.");

    Ok(())
}