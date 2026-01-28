use rocket_okapi::openapi;
use rocket::{delete, get, post, put, State};
use rocket::response::Redirect;
use rocket::serde::json::Json;
use rocket::http::{Cookie, CookieJar, SameSite};
use tracing::{debug, info, trace, warn};
use crate::auth::oidc_auth::OidcAuth;
use crate::auth::password_auth::Password;
use crate::auth::session_auth::{generate_token, invalidate_token, Authenticated, AuthenticatedPrivileged};
use crate::certs::common::{get_password, save_ca, Certificate, CA};
use crate::certs::ssh_cert::{get_ssh_pem, SSHCertificateBuilder};
use crate::certs::tls_cert::{get_timestamp, get_tls_pem, TLSCertificateBuilder};
use crate::constants::VAULTLS_VERSION;
use crate::data::api::{CallbackQuery, ChangePasswordRequest, CreateCARequest, CreateUserCertificateRequest, CreateUserRequest, DownloadResponse, IsSetupResponse, LoginRequest, SetupRequest};
use crate::data::enums::{CAType, CertificateType, PasswordRule, TimespanUnit, UserRole};
use crate::data::error::ApiError;
use crate::data::objects::{AppState, Name, User};
use crate::notification::mail::{MailMessage, Mailer};
    use crate::settings::{FrontendSettings, InnerSettings};

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
    let is_setup = state.db.is_setup().await.is_ok();
    let has_password = state.settings.get_password_enabled();
    let oidc_url = state.settings.get_oidc().auth_url.clone();
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
    if state.db.is_setup().await.is_ok() {
        warn!("Server is already setup.");
        return Err(ApiError::Unauthorized(None))
    }

    if setup_req.password.is_none() && state.settings.get_oidc().auth_url.is_empty() {
        return Err(ApiError::Other("Password is required".to_string()))
    }

    let trim_password = setup_req.password.as_deref().unwrap_or("").trim();

    let password = match trim_password {
        "" => None,
        _ => Some(trim_password)
    };

    let mut password_hash = None;
    if let Some(password) = password {
        state.settings.set_password_enabled(true)?;
        password_hash = Some(Password::new_server_hash(password)?);
    }

    let user = User{
        id: -1,
        name: setup_req.name.clone(),
        email: setup_req.email.clone(),
        password_hash,
        oidc_id: None,
        role: UserRole::Admin,
    };

    state.db.insert_user(user).await?;

    let cert_validity = setup_req.validity_duration.unwrap_or(5);
    let cert_validity_unit = setup_req.validity_unit.unwrap_or(TimespanUnit::Year);
    let name = Name {
        cn: setup_req.ca_name.clone(),
        ou: None
    };
    let mut ca = TLSCertificateBuilder::new()?
        .set_name(name)?
        .set_valid_until(cert_validity, cert_validity_unit)?
        .build_ca()?;
    ca = state.db.insert_ca(ca).await?;
    save_ca(&ca)?;

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
    if !state.settings.get_password_enabled() {
        warn!("Password login is disabled.");
        return Err(ApiError::Unauthorized(Some("Password login is disabled".to_string())))
    }
    let user: User = state.db.get_user_by_email(login_req_opt.email.clone()).await.map_err(|_| {
        warn!(user=login_req_opt.email, "Invalid email");
        ApiError::Unauthorized(Some("Invalid credentials".to_string()))
    })?;
    if let Some(password_hash) = user.password_hash {
        if password_hash.verify(&login_req_opt.password) {
            let jwt_key = state.settings.get_jwt_key()?;
            let token = generate_token(&jwt_key, user.id, user.role)?;

            let cookie = Cookie::build(("auth_token", token.clone()))
                .http_only(true)
                .same_site(SameSite::Lax);
            jar.add_private(cookie);

            info!(user=user.name, "Successful password-based user login.");

            if let Password::V1(_) = password_hash {
                info!(user=user.name, "Migrating a user' password to V2.");
                let migration_password = Password::new_double_hash(&login_req_opt.password)?;
                state.db.set_user_password(user.id, migration_password).await?;
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
    let user_id = authentication.claims.id;
    let user = state.db.get_user(user_id).await?;
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
    state.db.set_user_password(user_id, password_hash).await?;
    // todo unset

    info!(user=user.name, "Password Change: Success");

    Ok(())
}

#[openapi(tag = "Authentication")]
#[post("/auth/logout")]
/// Endpoint to logout.
pub(crate) async fn logout(
    jar: &CookieJar<'_>,
    authentication: Option<Authenticated>
) -> Result<(), ApiError> {
    if let Some(authentication) = authentication {
        invalidate_token(&authentication.claims.jti);
    }
    jar.remove_private("auth_token");
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

    match &mut *oidc_option {
        Some(oidc) => {
            trace!("Verifying OIDC authentication code.");
            let mut user = oidc.verify_auth_code(response.code.to_string(), response.state.to_string()).await?;

            user = state.db.register_oidc_user(user).await?;

            let jwt_key = state.settings.get_jwt_key()?;
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
    let user = state.db.get_user(authentication.claims.id).await?;
    Ok(Json(user))
}

#[openapi(tag = "Certificates")]
#[get("/certificates")]
/// Get all certificates. If admin all certificates are returned, otherwise only certificates owned by the user. Requires authentication.
pub(crate) async fn get_certificates(
    state: &State<AppState>,
    authentication: Authenticated
) -> Result<Json<Vec<Certificate>>, ApiError> {
    let user_id = match authentication.claims.role {
        UserRole::User => Some(authentication.claims.id),
        UserRole::Admin => None
    };
    let certificates = state.db.get_all_user_cert(user_id).await?;
    Ok(Json(certificates))
}

#[openapi(tag = "Certificates")]
#[get("/certificates/ca")]
/// Get all CAs.
pub(crate) async fn get_all_ca(
    state: &State<AppState>,
    _authentication: Authenticated
) -> Result<Json<Vec<CA>>, ApiError> {
    let certificates = state.db.get_all_ca().await?;
    Ok(Json(certificates))
}

#[openapi(tag = "Certificates")]
#[post("/certificates/ca", format = "json", data = "<payload>")]
/// Create a new certificate. Requires admin role.
pub(crate) async fn create_ca(
    state: &State<AppState>,
    payload: Json<CreateCARequest>,
    _authentication: AuthenticatedPrivileged
) -> Result<Json<i64>, ApiError> {
    let mut ca = match payload.ca_type {
        CAType::TLS => {
            let cert_validity = payload.validity_duration.unwrap_or(5);
            let cert_validity_unit = payload.validity_unit.unwrap_or(TimespanUnit::Year);
            TLSCertificateBuilder::new()?
                .set_name(payload.ca_name.clone())?
                .set_valid_until(cert_validity, cert_validity_unit)?
                .build_ca()?
        },
        CAType::SSH => {
            SSHCertificateBuilder::new()?
                .set_name(&payload.ca_name.cn)?
                .build_ca()?
        }
    };

    ca = state.db.insert_ca(ca).await?;
    save_ca(&ca)?;
    Ok(Json(ca.id))
}
#[openapi(tag = "Certificates")]
#[post("/certificates", format = "json", data = "<payload>")]
/// Create a new certificate. Requires admin role.
pub(crate) async fn create_user_certificate(
    state: &State<AppState>,
    payload: Json<CreateUserCertificateRequest>,
    _authentication: AuthenticatedPrivileged
) -> Result<Json<Certificate>, ApiError> {
    debug!(cert_name=?payload.cert_name, "Creating certificate");
    trace!("{:?}", payload);

    let use_random_password = should_use_random_password(&state, &payload);
    let cert_password = get_password(use_random_password, &payload.cert_password);
    
    let mut ca = get_appropriate_ca(state, &payload).await?;
    ca = ensure_ca_validity(&mut ca, state, &payload).await?;

    let cert_validity = payload.validity_duration.unwrap_or(1);
    let cert_validity_unit = payload.validity_unit.unwrap_or(TimespanUnit::Year);
    let mut cert = build_certificate(&payload, &ca, &cert_password, cert_validity, cert_validity_unit, state).await?;
    
    cert = state.db.insert_user_cert(cert).await?;
    
    info!(cert=cert.name.cn, "New certificate created.");
    trace!("{:?}", cert);
    
    if payload.notify_user == Some(true) {
        send_notification_email(state, payload.user_id, &cert).await;
    }
    
    Ok(Json(cert))
}

fn should_use_random_password(
    state: &State<AppState>,
    payload: &CreateUserCertificateRequest
) -> bool {
    let password_rule = state.settings.get_password_rule();
    let user_password_empty = payload.cert_password.as_deref().unwrap_or("").trim().is_empty();
    
    match password_rule {
        PasswordRule::System => {
            debug!(cert_name=?payload.cert_name, "Using system-supplied password");
            true
        }
        PasswordRule::Required if user_password_empty => {
            debug!(cert_name=?payload.cert_name, "Using system-supplied password");
            true
        }
        _ => {
            debug!(cert_name=?payload.cert_name, "Using user-supplied password");
            payload.system_generated_password
        }
    }
}

async fn get_appropriate_ca(state: &State<AppState>, payload: &CreateUserCertificateRequest) -> Result<CA, ApiError> {
    let ca_result = match payload.ca_id {
        Some(ca_id) => state.db.get_ca_by_id(ca_id).await,
        None => match payload.cert_type {
            Some(CertificateType::SSHClient) | Some(CertificateType::SSHServer) => {
                state.db.get_latest_ssh_ca().await
            }
            _ => state.db.get_latest_tls_ca().await
        }
    };
    
    ca_result.map_err(|_| ApiError::BadRequest(format!("The CA id {:?} does not exist", payload.ca_id)))
}

async fn ensure_ca_validity(ca: &mut CA, state: &State<AppState>, payload: &CreateUserCertificateRequest) -> Result<CA, ApiError> {
    let cert_validity = payload.validity_duration.unwrap_or(1);
    let cert_validity_unit = payload.validity_unit.unwrap_or(TimespanUnit::Year);
    let cert_validity_timestamp = get_timestamp(cert_validity, cert_validity_unit)?;
    
    if ca.valid_until == -1 || cert_validity_timestamp.0 <= ca.valid_until {
        return Ok(ca.clone());
    }
    
    if payload.ca_id.is_some() {
        return Err(ApiError::BadRequest("The CA to be used would expire before the certificate".to_string()));
    }
    
    // Auto-renew CA if no specific CA was requested
    if ca.ca_type == CAType::TLS {
        let new_ca = TLSCertificateBuilder::try_from_ca(ca)?;
        let renewed_ca = state.db.insert_ca(new_ca).await?;
        save_ca(&renewed_ca)?;
        Ok(renewed_ca)
    } else {
        Err(ApiError::Other("This error should never happen".to_string()))
    }
}

async fn build_certificate(
    payload: &CreateUserCertificateRequest,
    ca: &CA,
    cert_password: &str,
    validity_duration: u64,
    validity_unit: TimespanUnit,
    state: &State<AppState>
) -> Result<Certificate, ApiError> {
    let cert_type = payload.cert_type.ok_or_else(|| {
        ApiError::BadRequest("Certificate type is required".to_string())
    })?;

    match cert_type {
        CertificateType::SSHClient => build_ssh_cert(payload, ca, cert_password, validity_duration, validity_unit, true),
        CertificateType::SSHServer => build_ssh_cert(payload, ca, cert_password, validity_duration, validity_unit, false),
        CertificateType::TLSClient => build_tls_cert(payload, ca, cert_password, validity_duration, validity_unit, state, true).await,
        CertificateType::TLSServer => build_tls_cert(payload, ca, cert_password, validity_duration, validity_unit, state, false).await,
    }
}

fn build_ssh_cert(
    payload: &CreateUserCertificateRequest,
    ca: &CA,
    cert_password: &str,
    validity_duration: u64,
    validity_unit: TimespanUnit,
    is_client: bool,
) -> Result<Certificate, ApiError> {
    let mut cert_builder = SSHCertificateBuilder::new()?
        .set_name(&payload.cert_name.cn)?
        .set_valid_until(validity_duration, validity_unit)?
        .set_renew_method(payload.renew_method.unwrap_or_default())?
        .set_ca(ca)?
        .set_user_id(payload.user_id)?;

    if !cert_password.is_empty() {
        cert_builder = cert_builder.set_password(cert_password)?
    }

    if let Some(ref principals) = payload.usage_limit {
        cert_builder = cert_builder.set_principals(principals)?;
    }

    if is_client {
        cert_builder.build_user().map_err(ApiError::from)
    } else {
        cert_builder.build_host().map_err(ApiError::from)
    }
}

async fn build_tls_cert(
    payload: &CreateUserCertificateRequest,
    ca: &CA,
    pkcs12_password: &str,
    validity_duration: u64,
    validity_unit: TimespanUnit,
    state: &State<AppState>,
    is_client: bool,
) -> Result<Certificate, ApiError> {
    let mut cert_builder = TLSCertificateBuilder::new()?
        .set_name(payload.cert_name.clone())?
        .set_valid_until(validity_duration, validity_unit)?
        .set_renew_method(payload.renew_method.unwrap_or_default())?
        .set_password(pkcs12_password)?
        .set_ca(ca)?
        .set_user_id(payload.user_id)?;

    if is_client {
        let user = state.db.get_user(payload.user_id).await?;
        cert_builder = cert_builder.set_email_san(&user.email)?;
        cert_builder.build_client().map_err(ApiError::from)
    } else {
        let dns_names = payload.usage_limit.clone().unwrap_or_default();
        cert_builder = cert_builder.set_dns_san(&dns_names)?;
        cert_builder.build_server().map_err(ApiError::from)
    }
}

async fn send_notification_email(state: &State<AppState>, user_id: i64, cert: &Certificate) {
    let user_result = state.db.get_user(user_id).await;
    let Ok(user) = user_result else {
        warn!("Failed to get user for notification email");
        return;
    };
    
    let mail = MailMessage {
        to: format!("{} <{}>", user.name, user.email),
        username: user.name,
        certificate: cert.clone(),
    };
    
    debug!(mail=?mail, "Sending mail notification");
    
    let mailer = state.mailer.clone();
    tokio::spawn(async move {
        if let Some(mailer) = &mut *mailer.lock().await {
            let _ = mailer.notify_new_certificate(mail).await;
        }
    });
}

#[openapi(tag = "Certificates")]
#[get("/certificates/ca/download")]
/// Download the current CA certificate.
pub(crate) async fn download_current_tls_ca(
    state: &State<AppState>
) -> Result<DownloadResponse, ApiError> {
    let ca = state.db.get_latest_tls_ca().await?;
    let pem = get_tls_pem(&ca)?;
    Ok(DownloadResponse::new(pem, "ca_certificate.pem"))
}

#[openapi(tag = "Certificates")]
#[get("/certificates/ca/ssh/download")]
/// Download the current CA certificate.
pub(crate) async fn download_current_ssh_ca(
    state: &State<AppState>
) -> Result<DownloadResponse, ApiError> {
    let ca = state.db.get_latest_ssh_ca().await?;
    let pem = get_ssh_pem(&ca)?;
    Ok(DownloadResponse::new(pem, "ca.pub"))
}

#[openapi(tag = "Certificates")]
#[get("/certificates/ca/<id>/download")]
/// Download a CA certificate identified by id.
pub(crate) async fn download_ca(
    state: &State<AppState>,
    id: i64
) -> Result<DownloadResponse, ApiError> {
    let ca = state.db.get_ca_by_id(id).await?;

    let pem = match ca.ca_type {
        CAType::TLS => get_tls_pem(&ca)?,
        CAType::SSH => get_ssh_pem(&ca)?
    };

    let file_name = match ca.ca_type {
        CAType::TLS => format!("ca_{}.pem", ca.name),
        CAType::SSH => format!("ca_{}.pub", ca.name)
    };

    Ok(DownloadResponse::new(pem, &file_name))
}

#[openapi(tag = "Certificates")]
#[get("/certificates/<id>/download")]
/// Download a user-owned certificate. Requires authentication.
pub(crate) async fn download_certificate(
    state: &State<AppState>,
    id: i64,
    authentication: Authenticated
) -> Result<DownloadResponse, ApiError> {
    let (user_id, name, data, cert_type) = state.db.get_user_cert_data(id).await?;
    if user_id != authentication.claims.id && authentication.claims.role != UserRole::Admin { return Err(ApiError::Forbidden(None)) }

    let file_name = match cert_type {
        CertificateType::TLSClient | CertificateType::TLSServer => format!("{}.p12", name),
        CertificateType::SSHClient | CertificateType::SSHServer => format!("{}.zip", name),
    };

    Ok(DownloadResponse::new(data, &file_name))
}

#[openapi(tag = "Certificates")]
#[get("/certificates/<id>/password")]
/// Fetch the password for a user-owned certificate. Requires authentication.
pub(crate) async fn fetch_certificate_password(
    state: &State<AppState>,
    id: i64,
    authentication: Authenticated
) -> Result<Json<String>, ApiError> {
    let (user_id, password) = state.db.get_user_cert_password(id).await?;
    if user_id != authentication.claims.id && authentication.claims.role != UserRole::Admin { return Err(ApiError::Forbidden(None)) }
    Ok(Json(password))
}

#[openapi(tag = "Certificates")]
#[delete("/certificates/ca/<id>")]
/// Delete a CA. Requires admin role.
pub(crate) async fn delete_ca(
    state: &State<AppState>,
    id: i64,
    _authentication: AuthenticatedPrivileged
) -> Result<(), ApiError> {
    let related_cert_count = state.db.count_user_certs_by_ca_id(id).await?;
    if related_cert_count > 0 {
        return Err(ApiError::BadRequest("The CA still has user certificates attached to it.".to_string()));
    }
    state.db.delete_ca(id).await?;
    Ok(())
}

#[openapi(tag = "Certificates")]
#[delete("/certificates/<id>")]
/// Delete a user-owned certificate. Requires admin role.
pub(crate) async fn delete_user_cert(
    state: &State<AppState>,
    id: i64,
    _authentication: AuthenticatedPrivileged
) -> Result<(), ApiError> {
    state.db.delete_user_cert(id).await?;
    Ok(())
}

#[openapi(tag = "Settings")]
#[get("/settings")]
/// Fetch application settings. Requires admin role.
pub(crate) async fn fetch_settings(
    state: &State<AppState>,
    _authentication: AuthenticatedPrivileged
) -> Result<Json<FrontendSettings>, ApiError> {
    let frontend_settings = FrontendSettings(state.settings.clone());
    Ok(Json(frontend_settings))
}

#[openapi(tag = "Settings")]
#[put("/settings", format = "json", data = "<payload>")]
/// Update application settings. Requires admin role.
pub(crate) async fn update_settings(
    state: &State<AppState>,
    payload: Json<InnerSettings>,
    _authentication: AuthenticatedPrivileged
) -> Result<(), ApiError> {
    let mut oidc = state.oidc.lock().await;

    state.settings.set_settings(&payload)?;

    let oidc_settings = state.settings.get_oidc();
    if oidc_settings.is_valid() {
        *oidc = OidcAuth::new(&oidc_settings).await.ok()
    } else {
        *oidc = None;
    }

    match oidc.is_some() {
        true => info!("OIDC is active."),
        false => info!("OIDC is inactive.")
    }

    let mut mailer = state.mailer.lock().await;
    let mail_settings = state.settings.get_mail();
    if mail_settings.is_valid() {
        *mailer = Mailer::new(&mail_settings, &state.settings.get_vaultls_url()).await.ok()
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
    let users = state.db.get_all_user().await?;
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
    let trim_password = payload.password.as_deref().unwrap_or("").trim();

    let password = match trim_password {
        "" => None,
        _ => Some(trim_password)
    };

    let password_hash = match password {
        Some(p) => Some(Password::new_server_hash(p)?),
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

    user = state.db.insert_user(user).await?;

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
    state.db.update_user(user.clone()).await?;

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
    state.db.delete_user(id).await?;

    info!(user=?id, "User deleted.");

    Ok(())
}