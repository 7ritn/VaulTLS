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
use crate::data::crl::{CertificateStatusRequest, CertificateStatusResponse, CrlFormat, CrlInfo, RevocationStatistics, RevokeCertificateRequest, RevokeCertificateResponse};
use crate::data::token::{ApiToken, CreateTokenRequest, TokenResponse, UpdateTokenRequest, RotateTokenRequest, RotateTokenResponse};
use crate::cert::{CreateCaRequest, UpdateCaRequest, CaResponse, CaListResponse, KeyAlgorithm, CA};
use crate::crl::CrlManager;
use crate::auth::token_auth::{TokenAuthService, BearerAuthenticated, BearerTokenAdmin, BearerCaRead, BearerCaWrite};
use openssl::x509::X509;
use crate::data::enums::{CertificateType, PasswordRule, UserRole};
use crate::data::error::ApiError;
use crate::data::objects::{AppState, User};
use crate::notification::mail::{MailMessage, Mailer};
    use crate::settings::{FrontendSettings, InnerSettings};

#[openapi(tag = "Setup")]
#[get("/server/version")]
/// Get the current version of the server.
pub(crate) fn version() -> &'static str {
    VAULTLS_VERSION
}

#[openapi(tag = "Documentation")]
#[get("/docs")]
/// Get API documentation information and links.
pub(crate) fn api_docs() -> Json<serde_json::Value> {
    Json(serde_json::json!({
        "title": "VaulTLS API Documentation",
        "version": VAULTLS_VERSION,
        "description": "VaulTLS is a self-hosted web application for managing mTLS certificates",
        "links": {
            "interactive_docs": "/api-docs",
            "openapi_spec": "/api/openapi.json",
            "authentication_guide": "https://github.com/7ritn/VaulTLS/blob/main/docs/api/authentication.md",
            "getting_started": "https://github.com/7ritn/VaulTLS/blob/main/docs/api/getting-started.md",
            "endpoints_reference": "https://github.com/7ritn/VaulTLS/blob/main/docs/api/endpoints.md"
        },
        "authentication": {
            "session_auth": {
                "description": "Cookie-based authentication for web UI",
                "login_endpoint": "/api/auth/login",
                "logout_endpoint": "/api/auth/logout"
            },
            "bearer_auth": {
                "description": "Bearer token authentication for API automation (coming soon)",
                "format": "Bearer vlt_xxxxxx_<token-value>",
                "scopes": [
                    "cert.read", "cert.write", "cert.revoke", "cert.download",
                    "ca.read", "ca.write", "ca.keyop",
                    "profile.read", "profile.write",
                    "token.read", "token.write", "token.admin",
                    "audit.read", "metrics.read", "admin.tenant"
                ]
            }
        },
        "examples": {
            "login": {
                "method": "POST",
                "url": "/api/auth/login",
                "body": {
                    "email": "admin@example.com",
                    "password": "your-password"
                }
            },
            "list_certificates": {
                "method": "GET",
                "url": "/api/certificates",
                "auth": "session or bearer token"
            },
            "download_ca": {
                "method": "GET",
                "url": "/api/certificates/ca/download",
                "auth": "none required"
            }
        }
    }))
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
        tenant_id: "00000000-0000-0000-0000-000000000000".to_string(), // Default tenant
    };

    state.db.insert_user(user).await?;

    let ca = CertificateBuilder::new()?
        .set_name(&setup_req.ca_name)?
        .set_valid_until(setup_req.ca_validity_in_years)?
        .build_ca()?;
    save_ca(&ca)?;
    state.db.insert_ca(ca).await?;

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
#[post("/certificates", format = "json", data = "<payload>")]
/// Create a new certificate. Requires admin role.
pub(crate) async fn create_user_certificate(
    state: &State<AppState>,
    payload: Json<CreateUserCertificateRequest>,
    _authentication: AuthenticatedPrivileged
) -> Result<Json<Certificate>, ApiError> {
    debug!(cert_name=?payload.cert_name, "Creating certificate");

    let password_rule = state.settings.get_password_rule();
    let use_random_password = if password_rule == PasswordRule::System
        || (password_rule == PasswordRule::Required
            && payload.pkcs12_password.as_deref().unwrap_or("").trim().is_empty()) {
        debug!(cert_name=?payload.cert_name, "Using system-supplied password");
        true
    } else {
        debug!(cert_name=?payload.cert_name, "Using user-supplied password");
        payload.system_generated_password
    };

    let ca = state.db.get_current_ca().await?;
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
            let user = state.db.get_user(payload.user_id).await?;
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

    cert = state.db.insert_user_cert(cert).await?;

    info!(cert=cert.name, "New certificate created.");
    trace!("{:?}", cert);

    if Some(true) == payload.notify_user {
        let user = state.db.get_user(payload.user_id).await?;
        let mail = MailMessage{
            to: format!("{} <{}>", user.name, user.email),
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
    let ca = state.db.get_current_ca().await?;
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
    let (user_id, name, pkcs12) = state.db.get_user_cert_pkcs12(id).await?;
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
    let (user_id, pkcs12_password) = state.db.get_user_cert_pkcs12_password(id).await?;
    if user_id != authentication.claims.id && authentication.claims.role != UserRole::Admin { return Err(ApiError::Forbidden(None)) }
    Ok(Json(pkcs12_password))
}

#[openapi(tag = "Certificates")]
#[delete("/certificates/<id>")]
/// Delete a user-owned certificate. This now revokes the certificate instead of deleting it for security. Requires admin role.
pub(crate) async fn delete_user_cert(
    state: &State<AppState>,
    id: i64,
    authentication: AuthenticatedPrivileged
) -> Result<(), ApiError> {
    // Instead of deleting, we now revoke the certificate for security
    let base_url = std::env::var("VAULTLS_BASE_URL").unwrap_or_else(|_| "https://localhost:5173".to_string());
    let crl_manager = CrlManager::new(state.db.clone(), base_url);

    let revoke_request = RevokeCertificateRequest {
        reason: Some(crate::data::crl::RevocationReason::CessationOfOperation),
        effective_date: None, // Use current time
    };

    let _ = crl_manager.revoke_certificate(id, revoke_request, authentication.claims.id).await?;

    info!("Certificate {} revoked via delete endpoint", id);
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
        role: payload.role,
        tenant_id: "00000000-0000-0000-0000-000000000000".to_string(), // Default tenant
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

// ===== CRL ENDPOINTS =====

#[openapi(tag = "Certificate Revocation")]
#[post("/certificates/<id>/revoke", format = "json", data = "<payload>")]
/// Revoke a certificate. Requires admin role.
pub(crate) async fn revoke_certificate(
    state: &State<AppState>,
    id: i64,
    payload: Json<RevokeCertificateRequest>,
    authentication: AuthenticatedPrivileged
) -> Result<Json<RevokeCertificateResponse>, ApiError> {
    let base_url = std::env::var("VAULTLS_BASE_URL").unwrap_or_else(|_| "https://localhost:5173".to_string());
    let crl_manager = CrlManager::new(state.db.clone(), base_url);

    let response = crl_manager.revoke_certificate(id, payload.into_inner(), authentication.claims.id).await?;
    Ok(Json(response))
}

#[openapi(tag = "Certificate Revocation")]
#[post("/certificates/<id>/restore")]
/// Restore a revoked certificate. Requires admin role.
pub(crate) async fn restore_certificate(
    state: &State<AppState>,
    id: i64,
    authentication: AuthenticatedPrivileged
) -> Result<(), ApiError> {
    let base_url = std::env::var("VAULTLS_BASE_URL").unwrap_or_else(|_| "https://localhost:5173".to_string());
    let crl_manager = CrlManager::new(state.db.clone(), base_url);

    crl_manager.restore_certificate(id, authentication.claims.id).await?;
    Ok(())
}

#[openapi(tag = "Certificate Revocation")]
#[get("/crl/ca/<ca_id>/download?<format>")]
/// Download Certificate Revocation List (CRL) for a CA.
pub(crate) async fn download_crl(
    state: &State<AppState>,
    ca_id: i64,
    format: Option<String>
) -> Result<DownloadResponse, ApiError> {
    let base_url = std::env::var("VAULTLS_BASE_URL").unwrap_or_else(|_| "https://localhost:5173".to_string());
    let crl_manager = CrlManager::new(state.db.clone(), base_url);

    let crl_format = format
        .and_then(|f| CrlFormat::from_str(&f))
        .unwrap_or_default();

    let tenant_id = "00000000-0000-0000-0000-000000000000"; // Default tenant for now
    let crl_data = crl_manager.get_crl(ca_id, tenant_id, crl_format.clone()).await?;

    let filename = format!("ca_{}.{}", ca_id, crl_format.file_extension());
    let mut response = DownloadResponse::new(crl_data, &filename);
    response.content_type = Some(crl_format.content_type().to_string());

    Ok(response)
}

#[openapi(tag = "Certificate Revocation")]
#[get("/crl/ca/<ca_id>/info")]
/// Get CRL information for a CA. Requires authentication.
pub(crate) async fn get_crl_info(
    state: &State<AppState>,
    ca_id: i64,
    _authentication: Authenticated
) -> Result<Json<CrlInfo>, ApiError> {
    let base_url = std::env::var("VAULTLS_BASE_URL").unwrap_or_else(|_| "https://localhost:5173".to_string());
    let crl_manager = CrlManager::new(state.db.clone(), base_url);

    let tenant_id = "00000000-0000-0000-0000-000000000000"; // Default tenant for now
    let info = crl_manager.get_crl_info(ca_id, tenant_id).await?;

    Ok(Json(info))
}

#[openapi(tag = "Certificate Revocation")]
#[post("/certificates/status", format = "json", data = "<payload>")]
/// Check certificate revocation status.
pub(crate) async fn check_certificate_status(
    state: &State<AppState>,
    payload: Json<CertificateStatusRequest>
) -> Result<Json<CertificateStatusResponse>, ApiError> {
    let base_url = std::env::var("VAULTLS_BASE_URL").unwrap_or_else(|_| "https://localhost:5173".to_string());
    let crl_manager = CrlManager::new(state.db.clone(), base_url);

    let response = crl_manager.check_certificate_status(&payload.serial_number, payload.ca_id).await?;
    Ok(Json(response))
}

#[openapi(tag = "Certificate Revocation")]
#[get("/crl/ca/<ca_id>/statistics")]
/// Get revocation statistics for a CA. Requires admin role.
pub(crate) async fn get_revocation_statistics(
    state: &State<AppState>,
    ca_id: i64,
    _authentication: AuthenticatedPrivileged
) -> Result<Json<RevocationStatistics>, ApiError> {
    let base_url = std::env::var("VAULTLS_BASE_URL").unwrap_or_else(|_| "https://localhost:5173".to_string());
    let crl_manager = CrlManager::new(state.db.clone(), base_url);

    let tenant_id = "00000000-0000-0000-0000-000000000000"; // Default tenant for now
    let stats = crl_manager.get_revocation_statistics(ca_id, tenant_id).await?;

    Ok(Json(stats))
}

#[openapi(tag = "Certificate Revocation")]
#[post("/crl/ca/<ca_id>/generate")]
/// Manually generate CRL for a CA. Requires admin role.
pub(crate) async fn generate_crl(
    state: &State<AppState>,
    ca_id: i64,
    _authentication: AuthenticatedPrivileged
) -> Result<Json<CrlInfo>, ApiError> {
    let base_url = std::env::var("VAULTLS_BASE_URL").unwrap_or_else(|_| "https://localhost:5173".to_string());
    let crl_manager = CrlManager::new(state.db.clone(), base_url);

    let tenant_id = "00000000-0000-0000-0000-000000000000"; // Default tenant for now

    // Generate new CRL
    let _ = crl_manager.generate_crl_for_ca(ca_id, tenant_id).await?;

    // Return updated info
    let info = crl_manager.get_crl_info(ca_id, tenant_id).await?;
    Ok(Json(info))
}

// ===== API TOKEN ENDPOINTS =====

#[openapi(tag = "API Tokens")]
#[post("/tokens", format = "json", data = "<payload>")]
/// Create a new API token. Requires token.write scope or admin role.
pub(crate) async fn create_api_token(
    state: &State<AppState>,
    payload: Json<CreateTokenRequest>,
    authentication: BearerTokenAdmin
) -> Result<Json<CreateTokenResponse>, ApiError> {
    let request = payload.into_inner();

    // Create token service
    let token_service = TokenAuthService::new()?;

    // Generate token value and prefix
    let (token_value, prefix) = crate::auth::token_auth::token_utils::generate_token()?;

    // Create API token
    let mut api_token = ApiToken::new(
        request.description,
        request.scopes,
        authentication.auth.token.created_by_user_id,
        authentication.auth.token.tenant_id.clone(),
        request.expires_at,
        request.rate_limit_per_minute,
    );

    // Hash the token
    let api_token = token_service.create_token(api_token, &token_value)?;

    // Store in database
    state.db.insert_api_token(&api_token).await?;

    // Log audit event
    let _ = state.db.log_audit_event(
        "token.create",
        Some(authentication.auth.token.created_by_user_id),
        Some(&authentication.auth.token.tenant_id),
        Some(&api_token.id),
        Some(&format!("Created API token: {}", api_token.description)),
    ).await;

    let response = CreateTokenResponse {
        token: format!("vlt_{}_{}", prefix, token_value),
        token_info: TokenResponse::from(api_token),
    };

    Ok(Json(response))
}

#[openapi(tag = "API Tokens")]
#[get("/tokens?<page>&<per_page>")]
/// List API tokens for the current user/tenant. Requires token.read scope.
pub(crate) async fn list_api_tokens(
    state: &State<AppState>,
    page: Option<i32>,
    per_page: Option<i32>,
    authentication: BearerAuthenticated
) -> Result<Json<TokenListResponse>, ApiError> {
    let page = page.unwrap_or(1).max(1);
    let per_page = per_page.unwrap_or(20).min(100).max(1);

    // Get tokens for user
    let tokens = state.db.get_api_tokens_for_user(
        authentication.auth.token.created_by_user_id,
        &authentication.auth.token.tenant_id
    ).await?;

    // Apply pagination
    let total = tokens.len() as i64;
    let start = ((page - 1) * per_page) as usize;
    let end = (start + per_page as usize).min(tokens.len());
    let paginated_tokens = tokens[start..end].to_vec();

    let response = TokenListResponse {
        tokens: paginated_tokens.into_iter().map(TokenResponse::from).collect(),
        total,
        page,
        per_page,
        has_more: end < tokens.len(),
    };

    Ok(Json(response))
}

#[openapi(tag = "API Tokens")]
#[get("/tokens/<token_id>")]
/// Get API token details. Requires token.read scope.
pub(crate) async fn get_api_token(
    state: &State<AppState>,
    token_id: String,
    authentication: BearerAuthenticated
) -> Result<Json<TokenResponse>, ApiError> {
    // Get token by ID (this would need a new DB method)
    let token = state.db.get_api_token_by_id(&token_id).await?;

    // Check if user owns this token or has admin scope
    if token.created_by_user_id != authentication.auth.token.created_by_user_id
        && !authentication.auth.has_scope(&Scope::AdminTenant) {
        return Err(ApiError::Forbidden);
    }

    Ok(Json(TokenResponse::from(token)))
}

#[openapi(tag = "API Tokens")]
#[patch("/tokens/<token_id>", format = "json", data = "<payload>")]
/// Update API token. Requires token.write scope.
pub(crate) async fn update_api_token(
    state: &State<AppState>,
    token_id: String,
    payload: Json<UpdateTokenRequest>,
    authentication: BearerTokenAdmin
) -> Result<Json<TokenResponse>, ApiError> {
    let request = payload.into_inner();

    // Get existing token
    let mut token = state.db.get_api_token_by_id(&token_id).await?;

    // Check ownership
    if token.created_by_user_id != authentication.auth.token.created_by_user_id
        && !authentication.auth.has_scope(&Scope::AdminTenant) {
        return Err(ApiError::Forbidden);
    }

    // Update fields
    if let Some(description) = request.description {
        token.description = description;
    }
    if let Some(scopes) = request.scopes {
        token.scopes = scopes;
    }
    if let Some(is_enabled) = request.is_enabled {
        token.is_enabled = is_enabled;
    }
    if let Some(expires_at) = request.expires_at {
        token.expires_at = Some(expires_at);
    }
    if let Some(rate_limit) = request.rate_limit_per_minute {
        token.rate_limit_per_minute = Some(rate_limit);
    }

    // Update in database
    state.db.update_api_token(&token).await?;

    // Log audit event
    let _ = state.db.log_audit_event(
        "token.update",
        Some(authentication.auth.token.created_by_user_id),
        Some(&authentication.auth.token.tenant_id),
        Some(&token.id),
        Some(&format!("Updated API token: {}", token.description)),
    ).await;

    Ok(Json(TokenResponse::from(token)))
}

#[openapi(tag = "API Tokens")]
#[post("/tokens/<token_id>:rotate", format = "json", data = "<payload>")]
/// Rotate API token (generate new token value). Requires token.write scope.
pub(crate) async fn rotate_api_token(
    state: &State<AppState>,
    token_id: String,
    payload: Json<RotateTokenRequest>,
    authentication: BearerTokenAdmin
) -> Result<Json<RotateTokenResponse>, ApiError> {
    let request = payload.into_inner();

    // Get existing token
    let mut token = state.db.get_api_token_by_id(&token_id).await?;

    // Check ownership
    if token.created_by_user_id != authentication.auth.token.created_by_user_id
        && !authentication.auth.has_scope(&Scope::AdminTenant) {
        return Err(ApiError::Forbidden);
    }

    // Generate new token value
    let (new_token_value, new_prefix) = crate::auth::token_auth::token_utils::generate_token()?;

    // Create token service and rotate
    let token_service = TokenAuthService::new()?;
    token = token_service.rotate_token(token, &new_token_value)?;
    token.prefix = new_prefix;

    // Update description if provided
    if let Some(description) = request.description {
        token.description = description;
    }

    // Update in database
    state.db.update_api_token(&token).await?;

    // Log audit event
    let _ = state.db.log_audit_event(
        "token.rotate",
        Some(authentication.auth.token.created_by_user_id),
        Some(&authentication.auth.token.tenant_id),
        Some(&token.id),
        Some(&format!("Rotated API token: {}", token.description)),
    ).await;

    let response = RotateTokenResponse {
        token_plaintext_once: format!("vlt_{}_{}", token.prefix, new_token_value),
    };

    Ok(Json(response))
}

#[openapi(tag = "API Tokens")]
#[post("/tokens/<token_id>:revoke")]
/// Revoke API token. Requires token.write scope.
pub(crate) async fn revoke_api_token(
    state: &State<AppState>,
    token_id: String,
    authentication: BearerTokenAdmin
) -> Result<Json<TokenResponse>, ApiError> {
    // Get existing token
    let mut token = state.db.get_api_token_by_id(&token_id).await?;

    // Check ownership
    if token.created_by_user_id != authentication.auth.token.created_by_user_id
        && !authentication.auth.has_scope(&Scope::AdminTenant) {
        return Err(ApiError::Forbidden);
    }

    // Revoke token
    token.revoked_at = Some(chrono::Utc::now().timestamp());
    token.is_enabled = false;

    // Update in database
    state.db.update_api_token(&token).await?;

    // Log audit event
    let _ = state.db.log_audit_event(
        "token.revoke",
        Some(authentication.auth.token.created_by_user_id),
        Some(&authentication.auth.token.tenant_id),
        Some(&token.id),
        Some(&format!("Revoked API token: {}", token.description)),
    ).await;

    Ok(Json(TokenResponse::from(token)))
}

#[openapi(tag = "API Tokens")]
#[delete("/tokens/<token_id>")]
/// Delete API token. Requires token.write scope.
pub(crate) async fn delete_api_token(
    state: &State<AppState>,
    token_id: String,
    authentication: BearerTokenAdmin
) -> Result<(), ApiError> {
    // Get existing token to check ownership
    let token = state.db.get_api_token_by_id(&token_id).await?;

    // Check ownership
    if token.created_by_user_id != authentication.auth.token.created_by_user_id
        && !authentication.auth.has_scope(&Scope::AdminTenant) {
        return Err(ApiError::Forbidden);
    }

    // Delete from database
    state.db.delete_api_token(&token_id).await?;

    // Log audit event
    let _ = state.db.log_audit_event(
        "token.delete",
        Some(authentication.auth.token.created_by_user_id),
        Some(&authentication.auth.token.tenant_id),
        Some(&token.id),
        Some(&format!("Deleted API token: {}", token.description)),
    ).await;

    Ok(())
}

// ===== CA MANAGEMENT ENDPOINTS =====

#[openapi(tag = "Certificate Authorities")]
#[post("/cas", format = "json", data = "<payload>")]
/// Create a new Certificate Authority. Requires ca.write scope.
pub(crate) async fn create_ca(
    state: &State<AppState>,
    payload: Json<CreateCaRequest>,
    authentication: BearerCaWrite
) -> Result<Json<CaResponse>, ApiError> {
    let request = payload.into_inner();

    // Validate request
    if request.name.trim().is_empty() {
        return Err(ApiError::BadRequest("CA name cannot be empty".to_string()));
    }

    // Check if parent CA exists (for intermediate CAs)
    if let Some(parent_ca_id) = request.parent_ca_id {
        let parent_ca = state.db.get_ca_by_id(parent_ca_id).await?;
        if parent_ca.tenant_id != authentication.auth.token.tenant_id {
            return Err(ApiError::Forbidden);
        }
    }

    // Determine key algorithm
    let key_algorithm = request.key_algorithm.unwrap_or_default();

    // Create CA certificate using CertificateBuilder
    let ca_builder = crate::cert::CertificateBuilder::new_with_key_algorithm(key_algorithm.clone())?;
    let mut ca = ca_builder
        .set_name(&request.name)?
        .set_valid_until(request.validity_years.unwrap_or(10))?
        .build_ca()?;

    // Set CA properties
    ca.tenant_id = authentication.auth.token.tenant_id.clone();
    ca.name = Some(request.name.clone());
    ca.description = request.description;
    ca.key_algorithm = key_algorithm.as_str().to_string();
    ca.key_size = Some(key_algorithm.key_size());
    ca.is_root_ca = request.is_root_ca.unwrap_or(true);
    ca.parent_ca_id = request.parent_ca_id;
    ca.path_len = request.path_len;
    ca.created_by_user_id = authentication.auth.token.created_by_user_id;

    // Set extensions as JSON
    if let Some(key_usage) = request.key_usage {
        ca.key_usage = Some(serde_json::to_string(&key_usage)?);
    }
    if let Some(eku) = request.extended_key_usage {
        ca.extended_key_usage = Some(serde_json::to_string(&eku)?);
    }
    if let Some(policies) = request.certificate_policies {
        ca.certificate_policies = Some(serde_json::to_string(&policies)?);
    }
    if let Some(name_constraints) = request.name_constraints {
        ca.name_constraints = Some(serde_json::to_string(&name_constraints)?);
    }
    if let Some(crl_dps) = request.crl_distribution_points {
        ca.crl_distribution_points = Some(serde_json::to_string(&crl_dps)?);
    }
    if let Some(aia) = request.authority_info_access {
        ca.authority_info_access = Some(serde_json::to_string(&aia)?);
    }

    // Insert into database
    let ca_id = state.db.insert_ca(ca.clone()).await?;
    ca.id = ca_id;

    // Log audit event
    let _ = state.db.log_audit_event(
        "ca.create",
        Some(authentication.auth.token.created_by_user_id),
        Some(&authentication.auth.token.tenant_id),
        Some(&ca_id.to_string()),
        Some(&format!("Created CA: {}", request.name)),
    ).await;

    Ok(Json(CaResponse::from(ca)))
}

#[openapi(tag = "Certificate Authorities")]
#[get("/cas?<page>&<per_page>&<active_only>")]
/// List Certificate Authorities for the current tenant. Requires ca.read scope.
pub(crate) async fn list_cas(
    state: &State<AppState>,
    page: Option<i32>,
    per_page: Option<i32>,
    active_only: Option<bool>,
    authentication: BearerCaRead
) -> Result<Json<CaListResponse>, ApiError> {
    let page = page.unwrap_or(1).max(1);
    let per_page = per_page.unwrap_or(20).min(100).max(1);
    let active_only = active_only.unwrap_or(false);

    // Get CAs for tenant
    let mut cas = state.db.get_cas_for_tenant(&authentication.auth.token.tenant_id).await?;

    // Filter by active status if requested
    if active_only {
        cas.retain(|ca| ca.is_active);
    }

    // Apply pagination
    let total = cas.len() as i64;
    let start = ((page - 1) * per_page) as usize;
    let end = (start + per_page as usize).min(cas.len());
    let paginated_cas = cas[start..end].to_vec();

    // Convert to response format
    let mut ca_responses = Vec::new();
    for ca in paginated_cas {
        let mut ca_response = CaResponse::from(ca.clone());

        // Add certificate count
        ca_response.certificate_count = Some(
            state.db.get_certificate_count_for_ca(ca.id).await.unwrap_or(0)
        );

        // Add last CRL update
        ca_response.last_crl_update = state.db.get_last_crl_update(ca.id).await.ok();

        ca_responses.push(ca_response);
    }

    let response = CaListResponse {
        cas: ca_responses,
        total,
        page,
        per_page,
        has_more: end < cas.len(),
    };

    Ok(Json(response))
}

#[openapi(tag = "Certificate Authorities")]
#[get("/cas/<ca_id>")]
/// Get Certificate Authority details. Requires ca.read scope.
pub(crate) async fn get_ca(
    state: &State<AppState>,
    ca_id: i64,
    authentication: BearerCaRead
) -> Result<Json<CaResponse>, ApiError> {
    // Get CA
    let ca = state.db.get_ca_by_id(ca_id).await?;

    // Check tenant access
    if ca.tenant_id != authentication.auth.token.tenant_id {
        return Err(ApiError::Forbidden);
    }

    // Convert to response format with additional data
    let mut ca_response = CaResponse::from(ca.clone());

    // Add certificate count
    ca_response.certificate_count = Some(
        state.db.get_certificate_count_for_ca(ca.id).await.unwrap_or(0)
    );

    // Add last CRL update
    ca_response.last_crl_update = state.db.get_last_crl_update(ca.id).await.ok();

    Ok(Json(ca_response))
}

#[openapi(tag = "Certificate Authorities")]
#[patch("/cas/<ca_id>", format = "json", data = "<payload>")]
/// Update Certificate Authority. Requires ca.write scope.
pub(crate) async fn update_ca(
    state: &State<AppState>,
    ca_id: i64,
    payload: Json<UpdateCaRequest>,
    authentication: BearerCaWrite
) -> Result<Json<CaResponse>, ApiError> {
    let request = payload.into_inner();

    // Get existing CA
    let mut ca = state.db.get_ca_by_id(ca_id).await?;

    // Check tenant access
    if ca.tenant_id != authentication.auth.token.tenant_id {
        return Err(ApiError::Forbidden);
    }

    // Update fields
    if let Some(name) = request.name {
        if name.trim().is_empty() {
            return Err(ApiError::BadRequest("CA name cannot be empty".to_string()));
        }
        ca.name = Some(name);
    }

    if let Some(description) = request.description {
        ca.description = Some(description);
    }

    if let Some(is_active) = request.is_active {
        ca.is_active = is_active;
    }

    if let Some(crl_dps) = request.crl_distribution_points {
        ca.crl_distribution_points = Some(serde_json::to_string(&crl_dps)?);
    }

    if let Some(aia) = request.authority_info_access {
        ca.authority_info_access = Some(serde_json::to_string(&aia)?);
    }

    // Update in database
    state.db.update_ca(&ca).await?;

    // Log audit event
    let _ = state.db.log_audit_event(
        "ca.update",
        Some(authentication.auth.token.created_by_user_id),
        Some(&authentication.auth.token.tenant_id),
        Some(&ca_id.to_string()),
        Some(&format!("Updated CA: {}", ca.name.as_deref().unwrap_or("Unknown"))),
    ).await;

    Ok(Json(CaResponse::from(ca)))
}

#[openapi(tag = "Certificate Authorities")]
#[delete("/cas/<ca_id>")]
/// Delete Certificate Authority. Requires ca.write scope.
/// Note: This will also revoke all certificates issued by this CA.
pub(crate) async fn delete_ca(
    state: &State<AppState>,
    ca_id: i64,
    authentication: BearerCaWrite
) -> Result<(), ApiError> {
    // Get CA to check ownership
    let ca = state.db.get_ca_by_id(ca_id).await?;

    // Check tenant access
    if ca.tenant_id != authentication.auth.token.tenant_id {
        return Err(ApiError::Forbidden);
    }

    // Check if CA has child CAs
    let child_cas = state.db.get_child_cas(ca_id).await?;
    if !child_cas.is_empty() {
        return Err(ApiError::BadRequest(
            "Cannot delete CA with child CAs. Delete child CAs first.".to_string()
        ));
    }

    // Revoke all certificates issued by this CA
    let certificates = state.db.get_certificates_by_ca(ca_id).await?;
    for cert in certificates {
        if cert.status != "revoked" {
            let _ = state.db.revoke_certificate(
                cert.id,
                authentication.auth.token.created_by_user_id,
                Some(6), // cessationOfOperation
                Some("CA deletion".to_string())
            ).await;
        }
    }

    // Mark CA as inactive instead of deleting (for audit trail)
    let mut ca_mut = ca.clone();
    ca_mut.is_active = false;
    state.db.update_ca(&ca_mut).await?;

    // Log audit event
    let _ = state.db.log_audit_event(
        "ca.delete",
        Some(authentication.auth.token.created_by_user_id),
        Some(&authentication.auth.token.tenant_id),
        Some(&ca_id.to_string()),
        Some(&format!("Deleted CA: {}", ca.name.as_deref().unwrap_or("Unknown"))),
    ).await;

    Ok(())
}

#[openapi(tag = "Certificate Authorities")]
#[get("/cas/<ca_id>/cert?<format>")]
/// Download CA certificate in various formats. Requires ca.read scope.
pub(crate) async fn download_ca_certificate(
    state: &State<AppState>,
    ca_id: i64,
    format: Option<String>,
    authentication: BearerCaRead
) -> Result<DownloadResponse, ApiError> {
    // Get CA
    let ca = state.db.get_ca_by_id(ca_id).await?;

    // Check tenant access
    if ca.tenant_id != authentication.auth.token.tenant_id {
        return Err(ApiError::Forbidden);
    }

    // Determine format (default to PEM)
    let format = format.unwrap_or_else(|| "pem".to_string()).to_lowercase();

    // Parse X509 certificate from DER
    let cert = X509::from_der(&ca.cert)
        .map_err(|e| ApiError::InternalServerError)?;

    // Generate filename
    let ca_name = ca.name.as_deref().unwrap_or("ca");
    let safe_name = ca_name.replace(' ', "_").replace(['/', '\\', ':', '*', '?', '"', '<', '>', '|'], "_");

    let (content_type, file_extension, cert_data) = match format.as_str() {
        "pem" => {
            let pem_data = cert.to_pem()
                .map_err(|_| ApiError::InternalServerError)?;
            ("application/x-pem-file", "pem", pem_data)
        },
        "der" => {
            let der_data = cert.to_der()
                .map_err(|_| ApiError::InternalServerError)?;
            ("application/x-x509-ca-cert", "der", der_data)
        },
        "cer" => {
            // CER is just DER with different extension
            let der_data = cert.to_der()
                .map_err(|_| ApiError::InternalServerError)?;
            ("application/pkix-cert", "cer", der_data)
        },
        "crt" => {
            // CRT can be either PEM or DER, we'll use PEM
            let pem_data = cert.to_pem()
                .map_err(|_| ApiError::InternalServerError)?;
            ("application/x-x509-ca-cert", "crt", pem_data)
        },
        "p7b" | "p7c" => {
            // PKCS#7 format (certificate chain)
            let pkcs7_data = create_pkcs7_certificate_chain(&ca, state).await?;
            ("application/x-pkcs7-certificates", "p7b", pkcs7_data)
        },
        _ => {
            return Err(ApiError::BadRequest(
                "Unsupported format. Supported formats: pem, der, cer, crt, p7b, p7c".to_string()
            ));
        }
    };

    let filename = format!("{}_{}.{}", safe_name, ca.id, file_extension);

    // Log audit event
    let _ = state.db.log_audit_event(
        "ca.download",
        Some(authentication.auth.token.created_by_user_id),
        Some(&authentication.auth.token.tenant_id),
        Some(&ca_id.to_string()),
        Some(&format!("Downloaded CA certificate: {} (format: {})", ca_name, format)),
    ).await;

    Ok(DownloadResponse {
        content_type: content_type.to_string(),
        filename,
        body: cert_data,
    })
}

#[openapi(tag = "Certificate Authorities")]
#[get("/cas/<ca_id>/chain?<format>")]
/// Download CA certificate chain (including parent CAs). Requires ca.read scope.
pub(crate) async fn download_ca_chain(
    state: &State<AppState>,
    ca_id: i64,
    format: Option<String>,
    authentication: BearerCaRead
) -> Result<DownloadResponse, ApiError> {
    // Get CA
    let ca = state.db.get_ca_by_id(ca_id).await?;

    // Check tenant access
    if ca.tenant_id != authentication.auth.token.tenant_id {
        return Err(ApiError::Forbidden);
    }

    // Determine format (default to PEM)
    let format = format.unwrap_or_else(|| "pem".to_string()).to_lowercase();

    // Build certificate chain
    let chain = build_certificate_chain(&ca, state).await?;

    // Generate filename
    let ca_name = ca.name.as_deref().unwrap_or("ca");
    let safe_name = ca_name.replace(' ', "_").replace(['/', '\\', ':', '*', '?', '"', '<', '>', '|'], "_");

    let (content_type, file_extension, chain_data) = match format.as_str() {
        "pem" => {
            let mut pem_chain = Vec::new();
            for cert_der in chain {
                let cert = X509::from_der(&cert_der)
                    .map_err(|_| ApiError::InternalServerError)?;
                let pem_data = cert.to_pem()
                    .map_err(|_| ApiError::InternalServerError)?;
                pem_chain.extend_from_slice(&pem_data);
            }
            ("application/x-pem-file", "pem", pem_chain)
        },
        "p7b" | "p7c" => {
            // PKCS#7 format with full chain
            let pkcs7_data = create_pkcs7_chain(&chain)?;
            ("application/x-pkcs7-certificates", "p7b", pkcs7_data)
        },
        _ => {
            return Err(ApiError::BadRequest(
                "Unsupported format for chain. Supported formats: pem, p7b, p7c".to_string()
            ));
        }
    };

    let filename = format!("{}_chain_{}.{}", safe_name, ca.id, file_extension);

    // Log audit event
    let _ = state.db.log_audit_event(
        "ca.download_chain",
        Some(authentication.auth.token.created_by_user_id),
        Some(&authentication.auth.token.tenant_id),
        Some(&ca_id.to_string()),
        Some(&format!("Downloaded CA certificate chain: {} (format: {})", ca_name, format)),
    ).await;

    Ok(DownloadResponse {
        content_type: content_type.to_string(),
        filename,
        body: chain_data,
    })
}

/// Helper function to create PKCS#7 certificate chain
async fn create_pkcs7_certificate_chain(ca: &CA, state: &State<AppState>) -> Result<Vec<u8>, ApiError> {
    let chain = build_certificate_chain(ca, state).await?;
    create_pkcs7_chain(&chain)
}

/// Helper function to build certificate chain from CA to root
async fn build_certificate_chain(ca: &CA, state: &State<AppState>) -> Result<Vec<Vec<u8>>, ApiError> {
    let mut chain = Vec::new();
    let mut current_ca = ca.clone();

    // Add current CA certificate
    chain.push(current_ca.cert.clone());

    // Walk up the chain to root CA
    while let Some(parent_ca_id) = current_ca.parent_ca_id {
        match state.db.get_ca_by_id(parent_ca_id).await {
            Ok(parent_ca) => {
                chain.push(parent_ca.cert.clone());
                current_ca = parent_ca;
            },
            Err(_) => break, // Parent CA not found, stop chain building
        }
    }

    Ok(chain)
}

/// Helper function to create PKCS#7 format from certificate chain
fn create_pkcs7_chain(chain: &[Vec<u8>]) -> Result<Vec<u8>, ApiError> {
    use openssl::pkcs7::Pkcs7;
    use openssl::stack::Stack;

    let mut cert_stack = Stack::new()
        .map_err(|_| ApiError::InternalServerError)?;

    for cert_der in chain {
        let cert = X509::from_der(cert_der)
            .map_err(|_| ApiError::InternalServerError)?;
        cert_stack.push(cert)
            .map_err(|_| ApiError::InternalServerError)?;
    }

    let pkcs7 = Pkcs7::from_certificates(&cert_stack)
        .map_err(|_| ApiError::InternalServerError)?;

    pkcs7.to_der()
        .map_err(|_| ApiError::InternalServerError)
}