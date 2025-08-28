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
use crate::cert::{CreateCaRequest, UpdateCaRequest, CaResponse, CaListResponse, KeyAlgorithm, CA, RotateCaRequest, CaRotationResponse, CertificateAction, CreateCertificateWithCaRequest, CaSelection, CertificateBuilder, CertificateSearchRequest, CertificateSearchResponse, BatchOperationRequest, BatchOperationResponse, ChainValidationRequest, ChainValidationResponse, CertificateStatistics, BulkDownloadRequest, CertificateTemplate, CreateCertificateTemplateRequest, UpdateCertificateTemplateRequest, CertificateTemplateListResponse, CreateCertificateFromTemplateRequest, WebhookConfig, CreateWebhookRequest, UpdateWebhookRequest, WebhookListResponse, WebhookEvent};

// Import route definitions and deprecation management
pub mod routes;
pub mod deprecation;
use crate::data::enums::CertificateType;
use crate::data::profile::{Profile, CreateProfileRequest, UpdateProfileRequest, ProfileListResponse};
use crate::data::audit::{AuditEvent, AuditEventQuery, AuditEventType, AuditResourceType, AuditEventListResponse, AuditStatistics, AuditActivityResponse, AuditExportRequest};
use crate::crl::CrlManager;
use crate::auth::token_auth::{TokenAuthService, BearerAuthenticated, BearerTokenAdmin, BearerCaRead, BearerCaWrite, BearerCaKeyop, BearerCertWrite, BearerProfileRead, BearerProfileWrite, BearerCertRead, BearerAuditRead};
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
            "redoc_docs": "/redoc",
            "openapi_spec": "/api/openapi.json",
            "authentication_guide": "https://github.com/7ritn/VaulTLS/blob/main/docs/api/authentication.md",
            "getting_started": "https://github.com/7ritn/VaulTLS/blob/main/docs/api/getting-started.md",
            "endpoints_reference": "https://github.com/7ritn/VaulTLS/blob/main/docs/api/endpoints.md"
        },
        "documentation_security": {
            "enabled": std::env::var("VAULTLS_API_DOCS_ENABLED").unwrap_or_else(|_| "true".to_string()),
            "requires_auth": std::env::var("VAULTLS_API_DOCS_REQUIRE_AUTH").unwrap_or_else(|_| "false".to_string()),
            "note": "API documentation access can be controlled via environment variables"
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
            return Err(ApiError::tenant_access_denied());
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
        return Err(ApiError::tenant_access_denied());
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
        return Err(ApiError::tenant_access_denied());
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
        return Err(ApiError::tenant_access_denied());
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
        return Err(ApiError::tenant_access_denied());
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
        return Err(ApiError::tenant_access_denied());
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

#[openapi(tag = "Certificate Authorities")]
#[post("/cas/<ca_id>:rotate", format = "json", data = "<payload>")]
/// Rotate CA key and certificate while preserving chain integrity. Requires ca.keyop scope.
pub(crate) async fn rotate_ca_key(
    state: &State<AppState>,
    ca_id: i64,
    payload: Json<RotateCaRequest>,
    authentication: BearerCaKeyop
) -> Result<Json<CaRotationResponse>, ApiError> {
    let request = payload.into_inner();

    // Get existing CA
    let old_ca = state.db.get_ca_by_id(ca_id).await?;

    // Check tenant access
    if old_ca.tenant_id != authentication.auth.token.tenant_id {
        return Err(ApiError::tenant_access_denied());
    }

    // Validate rotation request
    if old_ca.is_root_ca && request.preserve_chain.unwrap_or(true) {
        return Err(ApiError::BadRequest(
            "Root CA rotation requires preserve_chain=false".to_string()
        ));
    }

    // Check if CA has active certificates
    let cert_count = state.db.get_certificate_count_for_ca(ca_id).await?;
    if cert_count > 0 && !request.force_rotation.unwrap_or(false) {
        return Err(ApiError::BadRequest(
            format!("CA has {} active certificates. Use force_rotation=true to proceed.", cert_count)
        ));
    }

    // Determine new key algorithm (default to same as current)
    let new_key_algorithm = request.new_key_algorithm
        .unwrap_or_else(|| KeyAlgorithm::from_str(&old_ca.key_algorithm).unwrap_or_default());

    // Create new CA certificate
    let ca_builder = crate::cert::CertificateBuilder::new_with_key_algorithm(new_key_algorithm.clone())?;
    let mut new_ca = ca_builder
        .set_name(old_ca.name.as_deref().unwrap_or("Rotated CA"))
        .set_valid_until(request.validity_years.unwrap_or(10))
        .build_ca()?;

    // Preserve CA properties from old CA
    new_ca.tenant_id = old_ca.tenant_id.clone();
    new_ca.name = old_ca.name.clone();
    new_ca.description = request.new_description.or(old_ca.description);
    new_ca.key_algorithm = new_key_algorithm.as_str().to_string();
    new_ca.key_size = Some(new_key_algorithm.key_size());
    new_ca.is_root_ca = old_ca.is_root_ca;
    new_ca.parent_ca_id = old_ca.parent_ca_id;
    new_ca.path_len = old_ca.path_len;
    new_ca.created_by_user_id = authentication.auth.token.created_by_user_id;

    // Preserve extensions
    new_ca.key_usage = old_ca.key_usage.clone();
    new_ca.extended_key_usage = old_ca.extended_key_usage.clone();
    new_ca.certificate_policies = old_ca.certificate_policies.clone();
    new_ca.policy_constraints = old_ca.policy_constraints.clone();
    new_ca.name_constraints = old_ca.name_constraints.clone();
    new_ca.crl_distribution_points = old_ca.crl_distribution_points.clone();
    new_ca.authority_info_access = old_ca.authority_info_access.clone();

    // Insert new CA into database
    let new_ca_id = state.db.insert_ca(new_ca.clone()).await?;
    new_ca.id = new_ca_id;

    // Handle chain preservation
    if request.preserve_chain.unwrap_or(true) && !old_ca.is_root_ca {
        // For intermediate CAs, we create a new intermediate under the same parent
        // The old CA remains in the database but is marked as inactive

        // Deactivate old CA
        let mut old_ca_mut = old_ca.clone();
        old_ca_mut.is_active = false;
        state.db.update_ca(&old_ca_mut).await?;

        // Update child CAs to point to new CA (if any)
        let child_cas = state.db.get_child_cas(ca_id).await?;
        for mut child_ca in child_cas {
            child_ca.parent_ca_id = Some(new_ca_id);
            state.db.update_ca(&child_ca).await?;
        }
    } else {
        // For root CA rotation or when not preserving chain
        // Replace the old CA entirely
        state.db.replace_ca(ca_id, &new_ca).await?;
    }

    // Handle certificate migration
    match request.certificate_action.unwrap_or(CertificateAction::Revoke) {
        CertificateAction::Revoke => {
            // Revoke all certificates issued by old CA
            let certificates = state.db.get_certificates_by_ca(ca_id).await?;
            for cert in certificates {
                if cert.status != "revoked" {
                    let _ = state.db.revoke_certificate(
                        cert.id,
                        authentication.auth.token.created_by_user_id,
                        Some(4), // superseded
                        Some("CA key rotation".to_string())
                    ).await;
                }
            }
        },
        CertificateAction::Migrate => {
            // Update certificates to reference new CA
            state.db.migrate_certificates_to_new_ca(ca_id, new_ca_id).await?;
        },
        CertificateAction::Keep => {
            // Keep certificates as-is (they will reference the old, inactive CA)
        }
    }

    // Generate new CRL for the new CA
    let crl_manager = CrlManager::new(state.db.clone());
    let _ = crl_manager.generate_crl_for_ca(new_ca_id, &new_ca.tenant_id).await;

    // Log audit event
    let _ = state.db.log_audit_event(
        "ca.rotate",
        Some(authentication.auth.token.created_by_user_id),
        Some(&authentication.auth.token.tenant_id),
        Some(&ca_id.to_string()),
        Some(&format!("Rotated CA key: {} -> {}", ca_id, new_ca_id)),
    ).await;

    let response = CaRotationResponse {
        old_ca_id: ca_id,
        new_ca_id,
        new_ca: CaResponse::from(new_ca),
        certificates_affected: cert_count,
        rotation_timestamp: chrono::Utc::now().timestamp(),
        chain_preserved: request.preserve_chain.unwrap_or(true),
    };

    Ok(Json(response))
}

#[openapi(tag = "Certificates")]
#[post("/certificates/with-ca", format = "json", data = "<payload>")]
/// Create a certificate with specific CA selection. Requires cert.write scope.
pub(crate) async fn create_certificate_with_ca(
    state: &State<AppState>,
    payload: Json<CreateCertificateWithCaRequest>,
    authentication: BearerCertWrite
) -> Result<Json<Certificate>, ApiError> {
    let request = payload.into_inner();

    // Validate request
    if request.cert_name.trim().is_empty() {
        return Err(ApiError::BadRequest("Certificate name cannot be empty".to_string()));
    }

    // Get CA based on selection criteria
    let ca = match request.ca_selection {
        CaSelection::ById(ca_id) => {
            let ca = state.db.get_ca_by_id(ca_id).await?;
            // Check tenant access
            if ca.tenant_id != authentication.auth.token.tenant_id {
                return Err(ApiError::tenant_access_denied());
            }
            ca
        },
        CaSelection::ByName(ca_name) => {
            state.db.get_ca_by_name(&ca_name, &authentication.auth.token.tenant_id).await?
        },
        CaSelection::Auto => {
            state.db.get_best_ca_for_issuance(
                &authentication.auth.token.tenant_id,
                &request.cert_type.unwrap_or_default()
            ).await?
        }
    };

    // Generate PKCS12 password
    let use_random_password = state.settings.get_pkcs12_password().is_empty();
    let pkcs12_password = get_password(use_random_password, &request.pkcs12_password);

    // Create certificate builder
    let cert_builder = CertificateBuilder::new()?
        .set_name(&request.cert_name)?
        .set_valid_until(request.validity_in_years.unwrap_or(1))?
        .set_renew_method(request.renew_method.unwrap_or_default())?
        .set_pkcs12_password(&pkcs12_password)?
        .set_ca_with_validation(&ca, &request.cert_type.unwrap_or_default())?
        .set_user_id(request.user_id)?;

    // Build certificate based on type
    let mut cert = match request.cert_type.unwrap_or_default() {
        CertificateType::Client => {
            let user = state.db.get_user(request.user_id).await?;
            cert_builder
                .set_email_san(&user.email)?
                .build_client()?
        }
        CertificateType::Server => {
            let dns = request.dns_names.clone().unwrap_or_default();
            cert_builder
                .set_dns_san(&dns)?
                .build_server()?
        }
    };

    // Set additional certificate properties
    cert.tenant_id = authentication.auth.token.tenant_id.clone();
    cert.ca_id = ca.id;

    // Insert certificate into database
    let cert_id = state.db.insert_certificate(cert.clone()).await?;
    cert.id = cert_id;

    // Log audit event
    let _ = state.db.log_audit_event(
        "certificate.create_with_ca",
        Some(authentication.auth.token.created_by_user_id),
        Some(&authentication.auth.token.tenant_id),
        Some(&cert_id.to_string()),
        Some(&format!("Created certificate {} with CA {}", request.cert_name, ca.name.as_deref().unwrap_or("Unknown"))),
    ).await;

    Ok(Json(cert))
}

#[openapi(tag = "Certificate Authorities")]
#[get("/cas/available?<cert_type>")]
/// Get available CAs for certificate issuance. Requires ca.read scope.
pub(crate) async fn get_available_cas(
    state: &State<AppState>,
    cert_type: Option<String>,
    authentication: BearerCaRead
) -> Result<Json<Vec<CaResponse>>, ApiError> {
    // Get active CAs for tenant
    let cas = state.db.get_active_cas_for_tenant(&authentication.auth.token.tenant_id).await?;

    // Filter CAs based on certificate type if specified
    let filtered_cas = if let Some(cert_type_str) = cert_type {
        let cert_type = match cert_type_str.as_str() {
            "client" => CertificateType::Client,
            "server" => CertificateType::Server,
            _ => return Err(ApiError::BadRequest("Invalid certificate type".to_string())),
        };

        cas.into_iter()
            .filter(|ca| {
                // Check if CA is suitable for the certificate type
                if let Some(key_usage) = &ca.key_usage {
                    let key_usage_vec: Vec<String> = serde_json::from_str(key_usage)
                        .unwrap_or_default();
                    key_usage_vec.contains(&"keyCertSign".to_string())
                } else {
                    true // Assume suitable if no key usage specified
                }
            })
            .collect()
    } else {
        cas
    };

    // Convert to response format
    let ca_responses: Vec<CaResponse> = filtered_cas
        .into_iter()
        .map(CaResponse::from)
        .collect();

    Ok(Json(ca_responses))
}

// ===== CERTIFICATE PROFILE ENDPOINTS =====

#[openapi(tag = "Certificate Profiles")]
#[post("/profiles", format = "json", data = "<payload>")]
/// Create a new certificate profile. Requires profile.write scope.
pub(crate) async fn create_profile(
    state: &State<AppState>,
    payload: Json<CreateProfileRequest>,
    authentication: BearerProfileWrite
) -> Result<Json<Profile>, ApiError> {
    let request = payload.into_inner();

    // Validate request
    if request.name.trim().is_empty() {
        return Err(ApiError::BadRequest("Profile name cannot be empty".to_string()));
    }

    if request.max_days < request.default_days {
        return Err(ApiError::BadRequest("Maximum days must be greater than or equal to default days".to_string()));
    }

    if request.eku.is_empty() {
        return Err(ApiError::BadRequest("Extended Key Usage (EKU) cannot be empty".to_string()));
    }

    if request.key_usage.is_empty() {
        return Err(ApiError::BadRequest("Key Usage cannot be empty".to_string()));
    }

    // Check if profile name already exists for this tenant
    if let Ok(_) = state.db.get_profile_by_name(&request.name, &authentication.auth.token.tenant_id).await {
        return Err(ApiError::resource_already_exists("Profile", &request.name));
    }

    // Create profile
    let mut profile = Profile::new(
        request.name.clone(),
        request.eku,
        request.key_usage,
        request.default_days,
        request.max_days,
        request.key_alg_options,
        authentication.auth.token.tenant_id.clone(),
    );

    // Set optional fields
    profile.san_rules = request.san_rules;
    if let Some(renewal_window) = request.renewal_window_pct {
        profile.renewal_window_pct = renewal_window;
    }

    // Insert into database
    state.db.insert_profile(&profile).await?;

    // Log audit event
    let _ = state.db.log_audit_event(
        "profile.create",
        Some(authentication.auth.token.created_by_user_id),
        Some(&authentication.auth.token.tenant_id),
        Some(&profile.id),
        Some(&format!("Created profile: {}", request.name)),
    ).await;

    Ok(Json(profile))
}

#[openapi(tag = "Certificate Profiles")]
#[get("/profiles?<page>&<per_page>")]
/// List certificate profiles for the current tenant. Requires profile.read scope.
pub(crate) async fn list_profiles(
    state: &State<AppState>,
    page: Option<i32>,
    per_page: Option<i32>,
    authentication: BearerProfileRead
) -> Result<Json<ProfileListResponse>, ApiError> {
    let page = page.unwrap_or(1).max(1);
    let per_page = per_page.unwrap_or(20).min(100).max(1);

    // Get profiles for tenant
    let profiles = state.db.get_profiles_for_tenant(&authentication.auth.token.tenant_id).await?;

    // Apply pagination
    let total = profiles.len() as i64;
    let start = ((page - 1) * per_page) as usize;
    let end = (start + per_page as usize).min(profiles.len());
    let paginated_profiles = profiles[start..end].to_vec();

    let response = ProfileListResponse {
        profiles: paginated_profiles,
        total,
        page,
        per_page,
        has_more: end < profiles.len(),
    };

    Ok(Json(response))
}

#[openapi(tag = "Certificate Profiles")]
#[get("/profiles/<profile_id>")]
/// Get certificate profile details. Requires profile.read scope.
pub(crate) async fn get_profile(
    state: &State<AppState>,
    profile_id: String,
    authentication: BearerProfileRead
) -> Result<Json<Profile>, ApiError> {
    // Get profile
    let profile = state.db.get_profile_by_id(&profile_id).await?;

    // Check tenant access
    if profile.tenant_id != authentication.auth.token.tenant_id {
        return Err(ApiError::tenant_access_denied());
    }

    Ok(Json(profile))
}

#[openapi(tag = "Certificate Profiles")]
#[patch("/profiles/<profile_id>", format = "json", data = "<payload>")]
/// Update certificate profile. Requires profile.write scope.
pub(crate) async fn update_profile(
    state: &State<AppState>,
    profile_id: String,
    payload: Json<UpdateProfileRequest>,
    authentication: BearerProfileWrite
) -> Result<Json<Profile>, ApiError> {
    let request = payload.into_inner();

    // Get existing profile
    let mut profile = state.db.get_profile_by_id(&profile_id).await?;

    // Check tenant access
    if profile.tenant_id != authentication.auth.token.tenant_id {
        return Err(ApiError::tenant_access_denied());
    }

    // Update fields
    if let Some(name) = request.name {
        if name.trim().is_empty() {
            return Err(ApiError::BadRequest("Profile name cannot be empty".to_string()));
        }

        // Check if new name conflicts with existing profile
        if name != profile.name {
            if let Ok(_) = state.db.get_profile_by_name(&name, &authentication.auth.token.tenant_id).await {
                return Err(ApiError::resource_already_exists("Profile", &name));
            }
        }

        profile.name = name;
    }

    if let Some(eku) = request.eku {
        if eku.is_empty() {
            return Err(ApiError::BadRequest("Extended Key Usage (EKU) cannot be empty".to_string()));
        }
        profile.eku = eku;
    }

    if let Some(key_usage) = request.key_usage {
        if key_usage.is_empty() {
            return Err(ApiError::BadRequest("Key Usage cannot be empty".to_string()));
        }
        profile.key_usage = key_usage;
    }

    if let Some(san_rules) = request.san_rules {
        profile.san_rules = Some(san_rules);
    }

    if let Some(default_days) = request.default_days {
        if default_days > profile.max_days {
            return Err(ApiError::BadRequest("Default days cannot be greater than maximum days".to_string()));
        }
        profile.default_days = default_days;
    }

    if let Some(max_days) = request.max_days {
        if max_days < profile.default_days {
            return Err(ApiError::BadRequest("Maximum days must be greater than or equal to default days".to_string()));
        }
        profile.max_days = max_days;
    }

    if let Some(renewal_window_pct) = request.renewal_window_pct {
        if renewal_window_pct < 1 || renewal_window_pct > 100 {
            return Err(ApiError::BadRequest("Renewal window percentage must be between 1 and 100".to_string()));
        }
        profile.renewal_window_pct = renewal_window_pct;
    }

    if let Some(key_alg_options) = request.key_alg_options {
        if key_alg_options.is_empty() {
            return Err(ApiError::BadRequest("Key algorithm options cannot be empty".to_string()));
        }
        profile.key_alg_options = key_alg_options;
    }

    // Update in database
    state.db.update_profile(&profile).await?;

    // Log audit event
    let _ = state.db.log_audit_event(
        "profile.update",
        Some(authentication.auth.token.created_by_user_id),
        Some(&authentication.auth.token.tenant_id),
        Some(&profile.id),
        Some(&format!("Updated profile: {}", profile.name)),
    ).await;

    Ok(Json(profile))
}

#[openapi(tag = "Certificate Profiles")]
#[delete("/profiles/<profile_id>")]
/// Delete certificate profile. Requires profile.write scope.
pub(crate) async fn delete_profile(
    state: &State<AppState>,
    profile_id: String,
    authentication: BearerProfileWrite
) -> Result<(), ApiError> {
    // Get profile to check ownership
    let profile = state.db.get_profile_by_id(&profile_id).await?;

    // Check tenant access
    if profile.tenant_id != authentication.auth.token.tenant_id {
        return Err(ApiError::tenant_access_denied());
    }

    // Check if profile is in use by any certificates
    let cert_count = state.db.get_certificate_count_for_profile(&profile_id).await?;
    if cert_count > 0 {
        return Err(ApiError::Conflict(
            format!("Cannot delete profile '{}' as it is used by {} certificates", profile.name, cert_count)
        ));
    }

    // Delete from database
    state.db.delete_profile(&profile_id).await?;

    // Log audit event
    let _ = state.db.log_audit_event(
        "profile.delete",
        Some(authentication.auth.token.created_by_user_id),
        Some(&authentication.auth.token.tenant_id),
        Some(&profile.id),
        Some(&format!("Deleted profile: {}", profile.name)),
    ).await;

    Ok(())
}

// ===== ENHANCED CERTIFICATE MANAGEMENT ENDPOINTS =====

#[openapi(tag = "Certificates")]
#[post("/certificates/search", format = "json", data = "<payload>")]
/// Advanced certificate search with filters and operators. Requires cert.read scope.
pub(crate) async fn search_certificates(
    state: &State<AppState>,
    payload: Json<CertificateSearchRequest>,
    authentication: BearerCertRead
) -> Result<Json<CertificateSearchResponse>, ApiError> {
    let request = payload.into_inner();

    // Build search query
    let search_result = state.db.search_certificates(
        &authentication.auth.token.tenant_id,
        &request
    ).await?;

    // Log audit event for search
    let _ = state.db.log_audit_event(
        "certificate.search",
        Some(authentication.auth.token.created_by_user_id),
        Some(&authentication.auth.token.tenant_id),
        None,
        Some(&format!("Certificate search with {} filters",
            request.filters.as_ref().map(|f| f.len()).unwrap_or(0))),
    ).await;

    Ok(Json(search_result))
}

#[openapi(tag = "Certificates")]
#[post("/certificates/batch", format = "json", data = "<payload>")]
/// Perform batch operations on certificates. Requires cert.write scope.
pub(crate) async fn batch_certificate_operation(
    state: &State<AppState>,
    payload: Json<BatchOperationRequest>,
    authentication: BearerCertWrite
) -> Result<Json<BatchOperationResponse>, ApiError> {
    let request = payload.into_inner();

    // Validate certificate IDs belong to tenant
    for cert_id in &request.certificate_ids {
        let cert = state.db.get_certificate(*cert_id).await?;
        if cert.tenant_id != authentication.auth.token.tenant_id {
            return Err(ApiError::tenant_access_denied());
        }
    }

    // Perform batch operation
    let result = state.db.execute_batch_operation(
        &request,
        authentication.auth.token.created_by_user_id,
        &authentication.auth.token.tenant_id
    ).await?;

    // Log audit event
    let _ = state.db.log_audit_event(
        "certificate.batch_operation",
        Some(authentication.auth.token.created_by_user_id),
        Some(&authentication.auth.token.tenant_id),
        None,
        Some(&format!("Batch {:?} operation on {} certificates",
            request.operation, request.certificate_ids.len())),
    ).await;

    Ok(Json(result))
}

#[openapi(tag = "Certificates")]
#[get("/certificates/<cert_id>/chain")]
/// Get certificate chain information. Requires cert.read scope.
pub(crate) async fn get_certificate_chain(
    state: &State<AppState>,
    cert_id: i64,
    authentication: BearerCertRead
) -> Result<Json<crate::cert::CertificateChain>, ApiError> {
    // Get certificate and verify tenant access
    let cert = state.db.get_certificate(cert_id).await?;
    if cert.tenant_id != authentication.auth.token.tenant_id {
        return Err(ApiError::tenant_access_denied());
    }

    // Build certificate chain
    let chain = state.db.build_certificate_chain(cert_id).await?;

    Ok(Json(chain))
}

#[openapi(tag = "Certificates")]
#[post("/certificates/<cert_id>/validate-chain", format = "json", data = "<payload>")]
/// Validate certificate chain. Requires cert.read scope.
pub(crate) async fn validate_certificate_chain(
    state: &State<AppState>,
    cert_id: i64,
    payload: Json<ChainValidationRequest>,
    authentication: BearerCertRead
) -> Result<Json<ChainValidationResponse>, ApiError> {
    let request = payload.into_inner();

    // Get certificate and verify tenant access
    let cert = state.db.get_certificate(cert_id).await?;
    if cert.tenant_id != authentication.auth.token.tenant_id {
        return Err(ApiError::tenant_access_denied());
    }

    // Validate chain
    let validation_result = state.db.validate_certificate_chain(cert_id, &request).await?;

    // Log audit event
    let _ = state.db.log_audit_event(
        "certificate.validate_chain",
        Some(authentication.auth.token.created_by_user_id),
        Some(&authentication.auth.token.tenant_id),
        Some(&cert_id.to_string()),
        Some(&format!("Validated certificate chain for {}", cert.name)),
    ).await;

    Ok(Json(validation_result))
}

#[openapi(tag = "Certificates")]
#[get("/certificates/expiring?<days_ahead>&<page>&<per_page>")]
/// Get certificates expiring within specified days. Requires cert.read scope.
pub(crate) async fn get_expiring_certificates(
    state: &State<AppState>,
    days_ahead: Option<i32>,
    page: Option<i32>,
    per_page: Option<i32>,
    authentication: BearerCertRead
) -> Result<Json<CertificateSearchResponse>, ApiError> {
    let days_ahead = days_ahead.unwrap_or(30);
    let page = page.unwrap_or(1).max(1);
    let per_page = per_page.unwrap_or(20).min(100).max(1);

    // Calculate expiry threshold
    let threshold = chrono::Utc::now().timestamp() + (days_ahead as i64 * 24 * 60 * 60);

    // Get expiring certificates
    let result = state.db.get_expiring_certificates(
        &authentication.auth.token.tenant_id,
        threshold,
        page,
        per_page
    ).await?;

    Ok(Json(result))
}

#[openapi(tag = "Certificates")]
#[get("/certificates/statistics")]
/// Get certificate statistics for the tenant. Requires cert.read scope.
pub(crate) async fn get_certificate_statistics(
    state: &State<AppState>,
    authentication: BearerCertRead
) -> Result<Json<CertificateStatistics>, ApiError> {
    let stats = state.db.get_certificate_statistics(&authentication.auth.token.tenant_id).await?;
    Ok(Json(stats))
}

#[openapi(tag = "Certificates")]
#[post("/certificates/bulk-download", format = "json", data = "<payload>")]
/// Download multiple certificates as ZIP archive. Requires cert.read scope.
pub(crate) async fn bulk_download_certificates(
    state: &State<AppState>,
    payload: Json<BulkDownloadRequest>,
    authentication: BearerCertRead
) -> Result<DownloadResponse, ApiError> {
    let request = payload.into_inner();

    // Validate certificate IDs belong to tenant
    for cert_id in &request.certificate_ids {
        let cert = state.db.get_certificate(*cert_id).await?;
        if cert.tenant_id != authentication.auth.token.tenant_id {
            return Err(ApiError::tenant_access_denied());
        }
    }

    // Create ZIP archive
    let zip_data = state.db.create_certificate_zip_archive(
        &request.certificate_ids,
        &request.format.unwrap_or_else(|| "pem".to_string()),
        request.include_chain.unwrap_or(false)
    ).await?;

    // Log audit event
    let _ = state.db.log_audit_event(
        "certificate.bulk_download",
        Some(authentication.auth.token.created_by_user_id),
        Some(&authentication.auth.token.tenant_id),
        None,
        Some(&format!("Bulk download of {} certificates", request.certificate_ids.len())),
    ).await;

    let filename = format!("certificates_{}.zip", chrono::Utc::now().format("%Y%m%d_%H%M%S"));

    Ok(DownloadResponse {
        content_type: "application/zip".to_string(),
        filename,
        body: zip_data,
    })
}

// ===== AUDIT LOGGING & REPORTING ENDPOINTS =====

#[openapi(tag = "Audit")]
#[get("/audit/events?<event_type>&<resource_type>&<resource_id>&<user_id>&<start_date>&<end_date>&<page>&<per_page>")]
/// Get audit events with filtering. Requires audit.read scope.
pub(crate) async fn get_audit_events(
    state: &State<AppState>,
    event_type: Option<String>,
    resource_type: Option<String>,
    resource_id: Option<String>,
    user_id: Option<i64>,
    start_date: Option<i64>,
    end_date: Option<i64>,
    page: Option<i32>,
    per_page: Option<i32>,
    authentication: BearerAuditRead
) -> Result<Json<AuditEventListResponse>, ApiError> {
    let page = page.unwrap_or(1).max(1);
    let per_page = per_page.unwrap_or(50).min(1000).max(1);
    let offset = (page - 1) * per_page;

    // Get audit events for tenant
    let events = state.db.get_audit_events(
        Some(&authentication.auth.token.tenant_id),
        event_type.as_deref(),
        resource_type.as_deref(),
        start_date,
        end_date,
        Some(per_page),
        Some(offset),
    ).await?;

    // Get total count
    let total = state.db.count_audit_events(
        Some(&authentication.auth.token.tenant_id),
        event_type.as_deref(),
        resource_type.as_deref(),
        start_date,
        end_date,
    ).await?;

    let response = AuditEventListResponse {
        events,
        total,
        page,
        per_page,
        has_more: offset + per_page < total as i32,
    };

    Ok(Json(response))
}

#[openapi(tag = "Audit")]
#[post("/audit/events/search", format = "json", data = "<payload>")]
/// Advanced audit event search. Requires audit.read scope.
pub(crate) async fn search_audit_events(
    state: &State<AppState>,
    payload: Json<AuditEventQuery>,
    authentication: BearerAuditRead
) -> Result<Json<AuditEventListResponse>, ApiError> {
    let query = payload.into_inner();

    // Ensure tenant isolation
    let mut tenant_query = query;
    tenant_query.tenant_id = Some(authentication.auth.token.tenant_id.clone());

    let events = state.db.search_audit_events(&tenant_query).await?;
    let total = state.db.count_audit_events_by_query(&tenant_query).await?;

    let page = tenant_query.page.unwrap_or(1);
    let per_page = tenant_query.page_size.unwrap_or(50);

    let response = AuditEventListResponse {
        events,
        total,
        page,
        per_page,
        has_more: (page * per_page) < total as i32,
    };

    Ok(Json(response))
}

#[openapi(tag = "Audit")]
#[get("/audit/statistics?<days>&<resource_type>")]
/// Get audit statistics for the tenant. Requires audit.read scope.
pub(crate) async fn get_audit_statistics(
    state: &State<AppState>,
    days: Option<i32>,
    resource_type: Option<String>,
    authentication: BearerAuditRead
) -> Result<Json<AuditStatistics>, ApiError> {
    let days = days.unwrap_or(30).min(365).max(1);
    let start_date = chrono::Utc::now().timestamp() - (days as i64 * 24 * 60 * 60);

    let stats = state.db.get_audit_statistics(
        &authentication.auth.token.tenant_id,
        start_date,
        resource_type.as_deref(),
    ).await?;

    Ok(Json(stats))
}

#[openapi(tag = "Audit")]
#[get("/audit/activity?<hours>")]
/// Get recent activity timeline. Requires audit.read scope.
pub(crate) async fn get_audit_activity(
    state: &State<AppState>,
    hours: Option<i32>,
    authentication: BearerAuditRead
) -> Result<Json<AuditActivityResponse>, ApiError> {
    let hours = hours.unwrap_or(24).min(168).max(1); // Max 1 week
    let start_date = chrono::Utc::now().timestamp() - (hours as i64 * 60 * 60);

    let activity = state.db.get_audit_activity(
        &authentication.auth.token.tenant_id,
        start_date,
    ).await?;

    Ok(Json(activity))
}

#[openapi(tag = "Audit")]
#[post("/audit/export", format = "json", data = "<payload>")]
/// Export audit events as CSV. Requires audit.read scope.
pub(crate) async fn export_audit_events(
    state: &State<AppState>,
    payload: Json<AuditExportRequest>,
    authentication: BearerAuditRead
) -> Result<DownloadResponse, ApiError> {
    let request = payload.into_inner();

    // Ensure tenant isolation
    let mut query = request.query;
    query.tenant_id = Some(authentication.auth.token.tenant_id.clone());

    // Get events for export
    let events = state.db.search_audit_events(&query).await?;

    // Generate CSV
    let csv_data = state.db.generate_audit_csv(&events, &request.fields).await?;

    // Log audit event for export
    let _ = state.db.log_audit_event(
        "audit.export",
        Some(authentication.auth.token.created_by_user_id),
        Some(&authentication.auth.token.tenant_id),
        None,
        Some(&format!("Exported {} audit events", events.len())),
    ).await;

    let filename = format!("audit_export_{}.csv", chrono::Utc::now().format("%Y%m%d_%H%M%S"));

    Ok(DownloadResponse {
        content_type: "text/csv".to_string(),
        filename,
        body: csv_data.into_bytes(),
    })
}

#[openapi(tag = "Audit")]
#[get("/audit/compliance-report?<start_date>&<end_date>&<format>")]
/// Generate compliance report. Requires audit.read scope.
pub(crate) async fn generate_compliance_report(
    state: &State<AppState>,
    start_date: Option<i64>,
    end_date: Option<i64>,
    format: Option<String>,
    authentication: BearerAuditRead
) -> Result<DownloadResponse, ApiError> {
    let end_date = end_date.unwrap_or_else(|| chrono::Utc::now().timestamp());
    let start_date = start_date.unwrap_or(end_date - (30 * 24 * 60 * 60)); // Default 30 days
    let format = format.unwrap_or_else(|| "pdf".to_string()).to_lowercase();

    let report = state.db.generate_compliance_report(
        &authentication.auth.token.tenant_id,
        start_date,
        end_date,
        &format,
    ).await?;

    // Log audit event for compliance report
    let _ = state.db.log_audit_event(
        "audit.compliance_report",
        Some(authentication.auth.token.created_by_user_id),
        Some(&authentication.auth.token.tenant_id),
        None,
        Some(&format!("Generated compliance report for {} to {}",
            chrono::DateTime::from_timestamp(start_date, 0).unwrap().format("%Y-%m-%d"),
            chrono::DateTime::from_timestamp(end_date, 0).unwrap().format("%Y-%m-%d"))),
    ).await;

    let filename = format!("compliance_report_{}_{}.{}",
        chrono::DateTime::from_timestamp(start_date, 0).unwrap().format("%Y%m%d"),
        chrono::DateTime::from_timestamp(end_date, 0).unwrap().format("%Y%m%d"),
        format);

    let content_type = match format.as_str() {
        "pdf" => "application/pdf",
        "html" => "text/html",
        "json" => "application/json",
        _ => "application/octet-stream",
    };

    Ok(DownloadResponse {
        content_type: content_type.to_string(),
        filename,
        body: report,
    })
}

// ===== PROTECTED API DOCUMENTATION ENDPOINTS =====

#[get("/")]
/// Protected RapiDoc documentation (requires authentication)
pub(crate) async fn protected_rapidoc(
    _authentication: BearerAuthenticated
) -> rocket::response::content::RawHtml<String> {
    let html = format!(r#"
<!DOCTYPE html>
<html>
<head>
    <title>VaulTLS API Documentation</title>
    <meta charset="utf-8">
    <script type="module" src="https://unpkg.com/rapidoc/dist/rapidoc-min.js"></script>
</head>
<body>
    <rapi-doc
        spec-url="/api/openapi.json"
        theme="dark"
        render-style="read"
        layout="column"
        schema-style="tree"
        allow-try="true"
        allow-server-selection="true"
        show-header="true"
        show-info="true"
        show-components="true"
        response-area-height="400px">
        <div slot="nav-logo">
            <h2>🔒 VaulTLS API</h2>
            <p>Protected Documentation</p>
        </div>
    </rapi-doc>
</body>
</html>
"#);
    rocket::response::content::RawHtml(html)
}

#[get("/")]
/// Protected Redoc documentation (requires authentication)
pub(crate) async fn protected_redoc(
    _authentication: BearerAuthenticated
) -> rocket::response::content::RawHtml<String> {
    let html = format!(r#"
<!DOCTYPE html>
<html>
<head>
    <title>VaulTLS API Documentation</title>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <link href="https://fonts.googleapis.com/css?family=Montserrat:300,400,700|Roboto:300,400,700" rel="stylesheet">
    <style>
        body {{ margin: 0; padding: 0; }}
        .redoc-container {{ padding: 20px; }}
        .auth-notice {{
            background: #1a1a1a;
            color: #fff;
            padding: 10px 20px;
            text-align: center;
            font-family: 'Roboto', sans-serif;
        }}
    </style>
</head>
<body>
    <div class="auth-notice">
        🔒 Protected VaulTLS API Documentation - Authentication Required
    </div>
    <div id="redoc-container" class="redoc-container"></div>
    <script src="https://cdn.redoc.ly/redoc/latest/bundles/redoc.standalone.js"></script>
    <script>
        Redoc.init('/api/openapi.json', {{
            theme: {{
                colors: {{
                    primary: {{ main: '#3b82f6' }}
                }}
            }}
        }}, document.getElementById('redoc-container'));
    </script>
</body>
</html>
"#);
    rocket::response::content::RawHtml(html)
}

#[get("/")]
/// Protected OpenAPI specification (requires authentication)
pub(crate) async fn protected_openapi_spec(
    _authentication: BearerAuthenticated
) -> rocket::serde::json::Json<rocket_okapi::okapi::openapi3::OpenApi> {
    // Return the OpenAPI specification
    // This would need to be generated from the actual OpenAPI spec
    // For now, return a minimal spec
    use rocket_okapi::okapi::openapi3::*;

    let spec = OpenApi {
        openapi: "3.1.0".to_string(),
        info: Info {
            title: "VaulTLS API".to_string(),
            version: "1.0.0".to_string(),
            description: Some("Protected VaulTLS Certificate Management API".to_string()),
            ..Default::default()
        },
        servers: vec![
            Server {
                url: "/api".to_string(),
                description: Some("VaulTLS API Server".to_string()),
                ..Default::default()
            }
        ],
        paths: Default::default(),
        components: Some(Components {
            security_schemes: {
                let mut schemes = std::collections::BTreeMap::new();
                schemes.insert(
                    "BearerAuth".to_string(),
                    ReferenceOr::Object(SecurityScheme {
                        scheme_type: SecuritySchemeType::Http {
                            scheme: "bearer".to_string(),
                            bearer_format: Some("JWT".to_string()),
                        },
                        description: Some("Bearer token authentication".to_string()),
                        ..Default::default()
                    })
                );
                schemes
            },
            ..Default::default()
        }),
        ..Default::default()
    };

    rocket::serde::json::Json(spec)
}

// ===== CERTIFICATE TEMPLATE ENDPOINTS =====

#[openapi(tag = "Certificate Templates")]
#[post("/templates", format = "json", data = "<payload>")]
/// Create a new certificate template. Requires cert.write scope.
pub(crate) async fn create_certificate_template(
    state: &State<AppState>,
    payload: Json<CreateCertificateTemplateRequest>,
    authentication: BearerCertWrite
) -> Result<Json<CertificateTemplate>, ApiError> {
    let request = payload.into_inner();

    // Validate request
    if request.name.trim().is_empty() {
        return Err(ApiError::BadRequest("Template name cannot be empty".to_string()));
    }

    if request.default_validity_years < 1 || request.default_validity_years > 10 {
        return Err(ApiError::BadRequest("Validity years must be between 1 and 10".to_string()));
    }

    // Check if template name already exists for this tenant
    if let Ok(_) = state.db.get_template_by_name(&request.name, &authentication.auth.token.tenant_id).await {
        return Err(ApiError::resource_already_exists("Template", &request.name));
    }

    // Validate profile exists
    let _profile = state.db.get_profile_by_id(&request.profile_id).await?;

    // Create template
    let template = CertificateTemplate {
        id: uuid::Uuid::new_v4().to_string(),
        name: request.name.clone(),
        description: request.description,
        certificate_type: request.certificate_type,
        profile_id: request.profile_id,
        default_validity_years: request.default_validity_years,
        default_key_algorithm: request.default_key_algorithm,
        san_template: request.san_template,
        metadata_template: request.metadata_template,
        tenant_id: authentication.auth.token.tenant_id.clone(),
        created_at: chrono::Utc::now().timestamp(),
    };

    // Insert into database
    state.db.insert_certificate_template(&template).await?;

    // Log audit event
    let _ = state.db.log_audit_event(
        "template.create",
        Some(authentication.auth.token.created_by_user_id),
        Some(&authentication.auth.token.tenant_id),
        Some(&template.id),
        Some(&format!("Created certificate template: {}", request.name)),
    ).await;

    Ok(Json(template))
}

#[openapi(tag = "Certificate Templates")]
#[get("/templates?<page>&<per_page>")]
/// List certificate templates for the current tenant. Requires cert.read scope.
pub(crate) async fn list_certificate_templates(
    state: &State<AppState>,
    page: Option<i32>,
    per_page: Option<i32>,
    authentication: BearerCertRead
) -> Result<Json<CertificateTemplateListResponse>, ApiError> {
    let page = page.unwrap_or(1).max(1);
    let per_page = per_page.unwrap_or(20).min(100).max(1);

    // Get templates for tenant
    let templates = state.db.get_templates_for_tenant(&authentication.auth.token.tenant_id).await?;

    // Apply pagination
    let total = templates.len() as i64;
    let start = ((page - 1) * per_page) as usize;
    let end = (start + per_page as usize).min(templates.len());
    let paginated_templates = templates[start..end].to_vec();

    let response = CertificateTemplateListResponse {
        templates: paginated_templates,
        total,
        page,
        per_page,
        has_more: end < templates.len(),
    };

    Ok(Json(response))
}

#[openapi(tag = "Certificate Templates")]
#[get("/templates/<template_id>")]
/// Get certificate template details. Requires cert.read scope.
pub(crate) async fn get_certificate_template(
    state: &State<AppState>,
    template_id: String,
    authentication: BearerCertRead
) -> Result<Json<CertificateTemplate>, ApiError> {
    // Get template
    let template = state.db.get_certificate_template_by_id(&template_id).await?;

    // Check tenant access
    if template.tenant_id != authentication.auth.token.tenant_id {
        return Err(ApiError::tenant_access_denied());
    }

    Ok(Json(template))
}

#[openapi(tag = "Certificate Templates")]
#[patch("/templates/<template_id>", format = "json", data = "<payload>")]
/// Update certificate template. Requires cert.write scope.
pub(crate) async fn update_certificate_template(
    state: &State<AppState>,
    template_id: String,
    payload: Json<UpdateCertificateTemplateRequest>,
    authentication: BearerCertWrite
) -> Result<Json<CertificateTemplate>, ApiError> {
    let request = payload.into_inner();

    // Get existing template
    let mut template = state.db.get_certificate_template_by_id(&template_id).await?;

    // Check tenant access
    if template.tenant_id != authentication.auth.token.tenant_id {
        return Err(ApiError::tenant_access_denied());
    }

    // Update fields
    if let Some(name) = request.name {
        if name.trim().is_empty() {
            return Err(ApiError::BadRequest("Template name cannot be empty".to_string()));
        }

        // Check if new name conflicts with existing template
        if name != template.name {
            if let Ok(_) = state.db.get_template_by_name(&name, &authentication.auth.token.tenant_id).await {
                return Err(ApiError::resource_already_exists("Template", &name));
            }
        }

        template.name = name;
    }

    if let Some(description) = request.description {
        template.description = description;
    }

    if let Some(certificate_type) = request.certificate_type {
        template.certificate_type = certificate_type;
    }

    if let Some(profile_id) = request.profile_id {
        // Validate profile exists
        let _profile = state.db.get_profile_by_id(&profile_id).await?;
        template.profile_id = profile_id;
    }

    if let Some(validity_years) = request.default_validity_years {
        if validity_years < 1 || validity_years > 10 {
            return Err(ApiError::BadRequest("Validity years must be between 1 and 10".to_string()));
        }
        template.default_validity_years = validity_years;
    }

    if let Some(key_algorithm) = request.default_key_algorithm {
        template.default_key_algorithm = key_algorithm;
    }

    if let Some(san_template) = request.san_template {
        template.san_template = Some(san_template);
    }

    if let Some(metadata_template) = request.metadata_template {
        template.metadata_template = Some(metadata_template);
    }

    // Update in database
    state.db.update_certificate_template(&template).await?;

    // Log audit event
    let _ = state.db.log_audit_event(
        "template.update",
        Some(authentication.auth.token.created_by_user_id),
        Some(&authentication.auth.token.tenant_id),
        Some(&template.id),
        Some(&format!("Updated certificate template: {}", template.name)),
    ).await;

    Ok(Json(template))
}

#[openapi(tag = "Certificate Templates")]
#[delete("/templates/<template_id>")]
/// Delete certificate template. Requires cert.write scope.
pub(crate) async fn delete_certificate_template(
    state: &State<AppState>,
    template_id: String,
    authentication: BearerCertWrite
) -> Result<(), ApiError> {
    // Get template to check ownership
    let template = state.db.get_certificate_template_by_id(&template_id).await?;

    // Check tenant access
    if template.tenant_id != authentication.auth.token.tenant_id {
        return Err(ApiError::tenant_access_denied());
    }

    // Check if template is in use
    let usage_count = state.db.get_certificate_count_for_template(&template_id).await?;
    if usage_count > 0 {
        return Err(ApiError::Conflict(
            format!("Cannot delete template '{}' as it is used by {} certificates", template.name, usage_count)
        ));
    }

    // Delete from database
    state.db.delete_certificate_template(&template_id).await?;

    // Log audit event
    let _ = state.db.log_audit_event(
        "template.delete",
        Some(authentication.auth.token.created_by_user_id),
        Some(&authentication.auth.token.tenant_id),
        Some(&template.id),
        Some(&format!("Deleted certificate template: {}", template.name)),
    ).await;

    Ok(())
}

#[openapi(tag = "Certificate Templates")]
#[post("/templates/<template_id>/certificates", format = "json", data = "<payload>")]
/// Create certificate from template. Requires cert.write scope.
pub(crate) async fn create_certificate_from_template(
    state: &State<AppState>,
    template_id: String,
    payload: Json<CreateCertificateFromTemplateRequest>,
    authentication: BearerCertWrite
) -> Result<Json<Certificate>, ApiError> {
    let request = payload.into_inner();

    // Get template
    let template = state.db.get_certificate_template_by_id(&template_id).await?;

    // Check tenant access
    if template.tenant_id != authentication.auth.token.tenant_id {
        return Err(ApiError::tenant_access_denied());
    }

    // Process template variables and create certificate
    let processed_san = if let Some(san_template) = &template.san_template {
        if let Some(variables) = &request.template_variables {
            state.db.process_template_variables(san_template, variables).await?
        } else {
            san_template.clone()
        }
    } else {
        String::new()
    };

    // Create certificate using template settings
    let validity_years = request.validity_years.unwrap_or(template.default_validity_years);

    // Build certificate request from template
    let cert_request = CreateCertificateWithCaRequest {
        name: request.name,
        user_id: request.user_id,
        certificate_type: template.certificate_type.clone(),
        validity_years,
        ca_selection: request.ca_selection.unwrap_or(CaSelection::Auto),
        profile_id: Some(template.profile_id.clone()),
        sans: if processed_san.is_empty() { None } else { Some(processed_san) },
        metadata: template.metadata_template.clone(),
    };

    // Create the certificate
    let certificate = state.db.create_certificate_with_ca(&cert_request, &authentication.auth.token.tenant_id).await?;

    // Log audit event
    let _ = state.db.log_audit_event(
        "certificate.create_from_template",
        Some(authentication.auth.token.created_by_user_id),
        Some(&authentication.auth.token.tenant_id),
        Some(&certificate.id.to_string()),
        Some(&format!("Created certificate '{}' from template '{}'", certificate.name, template.name)),
    ).await;

    // Trigger webhook notification
    let _ = state.webhook_service.trigger_certificate_event(
        WebhookEvent::CertificateCreated,
        &certificate,
        &authentication.auth.token.tenant_id
    ).await;

    Ok(Json(certificate))
}

// ===== WEBHOOK ENDPOINTS =====

#[openapi(tag = "Webhooks")]
#[post("/webhooks", format = "json", data = "<payload>")]
/// Create a new webhook configuration. Requires admin scope.
pub(crate) async fn create_webhook(
    state: &State<AppState>,
    payload: Json<CreateWebhookRequest>,
    authentication: BearerTokenAdmin
) -> Result<Json<WebhookConfig>, ApiError> {
    let request = payload.into_inner();

    // Validate request
    if request.name.trim().is_empty() {
        return Err(ApiError::BadRequest("Webhook name cannot be empty".to_string()));
    }

    if !request.url.starts_with("http://") && !request.url.starts_with("https://") {
        return Err(ApiError::BadRequest("Webhook URL must be a valid HTTP/HTTPS URL".to_string()));
    }

    if request.events.is_empty() {
        return Err(ApiError::BadRequest("At least one webhook event must be specified".to_string()));
    }

    // Check if webhook name already exists for this tenant
    if let Ok(_) = state.db.get_webhook_by_name(&request.name, &authentication.auth.token.tenant_id).await {
        return Err(ApiError::resource_already_exists("Webhook", &request.name));
    }

    // Create webhook
    let webhook = WebhookConfig {
        id: uuid::Uuid::new_v4().to_string(),
        name: request.name.clone(),
        url: request.url,
        events: request.events,
        secret: request.secret,
        headers: request.headers,
        timeout_seconds: request.timeout_seconds.unwrap_or(30),
        retry_attempts: request.retry_attempts.unwrap_or(3),
        is_active: true,
        tenant_id: authentication.auth.token.tenant_id.clone(),
        created_at: chrono::Utc::now().timestamp(),
        last_triggered: None,
        success_count: 0,
        failure_count: 0,
    };

    // Insert into database
    state.db.insert_webhook(&webhook).await?;

    // Log audit event
    let _ = state.db.log_audit_event(
        "webhook.create",
        Some(authentication.auth.token.created_by_user_id),
        Some(&authentication.auth.token.tenant_id),
        Some(&webhook.id),
        Some(&format!("Created webhook: {}", request.name)),
    ).await;

    Ok(Json(webhook))
}

#[openapi(tag = "Webhooks")]
#[get("/webhooks?<page>&<per_page>")]
/// List webhook configurations for the current tenant. Requires admin scope.
pub(crate) async fn list_webhooks(
    state: &State<AppState>,
    page: Option<i32>,
    per_page: Option<i32>,
    authentication: BearerTokenAdmin
) -> Result<Json<WebhookListResponse>, ApiError> {
    let page = page.unwrap_or(1).max(1);
    let per_page = per_page.unwrap_or(20).min(100).max(1);

    // Get webhooks for tenant
    let webhooks = state.db.get_webhooks_for_tenant(&authentication.auth.token.tenant_id).await?;

    // Apply pagination
    let total = webhooks.len() as i64;
    let start = ((page - 1) * per_page) as usize;
    let end = (start + per_page as usize).min(webhooks.len());
    let paginated_webhooks = webhooks[start..end].to_vec();

    let response = WebhookListResponse {
        webhooks: paginated_webhooks,
        total,
        page,
        per_page,
        has_more: end < webhooks.len(),
    };

    Ok(Json(response))
}

#[openapi(tag = "Webhooks")]
#[get("/webhooks/<webhook_id>")]
/// Get webhook configuration details. Requires admin scope.
pub(crate) async fn get_webhook(
    state: &State<AppState>,
    webhook_id: String,
    authentication: BearerTokenAdmin
) -> Result<Json<WebhookConfig>, ApiError> {
    // Get webhook
    let webhook = state.db.get_webhook_by_id(&webhook_id).await?;

    // Check tenant access
    if webhook.tenant_id != authentication.auth.token.tenant_id {
        return Err(ApiError::tenant_access_denied());
    }

    Ok(Json(webhook))
}

#[openapi(tag = "Webhooks")]
#[patch("/webhooks/<webhook_id>", format = "json", data = "<payload>")]
/// Update webhook configuration. Requires admin scope.
pub(crate) async fn update_webhook(
    state: &State<AppState>,
    webhook_id: String,
    payload: Json<UpdateWebhookRequest>,
    authentication: BearerTokenAdmin
) -> Result<Json<WebhookConfig>, ApiError> {
    let request = payload.into_inner();

    // Get existing webhook
    let mut webhook = state.db.get_webhook_by_id(&webhook_id).await?;

    // Check tenant access
    if webhook.tenant_id != authentication.auth.token.tenant_id {
        return Err(ApiError::tenant_access_denied());
    }

    // Update fields
    if let Some(name) = request.name {
        if name.trim().is_empty() {
            return Err(ApiError::BadRequest("Webhook name cannot be empty".to_string()));
        }

        // Check if new name conflicts with existing webhook
        if name != webhook.name {
            if let Ok(_) = state.db.get_webhook_by_name(&name, &authentication.auth.token.tenant_id).await {
                return Err(ApiError::resource_already_exists("Webhook", &name));
            }
        }

        webhook.name = name;
    }

    if let Some(url) = request.url {
        if !url.starts_with("http://") && !url.starts_with("https://") {
            return Err(ApiError::BadRequest("Webhook URL must be a valid HTTP/HTTPS URL".to_string()));
        }
        webhook.url = url;
    }

    if let Some(events) = request.events {
        if events.is_empty() {
            return Err(ApiError::BadRequest("At least one webhook event must be specified".to_string()));
        }
        webhook.events = events;
    }

    if let Some(secret) = request.secret {
        webhook.secret = Some(secret);
    }

    if let Some(headers) = request.headers {
        webhook.headers = Some(headers);
    }

    if let Some(timeout_seconds) = request.timeout_seconds {
        if timeout_seconds < 1 || timeout_seconds > 300 {
            return Err(ApiError::BadRequest("Timeout must be between 1 and 300 seconds".to_string()));
        }
        webhook.timeout_seconds = timeout_seconds;
    }

    if let Some(retry_attempts) = request.retry_attempts {
        if retry_attempts < 0 || retry_attempts > 10 {
            return Err(ApiError::BadRequest("Retry attempts must be between 0 and 10".to_string()));
        }
        webhook.retry_attempts = retry_attempts;
    }

    if let Some(is_active) = request.is_active {
        webhook.is_active = is_active;
    }

    // Update in database
    state.db.update_webhook(&webhook).await?;

    // Log audit event
    let _ = state.db.log_audit_event(
        "webhook.update",
        Some(authentication.auth.token.created_by_user_id),
        Some(&authentication.auth.token.tenant_id),
        Some(&webhook.id),
        Some(&format!("Updated webhook: {}", webhook.name)),
    ).await;

    Ok(Json(webhook))
}

#[openapi(tag = "Webhooks")]
#[delete("/webhooks/<webhook_id>")]
/// Delete webhook configuration. Requires admin scope.
pub(crate) async fn delete_webhook(
    state: &State<AppState>,
    webhook_id: String,
    authentication: BearerTokenAdmin
) -> Result<(), ApiError> {
    // Get webhook to check ownership
    let webhook = state.db.get_webhook_by_id(&webhook_id).await?;

    // Check tenant access
    if webhook.tenant_id != authentication.auth.token.tenant_id {
        return Err(ApiError::tenant_access_denied());
    }

    // Delete from database
    state.db.delete_webhook(&webhook_id).await?;

    // Log audit event
    let _ = state.db.log_audit_event(
        "webhook.delete",
        Some(authentication.auth.token.created_by_user_id),
        Some(&authentication.auth.token.tenant_id),
        Some(&webhook.id),
        Some(&format!("Deleted webhook: {}", webhook.name)),
    ).await;

    Ok(())
}

#[openapi(tag = "Webhooks")]
#[post("/webhooks/<webhook_id>/test")]
/// Test webhook configuration by sending a test event. Requires admin scope.
pub(crate) async fn test_webhook(
    state: &State<AppState>,
    webhook_id: String,
    authentication: BearerTokenAdmin
) -> Result<Json<serde_json::Value>, ApiError> {
    // Get webhook
    let webhook = state.db.get_webhook_by_id(&webhook_id).await?;

    // Check tenant access
    if webhook.tenant_id != authentication.auth.token.tenant_id {
        return Err(ApiError::tenant_access_denied());
    }

    // Send test webhook
    let test_result = state.webhook_service.send_test_webhook(&webhook).await?;

    // Log audit event
    let _ = state.db.log_audit_event(
        "webhook.test",
        Some(authentication.auth.token.created_by_user_id),
        Some(&authentication.auth.token.tenant_id),
        Some(&webhook.id),
        Some(&format!("Tested webhook: {}", webhook.name)),
    ).await;

    Ok(Json(serde_json::json!({
        "webhook_id": webhook.id,
        "test_result": test_result,
        "timestamp": chrono::Utc::now().timestamp()
    })))
}

// ===== LEGACY API ENDPOINTS (DEPRECATED) =====

/// Legacy certificate listing endpoint (DEPRECATED)
/// Use POST /certificates/search instead
#[openapi(tag = "Legacy (Deprecated)")]
#[get("/certificates")]
pub(crate) async fn get_certificates_legacy(
    state: &State<AppState>,
    authentication: SessionAuthenticated
) -> Result<Json<Vec<Certificate>>, ApiError> {
    // Check deprecation policy
    deprecation::check_deprecation_policy("/certificates")?;

    // Get certificates using legacy format
    let certificates = state.db.get_certificates_for_user(authentication.user.id).await?;

    // Add deprecation warning to response
    // Note: In a real implementation, you'd add this to response headers
    warn!("Legacy endpoint /certificates used. Migrate to POST /certificates/search");

    Ok(Json(certificates))
}

/// Legacy certificate creation endpoint (DEPRECATED)
/// Use modern POST /certificates with enhanced format
#[openapi(tag = "Legacy (Deprecated)")]
#[post("/certificates/legacy", format = "json", data = "<payload>")]
pub(crate) async fn create_user_certificate_legacy(
    state: &State<AppState>,
    payload: Json<CreateCertificateRequest>,
    authentication: SessionAuthenticated
) -> Result<Json<Certificate>, ApiError> {
    // Check deprecation policy
    deprecation::check_deprecation_policy("POST /certificates")?;

    let request = payload.into_inner();

    // Convert legacy request to modern format
    let modern_request = CreateCertificateWithCaRequest {
        name: request.name,
        user_id: request.user_id,
        certificate_type: request.certificate_type,
        validity_years: request.validity_years,
        ca_selection: CaSelection::Auto,
        profile_id: None,
        sans: None,
        metadata: None,
    };

    // Create certificate using modern implementation
    let certificate = state.db.create_certificate_with_ca(&modern_request, &authentication.user.tenant_id).await?;

    warn!("Legacy endpoint POST /certificates used. Migrate to modern format");

    Ok(Json(certificate))
}

/// Legacy certificate download endpoint (DEPRECATED)
/// Use POST /certificates/bulk-download instead
#[openapi(tag = "Legacy (Deprecated)")]
#[get("/certificates/<cert_id>/download")]
pub(crate) async fn download_certificate_legacy(
    state: &State<AppState>,
    cert_id: i64,
    authentication: SessionAuthenticated
) -> Result<DownloadResponse, ApiError> {
    // Check deprecation policy
    deprecation::check_deprecation_policy("/certificates/<id>/download")?;

    // Get certificate
    let certificate = state.db.get_certificate_by_id(cert_id).await?;

    // Check ownership
    if certificate.user_id != authentication.user.id {
        return Err(ApiError::Forbidden("Access denied".to_string()));
    }

    // Create bulk download request for single certificate
    let bulk_request = BulkDownloadRequest {
        certificate_ids: vec![cert_id],
        format: "pem".to_string(),
        include_chain: true,
        include_private_key: false,
        archive_format: Some("zip".to_string()),
    };

    // Use modern bulk download implementation
    let download_response = bulk_download_certificates(state, Json(bulk_request),
        BearerCertRead { auth: BearerAuthenticated { token: create_legacy_token(&authentication.user) } }).await?;

    warn!("Legacy endpoint GET /certificates/{}/download used. Migrate to POST /certificates/bulk-download", cert_id);

    Ok(download_response.into_inner())
}

/// Legacy certificate deletion endpoint (DEPRECATED)
/// Use POST /certificates/batch instead
#[openapi(tag = "Legacy (Deprecated)")]
#[delete("/certificates/<cert_id>")]
pub(crate) async fn delete_user_cert_legacy(
    state: &State<AppState>,
    cert_id: i64,
    authentication: SessionAuthenticated
) -> Result<(), ApiError> {
    // Check deprecation policy
    deprecation::check_deprecation_policy("/certificates/<id>")?;

    // Create batch operation request
    let batch_request = BatchOperationRequest {
        certificate_ids: vec![cert_id],
        operation: "delete".to_string(),
        parameters: Some(serde_json::json!({
            "reason": "Legacy deletion"
        })),
    };

    // Use modern batch operation implementation
    let _batch_response = batch_certificate_operation(state, Json(batch_request),
        BearerCertWrite { auth: BearerAuthenticated { token: create_legacy_token(&authentication.user) } }).await?;

    warn!("Legacy endpoint DELETE /certificates/{} used. Migrate to POST /certificates/batch", cert_id);

    Ok(())
}

/// Legacy certificate password fetch endpoint (DEPRECATED)
/// Use POST /certificates/search with metadata instead
#[openapi(tag = "Legacy (Deprecated)")]
#[get("/certificates/<cert_id>/password")]
pub(crate) async fn fetch_certificate_password_legacy(
    state: &State<AppState>,
    cert_id: i64,
    authentication: SessionAuthenticated
) -> Result<Json<serde_json::Value>, ApiError> {
    // Check deprecation policy
    deprecation::check_deprecation_policy("/certificates/<id>/password")?;

    // Get certificate
    let certificate = state.db.get_certificate_by_id(cert_id).await?;

    // Check ownership
    if certificate.user_id != authentication.user.id {
        return Err(ApiError::Forbidden("Access denied".to_string()));
    }

    // Extract password from metadata (if available)
    let password = if let Some(metadata) = &certificate.metadata {
        if let Ok(meta_obj) = serde_json::from_str::<serde_json::Value>(metadata) {
            meta_obj.get("password").and_then(|p| p.as_str()).map(|s| s.to_string())
        } else {
            None
        }
    } else {
        None
    };

    warn!("Legacy endpoint GET /certificates/{}/password used. Migrate to certificate search with metadata", cert_id);

    Ok(Json(serde_json::json!({
        "certificate_id": cert_id,
        "password": password,
        "note": "This endpoint is deprecated. Use certificate search with metadata instead."
    })))
}

/// Legacy CA download endpoint (DEPRECATED)
/// Use GET /cas/{ca_id}/certificate instead
#[openapi(tag = "Legacy (Deprecated)")]
#[get("/certificates/ca/download")]
pub(crate) async fn download_ca_legacy(
    state: &State<AppState>,
    authentication: SessionAuthenticated
) -> Result<DownloadResponse, ApiError> {
    // Check deprecation policy
    deprecation::check_deprecation_policy("/certificates/ca/download")?;

    // Get default CA for user's tenant
    let cas = state.db.get_cas_for_tenant(&authentication.user.tenant_id).await?;
    let default_ca = cas.into_iter().find(|ca| ca.is_root_ca)
        .ok_or_else(|| ApiError::NotFound("No root CA found".to_string()))?;

    // Use modern CA download implementation
    let download_response = download_ca_certificate(state, default_ca.id,
        BearerCaRead { auth: BearerAuthenticated { token: create_legacy_token(&authentication.user) } }).await?;

    warn!("Legacy endpoint GET /certificates/ca/download used. Migrate to GET /cas/{}/certificate", default_ca.id);

    Ok(download_response.into_inner())
}

/// Helper function to create a legacy token for session-authenticated users
fn create_legacy_token(user: &User) -> crate::data::token::ApiToken {
    crate::data::token::ApiToken {
        id: "legacy-session".to_string(),
        prefix: "legacy".to_string(),
        description: "Legacy session token".to_string(),
        scopes: vec![
            crate::data::token::Scope::CertRead,
            crate::data::token::Scope::CertWrite,
            crate::data::token::Scope::CaRead,
        ],
        created_by_user_id: user.id,
        tenant_id: user.tenant_id.clone(),
        expires_at: None,
        rate_limit_per_minute: 1000,
        last_used_at: None,
        is_active: true,
        created_at: chrono::Utc::now().timestamp(),
        updated_at: chrono::Utc::now().timestamp(),
    }
}