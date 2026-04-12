use rand_core::Rng;
use rocket::{delete, get, post, put, State};
use rocket::serde::json::Json;
use rocket_okapi::openapi;
use crate::acme::guard::AcmeEnabled;
use crate::acme::jws::base64url_encode;
use crate::acme::types::{AcmeAccount, AdminAcmeOrder, CreateAcmeAccountRequest, CreateAcmeAccountResponse, UpdateAcmeAccountRequest};
use crate::auth::session_auth::AuthenticatedPrivileged;
use crate::data::error::ApiError;
use crate::data::objects::AppState;
use uuid::Uuid;

#[openapi(tag = "ACME")]
#[get("/acme/orders")]
pub async fn get_acme_orders(
    state: &State<AppState>,
    _auth: AuthenticatedPrivileged,
    _acme: AcmeEnabled,
) -> Result<Json<Vec<AdminAcmeOrder>>, ApiError> {
    let orders = state.db.get_all_acme_orders().await?;
    Ok(Json(orders))
}

#[openapi(tag = "ACME")]
#[get("/acme/accounts")]
pub async fn get_acme_accounts(
    state: &State<AppState>,
    _auth: AuthenticatedPrivileged,
    _acme: AcmeEnabled,
) -> Result<Json<Vec<AcmeAccount>>, ApiError> {
    let accounts = state.db.get_all_acme_accounts().await?;
    Ok(Json(accounts))
}

#[openapi(tag = "ACME")]
#[post("/acme/accounts", format = "json", data = "<req>")]
pub async fn create_acme_account(
    state: &State<AppState>,
    auth: AuthenticatedPrivileged,
    req: Json<CreateAcmeAccountRequest>,
    _acme: AcmeEnabled,
) -> Result<Json<CreateAcmeAccountResponse>, ApiError> {
    let eab_kid = Uuid::new_v4().to_string();

    let mut eab_hmac_key = vec![0u8; 32];
    rand::rng().fill_bytes(eab_hmac_key.as_mut_slice());

    let allowed_domains = req.allowed_domains.join(",");

    let account = state.db.insert_acme_account(
        req.name.clone(),
        allowed_domains,
        eab_kid.clone(),
        eab_hmac_key.clone(),
        req.ca_id,
        auth._claims.id,
        req.auto_validate,
    ).await?;

    Ok(Json(CreateAcmeAccountResponse {
        id: account.id,
        name: account.name,
        eab_kid,
        eab_hmac_key: base64url_encode(&eab_hmac_key),
    }))
}

#[openapi(tag = "ACME")]
#[put("/acme/accounts/<id>", format = "json", data = "<req>")]
pub async fn update_acme_account(
    state: &State<AppState>,
    _auth: AuthenticatedPrivileged,
    id: i64,
    req: Json<UpdateAcmeAccountRequest>,
    _acme: AcmeEnabled,
) -> Result<Json<AcmeAccount>, ApiError> {
    if let Some(ref s) = req.status {
        if s != "valid" && s != "deactivated" {
            return Err(ApiError::BadRequest("Status must be 'valid' or 'deactivated'".to_string()));
        }
    }

    let allowed_domains = req.allowed_domains.as_ref().map(|d| d.join(","));

    state.db.update_acme_account(
        id,
        req.name.clone(),
        allowed_domains,
        req.ca_id.map(Some),  // Some(Some(x)) = set to x; None = don't change
        req.status.clone(),
        req.auto_validate,
    ).await?;

    let account = state.db.get_acme_account(id).await?;
    Ok(Json(account))
}

#[openapi(tag = "ACME")]
#[delete("/acme/accounts/<id>")]
pub async fn delete_acme_account(
    state: &State<AppState>,
    _auth: AuthenticatedPrivileged,
    id: i64,
    _acme: AcmeEnabled,
) -> Result<(), ApiError> {
    state.db.delete_acme_account(id).await?;
    Ok(())
}
