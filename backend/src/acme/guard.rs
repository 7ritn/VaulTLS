use std::convert::Infallible;
use rocket::data::{Data, FromData, ToByteUnit, Outcome as DataOutcome};
use rocket::http::Status;
use rocket::request::{FromRequest, Outcome, Request};
use rocket_okapi::r#gen::OpenApiGenerator;
use rocket_okapi::request::{OpenApiFromRequest, RequestHeaderInput};
use tracing::warn;
use crate::acme::jws::authenticate_jws;
use crate::acme::types::AcmeError;
use crate::data::objects::AppState;

/// Request guard that rejects requests with 404 when ACME is disabled.
pub(crate) struct AcmeEnabled;

#[rocket::async_trait]
impl<'r> FromRequest<'r> for AcmeEnabled {
    type Error = ();

    async fn from_request(req: &'r Request<'_>) -> Outcome<Self, Self::Error> {
        match req.rocket().state::<AppState>() {
            Some(state) if state.settings.get_acme_enabled() => Outcome::Success(AcmeEnabled),
            _ => Outcome::Error((Status::NotFound, ())), // Returns 404, rather than 403 when not enabled
        }
    }
}

impl<'r> OpenApiFromRequest<'r> for AcmeEnabled {
    fn from_request_input(
        _gen: &mut OpenApiGenerator,
        _name: String,
        _required: bool,
    ) -> rocket_okapi::Result<RequestHeaderInput> {
        Ok(RequestHeaderInput::None)
    }
}

pub struct JoseBody(pub Result<String, AcmeError>);

#[rocket::async_trait]
impl<'r> FromData<'r> for JoseBody {
    type Error = Infallible;

    async fn from_data(_req: &'r Request<'_>, data: Data<'r>) -> DataOutcome<'r, Self> {
        let limit = 1.mebibytes();
        let result = match data.open(limit).into_string().await {
            Ok(s) if s.is_complete() => Ok(s.into_inner()),
            Ok(_) => Err(AcmeError::malformed("Request body too large")),
            Err(_) => Err(AcmeError::server_internal("Failed to read body")),
        };
        DataOutcome::Success(JoseBody(result))
    }
}

pub struct JwsData {
    pub account_id: i64,
    pub payload: Vec<u8>,
}

pub struct AuthenticatedJws(pub Result<JwsData, AcmeError>);

#[rocket::async_trait]
impl<'r> FromData<'r> for AuthenticatedJws {
    type Error = Infallible;

    async fn from_data(req: &'r Request<'_>, data: Data<'r>) -> DataOutcome<'r, Self> {
        let limit = 1.mebibytes();
        let body = match data.open(limit).into_string().await {
            Ok(s) if s.is_complete() => s.into_inner(),
            Ok(_) => return DataOutcome::Success(AuthenticatedJws(Err(AcmeError::malformed("Request body too large")))),
            Err(_) => return DataOutcome::Success(AuthenticatedJws(Err(AcmeError::server_internal("Failed to read body")))),
        };

        let state = match req.rocket().state::<AppState>() {
            Some(s) => s,
            None => return DataOutcome::Success(AuthenticatedJws(Err(AcmeError::server_internal("Missing app state")))),
        };

        let base = state.settings.get_vaultls_url();
        let expected_url = format!("{base}{}", req.uri().path());

        let result = match authenticate_jws(state, &body, &expected_url).await {
            Ok((account_id, payload)) => Ok(JwsData { account_id, payload }),
            Err(e) => {
                warn!(path=%req.uri().path(), error=%e.detail, "ACME JWS authentication failed");
                Err(e)
            }
        };
        DataOutcome::Success(AuthenticatedJws(result))
    }
}
