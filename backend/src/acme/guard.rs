use rocket::http::Status;
use rocket::request::{FromRequest, Outcome, Request};
use rocket_okapi::r#gen::OpenApiGenerator;
use rocket_okapi::request::{OpenApiFromRequest, RequestHeaderInput};
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
