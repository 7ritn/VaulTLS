use rocket::request::{FromRequest, Outcome, Request};
use rocket_okapi::r#gen::OpenApiGenerator;
use rocket_okapi::request::{OpenApiFromRequest, RequestHeaderInput};

/// Request guard that extracts the client IP address.
/// Checks the `X-Real-IP` header first, then falls back to the socket peer address.
pub(crate) struct ClientIp(pub String);

#[rocket::async_trait]
impl<'r> FromRequest<'r> for ClientIp {
    type Error = ();

    async fn from_request(req: &'r Request<'_>) -> Outcome<Self, Self::Error> {
        let ip = req
            .headers()
            .get_one("X-Real-IP")
            .map(|s| s.to_string())
            .or_else(|| req.remote().map(|addr| addr.ip().to_string()));

        match ip {
            Some(ip) => Outcome::Success(ClientIp(ip)),
            None => Outcome::Success(ClientIp("unknown".to_string())),
        }
    }
}

impl<'r> OpenApiFromRequest<'r> for ClientIp {
    fn from_request_input(
        _gen: &mut OpenApiGenerator,
        _name: String,
        _required: bool,
    ) -> rocket_okapi::Result<RequestHeaderInput> {
        Ok(RequestHeaderInput::None)
    }
}
