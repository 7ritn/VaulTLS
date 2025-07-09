use crate::{ApiError, AppState};
use jsonwebtoken::{decode, encode, DecodingKey, EncodingKey, Header, Validation};
use rocket::http::Status;
use rocket::request::{FromRequest, Outcome, Request};
use serde::{Deserialize, Serialize};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use rocket_okapi::gen::OpenApiGenerator;
use rocket_okapi::okapi::openapi3::{Object, SecurityRequirement, SecurityScheme, SecuritySchemeData};
use rocket_okapi::request::{OpenApiFromRequest, RequestHeaderInput};
use crate::data::enums::UserRole;

/// Struct for Rocket guard
pub struct Authenticated {
    pub claims: Claims,
}

/// JWT claims
#[derive(Serialize, Deserialize, Debug)]
pub(crate) struct Claims {
    pub(crate) id: i64,
    pub(crate) role: UserRole,
    pub(crate) exp: usize
}

/// Rocket guard implementation
/// Authenticate user through auth_token cookie
#[rocket::async_trait]
impl<'r> FromRequest<'r> for Authenticated {
    type Error = ();

    async fn from_request(request: &'r Request<'_>) -> Outcome<Self, Self::Error> {
        let token = match request.cookies().get_private("auth_token") {
            Some(cookie) => cookie.value().to_string(),
            _ => return Outcome::Error((Status::Unauthorized, ())),
        };

        let config = match request.rocket().state::<AppState>() {
            Some(c) => c,
            None => return Outcome::Error((Status::InternalServerError, ())),
        };

        let settings = config.settings.lock().await;
        let jwt_key = match settings.get_jwt_key() {
            Ok(k) => k,
            Err(_) => return Outcome::Error((Status::InternalServerError, ())),
        };
        let decoding_key = DecodingKey::from_secret(&jwt_key);
        let validation = Validation::default();

        let claims = match decode::<Claims>(&*token, &decoding_key, &validation) {
            Ok(c) => c.claims,
            Err(_) => return Outcome::Error((Status::Unauthorized, ())),
        };

        Outcome::Success(Authenticated { claims })
    }
}

/// Generate OpenAPI documentation for Authenticated guard
impl<'r> OpenApiFromRequest<'r> for Authenticated {
    fn from_request_input(
        _gen: &mut OpenApiGenerator,
        _name: String,
        _required: bool,
    ) -> rocket_okapi::Result<RequestHeaderInput> {
        let security_scheme = SecurityScheme {
            description: Some(
                "Use secure auth_token set by server to authenticate".to_owned(),
            ),
            data: SecuritySchemeData::ApiKey {
                name: "auth_token".to_string(),
                location: "cookie".to_string(),
            },
            extensions: Object::default(),
        };
        let mut security_req = SecurityRequirement::new();
        security_req.insert("JWT Token".to_owned(), Vec::new());
        Ok(RequestHeaderInput::Security(
            "JWT Token".to_owned(),
            security_scheme,
            security_req,
        ))
    }
}

/// Generate JWT Token for authentication
pub(crate) fn generate_token(jwt_key: &[u8], user_id: i64, user_role: UserRole) -> Result<String, ApiError> {
    let expires = SystemTime::now() + Duration::from_secs(60 * 60 /* 1 hour */);
    let expires_unix = expires.duration_since(UNIX_EPOCH).unwrap().as_secs() as usize;
    let claims = Claims {
        exp: expires_unix,
        id: user_id,
        role: user_role
    };

    encode(
        &Header::default(),
        &claims,
        &EncodingKey::from_secret(jwt_key),
    ).map_err(|_| ApiError::Other("Failed to generate JWT".to_string()))
}