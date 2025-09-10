use std::collections::HashSet;
use crate::ApiError;
use jsonwebtoken::{decode, encode, DecodingKey, EncodingKey, Header, Validation};
use rocket::http::Status;
use rocket::request::{FromRequest, Outcome, Request};
use serde::{Deserialize, Serialize};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use const_format::concatcp;
use rocket_okapi::r#gen::OpenApiGenerator;
use rocket_okapi::okapi::openapi3::{Object, SecurityRequirement, SecurityScheme, SecuritySchemeData};
use rocket_okapi::request::{OpenApiFromRequest, RequestHeaderInput};
use uuid::Uuid;
use once_cell::sync::Lazy;
use parking_lot::RwLock;
use crate::data::enums::UserRole;
use crate::data::objects::AppState;

macro_rules! impl_openapi_auth {
    ($guard:ty, $role:literal) => {
        /// Generate OpenAPI documentation fora authentication guard
        impl<'r> OpenApiFromRequest<'r> for $guard {
            fn from_request_input(
                _gen: &mut OpenApiGenerator,
                _name: String,
                _required: bool,
            ) -> rocket_okapi::Result<RequestHeaderInput> {
                let security_scheme = SecurityScheme {
                    description: Some(
                        concatcp!("Use secure auth_token set by server to authenticate. Requires user role ", $role).to_owned(),
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
    };
}

static JTI_STORE: Lazy<RwLock<HashSet<String>>> = Lazy::new(|| {
    RwLock::new(HashSet::new())
});

/// Struct for Rocket guard
pub struct Authenticated {
    pub claims: Claims,
}

pub struct AuthenticatedPrivileged {
    pub _claims: Claims,
}

/// JWT claims
#[derive(Serialize, Deserialize, Debug)]
pub(crate) struct Claims {
    pub(crate) jti: String,
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
        match authenticate_auth_token(request) {
            Some(claims) => Outcome::Success(Authenticated { claims }),
            None => Outcome::Error((Status::Unauthorized, ()))
        }
    }
}

impl_openapi_auth!(Authenticated, "UserRole::User");

/// Rocket guard implementation
/// Authenticate user through auth_token cookie, requiring UserRole::Admin
#[rocket::async_trait]
impl<'r> FromRequest<'r> for AuthenticatedPrivileged {
    type Error = ();

    async fn from_request(request: &'r Request<'_>) -> Outcome<Self, Self::Error> {
        let Some(claims) =  authenticate_auth_token(request) else { return Outcome::Error((Status::Unauthorized, ())) };
        if claims.role == UserRole::Admin {
            Outcome::Success(AuthenticatedPrivileged { _claims: claims })
        } else {
            Outcome::Error((Status::Forbidden, ()))
        }
    }
}

impl_openapi_auth!(AuthenticatedPrivileged, "UserRole::Admin");

pub(crate) fn authenticate_auth_token(request: &Request<'_>) -> Option<Claims> {
    let token = request.cookies().get_private("auth_token")?.value().to_string();
    let config = request.rocket().state::<AppState>()?;

    let jwt_key = config.settings.get_jwt_key().ok()?;
    let decoding_key = DecodingKey::from_secret(&jwt_key);
    let validation = Validation::default();

    let claims = decode::<Claims>(&token, &decoding_key, &validation).ok()?.claims;

    match JTI_STORE.read().contains(&claims.jti) {
        true => Some(claims),
        false => None
    }
}

/// Generate JWT Token for authentication
pub(crate) fn generate_token(jwt_key: &[u8], user_id: i64, user_role: UserRole) -> Result<String, ApiError> {
    let expires = SystemTime::now() + Duration::from_secs(60 * 60 /* 1 hour */);
    let expires_unix = expires.duration_since(UNIX_EPOCH).unwrap().as_secs() as usize;
    let jti = Uuid::new_v4().to_string();

    let claims = Claims {
        jti: jti.clone(),
        exp: expires_unix,
        id: user_id,
        role: user_role
    };

    JTI_STORE.write().insert(jti);

    encode(
        &Header::default(),
        &claims,
        &EncodingKey::from_secret(jwt_key),
    ).map_err(|_| ApiError::Other("Failed to generate JWT".to_string()))
}

pub(crate) fn invalidate_token(jti: &str) {
    JTI_STORE.write().remove(jti);
}