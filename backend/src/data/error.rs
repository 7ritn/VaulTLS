use std::fmt::Display;
use rocket::http::Status;
use rocket::Request;
use rocket::response::Responder;
use rocket::response::status::Custom;
use rocket_okapi::{okapi, JsonSchema, OpenApiError};
use rocket_okapi::gen::OpenApiGenerator;
use rocket_okapi::okapi::openapi3::Responses;
use rocket_okapi::response::OpenApiResponderInner;
use serde::Serialize;

#[derive(Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct ErrorResponse {
    pub error: String,
}

#[derive(Debug)]
pub enum ApiError {
    Database(rusqlite::Error),
    OpenSsl(openssl::error::ErrorStack),
    Unauthorized(Option<String>),
    BadRequest(String),
    Forbidden(Option<String>),
    Other(String),
}

impl<'r> Responder<'r, 'static> for ApiError {
    fn respond_to(self, req: &'r Request<'_>) -> rocket::response::Result<'static> {
        let (status, message) = match self {
            ApiError::Database(e) => (Status::InternalServerError, e.to_string()),
            ApiError::OpenSsl(e) => (Status::InternalServerError, e.to_string()),
            ApiError::Unauthorized(e) => (Status::Unauthorized, e.unwrap_or_default()),
            ApiError::BadRequest(e) => (Status::BadRequest, e),
            ApiError::Forbidden(e) => (Status::Forbidden, e.unwrap_or_default()),
            ApiError::Other(e) => (Status::InternalServerError, e),
        };

        let body = rocket::serde::json::Json(ErrorResponse {
            error: message,
        });

        Custom(status, body).respond_to(req)
    }
}

impl OpenApiResponderInner for ApiError {
    fn responses(gen: &mut OpenApiGenerator) -> Result<Responses, OpenApiError> {
        use rocket_okapi::okapi::openapi3::{Responses, Response as OpenApiResponse, RefOr};

        let schema = gen.json_schema::<ErrorResponse>();
        let json_response = OpenApiResponse {
            description: "API error".to_owned(),
            content: {
                let mut map = okapi::Map::new();
                map.insert(
                    "application/json".to_owned(),
                    okapi::openapi3::MediaType {
                        schema: Some(schema),
                        ..Default::default()
                    },
                );
                map
            },
            ..Default::default()
        };

        let mut responses = Responses::default();
        for code in &[400, 401, 403, 500] {
            responses.responses.insert(
                code.to_string(),
                RefOr::Object(json_response.clone()),
            );
        }

        Ok(responses)
    }
}

impl Display for ApiError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self)
    }
}

impl From<rusqlite::Error> for ApiError {
    fn from(error: rusqlite::Error) -> Self {
        ApiError::Database(error)
    }
}

impl From<openssl::error::ErrorStack> for ApiError {
    fn from(error: openssl::error::ErrorStack) -> Self {
        ApiError::OpenSsl(error)
    }
}

impl From<argon2::password_hash::Error> for ApiError {
    fn from(error: argon2::password_hash::Error) -> Self {
        ApiError::Unauthorized(Some(error.to_string()))
    }
}

impl From<anyhow::Error> for ApiError {
    fn from(error: anyhow::Error) -> Self {
        ApiError::Other(error.to_string())
    }
}