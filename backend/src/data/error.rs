use std::error::Error;
use std::fmt::Display;
use rocket::http::Status;
use rocket::Request;
use rocket::response::Responder;
use rocket::response::status::Custom;
use rocket_okapi::{okapi, JsonSchema, OpenApiError};
use rocket_okapi::r#gen::OpenApiGenerator;
use rocket_okapi::okapi::openapi3::Responses;
use rocket_okapi::response::OpenApiResponderInner;
use serde::Serialize;

/// RFC 9457 Problem Details for HTTP APIs
#[derive(Serialize, JsonSchema)]
pub struct ProblemDetails {
    #[serde(rename = "type")]
    pub problem_type: String,
    pub title: String,
    pub status: u16,
    pub detail: Option<String>,
    pub instance: Option<String>,
}

impl ProblemDetails {
    /// Create a new problem details response
    pub fn new(problem_type: &str, title: &str, status: u16) -> Self {
        Self {
            problem_type: problem_type.to_string(),
            title: title.to_string(),
            status,
            detail: None,
            instance: None,
        }
    }

    /// Set the detail field
    pub fn with_detail(mut self, detail: &str) -> Self {
        self.detail = Some(detail.to_string());
        self
    }

    /// Set the instance field
    pub fn with_instance(mut self, instance: &str) -> Self {
        self.instance = Some(instance.to_string());
        self
    }

    /// Create a 400 Bad Request problem
    pub fn bad_request(detail: &str) -> Self {
        Self::new(
            "https://tools.ietf.org/html/rfc9110#section-15.5.1",
            "Bad Request",
            400,
        ).with_detail(detail)
    }

    /// Create a 401 Unauthorized problem
    pub fn unauthorized(detail: Option<&str>) -> Self {
        let mut problem = Self::new(
            "https://tools.ietf.org/html/rfc9110#section-15.5.2",
            "Unauthorized",
            401,
        );
        if let Some(detail) = detail {
            problem = problem.with_detail(detail);
        } else {
            problem = problem.with_detail("Authentication credentials are missing or invalid");
        }
        problem
    }

    /// Create a 403 Forbidden problem
    pub fn forbidden(detail: Option<&str>) -> Self {
        let mut problem = Self::new(
            "https://tools.ietf.org/html/rfc9110#section-15.5.4",
            "Forbidden",
            403,
        );
        if let Some(detail) = detail {
            problem = problem.with_detail(detail);
        } else {
            problem = problem.with_detail("Insufficient permissions to access this resource");
        }
        problem
    }

    /// Create a 404 Not Found problem
    pub fn not_found(detail: Option<&str>) -> Self {
        let mut problem = Self::new(
            "https://tools.ietf.org/html/rfc9110#section-15.5.5",
            "Not Found",
            404,
        );
        if let Some(detail) = detail {
            problem = problem.with_detail(detail);
        } else {
            problem = problem.with_detail("The requested resource was not found");
        }
        problem
    }

    /// Create a 409 Conflict problem
    pub fn conflict(detail: &str) -> Self {
        Self::new(
            "https://tools.ietf.org/html/rfc9110#section-15.5.10",
            "Conflict",
            409,
        ).with_detail(detail)
    }

    /// Create a 429 Too Many Requests problem
    pub fn too_many_requests(detail: Option<&str>) -> Self {
        let mut problem = Self::new(
            "https://tools.ietf.org/html/rfc6585#section-4",
            "Too Many Requests",
            429,
        );
        if let Some(detail) = detail {
            problem = problem.with_detail(detail);
        } else {
            problem = problem.with_detail("Rate limit exceeded");
        }
        problem
    }

    /// Create a 500 Internal Server Error problem
    pub fn internal_server_error(detail: Option<&str>) -> Self {
        let mut problem = Self::new(
            "https://tools.ietf.org/html/rfc9110#section-15.6.1",
            "Internal Server Error",
            500,
        );
        if let Some(detail) = detail {
            problem = problem.with_detail(detail);
        } else {
            problem = problem.with_detail("An unexpected error occurred");
        }
        problem
    }
}

/// Legacy error response for backward compatibility
#[derive(Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct ErrorResponse {
    pub error: String,
}

#[derive(Debug)]
pub enum ApiError {
    OpenSsl(openssl::error::ErrorStack),
    Unauthorized,
    UnauthorizedWithDetail(String),
    BadRequest(String),
    Forbidden,
    ForbiddenWithDetail(String),
    NotFound,
    NotFoundWithDetail(String),
    Conflict(String),
    TooManyRequests,
    TooManyRequestsWithDetail(String),
    InternalServerError,
    InternalServerErrorWithDetail(String),
    Other(String),
}

impl ApiError {
    /// Create an unauthorized error with custom detail
    pub fn unauthorized_with_detail(detail: &str) -> Self {
        Self::UnauthorizedWithDetail(detail.to_string())
    }

    /// Create a forbidden error with custom detail
    pub fn forbidden_with_detail(detail: &str) -> Self {
        Self::ForbiddenWithDetail(detail.to_string())
    }

    /// Create a not found error with custom detail
    pub fn not_found_with_detail(detail: &str) -> Self {
        Self::NotFoundWithDetail(detail.to_string())
    }

    /// Create a too many requests error with custom detail
    pub fn too_many_requests_with_detail(detail: &str) -> Self {
        Self::TooManyRequestsWithDetail(detail.to_string())
    }

    /// Create an internal server error with custom detail
    pub fn internal_server_error_with_detail(detail: &str) -> Self {
        Self::InternalServerErrorWithDetail(detail.to_string())
    }
}

impl<'r> Responder<'r, 'static> for ApiError {
    fn respond_to(self, req: &'r Request<'_>) -> rocket::response::Result<'static> {
        let problem_details = match self {
            ApiError::OpenSsl(e) => {
                ProblemDetails::internal_server_error(Some(&format!("OpenSSL error: {}", e)))
            },
            ApiError::Unauthorized => {
                ProblemDetails::unauthorized(None)
            },
            ApiError::UnauthorizedWithDetail(detail) => {
                ProblemDetails::unauthorized(Some(&detail))
            },
            ApiError::BadRequest(detail) => {
                ProblemDetails::bad_request(&detail)
            },
            ApiError::Forbidden => {
                ProblemDetails::forbidden(None)
            },
            ApiError::ForbiddenWithDetail(detail) => {
                ProblemDetails::forbidden(Some(&detail))
            },
            ApiError::NotFound => {
                ProblemDetails::not_found(None)
            },
            ApiError::NotFoundWithDetail(detail) => {
                ProblemDetails::not_found(Some(&detail))
            },
            ApiError::Conflict(detail) => {
                ProblemDetails::conflict(&detail)
            },
            ApiError::TooManyRequests => {
                ProblemDetails::too_many_requests(None)
            },
            ApiError::TooManyRequestsWithDetail(detail) => {
                ProblemDetails::too_many_requests(Some(&detail))
            },
            ApiError::InternalServerError => {
                ProblemDetails::internal_server_error(None)
            },
            ApiError::InternalServerErrorWithDetail(detail) => {
                ProblemDetails::internal_server_error(Some(&detail))
            },
            ApiError::Other(detail) => {
                ProblemDetails::internal_server_error(Some(&detail))
            },
        };

        // Set the instance field to the request URI
        let mut problem_with_instance = problem_details;
        problem_with_instance.instance = Some(req.uri().to_string());

        let status = Status::from_code(problem_with_instance.status).unwrap_or(Status::InternalServerError);

        // Use application/problem+json content type as per RFC 9457
        let response = rocket::Response::build()
            .status(status)
            .header(rocket::http::ContentType::new("application", "problem+json"))
            .sized_body(None, std::io::Cursor::new(
                serde_json::to_string(&problem_with_instance).unwrap_or_default()
            ))
            .finalize();

        Ok(response)
    }
}

impl OpenApiResponderInner for ApiError {
    fn responses(generator: &mut OpenApiGenerator) -> Result<Responses, OpenApiError> {
        use rocket_okapi::okapi::openapi3::{Responses, Response as OpenApiResponse, RefOr};

        let schema = generator.json_schema::<ProblemDetails>();

        let mut responses = Responses::default();

        let error_definitions = [
            (400, "Bad Request - Invalid input parameters or request"),
            (401, "Unauthorized - Authentication failed or invalid credentials"),
            (403, "Forbidden - User doesn't have required permissions"),
            (404, "Not Found - Resource not found"),
            (409, "Conflict - Resource conflict or constraint violation"),
            (429, "Too Many Requests - Rate limit exceeded"),
            (500, "Internal Server Error - Database error, OpenSSL error, or other internal errors")
        ];

        for (code, description) in &error_definitions {
            let response = OpenApiResponse {
                description: description.to_string(),
                content: {
                    let mut map = okapi::Map::new();
                    map.insert(
                        "application/problem+json".to_owned(),
                        okapi::openapi3::MediaType {
                            schema: Some(schema.clone()),
                            ..Default::default()
                        },
                    );
                    // Also include application/json for backward compatibility
                    map.insert(
                        "application/json".to_owned(),
                        okapi::openapi3::MediaType {
                            schema: Some(schema.clone()),
                            ..Default::default()
                        },
                    );
                    map
                },
                ..Default::default()
            };

            responses.responses.insert(
                code.to_string(),
                RefOr::Object(response),
            );
        }

        Ok(responses)
    }
}


impl Display for ApiError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}

impl From<rusqlite::Error> for ApiError {
    fn from(error: rusqlite::Error) -> Self {
        match error {
            rusqlite::Error::QueryReturnedNoRows => ApiError::NotFound,
            _ => ApiError::NotFoundWithDetail(error.to_string()),
        }
    }
}

impl From<openssl::error::ErrorStack> for ApiError {
    fn from(error: openssl::error::ErrorStack) -> Self {
        ApiError::OpenSsl(error)
    }
}

impl From<argon2::password_hash::Error> for ApiError {
    fn from(error: argon2::password_hash::Error) -> Self {
        ApiError::UnauthorizedWithDetail(error.to_string())
    }
}

impl From<anyhow::Error> for ApiError {
    fn from(error: anyhow::Error) -> Self {
        ApiError::Other(error.to_string())
    }
}

impl From<serde_json::Error> for ApiError {
    fn from(error: serde_json::Error) -> Self {
        ApiError::BadRequest(format!("JSON parsing error: {}", error))
    }
}

impl From<std::io::Error> for ApiError {
    fn from(error: std::io::Error) -> Self {
        ApiError::InternalServerErrorWithDetail(format!("I/O error: {}", error))
    }
}

impl Error for ApiError {}

// Convenience constructors for common error scenarios
impl ApiError {
    /// Missing or invalid Bearer token
    pub fn missing_bearer_token() -> Self {
        Self::UnauthorizedWithDetail("Bearer token is missing or invalid".to_string())
    }

    /// Invalid token format
    pub fn invalid_token_format() -> Self {
        Self::UnauthorizedWithDetail("Token format is invalid".to_string())
    }

    /// Token has expired
    pub fn token_expired() -> Self {
        Self::UnauthorizedWithDetail("Token has expired".to_string())
    }

    /// Token has been revoked
    pub fn token_revoked() -> Self {
        Self::UnauthorizedWithDetail("Token has been revoked".to_string())
    }

    /// Insufficient scope for operation
    pub fn insufficient_scope(required_scope: &str) -> Self {
        Self::ForbiddenWithDetail(format!("Token missing required scope: {}", required_scope))
    }

    /// Tenant access denied
    pub fn tenant_access_denied() -> Self {
        Self::ForbiddenWithDetail("Access denied for this tenant".to_string())
    }

    /// Resource not found by ID
    pub fn resource_not_found(resource_type: &str, id: &str) -> Self {
        Self::NotFoundWithDetail(format!("{} with ID {} not found", resource_type, id))
    }

    /// Resource already exists
    pub fn resource_already_exists(resource_type: &str, identifier: &str) -> Self {
        Self::Conflict(format!("{} with {} already exists", resource_type, identifier))
    }

    /// Rate limit exceeded
    pub fn rate_limit_exceeded(limit: u32, window: &str) -> Self {
        Self::TooManyRequestsWithDetail(format!("Rate limit of {} requests per {} exceeded", limit, window))
    }

    /// Database connection error
    pub fn database_error(detail: &str) -> Self {
        Self::InternalServerErrorWithDetail(format!("Database error: {}", detail))
    }

    /// Certificate operation error
    pub fn certificate_error(detail: &str) -> Self {
        Self::InternalServerErrorWithDetail(format!("Certificate operation failed: {}", detail))
    }
}