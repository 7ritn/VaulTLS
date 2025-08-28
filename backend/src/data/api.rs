use std::io::Cursor;
use rocket::{FromForm, Request, Response};
use rocket::http::{ContentType, Header, Status};
use rocket::response::Responder;
use rocket::serde::{Deserialize, Serialize};
use rocket_okapi::r#gen::OpenApiGenerator;
use rocket_okapi::okapi::schemars;
use rocket_okapi::{okapi, JsonSchema, OpenApiError};
use rocket_okapi::okapi::openapi3::{Responses, Response as OAResponse, MediaType, RefOr};
use rocket_okapi::response::OpenApiResponderInner;
use crate::data::enums::{CertificateRenewMethod, CertificateType, ClientCertificateType, UserRole};

#[derive(Serialize, Deserialize, JsonSchema)]
pub struct IsSetupResponse {
    pub setup: bool,
    pub password: bool,
    pub oidc: String
}

#[derive(Serialize, Deserialize, JsonSchema)]
pub struct SetupRequest {
    pub name: String,
    pub email: String,
    pub ca_name: String,
    pub ca_validity_in_years: u64,
    pub password: Option<String>,
}

#[derive(Serialize, Deserialize, JsonSchema)]
pub struct LoginRequest {
    pub email: String,
    pub password: String
}

#[derive(Serialize, Deserialize, JsonSchema)]
pub struct ChangePasswordRequest {
    pub old_password: Option<String>,
    pub new_password: String,
}

#[derive(FromForm, JsonSchema)]
pub struct CallbackQuery {
    pub code: String,
    pub state: String
}

#[derive(Serialize, Deserialize, JsonSchema)]
pub struct CreateUserCertificateRequest {
    pub cert_name: String,
    pub validity_in_years: Option<u64>,
    pub user_id: i64,
    pub notify_user: Option<bool>,
    pub system_generated_password: bool,
    pub pkcs12_password: Option<String>,
    pub cert_type: Option<CertificateType>,
    pub client_cert_type: Option<ClientCertificateType>, // Required for Client certificates
    pub dns_names: Option<Vec<String>>,
    pub renew_method: Option<CertificateRenewMethod>
}

#[derive(Deserialize, Serialize, Debug)]
pub struct DownloadResponse {
    pub content: Vec<u8>,
    pub filename: String,
}

impl DownloadResponse {
    pub fn new(content: Vec<u8>, filename: &str) -> Self {
        Self {
            content,
            filename: filename.to_string(),
        }
    }
}

impl<'r> Responder<'r, 'static> for DownloadResponse {
    fn respond_to(self, _req: &'r Request<'_>) -> rocket::response::Result<'static> {
        Response::build()
            .status(Status::Ok)
            .header(ContentType::Text)
            .header(Header::new(
                "Content-Disposition",
                format!("attachment; filename=\"{}\"", self.filename),
            ))
            .sized_body(self.content.len(), Cursor::new(self.content))
            .ok()
    }
}

impl OpenApiResponderInner for DownloadResponse {
    fn responses(_gen: &mut OpenApiGenerator) -> Result<Responses, OpenApiError> {
        let mut responses = Responses::default();

        responses.responses.insert(
            "200".to_string(),
            RefOr::Object(OAResponse {
                description: "Downloadable binary file".to_string(),
                content: {
                    let mut content = okapi::Map::new();
                    content.insert(
                        "application/octet-stream".to_string(),
                        MediaType {
                            schema: None, // No schema needed for binary
                            ..Default::default()
                        },
                    );
                    content
                },
                ..Default::default()
            }),
        );

        Ok(responses)
    }
}

#[derive(Serialize, Deserialize, JsonSchema)]
pub struct CreateUserRequest {
    pub user_name: String,
    pub user_email: String,
    pub password: Option<String>,
    pub role: UserRole
}
