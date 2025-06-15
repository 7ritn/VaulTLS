use std::io::Cursor;
use rocket::{Request, Response};
use rocket::http::{ContentType, Header, Status};
use rocket::response::Responder;
use rocket::serde::{Deserialize, Serialize};
use crate::data::enums::UserRole;

#[derive(Serialize)]
pub struct IsSetupResponse {
    pub setup: bool,
    pub password: bool,
    pub oidc: String
}

#[derive(Deserialize)]
pub struct SetupRequest {
    pub name: String,
    pub email: String,
    pub ca_name: String,
    pub ca_validity_in_years: u64,
    pub password: Option<String>,
}

#[derive(Deserialize)]
pub struct LoginRequest {
    pub email: String,
    pub password: String
}

#[derive(Serialize)]
pub struct LoginResponse {
    pub token: String
}

#[derive(Deserialize)]
pub struct ChangePasswordRequest {
    pub old_password: Option<String>,
    pub new_password: String,
}

#[derive(FromForm)]
pub struct CallbackQuery {
    pub code: String,
    pub state: String
}

#[derive(Deserialize)]
pub struct CreateCertificateRequest {
    pub cert_name: String,
    pub subject_alt_name: Option<String>,
    pub user_id: i64,
    pub validity_in_years: Option<u64>,
    pub notify_user: Option<bool>
}

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

//todo: respect filename
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


#[derive(Deserialize)]
pub struct CreateUserRequest {
    pub user_name: String,
    pub user_email: String,
    pub password: Option<String>,
    pub role: UserRole
}
