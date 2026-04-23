use std::io::Cursor;
use rocket::http::{ContentType, Status};
use rocket::Request;
use rocket::response::{Responder, Response};
use rocket::serde::{Deserialize, Serialize};
use rocket_okapi::JsonSchema;
use serde_json::Value;

// ---------------------------------------------------------------------------
// AcmeError — RFC 8555 §6.7 problem document
// ---------------------------------------------------------------------------

#[derive(Serialize, Deserialize, Debug)]
pub struct AcmeError {
    #[serde(rename = "type")]
    pub error_type: String,
    pub detail: String,
    pub status: u16,
}

impl AcmeError {
    pub fn bad_nonce(detail: impl Into<String>) -> Self {
        Self {
            error_type: "urn:ietf:params:acme:error:badNonce".into(),
            detail: detail.into(),
            status: 400,
        }
    }

    pub fn malformed(detail: impl Into<String>) -> Self {
        Self {
            error_type: "urn:ietf:params:acme:error:malformed".into(),
            detail: detail.into(),
            status: 400,
        }
    }

    pub fn unauthorized(detail: impl Into<String>) -> Self {
        Self {
            error_type: "urn:ietf:params:acme:error:unauthorized".into(),
            detail: detail.into(),
            status: 403,
        }
    }

    pub fn not_found() -> Self {
        Self {
            error_type: "urn:ietf:params:acme:error:malformed".into(),
            detail: "Resource not found".into(),
            status: 404,
        }
    }

    pub fn server_internal(detail: impl Into<String>) -> Self {
        Self {
            error_type: "urn:ietf:params:acme:error:serverInternal".into(),
            detail: detail.into(),
            status: 500,
        }
    }

    pub fn account_does_not_exist() -> Self {
        Self {
            error_type: "urn:ietf:params:acme:error:accountDoesNotExist".into(),
            detail: "Account does not exist".into(),
            status: 400,
        }
    }

    pub fn rejected_identifier(detail: impl Into<String>) -> Self {
        Self {
            error_type: "urn:ietf:params:acme:error:rejectedIdentifier".into(),
            detail: detail.into(),
            status: 403,
        }
    }
}

impl<'r> Responder<'r, 'static> for AcmeError {
    fn respond_to(self, _req: &'r Request<'_>) -> rocket::response::Result<'static> {
        let status = Status::from_code(self.status).unwrap_or(Status::InternalServerError);
        let body = serde_json::to_vec(&self).map_err(|_| Status::InternalServerError)?;

        rocket::response::Response::build()
            .status(status)
            .header(ContentType::new("application", "problem+json"))
            .sized_body(body.len(), Cursor::new(body))
            .ok()
    }
}

#[derive(Serialize, Deserialize, JsonSchema, Debug, Clone)]
#[serde(rename_all = "camelCase")]
pub struct DirectoryMeta {
    pub external_account_required: bool,
}

#[derive(Serialize, Deserialize, JsonSchema, Debug, Clone)]
#[serde(rename_all = "camelCase")]
pub struct Directory {
    pub new_nonce: String,
    pub new_account: String,
    pub new_order: String,
    pub revoke_cert: String,
    pub meta: DirectoryMeta,
}

#[derive(Serialize, Deserialize, JsonSchema, Clone, Debug)]
pub struct AcmeAccount {
    pub id: i64,
    pub name: String,
    /// Comma-separated list of allowed domains.
    pub allowed_domains: String,
    pub eab_kid: String,
    #[serde(skip)]
    pub eab_hmac_key: Vec<u8>,
    pub acme_jwk: Option<String>,
    pub status: String,
    pub ca_id: Option<i64>,
    pub contacts: String,
    pub created_on: i64,
    pub user_id: i64,
    pub auto_validate: bool,
}

#[derive(Serialize, Deserialize, JsonSchema)]
pub struct CreateAcmeAccountRequest {
    pub name: String,
    pub allowed_domains: Vec<String>,
    pub ca_id: Option<i64>,
    #[serde(default)]
    pub auto_validate: bool,
}

#[derive(Serialize, Deserialize, JsonSchema)]
pub struct UpdateAcmeAccountRequest {
    pub name: Option<String>,
    pub allowed_domains: Option<Vec<String>>,
    pub ca_id: Option<i64>,
    pub status: Option<String>,
    pub auto_validate: Option<bool>,
}

#[derive(Serialize, JsonSchema)]
pub struct CreateAcmeAccountResponse {
    pub id: i64,
    pub name: String,
    pub eab_kid: String,
    /// Base64url-encoded HMAC key.
    pub eab_hmac_key: String,
}

#[derive(Serialize, Debug)]
pub struct AcmeOrder {
    pub status: String,
    pub expires: String,
    pub identifiers: Vec<AcmeIdentifier>,
    pub authorizations: Vec<String>,
    pub finalize: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub certificate: Option<String>,
}

#[derive(Debug, Clone)]
pub(crate) struct AcmeOrderRow {
    pub id: i64,
    pub account_id: i64,
    pub status: String,
    pub identifiers: String,
    pub not_after: i64,
    pub expires: i64,
    pub certificate_id: Option<i64>,
    pub created_on: i64,
    pub client_ip: Option<String>,
    pub error: Option<String>,
}

#[derive(Serialize, Deserialize, JsonSchema, Debug, Clone)]
pub struct AcmeIdentifier {
    #[serde(rename = "type")]
    pub identifier_type: String,
    pub value: String,
    #[serde(default, skip_serializing)]
    pub token: String,
    #[serde(default = "default_pending", skip_serializing)]
    pub status: String,
}

fn default_pending() -> String {
    "pending".to_string()
}

#[derive(Serialize, Deserialize, JsonSchema, Debug)]
pub struct AdminAcmeOrder {
    pub id: i64,
    pub account_id: i64,
    pub account_name: String,
    pub status: String,
    pub identifiers: Vec<AcmeIdentifier>,
    pub not_after: i64,
    pub expires: i64,
    pub certificate_id: Option<i64>,
    pub created_on: i64,
    pub client_ip: Option<String>,
    pub error: Option<String>,
}

#[derive(Serialize, Debug)]
pub struct AcmeAuthorization {
    pub identifier: AcmeIdentifier,
    pub status: String,
    pub challenges: Vec<AcmeChallenge>,
}

#[derive(Serialize, Debug)]
pub struct AcmeChallenge {
    #[serde(rename = "type")]
    pub challenge_type: String,
    pub url: String,
    pub token: String,
    pub status: String,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct JwsRequest {
    pub protected: String,
    pub payload: String,
    pub signature: String,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct JwsProtectedHeader {
    pub alg: String,
    pub nonce: Option<String>,
    pub url: Option<String>,
    pub jwk: Option<Value>,
    pub kid: Option<String>,
}

#[derive(Debug)]
pub struct AcmeCertificate {
    pub cert_pem: Vec<u8>,
    /// Full PEM chain: leaf certificate followed by CA certificate(s).
    pub chain_pem: Vec<u8>,
    pub serial_number: Vec<u8>,
}

pub struct AcmeCreatedResponse {
    pub location: String,
    pub body: Vec<u8>,
}

impl<'r> Responder<'r, 'static> for AcmeCreatedResponse {
    fn respond_to(self, _req: &'r Request<'_>) -> rocket::response::Result<'static> {
        Response::build()
            .status(Status::Created)
            .header(ContentType::JSON)
            .raw_header("Location", self.location)
            .sized_body(self.body.len(), Cursor::new(self.body))
            .ok()
    }
}

pub struct AcmePemResponse {
    pub body: Vec<u8>,
}

impl<'r> Responder<'r, 'static> for AcmePemResponse {
    fn respond_to(self, _req: &'r Request<'_>) -> rocket::response::Result<'static> {
        Response::build()
            .status(Status::Ok)
            .raw_header("Content-Type", "application/pem-certificate-chain")
            .sized_body(self.body.len(), Cursor::new(self.body))
            .ok()
    }
}
