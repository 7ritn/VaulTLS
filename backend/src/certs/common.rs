use rocket::serde::{Deserialize, Serialize};
use rocket_okapi::JsonSchema;
use crate::data::enums::{CertificateRenewMethod, CertificateType};

#[derive(Debug, Clone, Default, Serialize, Deserialize, JsonSchema)]
/// Certificate can be either SSH or TLS certificate.
pub struct Certificate {
    pub id: i64,
    pub name: String,
    pub created_on: i64,
    pub valid_until: i64,
    pub certificate_type: CertificateType,
    pub user_id: i64,
    pub renew_method: CertificateRenewMethod,
    pub ca_id: i64,
    #[serde(skip)]
    pub data: Vec<u8>,
    #[serde(skip)]
    pub password: String
}

#[derive(Clone, Serialize, Deserialize, JsonSchema, Debug)]
pub struct CA {
    pub id: i64,
    pub name: String,
    pub created_on: i64,
    pub valid_until: i64,
    #[serde(skip)]
    pub cert: Vec<u8>,
    #[serde(skip)]
    pub key: Vec<u8>,
}