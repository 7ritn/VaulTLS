use rocket::serde::{Deserialize, Serialize};
use rocket_okapi::JsonSchema;
use uuid::Uuid;

/// Tenant represents a multi-tenant organization in VaulTLS
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct Tenant {
    pub id: String,  // UUID v4
    pub name: String,
    pub created_at: i64,
    pub is_active: bool,
}

impl Tenant {
    /// Create a new tenant with a generated UUID
    pub fn new(name: String) -> Self {
        Self {
            id: Uuid::new_v4().to_string(),
            name,
            created_at: chrono::Utc::now().timestamp(),
            is_active: true,
        }
    }

    /// Create the default tenant for existing installations
    pub fn default_tenant() -> Self {
        Self {
            id: "00000000-0000-0000-0000-000000000000".to_string(),
            name: "Default Tenant".to_string(),
            created_at: chrono::Utc::now().timestamp(),
            is_active: true,
        }
    }
}

/// Request to create a new tenant
#[derive(Debug, Serialize, Deserialize, JsonSchema)]
pub struct CreateTenantRequest {
    pub name: String,
}

/// Request to update a tenant
#[derive(Debug, Serialize, Deserialize, JsonSchema)]
pub struct UpdateTenantRequest {
    pub name: Option<String>,
    pub is_active: Option<bool>,
}
