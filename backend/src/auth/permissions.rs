use crate::data::enums::UserRole;
use crate::data::token::Scope;
use crate::db::VaulTLSDB;
use anyhow::{anyhow, Result};
use std::collections::HashMap;
use tracing::{debug, warn};

/// Role-to-scope mapping entry
#[derive(Debug, Clone)]
pub struct RoleScopeMapping {
    pub id: i64,
    pub role: UserRole,
    pub scope: String,
    pub tenant_id: Option<String>,
}

/// Endpoint-to-scope mapping entry
#[derive(Debug, Clone)]
pub struct EndpointScopeMapping {
    pub id: i64,
    pub endpoint_pattern: String,
    pub method: String,
    pub required_scopes: Vec<String>,
    pub description: Option<String>,
}

/// Central permission system for managing role-based and scope-based access control
pub struct PermissionSystem {
    db: VaulTLSDB,
    // Cache for performance (could be extended with Redis)
    role_scope_cache: HashMap<(UserRole, Option<String>), Vec<String>>,
    endpoint_scope_cache: HashMap<(String, String), Vec<String>>,
}

impl PermissionSystem {
    /// Create a new permission system
    pub fn new(db: VaulTLSDB) -> Self {
        Self {
            db,
            role_scope_cache: HashMap::new(),
            endpoint_scope_cache: HashMap::new(),
        }
    }

    /// Initialize default role-scope mappings
    pub async fn initialize_default_mappings(&self) -> Result<()> {
        debug!("Initializing default role-scope mappings");

        // Admin role gets all scopes
        let admin_scopes = Scope::all();
        for scope in admin_scopes {
            self.add_role_scope_mapping(UserRole::Admin, scope.as_str(), None).await?;
        }

        // User role gets limited scopes
        let user_scopes = vec![
            Scope::CertRead,
            Scope::CertWrite,
            Scope::CertDownload,
            Scope::CaRead,
            Scope::ProfileRead,
        ];
        for scope in user_scopes {
            self.add_role_scope_mapping(UserRole::User, scope.as_str(), None).await?;
        }

        // Initialize endpoint-scope mappings
        self.initialize_endpoint_mappings().await?;

        Ok(())
    }

    /// Initialize endpoint-to-scope mappings
    async fn initialize_endpoint_mappings(&self) -> Result<()> {
        let mappings = vec![
            // Certificate endpoints
            ("/api/certificates", "GET", vec!["cert.read"]),
            ("/api/certificates", "POST", vec!["cert.write"]),
            ("/api/certificates/{id}", "GET", vec!["cert.read"]),
            ("/api/certificates/{id}", "DELETE", vec!["cert.revoke"]),
            ("/api/certificates/{id}/download", "GET", vec!["cert.download"]),
            ("/api/certificates/{id}/revoke", "POST", vec!["cert.revoke"]),
            ("/api/certificates/{id}/restore", "POST", vec!["cert.revoke"]),
            
            // CA endpoints
            ("/api/cas", "GET", vec!["ca.read"]),
            ("/api/cas", "POST", vec!["ca.write"]),
            ("/api/cas/{id}", "GET", vec!["ca.read"]),
            ("/api/cas/{id}", "PATCH", vec!["ca.write"]),
            ("/api/cas/{id}", "DELETE", vec!["ca.write"]),
            ("/api/cas/{id}/cert", "GET", vec!["ca.read"]),
            ("/api/cas/{id}:rotate", "POST", vec!["ca.keyop"]),
            
            // CRL endpoints
            ("/api/crl/ca/{id}/download", "GET", vec![]), // Public endpoint
            ("/api/crl/ca/{id}/info", "GET", vec!["cert.read"]),
            ("/api/crl/ca/{id}/statistics", "GET", vec!["audit.read"]),
            ("/api/crl/ca/{id}/generate", "POST", vec!["ca.keyop"]),
            
            // Profile endpoints
            ("/api/profiles", "GET", vec!["profile.read"]),
            ("/api/profiles", "POST", vec!["profile.write"]),
            ("/api/profiles/{id}", "GET", vec!["profile.read"]),
            ("/api/profiles/{id}", "PATCH", vec!["profile.write"]),
            ("/api/profiles/{id}", "DELETE", vec!["profile.write"]),
            
            // Token endpoints
            ("/api/tokens", "GET", vec!["token.read"]),
            ("/api/tokens", "POST", vec!["token.write"]),
            ("/api/tokens/{id}", "GET", vec!["token.read"]),
            ("/api/tokens/{id}", "PATCH", vec!["token.write"]),
            ("/api/tokens/{id}", "DELETE", vec!["token.write"]),
            ("/api/tokens/{id}:rotate", "POST", vec!["token.write"]),
            ("/api/tokens/{id}:revoke", "POST", vec!["token.write"]),
            
            // Audit endpoints
            ("/api/audit/events", "GET", vec!["audit.read"]),
            ("/api/metrics", "GET", vec!["metrics.read"]),
            
            // Tenant endpoints (admin only)
            ("/api/tenants", "GET", vec!["admin.tenant"]),
            ("/api/tenants", "POST", vec!["admin.tenant"]),
            ("/api/tenants/{id}", "GET", vec!["admin.tenant"]),
            ("/api/tenants/{id}", "PATCH", vec!["admin.tenant"]),
            ("/api/tenants/{id}", "DELETE", vec!["admin.tenant"]),
            
            // User management (admin only)
            ("/api/users", "GET", vec!["admin.tenant"]),
            ("/api/users", "POST", vec!["admin.tenant"]),
            ("/api/users/{id}", "GET", vec!["admin.tenant"]),
            ("/api/users/{id}", "PATCH", vec!["admin.tenant"]),
            ("/api/users/{id}", "DELETE", vec!["admin.tenant"]),
        ];

        for (endpoint, method, scopes) in mappings {
            self.add_endpoint_scope_mapping(
                endpoint.to_string(),
                method.to_string(),
                scopes.into_iter().map(|s| s.to_string()).collect(),
                None,
            ).await?;
        }

        Ok(())
    }

    /// Add a role-scope mapping
    pub async fn add_role_scope_mapping(
        &self,
        role: UserRole,
        scope: &str,
        tenant_id: Option<String>,
    ) -> Result<()> {
        self.db.insert_role_scope_mapping(role, scope, tenant_id).await?;
        // Invalidate cache
        self.invalidate_role_cache(role, tenant_id.as_deref());
        Ok(())
    }

    /// Add an endpoint-scope mapping
    pub async fn add_endpoint_scope_mapping(
        &self,
        endpoint_pattern: String,
        method: String,
        required_scopes: Vec<String>,
        description: Option<String>,
    ) -> Result<()> {
        self.db.insert_endpoint_scope_mapping(
            endpoint_pattern.clone(),
            method.clone(),
            required_scopes,
            description,
        ).await?;
        // Invalidate cache
        self.invalidate_endpoint_cache(&endpoint_pattern, &method);
        Ok(())
    }

    /// Get scopes for a role (with caching)
    pub async fn get_scopes_for_role(
        &mut self,
        role: UserRole,
        tenant_id: Option<&str>,
    ) -> Result<Vec<String>> {
        let cache_key = (role, tenant_id.map(|s| s.to_string()));
        
        if let Some(cached_scopes) = self.role_scope_cache.get(&cache_key) {
            return Ok(cached_scopes.clone());
        }

        let scopes = self.db.get_scopes_for_role(role, tenant_id).await?;
        self.role_scope_cache.insert(cache_key, scopes.clone());
        
        Ok(scopes)
    }

    /// Get required scopes for an endpoint (with caching)
    pub async fn get_required_scopes_for_endpoint(
        &mut self,
        endpoint: &str,
        method: &str,
    ) -> Result<Vec<String>> {
        let cache_key = (endpoint.to_string(), method.to_string());
        
        if let Some(cached_scopes) = self.endpoint_scope_cache.get(&cache_key) {
            return Ok(cached_scopes.clone());
        }

        // Try exact match first
        if let Ok(scopes) = self.db.get_required_scopes_for_endpoint(endpoint, method).await {
            self.endpoint_scope_cache.insert(cache_key, scopes.clone());
            return Ok(scopes);
        }

        // Try pattern matching for parameterized endpoints
        let scopes = self.match_endpoint_pattern(endpoint, method).await?;
        self.endpoint_scope_cache.insert(cache_key, scopes.clone());
        
        Ok(scopes)
    }

    /// Match endpoint against patterns (for parameterized routes)
    async fn match_endpoint_pattern(&self, endpoint: &str, method: &str) -> Result<Vec<String>> {
        let all_patterns = self.db.get_all_endpoint_patterns().await?;
        
        for pattern in all_patterns {
            if self.matches_pattern(&pattern.endpoint_pattern, endpoint) && pattern.method == method {
                return Ok(pattern.required_scopes);
            }
        }
        
        // Default to no required scopes for unmatched endpoints
        warn!("No scope mapping found for endpoint: {} {}", method, endpoint);
        Ok(vec![])
    }

    /// Check if an endpoint matches a pattern
    fn matches_pattern(&self, pattern: &str, endpoint: &str) -> bool {
        // Simple pattern matching for {id} style parameters
        let pattern_parts: Vec<&str> = pattern.split('/').collect();
        let endpoint_parts: Vec<&str> = endpoint.split('/').collect();
        
        if pattern_parts.len() != endpoint_parts.len() {
            return false;
        }
        
        for (pattern_part, endpoint_part) in pattern_parts.iter().zip(endpoint_parts.iter()) {
            if pattern_part.starts_with('{') && pattern_part.ends_with('}') {
                // This is a parameter, so it matches anything
                continue;
            } else if pattern_part != endpoint_part {
                return false;
            }
        }
        
        true
    }

    /// Check if a user role has the required scopes for an endpoint
    pub async fn check_role_access(
        &mut self,
        role: UserRole,
        tenant_id: Option<&str>,
        endpoint: &str,
        method: &str,
    ) -> Result<bool> {
        let user_scopes = self.get_scopes_for_role(role, tenant_id).await?;
        let required_scopes = self.get_required_scopes_for_endpoint(endpoint, method).await?;
        
        // If no scopes are required, access is granted
        if required_scopes.is_empty() {
            return Ok(true);
        }
        
        // Check if user has all required scopes
        for required_scope in &required_scopes {
            if !user_scopes.contains(required_scope) {
                debug!("Role {:?} missing required scope: {}", role, required_scope);
                return Ok(false);
            }
        }
        
        Ok(true)
    }

    /// Check if token scopes satisfy endpoint requirements
    pub async fn check_token_access(
        &mut self,
        token_scopes: &[String],
        endpoint: &str,
        method: &str,
    ) -> Result<bool> {
        let required_scopes = self.get_required_scopes_for_endpoint(endpoint, method).await?;
        
        // If no scopes are required, access is granted
        if required_scopes.is_empty() {
            return Ok(true);
        }
        
        // Check if token has all required scopes
        for required_scope in &required_scopes {
            if !token_scopes.contains(required_scope) {
                debug!("Token missing required scope: {}", required_scope);
                return Ok(false);
            }
        }
        
        Ok(true)
    }

    /// Invalidate role cache
    fn invalidate_role_cache(&mut self, role: UserRole, tenant_id: Option<&str>) {
        let cache_key = (role, tenant_id.map(|s| s.to_string()));
        self.role_scope_cache.remove(&cache_key);
    }

    /// Invalidate endpoint cache
    fn invalidate_endpoint_cache(&mut self, endpoint: &str, method: &str) {
        let cache_key = (endpoint.to_string(), method.to_string());
        self.endpoint_scope_cache.remove(&cache_key);
    }

    /// Clear all caches
    pub fn clear_cache(&mut self) {
        self.role_scope_cache.clear();
        self.endpoint_scope_cache.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pattern_matching() {
        let permission_system = PermissionSystem::new(VaulTLSDB::new_test());
        
        assert!(permission_system.matches_pattern("/api/certificates/{id}", "/api/certificates/123"));
        assert!(permission_system.matches_pattern("/api/cas/{id}/cert", "/api/cas/456/cert"));
        assert!(!permission_system.matches_pattern("/api/certificates/{id}", "/api/certificates"));
        assert!(!permission_system.matches_pattern("/api/certificates", "/api/certificates/123"));
    }
}
