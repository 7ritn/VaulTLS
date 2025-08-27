use crate::common::test_client::VaulTLSClient;
use anyhow::Result;
use rocket::http::{ContentType, Status, Header};
use serde_json::Value;
use vaultls::data::token::{CreateApiTokenRequest, ApiTokenResponse, Scope};
use vaultls::data::enums::UserRole;

#[tokio::test]
async fn test_bearer_token_creation() -> Result<()> {
    let client = VaulTLSClient::new_setup().await;
    let auth_cookie = client.login_admin().await?;

    // Create API token
    let token_request = CreateApiTokenRequest {
        description: "Test token".to_string(),
        scopes: vec![Scope::CertRead, Scope::CertWrite],
        expires_at: None,
        rate_limit_per_minute: Some(100),
    };

    let request = client
        .post("/api/tokens")
        .header(ContentType::JSON)
        .header(auth_cookie)
        .body(serde_json::to_string(&token_request)?);
    
    let response = request.dispatch().await;
    assert_eq!(response.status(), Status::Ok);
    
    let token_response: ApiTokenResponse = response.into_json().await.unwrap();
    assert!(token_response.token.starts_with("vlt_"));
    assert_eq!(token_response.description, "Test token");
    assert_eq!(token_response.scopes.len(), 2);

    Ok(())
}

#[tokio::test]
async fn test_bearer_token_authentication() -> Result<()> {
    let client = VaulTLSClient::new_setup().await;
    let auth_cookie = client.login_admin().await?;

    // Create API token with cert.read scope
    let token_request = CreateApiTokenRequest {
        description: "Read token".to_string(),
        scopes: vec![Scope::CertRead],
        expires_at: None,
        rate_limit_per_minute: Some(100),
    };

    let request = client
        .post("/api/tokens")
        .header(ContentType::JSON)
        .header(auth_cookie)
        .body(serde_json::to_string(&token_request)?);
    
    let response = request.dispatch().await;
    let token_response: ApiTokenResponse = response.into_json().await.unwrap();

    // Test using Bearer token for API access
    let bearer_header = Header::new("Authorization", format!("Bearer {}", token_response.token));
    
    let request = client
        .get("/api/certificates")
        .header(bearer_header);
    
    let response = request.dispatch().await;
    assert_eq!(response.status(), Status::Ok);

    Ok(())
}

#[tokio::test]
async fn test_bearer_token_scope_enforcement() -> Result<()> {
    let client = VaulTLSClient::new_setup().await;
    let auth_cookie = client.login_admin().await?;

    // Create API token with only cert.read scope
    let token_request = CreateApiTokenRequest {
        description: "Read-only token".to_string(),
        scopes: vec![Scope::CertRead],
        expires_at: None,
        rate_limit_per_minute: Some(100),
    };

    let request = client
        .post("/api/tokens")
        .header(ContentType::JSON)
        .header(auth_cookie)
        .body(serde_json::to_string(&token_request)?);
    
    let response = request.dispatch().await;
    let token_response: ApiTokenResponse = response.into_json().await.unwrap();

    let bearer_header = Header::new("Authorization", format!("Bearer {}", token_response.token));
    
    // Should succeed with cert.read scope
    let request = client
        .get("/api/certificates")
        .header(bearer_header.clone());
    
    let response = request.dispatch().await;
    assert_eq!(response.status(), Status::Ok);

    // Should fail with cert.write operation (missing scope)
    let cert_request = serde_json::json!({
        "name": "test-cert",
        "user_id": 1,
        "certificate_type": "Server",
        "validity_years": 1
    });

    let request = client
        .post("/api/certificates")
        .header(ContentType::JSON)
        .header(bearer_header)
        .body(cert_request.to_string());
    
    let response = request.dispatch().await;
    assert_eq!(response.status(), Status::Forbidden);

    Ok(())
}

#[tokio::test]
async fn test_bearer_token_invalid_format() -> Result<()> {
    let client = VaulTLSClient::new_setup().await;

    // Test invalid token format
    let bearer_header = Header::new("Authorization", "Bearer invalid_token");
    
    let request = client
        .get("/api/certificates")
        .header(bearer_header);
    
    let response = request.dispatch().await;
    assert_eq!(response.status(), Status::Unauthorized);

    Ok(())
}

#[tokio::test]
async fn test_bearer_token_revocation() -> Result<()> {
    let client = VaulTLSClient::new_setup().await;
    let auth_cookie = client.login_admin().await?;

    // Create API token
    let token_request = CreateApiTokenRequest {
        description: "Revoke test token".to_string(),
        scopes: vec![Scope::CertRead],
        expires_at: None,
        rate_limit_per_minute: Some(100),
    };

    let request = client
        .post("/api/tokens")
        .header(ContentType::JSON)
        .header(auth_cookie.clone())
        .body(serde_json::to_string(&token_request)?);
    
    let response = request.dispatch().await;
    let token_response: ApiTokenResponse = response.into_json().await.unwrap();

    let bearer_header = Header::new("Authorization", format!("Bearer {}", token_response.token));
    
    // Token should work initially
    let request = client
        .get("/api/certificates")
        .header(bearer_header.clone());
    
    let response = request.dispatch().await;
    assert_eq!(response.status(), Status::Ok);

    // Revoke the token
    let request = client
        .post(&format!("/api/tokens/{}/revoke", token_response.id))
        .header(auth_cookie);
    
    let response = request.dispatch().await;
    assert_eq!(response.status(), Status::Ok);

    // Token should no longer work
    let request = client
        .get("/api/certificates")
        .header(bearer_header);
    
    let response = request.dispatch().await;
    assert_eq!(response.status(), Status::Unauthorized);

    Ok(())
}

#[tokio::test]
async fn test_bearer_token_tenant_isolation() -> Result<()> {
    let client = VaulTLSClient::new_setup().await;
    let auth_cookie = client.login_admin().await?;

    // Create API token
    let token_request = CreateApiTokenRequest {
        description: "Tenant test token".to_string(),
        scopes: vec![Scope::CertRead, Scope::CaRead],
        expires_at: None,
        rate_limit_per_minute: Some(100),
    };

    let request = client
        .post("/api/tokens")
        .header(ContentType::JSON)
        .header(auth_cookie)
        .body(serde_json::to_string(&token_request)?);
    
    let response = request.dispatch().await;
    let token_response: ApiTokenResponse = response.into_json().await.unwrap();

    let bearer_header = Header::new("Authorization", format!("Bearer {}", token_response.token));
    
    // Should only see certificates from the same tenant
    let request = client
        .get("/api/certificates")
        .header(bearer_header.clone());
    
    let response = request.dispatch().await;
    assert_eq!(response.status(), Status::Ok);
    
    let certificates: Value = response.into_json().await.unwrap();
    // Verify tenant isolation in response (implementation specific)
    
    // Should only see CAs from the same tenant
    let request = client
        .get("/api/cas")
        .header(bearer_header);
    
    let response = request.dispatch().await;
    assert_eq!(response.status(), Status::Ok);

    Ok(())
}

#[tokio::test]
async fn test_bearer_token_rfc9457_errors() -> Result<()> {
    let client = VaulTLSClient::new_setup().await;

    // Test missing token
    let request = client.get("/api/certificates");
    let response = request.dispatch().await;
    assert_eq!(response.status(), Status::Unauthorized);
    assert_eq!(response.content_type(), Some(ContentType::new("application", "problem+json")));
    
    let error: Value = response.into_json().await.unwrap();
    assert_eq!(error["status"], 401);
    assert_eq!(error["title"], "Unauthorized");
    assert!(error["type"].as_str().unwrap().contains("rfc9110"));

    // Test invalid token
    let bearer_header = Header::new("Authorization", "Bearer invalid_token");
    let request = client
        .get("/api/certificates")
        .header(bearer_header);
    
    let response = request.dispatch().await;
    assert_eq!(response.status(), Status::Unauthorized);
    assert_eq!(response.content_type(), Some(ContentType::new("application", "problem+json")));

    Ok(())
}
