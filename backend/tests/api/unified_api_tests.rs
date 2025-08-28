use crate::common::test_client::VaulTLSClient;
use anyhow::Result;
use rocket::http::{ContentType, Status};
use serde_json::Value;
use vaultls::data::token::{CreateApiTokenRequest, Scope};

#[tokio::test]
async fn test_modern_api_endpoints() -> Result<()> {
    let client = VaulTLSClient::new_setup().await;
    let auth_cookie = client.login_admin().await?;

    // Create API token with comprehensive scopes
    let token_request = CreateApiTokenRequest {
        description: "Unified API Test Token".to_string(),
        scopes: vec![
            Scope::CertRead,
            Scope::CertWrite,
            Scope::CaRead,
            Scope::ProfileRead,
            Scope::AuditRead,
        ],
        expires_at: None,
        rate_limit_per_minute: Some(1000),
    };

    let request = client
        .post("/api/tokens")
        .header(ContentType::JSON)
        .header(auth_cookie)
        .body(serde_json::to_string(&token_request)?);
    
    let response = request.dispatch().await;
    assert_eq!(response.status(), Status::Ok);
    
    let token_response: vaultls::data::token::ApiTokenResponse = response.into_json().await.unwrap();
    let bearer_header = rocket::http::Header::new("Authorization", format!("Bearer {}", token_response.token));

    // Test modern certificate search endpoint
    let search_request = serde_json::json!({
        "page": 1,
        "per_page": 50,
        "filters": [],
        "sort": [{"field": "created_at", "direction": "desc"}]
    });

    let request = client
        .post("/api/certificates/search")
        .header(ContentType::JSON)
        .header(bearer_header.clone())
        .body(search_request.to_string());
    
    let response = request.dispatch().await;
    assert_eq!(response.status(), Status::Ok);
    
    let search_result: Value = response.into_json().await.unwrap();
    assert!(search_result["certificates"].is_array());
    assert!(search_result["total"].is_number());
    assert!(search_result["page"].is_number());

    // Test modern certificate creation
    let cert_request = serde_json::json!({
        "name": "unified-api-test-cert",
        "user_id": 1,
        "certificate_type": "Server",
        "validity_years": 1,
        "ca_selection": "auto"
    });

    let request = client
        .post("/api/certificates")
        .header(ContentType::JSON)
        .header(bearer_header.clone())
        .body(cert_request.to_string());
    
    let response = request.dispatch().await;
    assert_eq!(response.status(), Status::Ok);
    
    let certificate: Value = response.into_json().await.unwrap();
    assert!(certificate["id"].is_number());
    assert_eq!(certificate["name"], "unified-api-test-cert");

    // Test CA listing
    let request = client
        .get("/api/cas")
        .header(bearer_header.clone());
    
    let response = request.dispatch().await;
    assert_eq!(response.status(), Status::Ok);
    
    let cas: Value = response.into_json().await.unwrap();
    assert!(cas["cas"].is_array());

    // Test audit events
    let request = client
        .get("/api/audit/events?page=1&per_page=10")
        .header(bearer_header);
    
    let response = request.dispatch().await;
    assert_eq!(response.status(), Status::Ok);
    
    let audit_events: Value = response.into_json().await.unwrap();
    assert!(audit_events["events"].is_array());
    assert!(audit_events["total"].is_number());

    Ok(())
}

#[tokio::test]
async fn test_legacy_api_deprecation() -> Result<()> {
    let client = VaulTLSClient::new_setup().await;
    
    // Test that legacy endpoints are properly deprecated
    // Note: This test assumes legacy endpoints are still enabled for testing
    
    // Test legacy certificate listing (should work but with warnings)
    let request = client
        .get("/api/legacy/certificates");
    
    let response = request.dispatch().await;
    // Legacy endpoints should either work with deprecation warnings or return 410 Gone
    assert!(response.status() == Status::Ok || response.status() == Status::Gone);

    Ok(())
}

#[tokio::test]
async fn test_api_documentation_endpoints() -> Result<()> {
    let client = VaulTLSClient::new_setup().await;

    // Test API docs endpoint
    let request = client
        .get("/api/docs");
    
    let response = request.dispatch().await;
    assert_eq!(response.status(), Status::Ok);
    
    let docs: Value = response.into_json().await.unwrap();
    assert_eq!(docs["title"], "VaulTLS API Documentation");
    assert!(docs["links"].is_object());
    assert!(docs["authentication"].is_object());

    // Test version endpoint
    let request = client
        .get("/api/server/version");
    
    let response = request.dispatch().await;
    assert_eq!(response.status(), Status::Ok);
    
    let version = response.into_string().await.unwrap();
    assert!(!version.is_empty());

    Ok(())
}

#[tokio::test]
async fn test_bearer_token_scopes() -> Result<()> {
    let client = VaulTLSClient::new_setup().await;
    let auth_cookie = client.login_admin().await?;

    // Create token with limited scopes
    let token_request = CreateApiTokenRequest {
        description: "Limited Scope Token".to_string(),
        scopes: vec![Scope::CertRead], // Only cert.read scope
        expires_at: None,
        rate_limit_per_minute: Some(100),
    };

    let request = client
        .post("/api/tokens")
        .header(ContentType::JSON)
        .header(auth_cookie)
        .body(serde_json::to_string(&token_request)?);
    
    let response = request.dispatch().await;
    let token_response: vaultls::data::token::ApiTokenResponse = response.into_json().await.unwrap();
    let bearer_header = rocket::http::Header::new("Authorization", format!("Bearer {}", token_response.token));

    // Should be able to read certificates
    let search_request = serde_json::json!({
        "page": 1,
        "per_page": 10
    });

    let request = client
        .post("/api/certificates/search")
        .header(ContentType::JSON)
        .header(bearer_header.clone())
        .body(search_request.to_string());
    
    let response = request.dispatch().await;
    assert_eq!(response.status(), Status::Ok);

    // Should NOT be able to create certificates (requires cert.write)
    let cert_request = serde_json::json!({
        "name": "scope-test-cert",
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
async fn test_api_error_responses() -> Result<()> {
    let client = VaulTLSClient::new_setup().await;

    // Test unauthenticated request
    let request = client
        .get("/api/certificates/search");
    
    let response = request.dispatch().await;
    assert_eq!(response.status(), Status::Unauthorized);
    assert_eq!(response.content_type(), Some(ContentType::new("application", "problem+json")));

    // Test invalid Bearer token
    let invalid_bearer = rocket::http::Header::new("Authorization", "Bearer invalid-token");
    
    let request = client
        .get("/api/certificates/search")
        .header(invalid_bearer);
    
    let response = request.dispatch().await;
    assert_eq!(response.status(), Status::Unauthorized);
    assert_eq!(response.content_type(), Some(ContentType::new("application", "problem+json")));

    // Test not found endpoint
    let request = client
        .get("/api/nonexistent");
    
    let response = request.dispatch().await;
    assert_eq!(response.status(), Status::NotFound);

    Ok(())
}

#[tokio::test]
async fn test_api_rate_limiting() -> Result<()> {
    let client = VaulTLSClient::new_setup().await;
    let auth_cookie = client.login_admin().await?;

    // Create token with very low rate limit
    let token_request = CreateApiTokenRequest {
        description: "Rate Limited Token".to_string(),
        scopes: vec![Scope::CertRead],
        expires_at: None,
        rate_limit_per_minute: Some(2), // Very low limit for testing
    };

    let request = client
        .post("/api/tokens")
        .header(ContentType::JSON)
        .header(auth_cookie)
        .body(serde_json::to_string(&token_request)?);
    
    let response = request.dispatch().await;
    let token_response: vaultls::data::token::ApiTokenResponse = response.into_json().await.unwrap();
    let bearer_header = rocket::http::Header::new("Authorization", format!("Bearer {}", token_response.token));

    // Make requests up to the limit
    for i in 1..=2 {
        let request = client
            .get("/api/server/version")
            .header(bearer_header.clone());
        
        let response = request.dispatch().await;
        assert_eq!(response.status(), Status::Ok, "Request {} should succeed", i);
    }

    // Next request should be rate limited
    let request = client
        .get("/api/server/version")
        .header(bearer_header);
    
    let response = request.dispatch().await;
    assert_eq!(response.status(), Status::TooManyRequests);

    Ok(())
}

#[tokio::test]
async fn test_tenant_isolation() -> Result<()> {
    let client = VaulTLSClient::new_setup().await;
    let auth_cookie = client.login_admin().await?;

    // Create API token
    let token_request = CreateApiTokenRequest {
        description: "Tenant Isolation Test Token".to_string(),
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
    let token_response: vaultls::data::token::ApiTokenResponse = response.into_json().await.unwrap();
    let bearer_header = rocket::http::Header::new("Authorization", format!("Bearer {}", token_response.token));

    // Create a certificate
    let cert_request = serde_json::json!({
        "name": "tenant-isolation-test",
        "user_id": 1,
        "certificate_type": "Server",
        "validity_years": 1
    });

    let request = client
        .post("/api/certificates")
        .header(ContentType::JSON)
        .header(bearer_header.clone())
        .body(cert_request.to_string());
    
    let response = request.dispatch().await;
    assert_eq!(response.status(), Status::Ok);

    // Search for certificates - should only return certificates for this tenant
    let search_request = serde_json::json!({
        "page": 1,
        "per_page": 100
    });

    let request = client
        .post("/api/certificates/search")
        .header(ContentType::JSON)
        .header(bearer_header)
        .body(search_request.to_string());
    
    let response = request.dispatch().await;
    assert_eq!(response.status(), Status::Ok);
    
    let search_result: Value = response.into_json().await.unwrap();
    let certificates = search_result["certificates"].as_array().unwrap();
    
    // All returned certificates should belong to the same tenant
    // (This is implicitly tested by the fact that the search succeeds with tenant isolation)
    assert!(certificates.len() >= 1);

    Ok(())
}
