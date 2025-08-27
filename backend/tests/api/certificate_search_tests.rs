use crate::common::test_client::VaulTLSClient;
use anyhow::Result;
use rocket::http::{ContentType, Status};
use serde_json::Value;
use vaultls::cert::{CertificateSearchRequest, SearchFilter, SearchField, SearchOperator, SearchValue, SortOption, SortDirection, BatchOperationRequest, BatchOperation};
use vaultls::data::token::{CreateApiTokenRequest, Scope};

#[tokio::test]
async fn test_certificate_search_basic() -> Result<()> {
    let client = VaulTLSClient::new_setup().await;
    let auth_cookie = client.login_admin().await?;

    // Create API token with cert.read scope
    let token_request = CreateApiTokenRequest {
        description: "Search test token".to_string(),
        scopes: vec![Scope::CertRead, Scope::CertWrite],
        expires_at: None,
        rate_limit_per_minute: Some(100),
    };

    let request = client
        .post("/api/tokens")
        .header(ContentType::JSON)
        .header(auth_cookie.clone())
        .body(serde_json::to_string(&token_request)?);
    
    let response = request.dispatch().await;
    let token_response: vaultls::data::token::ApiTokenResponse = response.into_json().await.unwrap();
    let bearer_header = rocket::http::Header::new("Authorization", format!("Bearer {}", token_response.token));

    // Create some test certificates first
    for i in 1..=3 {
        let cert_request = serde_json::json!({
            "name": format!("test-cert-{}", i),
            "user_id": 1,
            "certificate_type": "Server",
            "validity_years": 1
        });

        let request = client
            .post("/api/certificates")
            .header(ContentType::JSON)
            .header(auth_cookie.clone())
            .body(cert_request.to_string());
        
        let response = request.dispatch().await;
        assert_eq!(response.status(), Status::Ok);
    }

    // Basic search without filters
    let search_request = CertificateSearchRequest {
        filters: None,
        sort: None,
        page: Some(1),
        per_page: Some(10),
        include_revoked: Some(true),
        include_expired: Some(true),
    };

    let request = client
        .post("/api/certificates/search")
        .header(ContentType::JSON)
        .header(bearer_header)
        .body(serde_json::to_string(&search_request)?);
    
    let response = request.dispatch().await;
    assert_eq!(response.status(), Status::Ok);
    
    let search_result: Value = response.into_json().await.unwrap();
    assert!(search_result["total"].as_i64().unwrap() >= 3);
    assert!(search_result["certificates"].as_array().unwrap().len() >= 3);

    Ok(())
}

#[tokio::test]
async fn test_certificate_search_with_filters() -> Result<()> {
    let client = VaulTLSClient::new_setup().await;
    let auth_cookie = client.login_admin().await?;

    // Create API token
    let token_request = CreateApiTokenRequest {
        description: "Filter search test token".to_string(),
        scopes: vec![Scope::CertRead, Scope::CertWrite],
        expires_at: None,
        rate_limit_per_minute: Some(100),
    };

    let request = client
        .post("/api/tokens")
        .header(ContentType::JSON)
        .header(auth_cookie.clone())
        .body(serde_json::to_string(&token_request)?);
    
    let response = request.dispatch().await;
    let token_response: vaultls::data::token::ApiTokenResponse = response.into_json().await.unwrap();
    let bearer_header = rocket::http::Header::new("Authorization", format!("Bearer {}", token_response.token));

    // Create test certificates with different names
    let cert_names = vec!["server-cert", "client-cert", "api-cert"];
    for name in &cert_names {
        let cert_request = serde_json::json!({
            "name": name,
            "user_id": 1,
            "certificate_type": "Server",
            "validity_years": 1
        });

        let request = client
            .post("/api/certificates")
            .header(ContentType::JSON)
            .header(auth_cookie.clone())
            .body(cert_request.to_string());
        
        let response = request.dispatch().await;
        assert_eq!(response.status(), Status::Ok);
    }

    // Search with name filter
    let search_request = CertificateSearchRequest {
        filters: Some(vec![
            SearchFilter {
                field: SearchField::Name,
                operator: SearchOperator::Like,
                value: SearchValue::String("server%".to_string()),
            }
        ]),
        sort: None,
        page: Some(1),
        per_page: Some(10),
        include_revoked: Some(true),
        include_expired: Some(true),
    };

    let request = client
        .post("/api/certificates/search")
        .header(ContentType::JSON)
        .header(bearer_header.clone())
        .body(serde_json::to_string(&search_request)?);
    
    let response = request.dispatch().await;
    assert_eq!(response.status(), Status::Ok);
    
    let search_result: Value = response.into_json().await.unwrap();
    let certificates = search_result["certificates"].as_array().unwrap();
    
    // Should only find certificates with names starting with "server"
    for cert in certificates {
        let name = cert["name"].as_str().unwrap();
        assert!(name.starts_with("server"));
    }

    Ok(())
}

#[tokio::test]
async fn test_certificate_search_with_sorting() -> Result<()> {
    let client = VaulTLSClient::new_setup().await;
    let auth_cookie = client.login_admin().await?;

    // Create API token
    let token_request = CreateApiTokenRequest {
        description: "Sort search test token".to_string(),
        scopes: vec![Scope::CertRead, Scope::CertWrite],
        expires_at: None,
        rate_limit_per_minute: Some(100),
    };

    let request = client
        .post("/api/tokens")
        .header(ContentType::JSON)
        .header(auth_cookie.clone())
        .body(serde_json::to_string(&token_request)?);
    
    let response = request.dispatch().await;
    let token_response: vaultls::data::token::ApiTokenResponse = response.into_json().await.unwrap();
    let bearer_header = rocket::http::Header::new("Authorization", format!("Bearer {}", token_response.token));

    // Search with sorting by name ascending
    let search_request = CertificateSearchRequest {
        filters: None,
        sort: Some(vec![
            SortOption {
                field: SearchField::Name,
                direction: SortDirection::Asc,
            }
        ]),
        page: Some(1),
        per_page: Some(10),
        include_revoked: Some(true),
        include_expired: Some(true),
    };

    let request = client
        .post("/api/certificates/search")
        .header(ContentType::JSON)
        .header(bearer_header)
        .body(serde_json::to_string(&search_request)?);
    
    let response = request.dispatch().await;
    assert_eq!(response.status(), Status::Ok);
    
    let search_result: Value = response.into_json().await.unwrap();
    let certificates = search_result["certificates"].as_array().unwrap();
    
    // Verify sorting (names should be in ascending order)
    if certificates.len() > 1 {
        for i in 1..certificates.len() {
            let prev_name = certificates[i-1]["name"].as_str().unwrap();
            let curr_name = certificates[i]["name"].as_str().unwrap();
            assert!(prev_name <= curr_name);
        }
    }

    Ok(())
}

#[tokio::test]
async fn test_certificate_batch_operations() -> Result<()> {
    let client = VaulTLSClient::new_setup().await;
    let auth_cookie = client.login_admin().await?;

    // Create API token
    let token_request = CreateApiTokenRequest {
        description: "Batch test token".to_string(),
        scopes: vec![Scope::CertRead, Scope::CertWrite],
        expires_at: None,
        rate_limit_per_minute: Some(100),
    };

    let request = client
        .post("/api/tokens")
        .header(ContentType::JSON)
        .header(auth_cookie.clone())
        .body(serde_json::to_string(&token_request)?);
    
    let response = request.dispatch().await;
    let token_response: vaultls::data::token::ApiTokenResponse = response.into_json().await.unwrap();
    let bearer_header = rocket::http::Header::new("Authorization", format!("Bearer {}", token_response.token));

    // Create test certificates
    let mut cert_ids = Vec::new();
    for i in 1..=3 {
        let cert_request = serde_json::json!({
            "name": format!("batch-cert-{}", i),
            "user_id": 1,
            "certificate_type": "Server",
            "validity_years": 1
        });

        let request = client
            .post("/api/certificates")
            .header(ContentType::JSON)
            .header(auth_cookie.clone())
            .body(cert_request.to_string());
        
        let response = request.dispatch().await;
        let cert: Value = response.into_json().await.unwrap();
        cert_ids.push(cert["id"].as_i64().unwrap());
    }

    // Test batch revoke operation
    let batch_request = BatchOperationRequest {
        certificate_ids: cert_ids.clone(),
        operation: BatchOperation::Revoke,
        parameters: Some(vaultls::cert::BatchOperationParameters {
            revocation_reason: Some(1),
            revocation_note: Some("Test revocation".to_string()),
            format: None,
            include_chain: None,
            validity_years: None,
            metadata: None,
        }),
    };

    let request = client
        .post("/api/certificates/batch")
        .header(ContentType::JSON)
        .header(bearer_header)
        .body(serde_json::to_string(&batch_request)?);
    
    let response = request.dispatch().await;
    assert_eq!(response.status(), Status::Ok);
    
    let batch_result: Value = response.into_json().await.unwrap();
    assert_eq!(batch_result["total_requested"], cert_ids.len());
    assert_eq!(batch_result["successful"], cert_ids.len());
    assert_eq!(batch_result["failed"], 0);

    Ok(())
}

#[tokio::test]
async fn test_certificate_statistics() -> Result<()> {
    let client = VaulTLSClient::new_setup().await;
    let auth_cookie = client.login_admin().await?;

    // Create API token
    let token_request = CreateApiTokenRequest {
        description: "Stats test token".to_string(),
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
    let token_response: vaultls::data::token::ApiTokenResponse = response.into_json().await.unwrap();
    let bearer_header = rocket::http::Header::new("Authorization", format!("Bearer {}", token_response.token));

    // Get certificate statistics
    let request = client
        .get("/api/certificates/statistics")
        .header(bearer_header);
    
    let response = request.dispatch().await;
    assert_eq!(response.status(), Status::Ok);
    
    let stats: Value = response.into_json().await.unwrap();
    assert!(stats["total_certificates"].is_number());
    assert!(stats["active_certificates"].is_number());
    assert!(stats["revoked_certificates"].is_number());
    assert!(stats["expired_certificates"].is_number());
    assert!(stats["expiring_soon"].is_number());
    assert!(stats["by_type"].is_object());
    assert!(stats["recent_activity"].is_object());

    Ok(())
}

#[tokio::test]
async fn test_expiring_certificates() -> Result<()> {
    let client = VaulTLSClient::new_setup().await;
    let auth_cookie = client.login_admin().await?;

    // Create API token
    let token_request = CreateApiTokenRequest {
        description: "Expiring test token".to_string(),
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
    let token_response: vaultls::data::token::ApiTokenResponse = response.into_json().await.unwrap();
    let bearer_header = rocket::http::Header::new("Authorization", format!("Bearer {}", token_response.token));

    // Get expiring certificates (30 days ahead)
    let request = client
        .get("/api/certificates/expiring?days_ahead=30")
        .header(bearer_header);
    
    let response = request.dispatch().await;
    assert_eq!(response.status(), Status::Ok);
    
    let expiring: Value = response.into_json().await.unwrap();
    assert!(expiring["total"].is_number());
    assert!(expiring["certificates"].is_array());
    assert!(expiring["page"].is_number());
    assert!(expiring["per_page"].is_number());

    Ok(())
}
