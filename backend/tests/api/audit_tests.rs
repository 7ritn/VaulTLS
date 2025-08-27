use crate::common::test_client::VaulTLSClient;
use anyhow::Result;
use rocket::http::{ContentType, Status};
use serde_json::Value;
use vaultls::data::audit::{AuditEventQuery, AuditExportRequest};
use vaultls::data::token::{CreateApiTokenRequest, Scope};

#[tokio::test]
async fn test_audit_events_listing() -> Result<()> {
    let client = VaulTLSClient::new_setup().await;
    let auth_cookie = client.login_admin().await?;

    // Create API token with audit.read scope
    let token_request = CreateApiTokenRequest {
        description: "Audit test token".to_string(),
        scopes: vec![Scope::AuditRead, Scope::CertWrite],
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

    // Generate some audit events by creating a certificate
    let cert_request = serde_json::json!({
        "name": "audit-test-cert",
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

    // Get audit events
    let request = client
        .get("/api/audit/events?page=1&per_page=50")
        .header(bearer_header);
    
    let response = request.dispatch().await;
    assert_eq!(response.status(), Status::Ok);
    
    let audit_response: Value = response.into_json().await.unwrap();
    assert!(audit_response["total"].as_i64().unwrap() > 0);
    assert!(audit_response["events"].is_array());
    assert_eq!(audit_response["page"], 1);
    assert_eq!(audit_response["per_page"], 50);

    Ok(())
}

#[tokio::test]
async fn test_audit_events_search() -> Result<()> {
    let client = VaulTLSClient::new_setup().await;
    let auth_cookie = client.login_admin().await?;

    // Create API token
    let token_request = CreateApiTokenRequest {
        description: "Audit search test token".to_string(),
        scopes: vec![Scope::AuditRead, Scope::CertWrite],
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

    // Generate audit events
    let cert_request = serde_json::json!({
        "name": "search-test-cert",
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

    // Search audit events
    let search_query = AuditEventQuery {
        event_type: Some("certificate.create".to_string()),
        resource_type: Some("certificate".to_string()),
        resource_id: None,
        user_id: Some(1),
        token_prefix: None,
        tenant_id: None, // Will be set by the API
        start_date: None,
        end_date: None,
        page: Some(1),
        page_size: Some(10),
    };

    let request = client
        .post("/api/audit/events/search")
        .header(ContentType::JSON)
        .header(bearer_header)
        .body(serde_json::to_string(&search_query)?);
    
    let response = request.dispatch().await;
    assert_eq!(response.status(), Status::Ok);
    
    let search_result: Value = response.into_json().await.unwrap();
    assert!(search_result["total"].as_i64().unwrap() >= 0);
    assert!(search_result["events"].is_array());

    Ok(())
}

#[tokio::test]
async fn test_audit_statistics() -> Result<()> {
    let client = VaulTLSClient::new_setup().await;
    let auth_cookie = client.login_admin().await?;

    // Create API token
    let token_request = CreateApiTokenRequest {
        description: "Audit stats test token".to_string(),
        scopes: vec![Scope::AuditRead],
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

    // Get audit statistics
    let request = client
        .get("/api/audit/statistics?days=30")
        .header(bearer_header);
    
    let response = request.dispatch().await;
    assert_eq!(response.status(), Status::Ok);
    
    let stats: Value = response.into_json().await.unwrap();
    assert!(stats["total_events"].is_number());
    assert!(stats["events_by_type"].is_array());
    assert!(stats["events_by_resource"].is_array());
    assert!(stats["events_by_user"].is_array());
    assert!(stats["events_by_day"].is_array());
    assert!(stats["top_endpoints"].is_array());
    assert!(stats["error_rate"].is_number());
    assert!(stats["average_response_time"].is_number());

    Ok(())
}

#[tokio::test]
async fn test_audit_activity() -> Result<()> {
    let client = VaulTLSClient::new_setup().await;
    let auth_cookie = client.login_admin().await?;

    // Create API token
    let token_request = CreateApiTokenRequest {
        description: "Audit activity test token".to_string(),
        scopes: vec![Scope::AuditRead],
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

    // Get audit activity
    let request = client
        .get("/api/audit/activity?hours=24")
        .header(bearer_header);
    
    let response = request.dispatch().await;
    assert_eq!(response.status(), Status::Ok);
    
    let activity: Value = response.into_json().await.unwrap();
    assert!(activity["timeline"].is_array());
    assert!(activity["summary"].is_object());
    
    let summary = &activity["summary"];
    assert!(summary["total_events"].is_number());
    assert!(summary["successful_operations"].is_number());
    assert!(summary["failed_operations"].is_number());
    assert!(summary["unique_users"].is_number());

    Ok(())
}

#[tokio::test]
async fn test_audit_export() -> Result<()> {
    let client = VaulTLSClient::new_setup().await;
    let auth_cookie = client.login_admin().await?;

    // Create API token
    let token_request = CreateApiTokenRequest {
        description: "Audit export test token".to_string(),
        scopes: vec![Scope::AuditRead, Scope::CertWrite],
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

    // Generate some audit events
    let cert_request = serde_json::json!({
        "name": "export-test-cert",
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

    // Export audit events
    let export_request = AuditExportRequest {
        query: AuditEventQuery {
            event_type: None,
            resource_type: None,
            resource_id: None,
            user_id: None,
            token_prefix: None,
            tenant_id: None,
            start_date: None,
            end_date: None,
            page: Some(1),
            page_size: Some(100),
        },
        fields: vec![
            "id".to_string(),
            "event_type".to_string(),
            "resource_type".to_string(),
            "created_at".to_string(),
        ],
        format: Some("csv".to_string()),
    };

    let request = client
        .post("/api/audit/export")
        .header(ContentType::JSON)
        .header(bearer_header)
        .body(serde_json::to_string(&export_request)?);
    
    let response = request.dispatch().await;
    assert_eq!(response.status(), Status::Ok);
    assert_eq!(response.content_type(), Some(ContentType::new("text", "csv")));
    
    let csv_content = response.into_string().await.unwrap();
    assert!(csv_content.contains("id,event_type,resource_type,created_at"));

    Ok(())
}

#[tokio::test]
async fn test_compliance_report() -> Result<()> {
    let client = VaulTLSClient::new_setup().await;
    let auth_cookie = client.login_admin().await?;

    // Create API token
    let token_request = CreateApiTokenRequest {
        description: "Compliance test token".to_string(),
        scopes: vec![Scope::AuditRead],
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

    // Generate compliance report
    let now = chrono::Utc::now().timestamp();
    let thirty_days_ago = now - (30 * 24 * 60 * 60);

    let request = client
        .get(&format!("/api/audit/compliance-report?start_date={}&end_date={}&format=json", thirty_days_ago, now))
        .header(bearer_header);
    
    let response = request.dispatch().await;
    assert_eq!(response.status(), Status::Ok);
    assert_eq!(response.content_type(), Some(ContentType::JSON));

    Ok(())
}

#[tokio::test]
async fn test_audit_scope_enforcement() -> Result<()> {
    let client = VaulTLSClient::new_setup().await;
    let auth_cookie = client.login_admin().await?;

    // Create API token without audit.read scope
    let token_request = CreateApiTokenRequest {
        description: "No audit scope token".to_string(),
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

    // Should fail to access audit endpoints
    let request = client
        .get("/api/audit/events")
        .header(bearer_header);
    
    let response = request.dispatch().await;
    assert_eq!(response.status(), Status::Forbidden);
    assert_eq!(response.content_type(), Some(ContentType::new("application", "problem+json")));

    Ok(())
}
