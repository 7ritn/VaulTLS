use crate::common::test_client::VaulTLSClient;
use anyhow::Result;
use rocket::http::{ContentType, Status, Header};
use serde_json::Value;
use vaultls::data::token::{CreateApiTokenRequest, Scope};
use vaultls::data::profile::CreateProfileRequest;
use vaultls::cert::{CertificateSearchRequest, SearchFilter, SearchField, SearchOperator, SearchValue};

/// Integration test that demonstrates the complete VaulTLS workflow
/// with Bearer token authentication, profiles, and certificate management
#[tokio::test]
async fn test_complete_vaultls_workflow() -> Result<()> {
    let client = VaulTLSClient::new_setup().await;
    let auth_cookie = client.login_admin().await?;

    // Step 1: Create API token with comprehensive scopes
    let token_request = CreateApiTokenRequest {
        description: "Integration Test Token".to_string(),
        scopes: vec![
            Scope::CertRead,
            Scope::CertWrite,
            Scope::CaRead,
            Scope::CaWrite,
            Scope::ProfileRead,
            Scope::ProfileWrite,
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
    let bearer_header = Header::new("Authorization", format!("Bearer {}", token_response.token));

    // Step 2: Create certificate profiles
    let server_profile = CreateProfileRequest {
        name: "Server Certificate Profile".to_string(),
        eku: vec!["serverAuth".to_string()],
        key_usage: vec!["digitalSignature".to_string(), "keyEncipherment".to_string()],
        san_rules: None,
        default_days: 365,
        max_days: 730,
        renewal_window_pct: Some(30),
        key_alg_options: vec!["RSA-2048".to_string(), "RSA-4096".to_string(), "ECDSA-P256".to_string()],
    };

    let request = client
        .post("/api/profiles")
        .header(ContentType::JSON)
        .header(bearer_header.clone())
        .body(serde_json::to_string(&server_profile)?);
    
    let response = request.dispatch().await;
    assert_eq!(response.status(), Status::Ok);
    let server_profile_response: Value = response.into_json().await.unwrap();

    let client_profile = CreateProfileRequest {
        name: "Client Certificate Profile".to_string(),
        eku: vec!["clientAuth".to_string()],
        key_usage: vec!["digitalSignature".to_string()],
        san_rules: None,
        default_days: 180,
        max_days: 365,
        renewal_window_pct: Some(20),
        key_alg_options: vec!["RSA-2048".to_string(), "ECDSA-P256".to_string()],
    };

    let request = client
        .post("/api/profiles")
        .header(ContentType::JSON)
        .header(bearer_header.clone())
        .body(serde_json::to_string(&client_profile)?);
    
    let response = request.dispatch().await;
    assert_eq!(response.status(), Status::Ok);
    let client_profile_response: Value = response.into_json().await.unwrap();

    // Step 3: List profiles to verify creation
    let request = client
        .get("/api/profiles")
        .header(bearer_header.clone());
    
    let response = request.dispatch().await;
    assert_eq!(response.status(), Status::Ok);
    let profiles_list: Value = response.into_json().await.unwrap();
    assert_eq!(profiles_list["total"], 2);

    // Step 4: Create certificates using different profiles
    let mut certificate_ids = Vec::new();

    // Create server certificates
    for i in 1..=3 {
        let cert_request = serde_json::json!({
            "name": format!("server-cert-{}", i),
            "user_id": 1,
            "certificate_type": "Server",
            "validity_years": 1,
            "profile_id": server_profile_response["id"]
        });

        let request = client
            .post("/api/certificates")
            .header(ContentType::JSON)
            .header(bearer_header.clone())
            .body(cert_request.to_string());
        
        let response = request.dispatch().await;
        assert_eq!(response.status(), Status::Ok);
        let cert: Value = response.into_json().await.unwrap();
        certificate_ids.push(cert["id"].as_i64().unwrap());
    }

    // Create client certificates
    for i in 1..=2 {
        let cert_request = serde_json::json!({
            "name": format!("client-cert-{}", i),
            "user_id": 1,
            "certificate_type": "Client",
            "validity_years": 1,
            "profile_id": client_profile_response["id"]
        });

        let request = client
            .post("/api/certificates")
            .header(ContentType::JSON)
            .header(bearer_header.clone())
            .body(cert_request.to_string());
        
        let response = request.dispatch().await;
        assert_eq!(response.status(), Status::Ok);
        let cert: Value = response.into_json().await.unwrap();
        certificate_ids.push(cert["id"].as_i64().unwrap());
    }

    // Step 5: Test advanced certificate search
    let search_request = CertificateSearchRequest {
        filters: Some(vec![
            SearchFilter {
                field: SearchField::CertificateType,
                operator: SearchOperator::Eq,
                value: SearchValue::String("Server".to_string()),
            }
        ]),
        sort: None,
        page: Some(1),
        per_page: Some(10),
        include_revoked: Some(false),
        include_expired: Some(false),
    };

    let request = client
        .post("/api/certificates/search")
        .header(ContentType::JSON)
        .header(bearer_header.clone())
        .body(serde_json::to_string(&search_request)?);
    
    let response = request.dispatch().await;
    assert_eq!(response.status(), Status::Ok);
    let search_result: Value = response.into_json().await.unwrap();
    assert_eq!(search_result["certificates"].as_array().unwrap().len(), 3);

    // Step 6: Test certificate statistics
    let request = client
        .get("/api/certificates/statistics")
        .header(bearer_header.clone());
    
    let response = request.dispatch().await;
    assert_eq!(response.status(), Status::Ok);
    let stats: Value = response.into_json().await.unwrap();
    assert_eq!(stats["total_certificates"], 5);
    assert_eq!(stats["by_type"]["server"], 3);
    assert_eq!(stats["by_type"]["client"], 2);

    // Step 7: Test CA management
    let request = client
        .get("/api/cas")
        .header(bearer_header.clone());
    
    let response = request.dispatch().await;
    assert_eq!(response.status(), Status::Ok);
    let cas: Value = response.into_json().await.unwrap();
    assert!(cas["cas"].as_array().unwrap().len() >= 1);

    // Step 8: Test audit logging
    let request = client
        .get("/api/audit/events?page=1&per_page=50")
        .header(bearer_header.clone());
    
    let response = request.dispatch().await;
    assert_eq!(response.status(), Status::Ok);
    let audit_events: Value = response.into_json().await.unwrap();
    assert!(audit_events["total"].as_i64().unwrap() > 0);

    // Step 9: Test batch operations
    let batch_request = serde_json::json!({
        "certificate_ids": [certificate_ids[0], certificate_ids[1]],
        "operation": "revoke",
        "parameters": {
            "revocation_reason": 1,
            "revocation_note": "Integration test revocation"
        }
    });

    let request = client
        .post("/api/certificates/batch")
        .header(ContentType::JSON)
        .header(bearer_header.clone())
        .body(batch_request.to_string());
    
    let response = request.dispatch().await;
    assert_eq!(response.status(), Status::Ok);
    let batch_result: Value = response.into_json().await.unwrap();
    assert_eq!(batch_result["successful"], 2);
    assert_eq!(batch_result["failed"], 0);

    // Step 10: Verify revocation in search results
    let search_request = CertificateSearchRequest {
        filters: Some(vec![
            SearchFilter {
                field: SearchField::Status,
                operator: SearchOperator::Eq,
                value: SearchValue::String("revoked".to_string()),
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
    let revoked_certs: Value = response.into_json().await.unwrap();
    assert_eq!(revoked_certs["certificates"].as_array().unwrap().len(), 2);

    // Step 11: Test audit statistics after operations
    let request = client
        .get("/api/audit/statistics?days=1")
        .header(bearer_header);
    
    let response = request.dispatch().await;
    assert_eq!(response.status(), Status::Ok);
    let final_stats: Value = response.into_json().await.unwrap();
    assert!(final_stats["total_events"].as_i64().unwrap() > 0);

    println!("✅ Complete VaulTLS workflow integration test passed!");
    println!("   - Created API token with comprehensive scopes");
    println!("   - Created server and client certificate profiles");
    println!("   - Issued 5 certificates (3 server, 2 client)");
    println!("   - Performed advanced certificate search");
    println!("   - Verified certificate statistics");
    println!("   - Tested CA management endpoints");
    println!("   - Verified audit logging functionality");
    println!("   - Executed batch revocation operations");
    println!("   - Confirmed audit trail completeness");

    Ok(())
}
