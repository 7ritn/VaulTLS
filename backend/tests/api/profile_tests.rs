use crate::common::test_client::VaulTLSClient;
use anyhow::Result;
use rocket::http::{ContentType, Status};
use serde_json::Value;
use vaultls::data::profile::{CreateProfileRequest, UpdateProfileRequest, SanRules, SanRule};
use vaultls::data::token::{CreateApiTokenRequest, Scope};

#[tokio::test]
async fn test_create_certificate_profile() -> Result<()> {
    let client = VaulTLSClient::new_setup().await;
    let auth_cookie = client.login_admin().await?;

    // Create API token with profile.write scope
    let token_request = CreateApiTokenRequest {
        description: "Profile test token".to_string(),
        scopes: vec![Scope::ProfileRead, Scope::ProfileWrite],
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

    // Create certificate profile
    let san_rules = SanRules {
        dns_names: Some(vec![
            SanRule {
                pattern: "*.example.com".to_string(),
                required: false,
                max_count: Some(5),
            }
        ]),
        ip_addresses: None,
        email_addresses: None,
        uris: None,
    };

    let profile_request = CreateProfileRequest {
        name: "Server Certificate Profile".to_string(),
        eku: vec!["serverAuth".to_string()],
        key_usage: vec!["digitalSignature".to_string(), "keyEncipherment".to_string()],
        san_rules: Some(san_rules),
        default_days: 365,
        max_days: 730,
        renewal_window_pct: Some(30),
        key_alg_options: vec!["RSA-2048".to_string(), "RSA-4096".to_string()],
    };

    let request = client
        .post("/api/profiles")
        .header(ContentType::JSON)
        .header(bearer_header.clone())
        .body(serde_json::to_string(&profile_request)?);
    
    let response = request.dispatch().await;
    assert_eq!(response.status(), Status::Ok);
    
    let profile: Value = response.into_json().await.unwrap();
    assert_eq!(profile["name"], "Server Certificate Profile");
    assert_eq!(profile["eku"].as_array().unwrap().len(), 1);
    assert_eq!(profile["key_usage"].as_array().unwrap().len(), 2);
    assert_eq!(profile["default_days"], 365);
    assert_eq!(profile["max_days"], 730);

    Ok(())
}

#[tokio::test]
async fn test_list_certificate_profiles() -> Result<()> {
    let client = VaulTLSClient::new_setup().await;
    let auth_cookie = client.login_admin().await?;

    // Create API token
    let token_request = CreateApiTokenRequest {
        description: "Profile list test token".to_string(),
        scopes: vec![Scope::ProfileRead, Scope::ProfileWrite],
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

    // Create multiple profiles
    for i in 1..=3 {
        let profile_request = CreateProfileRequest {
            name: format!("Test Profile {}", i),
            eku: vec!["serverAuth".to_string()],
            key_usage: vec!["digitalSignature".to_string()],
            san_rules: None,
            default_days: 365,
            max_days: 730,
            renewal_window_pct: None,
            key_alg_options: vec!["RSA-2048".to_string()],
        };

        let request = client
            .post("/api/profiles")
            .header(ContentType::JSON)
            .header(bearer_header.clone())
            .body(serde_json::to_string(&profile_request)?);
        
        let response = request.dispatch().await;
        assert_eq!(response.status(), Status::Ok);
    }

    // List profiles
    let request = client
        .get("/api/profiles")
        .header(bearer_header);
    
    let response = request.dispatch().await;
    assert_eq!(response.status(), Status::Ok);
    
    let profile_list: Value = response.into_json().await.unwrap();
    assert_eq!(profile_list["total"], 3);
    assert_eq!(profile_list["profiles"].as_array().unwrap().len(), 3);

    Ok(())
}

#[tokio::test]
async fn test_update_certificate_profile() -> Result<()> {
    let client = VaulTLSClient::new_setup().await;
    let auth_cookie = client.login_admin().await?;

    // Create API token
    let token_request = CreateApiTokenRequest {
        description: "Profile update test token".to_string(),
        scopes: vec![Scope::ProfileRead, Scope::ProfileWrite],
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

    // Create profile
    let profile_request = CreateProfileRequest {
        name: "Update Test Profile".to_string(),
        eku: vec!["serverAuth".to_string()],
        key_usage: vec!["digitalSignature".to_string()],
        san_rules: None,
        default_days: 365,
        max_days: 730,
        renewal_window_pct: None,
        key_alg_options: vec!["RSA-2048".to_string()],
    };

    let request = client
        .post("/api/profiles")
        .header(ContentType::JSON)
        .header(bearer_header.clone())
        .body(serde_json::to_string(&profile_request)?);
    
    let response = request.dispatch().await;
    let profile: Value = response.into_json().await.unwrap();
    let profile_id = profile["id"].as_str().unwrap();

    // Update profile
    let update_request = UpdateProfileRequest {
        name: Some("Updated Profile Name".to_string()),
        eku: Some(vec!["serverAuth".to_string(), "clientAuth".to_string()]),
        key_usage: None,
        san_rules: None,
        default_days: Some(180),
        max_days: Some(365),
        renewal_window_pct: Some(20),
        key_alg_options: Some(vec!["RSA-2048".to_string(), "ECDSA-P256".to_string()]),
    };

    let request = client
        .patch(&format!("/api/profiles/{}", profile_id))
        .header(ContentType::JSON)
        .header(bearer_header)
        .body(serde_json::to_string(&update_request)?);
    
    let response = request.dispatch().await;
    assert_eq!(response.status(), Status::Ok);
    
    let updated_profile: Value = response.into_json().await.unwrap();
    assert_eq!(updated_profile["name"], "Updated Profile Name");
    assert_eq!(updated_profile["eku"].as_array().unwrap().len(), 2);
    assert_eq!(updated_profile["default_days"], 180);
    assert_eq!(updated_profile["max_days"], 365);
    assert_eq!(updated_profile["renewal_window_pct"], 20);

    Ok(())
}

#[tokio::test]
async fn test_delete_certificate_profile() -> Result<()> {
    let client = VaulTLSClient::new_setup().await;
    let auth_cookie = client.login_admin().await?;

    // Create API token
    let token_request = CreateApiTokenRequest {
        description: "Profile delete test token".to_string(),
        scopes: vec![Scope::ProfileRead, Scope::ProfileWrite],
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

    // Create profile
    let profile_request = CreateProfileRequest {
        name: "Delete Test Profile".to_string(),
        eku: vec!["serverAuth".to_string()],
        key_usage: vec!["digitalSignature".to_string()],
        san_rules: None,
        default_days: 365,
        max_days: 730,
        renewal_window_pct: None,
        key_alg_options: vec!["RSA-2048".to_string()],
    };

    let request = client
        .post("/api/profiles")
        .header(ContentType::JSON)
        .header(bearer_header.clone())
        .body(serde_json::to_string(&profile_request)?);
    
    let response = request.dispatch().await;
    let profile: Value = response.into_json().await.unwrap();
    let profile_id = profile["id"].as_str().unwrap();

    // Delete profile
    let request = client
        .delete(&format!("/api/profiles/{}", profile_id))
        .header(bearer_header.clone());
    
    let response = request.dispatch().await;
    assert_eq!(response.status(), Status::Ok);

    // Verify profile is deleted
    let request = client
        .get(&format!("/api/profiles/{}", profile_id))
        .header(bearer_header);
    
    let response = request.dispatch().await;
    assert_eq!(response.status(), Status::NotFound);

    Ok(())
}

#[tokio::test]
async fn test_profile_validation() -> Result<()> {
    let client = VaulTLSClient::new_setup().await;
    let auth_cookie = client.login_admin().await?;

    // Create API token
    let token_request = CreateApiTokenRequest {
        description: "Profile validation test token".to_string(),
        scopes: vec![Scope::ProfileWrite],
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

    // Test invalid profile (empty name)
    let invalid_profile = CreateProfileRequest {
        name: "".to_string(),
        eku: vec!["serverAuth".to_string()],
        key_usage: vec!["digitalSignature".to_string()],
        san_rules: None,
        default_days: 365,
        max_days: 730,
        renewal_window_pct: None,
        key_alg_options: vec!["RSA-2048".to_string()],
    };

    let request = client
        .post("/api/profiles")
        .header(ContentType::JSON)
        .header(bearer_header.clone())
        .body(serde_json::to_string(&invalid_profile)?);
    
    let response = request.dispatch().await;
    assert_eq!(response.status(), Status::BadRequest);

    // Test invalid profile (max_days < default_days)
    let invalid_profile = CreateProfileRequest {
        name: "Invalid Profile".to_string(),
        eku: vec!["serverAuth".to_string()],
        key_usage: vec!["digitalSignature".to_string()],
        san_rules: None,
        default_days: 730,
        max_days: 365,
        renewal_window_pct: None,
        key_alg_options: vec!["RSA-2048".to_string()],
    };

    let request = client
        .post("/api/profiles")
        .header(ContentType::JSON)
        .header(bearer_header)
        .body(serde_json::to_string(&invalid_profile)?);
    
    let response = request.dispatch().await;
    assert_eq!(response.status(), Status::BadRequest);

    Ok(())
}
