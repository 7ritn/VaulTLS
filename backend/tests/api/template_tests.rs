use crate::common::test_client::VaulTLSClient;
use anyhow::Result;
use rocket::http::{ContentType, Status};
use serde_json::Value;
use vaultls::data::token::{CreateApiTokenRequest, Scope};
use vaultls::cert::{CreateCertificateTemplateRequest, UpdateCertificateTemplateRequest, CreateCertificateFromTemplateRequest, CertificateType};

#[tokio::test]
async fn test_create_certificate_template() -> Result<()> {
    let client = VaulTLSClient::new_setup().await;
    let auth_cookie = client.login_admin().await?;

    // Create API token with cert.write scope
    let token_request = CreateApiTokenRequest {
        description: "Template test token".to_string(),
        scopes: vec![Scope::CertWrite, Scope::ProfileRead],
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

    // Create certificate template
    let template_request = CreateCertificateTemplateRequest {
        name: "Test Server Template".to_string(),
        description: "Template for server certificates".to_string(),
        certificate_type: CertificateType::Server,
        profile_id: "default-profile".to_string(),
        default_validity_years: 1,
        default_key_algorithm: "RSA-2048".to_string(),
        san_template: Some("{{hostname}}.{{domain}}".to_string()),
        metadata_template: Some(serde_json::json!({"template_type": "server"})),
        ca_selection: None,
        auto_renewal: Some(true),
        notification_settings: None,
    };

    let request = client
        .post("/api/templates")
        .header(ContentType::JSON)
        .header(bearer_header.clone())
        .body(serde_json::to_string(&template_request)?);
    
    let response = request.dispatch().await;
    assert_eq!(response.status(), Status::Ok);
    
    let template: Value = response.into_json().await.unwrap();
    assert_eq!(template["name"], "Test Server Template");
    assert_eq!(template["certificate_type"], "Server");
    assert_eq!(template["default_validity_years"], 1);
    assert!(template["id"].is_string());

    Ok(())
}

#[tokio::test]
async fn test_list_certificate_templates() -> Result<()> {
    let client = VaulTLSClient::new_setup().await;
    let auth_cookie = client.login_admin().await?;

    // Create API token
    let token_request = CreateApiTokenRequest {
        description: "Template list test token".to_string(),
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

    // Create multiple templates
    for i in 1..=3 {
        let template_request = CreateCertificateTemplateRequest {
            name: format!("Template {}", i),
            description: format!("Test template {}", i),
            certificate_type: if i % 2 == 0 { CertificateType::Client } else { CertificateType::Server },
            profile_id: "default-profile".to_string(),
            default_validity_years: i,
            default_key_algorithm: "RSA-2048".to_string(),
            san_template: None,
            metadata_template: None,
            ca_selection: None,
            auto_renewal: None,
            notification_settings: None,
        };

        let request = client
            .post("/api/templates")
            .header(ContentType::JSON)
            .header(bearer_header.clone())
            .body(serde_json::to_string(&template_request)?);
        
        let response = request.dispatch().await;
        assert_eq!(response.status(), Status::Ok);
    }

    // List templates
    let request = client
        .get("/api/templates?page=1&per_page=10")
        .header(bearer_header);
    
    let response = request.dispatch().await;
    assert_eq!(response.status(), Status::Ok);
    
    let templates_list: Value = response.into_json().await.unwrap();
    assert!(templates_list["total"].as_i64().unwrap() >= 3);
    assert!(templates_list["templates"].is_array());
    assert_eq!(templates_list["page"], 1);
    assert_eq!(templates_list["per_page"], 10);

    Ok(())
}

#[tokio::test]
async fn test_update_certificate_template() -> Result<()> {
    let client = VaulTLSClient::new_setup().await;
    let auth_cookie = client.login_admin().await?;

    // Create API token
    let token_request = CreateApiTokenRequest {
        description: "Template update test token".to_string(),
        scopes: vec![Scope::CertWrite],
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

    // Create template
    let template_request = CreateCertificateTemplateRequest {
        name: "Update Test Template".to_string(),
        description: "Original description".to_string(),
        certificate_type: CertificateType::Server,
        profile_id: "default-profile".to_string(),
        default_validity_years: 1,
        default_key_algorithm: "RSA-2048".to_string(),
        san_template: None,
        metadata_template: None,
        ca_selection: None,
        auto_renewal: None,
        notification_settings: None,
    };

    let request = client
        .post("/api/templates")
        .header(ContentType::JSON)
        .header(bearer_header.clone())
        .body(serde_json::to_string(&template_request)?);
    
    let response = request.dispatch().await;
    let template: Value = response.into_json().await.unwrap();
    let template_id = template["id"].as_str().unwrap();

    // Update template
    let update_request = UpdateCertificateTemplateRequest {
        name: Some("Updated Template Name".to_string()),
        description: Some("Updated description".to_string()),
        certificate_type: None,
        profile_id: None,
        default_validity_years: Some(2),
        default_key_algorithm: Some("RSA-4096".to_string()),
        san_template: Some("*.{{domain}}".to_string()),
        metadata_template: Some(serde_json::json!({"updated": true})),
        ca_selection: None,
        auto_renewal: None,
        notification_settings: None,
    };

    let request = client
        .patch(&format!("/api/templates/{}", template_id))
        .header(ContentType::JSON)
        .header(bearer_header)
        .body(serde_json::to_string(&update_request)?);
    
    let response = request.dispatch().await;
    assert_eq!(response.status(), Status::Ok);
    
    let updated_template: Value = response.into_json().await.unwrap();
    assert_eq!(updated_template["name"], "Updated Template Name");
    assert_eq!(updated_template["description"], "Updated description");
    assert_eq!(updated_template["default_validity_years"], 2);
    assert_eq!(updated_template["default_key_algorithm"], "RSA-4096");

    Ok(())
}

#[tokio::test]
async fn test_create_certificate_from_template() -> Result<()> {
    let client = VaulTLSClient::new_setup().await;
    let auth_cookie = client.login_admin().await?;

    // Create API token
    let token_request = CreateApiTokenRequest {
        description: "Template certificate test token".to_string(),
        scopes: vec![Scope::CertWrite],
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

    // Create template
    let template_request = CreateCertificateTemplateRequest {
        name: "Certificate Creation Template".to_string(),
        description: "Template for creating certificates".to_string(),
        certificate_type: CertificateType::Server,
        profile_id: "default-profile".to_string(),
        default_validity_years: 1,
        default_key_algorithm: "RSA-2048".to_string(),
        san_template: Some("{{hostname}}.{{domain}}".to_string()),
        metadata_template: Some(serde_json::json!({"from_template": true})),
        ca_selection: None,
        auto_renewal: None,
        notification_settings: None,
    };

    let request = client
        .post("/api/templates")
        .header(ContentType::JSON)
        .header(bearer_header.clone())
        .body(serde_json::to_string(&template_request)?);
    
    let response = request.dispatch().await;
    let template: Value = response.into_json().await.unwrap();
    let template_id = template["id"].as_str().unwrap();

    // Create certificate from template
    let cert_request = CreateCertificateFromTemplateRequest {
        template_id: template_id.to_string(),
        name: "Template Generated Certificate".to_string(),
        user_id: 1,
        template_variables: Some(serde_json::json!({
            "hostname": "api",
            "domain": "example.com"
        })),
        validity_years: None,
        ca_selection: None,
    };

    let request = client
        .post(&format!("/api/templates/{}/certificates", template_id))
        .header(ContentType::JSON)
        .header(bearer_header)
        .body(serde_json::to_string(&cert_request)?);
    
    let response = request.dispatch().await;
    assert_eq!(response.status(), Status::Ok);
    
    let certificate: Value = response.into_json().await.unwrap();
    assert_eq!(certificate["name"], "Template Generated Certificate");
    assert_eq!(certificate["certificate_type"], "Server");
    assert!(certificate["id"].is_number());

    Ok(())
}

#[tokio::test]
async fn test_delete_certificate_template() -> Result<()> {
    let client = VaulTLSClient::new_setup().await;
    let auth_cookie = client.login_admin().await?;

    // Create API token
    let token_request = CreateApiTokenRequest {
        description: "Template delete test token".to_string(),
        scopes: vec![Scope::CertWrite],
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

    // Create template
    let template_request = CreateCertificateTemplateRequest {
        name: "Delete Test Template".to_string(),
        description: "Template to be deleted".to_string(),
        certificate_type: CertificateType::Client,
        profile_id: "default-profile".to_string(),
        default_validity_years: 1,
        default_key_algorithm: "RSA-2048".to_string(),
        san_template: None,
        metadata_template: None,
        ca_selection: None,
        auto_renewal: None,
        notification_settings: None,
    };

    let request = client
        .post("/api/templates")
        .header(ContentType::JSON)
        .header(bearer_header.clone())
        .body(serde_json::to_string(&template_request)?);
    
    let response = request.dispatch().await;
    let template: Value = response.into_json().await.unwrap();
    let template_id = template["id"].as_str().unwrap();

    // Delete template
    let request = client
        .delete(&format!("/api/templates/{}", template_id))
        .header(bearer_header.clone());
    
    let response = request.dispatch().await;
    assert_eq!(response.status(), Status::Ok);

    // Verify template is deleted
    let request = client
        .get(&format!("/api/templates/{}", template_id))
        .header(bearer_header);
    
    let response = request.dispatch().await;
    assert_eq!(response.status(), Status::NotFound);

    Ok(())
}
