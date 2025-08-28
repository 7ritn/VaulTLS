use crate::common::test_client::VaulTLSClient;
use anyhow::Result;
use rocket::http::{ContentType, Status};
use serde_json::Value;
use vaultls::data::token::{CreateApiTokenRequest, Scope};
use vaultls::cert::{CreateWebhookRequest, UpdateWebhookRequest, WebhookEvent};

#[tokio::test]
async fn test_create_webhook() -> Result<()> {
    let client = VaulTLSClient::new_setup().await;
    let auth_cookie = client.login_admin().await?;

    // Create API token with admin scope
    let token_request = CreateApiTokenRequest {
        description: "Webhook test token".to_string(),
        scopes: vec![Scope::TokenAdmin],
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

    // Create webhook
    let webhook_request = CreateWebhookRequest {
        name: "Test Certificate Webhook".to_string(),
        url: "https://webhook.example.com/vaultls".to_string(),
        events: vec![
            WebhookEvent::CertificateCreated,
            WebhookEvent::CertificateExpiring,
            WebhookEvent::CertificateRevoked,
        ],
        secret: Some("webhook-secret-key".to_string()),
        headers: Some(serde_json::json!({
            "X-Custom-Header": "VaulTLS-Webhook",
            "Authorization": "Bearer webhook-token"
        })),
        timeout_seconds: Some(30),
        retry_attempts: Some(3),
    };

    let request = client
        .post("/api/webhooks")
        .header(ContentType::JSON)
        .header(bearer_header.clone())
        .body(serde_json::to_string(&webhook_request)?);
    
    let response = request.dispatch().await;
    assert_eq!(response.status(), Status::Ok);
    
    let webhook: Value = response.into_json().await.unwrap();
    assert_eq!(webhook["name"], "Test Certificate Webhook");
    assert_eq!(webhook["url"], "https://webhook.example.com/vaultls");
    assert_eq!(webhook["timeout_seconds"], 30);
    assert_eq!(webhook["retry_attempts"], 3);
    assert_eq!(webhook["is_active"], true);
    assert!(webhook["id"].is_string());
    assert!(webhook["events"].is_array());

    Ok(())
}

#[tokio::test]
async fn test_list_webhooks() -> Result<()> {
    let client = VaulTLSClient::new_setup().await;
    let auth_cookie = client.login_admin().await?;

    // Create API token
    let token_request = CreateApiTokenRequest {
        description: "Webhook list test token".to_string(),
        scopes: vec![Scope::TokenAdmin],
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

    // Create multiple webhooks
    for i in 1..=3 {
        let webhook_request = CreateWebhookRequest {
            name: format!("Webhook {}", i),
            url: format!("https://webhook{}.example.com/vaultls", i),
            events: vec![WebhookEvent::CertificateCreated],
            secret: None,
            headers: None,
            timeout_seconds: Some(30),
            retry_attempts: Some(3),
        };

        let request = client
            .post("/api/webhooks")
            .header(ContentType::JSON)
            .header(bearer_header.clone())
            .body(serde_json::to_string(&webhook_request)?);
        
        let response = request.dispatch().await;
        assert_eq!(response.status(), Status::Ok);
    }

    // List webhooks
    let request = client
        .get("/api/webhooks?page=1&per_page=10")
        .header(bearer_header);
    
    let response = request.dispatch().await;
    assert_eq!(response.status(), Status::Ok);
    
    let webhooks_list: Value = response.into_json().await.unwrap();
    assert!(webhooks_list["total"].as_i64().unwrap() >= 3);
    assert!(webhooks_list["webhooks"].is_array());
    assert_eq!(webhooks_list["page"], 1);
    assert_eq!(webhooks_list["per_page"], 10);

    Ok(())
}

#[tokio::test]
async fn test_update_webhook() -> Result<()> {
    let client = VaulTLSClient::new_setup().await;
    let auth_cookie = client.login_admin().await?;

    // Create API token
    let token_request = CreateApiTokenRequest {
        description: "Webhook update test token".to_string(),
        scopes: vec![Scope::TokenAdmin],
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

    // Create webhook
    let webhook_request = CreateWebhookRequest {
        name: "Update Test Webhook".to_string(),
        url: "https://original.example.com/webhook".to_string(),
        events: vec![WebhookEvent::CertificateCreated],
        secret: None,
        headers: None,
        timeout_seconds: Some(30),
        retry_attempts: Some(3),
    };

    let request = client
        .post("/api/webhooks")
        .header(ContentType::JSON)
        .header(bearer_header.clone())
        .body(serde_json::to_string(&webhook_request)?);
    
    let response = request.dispatch().await;
    let webhook: Value = response.into_json().await.unwrap();
    let webhook_id = webhook["id"].as_str().unwrap();

    // Update webhook
    let update_request = UpdateWebhookRequest {
        name: Some("Updated Webhook Name".to_string()),
        url: Some("https://updated.example.com/webhook".to_string()),
        events: Some(vec![
            WebhookEvent::CertificateCreated,
            WebhookEvent::CertificateRevoked,
            WebhookEvent::CertificateExpiring,
        ]),
        secret: Some("new-secret-key".to_string()),
        headers: Some(serde_json::json!({
            "X-Updated-Header": "true"
        })),
        timeout_seconds: Some(60),
        retry_attempts: Some(5),
        is_active: Some(false),
    };

    let request = client
        .patch(&format!("/api/webhooks/{}", webhook_id))
        .header(ContentType::JSON)
        .header(bearer_header)
        .body(serde_json::to_string(&update_request)?);
    
    let response = request.dispatch().await;
    assert_eq!(response.status(), Status::Ok);
    
    let updated_webhook: Value = response.into_json().await.unwrap();
    assert_eq!(updated_webhook["name"], "Updated Webhook Name");
    assert_eq!(updated_webhook["url"], "https://updated.example.com/webhook");
    assert_eq!(updated_webhook["timeout_seconds"], 60);
    assert_eq!(updated_webhook["retry_attempts"], 5);
    assert_eq!(updated_webhook["is_active"], false);
    assert_eq!(updated_webhook["events"].as_array().unwrap().len(), 3);

    Ok(())
}

#[tokio::test]
async fn test_webhook_validation() -> Result<()> {
    let client = VaulTLSClient::new_setup().await;
    let auth_cookie = client.login_admin().await?;

    // Create API token
    let token_request = CreateApiTokenRequest {
        description: "Webhook validation test token".to_string(),
        scopes: vec![Scope::TokenAdmin],
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

    // Test invalid URL
    let invalid_webhook = CreateWebhookRequest {
        name: "Invalid Webhook".to_string(),
        url: "not-a-valid-url".to_string(),
        events: vec![WebhookEvent::CertificateCreated],
        secret: None,
        headers: None,
        timeout_seconds: Some(30),
        retry_attempts: Some(3),
    };

    let request = client
        .post("/api/webhooks")
        .header(ContentType::JSON)
        .header(bearer_header.clone())
        .body(serde_json::to_string(&invalid_webhook)?);
    
    let response = request.dispatch().await;
    assert_eq!(response.status(), Status::BadRequest);

    // Test empty name
    let empty_name_webhook = CreateWebhookRequest {
        name: "".to_string(),
        url: "https://valid.example.com/webhook".to_string(),
        events: vec![WebhookEvent::CertificateCreated],
        secret: None,
        headers: None,
        timeout_seconds: Some(30),
        retry_attempts: Some(3),
    };

    let request = client
        .post("/api/webhooks")
        .header(ContentType::JSON)
        .header(bearer_header.clone())
        .body(serde_json::to_string(&empty_name_webhook)?);
    
    let response = request.dispatch().await;
    assert_eq!(response.status(), Status::BadRequest);

    // Test empty events
    let no_events_webhook = CreateWebhookRequest {
        name: "No Events Webhook".to_string(),
        url: "https://valid.example.com/webhook".to_string(),
        events: vec![],
        secret: None,
        headers: None,
        timeout_seconds: Some(30),
        retry_attempts: Some(3),
    };

    let request = client
        .post("/api/webhooks")
        .header(ContentType::JSON)
        .header(bearer_header)
        .body(serde_json::to_string(&no_events_webhook)?);
    
    let response = request.dispatch().await;
    assert_eq!(response.status(), Status::BadRequest);

    Ok(())
}

#[tokio::test]
async fn test_test_webhook() -> Result<()> {
    let client = VaulTLSClient::new_setup().await;
    let auth_cookie = client.login_admin().await?;

    // Create API token
    let token_request = CreateApiTokenRequest {
        description: "Webhook test endpoint token".to_string(),
        scopes: vec![Scope::TokenAdmin],
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

    // Create webhook
    let webhook_request = CreateWebhookRequest {
        name: "Test Webhook".to_string(),
        url: "https://httpbin.org/post".to_string(), // Public testing endpoint
        events: vec![WebhookEvent::SystemAlert],
        secret: None,
        headers: None,
        timeout_seconds: Some(30),
        retry_attempts: Some(1),
    };

    let request = client
        .post("/api/webhooks")
        .header(ContentType::JSON)
        .header(bearer_header.clone())
        .body(serde_json::to_string(&webhook_request)?);
    
    let response = request.dispatch().await;
    let webhook: Value = response.into_json().await.unwrap();
    let webhook_id = webhook["id"].as_str().unwrap();

    // Test webhook
    let request = client
        .post(&format!("/api/webhooks/{}/test", webhook_id))
        .header(bearer_header);
    
    let response = request.dispatch().await;
    assert_eq!(response.status(), Status::Ok);
    
    let test_result: Value = response.into_json().await.unwrap();
    assert!(test_result["webhook_id"].is_string());
    assert!(test_result["test_result"].is_object());
    assert!(test_result["timestamp"].is_number());

    Ok(())
}

#[tokio::test]
async fn test_delete_webhook() -> Result<()> {
    let client = VaulTLSClient::new_setup().await;
    let auth_cookie = client.login_admin().await?;

    // Create API token
    let token_request = CreateApiTokenRequest {
        description: "Webhook delete test token".to_string(),
        scopes: vec![Scope::TokenAdmin],
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

    // Create webhook
    let webhook_request = CreateWebhookRequest {
        name: "Delete Test Webhook".to_string(),
        url: "https://delete.example.com/webhook".to_string(),
        events: vec![WebhookEvent::CertificateCreated],
        secret: None,
        headers: None,
        timeout_seconds: Some(30),
        retry_attempts: Some(3),
    };

    let request = client
        .post("/api/webhooks")
        .header(ContentType::JSON)
        .header(bearer_header.clone())
        .body(serde_json::to_string(&webhook_request)?);
    
    let response = request.dispatch().await;
    let webhook: Value = response.into_json().await.unwrap();
    let webhook_id = webhook["id"].as_str().unwrap();

    // Delete webhook
    let request = client
        .delete(&format!("/api/webhooks/{}", webhook_id))
        .header(bearer_header.clone());
    
    let response = request.dispatch().await;
    assert_eq!(response.status(), Status::Ok);

    // Verify webhook is deleted
    let request = client
        .get(&format!("/api/webhooks/{}", webhook_id))
        .header(bearer_header);
    
    let response = request.dispatch().await;
    assert_eq!(response.status(), Status::NotFound);

    Ok(())
}
