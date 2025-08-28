use anyhow::Result;
use reqwest::Client;
use serde_json::Value;
use std::time::Duration;
use tokio::time::timeout;
use hmac::{Hmac, Mac};
use sha2::Sha256;
use hex;

use crate::cert::{
    WebhookConfig, WebhookEvent, WebhookPayload, WebhookEventData, 
    CertificateEventData, CaEventData, ProfileEventData, 
    AuditEventData, SystemEventData, WebhookDelivery, Certificate
};
use crate::data::audit::AuditEvent;
use crate::data::profile::Profile;
use crate::cert::CA;

type HmacSha256 = Hmac<Sha256>;

/// Webhook service for sending HTTP notifications
pub struct WebhookService {
    client: Client,
    db: crate::db::Database,
}

impl WebhookService {
    pub fn new(db: crate::db::Database) -> Self {
        let client = Client::builder()
            .timeout(Duration::from_secs(30))
            .user_agent("VaulTLS-Webhook/1.0")
            .build()
            .expect("Failed to create HTTP client");

        Self { client, db }
    }

    /// Trigger webhook for certificate events
    pub async fn trigger_certificate_event(
        &self,
        event: WebhookEvent,
        certificate: &Certificate,
        tenant_id: &str,
    ) -> Result<()> {
        let event_data = WebhookEventData::Certificate(CertificateEventData {
            certificate_id: certificate.id,
            certificate_name: certificate.name.clone(),
            certificate_type: certificate.certificate_type.to_string(),
            serial_number: certificate.serial_number.clone(),
            subject: certificate.subject.clone(),
            issuer: certificate.issuer.clone(),
            valid_until: certificate.valid_until,
            status: certificate.status.clone(),
            user_id: certificate.user_id,
            ca_id: certificate.ca_id,
            profile_id: certificate.profile_id.clone(),
            metadata: certificate.metadata.as_ref()
                .and_then(|m| serde_json::from_str(m).ok()),
        });

        self.send_webhook_event(event, event_data, tenant_id).await
    }

    /// Trigger webhook for CA events
    pub async fn trigger_ca_event(
        &self,
        event: WebhookEvent,
        ca: &CA,
        tenant_id: &str,
    ) -> Result<()> {
        let event_data = WebhookEventData::Ca(CaEventData {
            ca_id: ca.id,
            ca_name: ca.name.clone(),
            subject: ca.subject.clone(),
            valid_until: ca.valid_until,
            is_root_ca: ca.is_root_ca,
            parent_ca_id: ca.parent_ca_id,
            key_algorithm: ca.key_algorithm.clone(),
            created_by_user_id: ca.created_by_user_id,
        });

        self.send_webhook_event(event, event_data, tenant_id).await
    }

    /// Trigger webhook for profile events
    pub async fn trigger_profile_event(
        &self,
        event: WebhookEvent,
        profile: &Profile,
        tenant_id: &str,
    ) -> Result<()> {
        let event_data = WebhookEventData::Profile(ProfileEventData {
            profile_id: profile.id.clone(),
            profile_name: profile.name.clone(),
            certificate_type: "Server".to_string(), // TODO: Get from profile
            default_days: profile.default_days,
            max_days: profile.max_days,
            eku: profile.eku.clone(),
            key_usage: profile.key_usage.clone(),
        });

        self.send_webhook_event(event, event_data, tenant_id).await
    }

    /// Trigger webhook for audit threshold events
    pub async fn trigger_audit_event(
        &self,
        threshold_type: &str,
        threshold_value: i64,
        current_value: i64,
        tenant_id: &str,
    ) -> Result<()> {
        let event_data = WebhookEventData::Audit(AuditEventData {
            threshold_type: threshold_type.to_string(),
            threshold_value,
            current_value,
            time_period: "1h".to_string(),
            description: format!(
                "{} threshold exceeded: {} > {}",
                threshold_type, current_value, threshold_value
            ),
        });

        self.send_webhook_event(WebhookEvent::AuditThreshold, event_data, tenant_id).await
    }

    /// Trigger webhook for system alerts
    pub async fn trigger_system_alert(
        &self,
        alert_type: &str,
        severity: &str,
        message: &str,
        details: Option<Value>,
        tenant_id: &str,
    ) -> Result<()> {
        let event_data = WebhookEventData::System(SystemEventData {
            alert_type: alert_type.to_string(),
            severity: severity.to_string(),
            message: message.to_string(),
            details,
        });

        self.send_webhook_event(WebhookEvent::SystemAlert, event_data, tenant_id).await
    }

    /// Send webhook event to all configured webhooks
    async fn send_webhook_event(
        &self,
        event: WebhookEvent,
        event_data: WebhookEventData,
        tenant_id: &str,
    ) -> Result<()> {
        // Get all active webhooks for this tenant that listen to this event
        let webhooks = self.db.get_webhooks_for_event(&event, tenant_id).await?;

        for webhook in webhooks {
            if webhook.is_active && webhook.events.contains(&event) {
                let _ = self.send_webhook(&webhook, &event, &event_data).await;
            }
        }

        Ok(())
    }

    /// Send individual webhook
    async fn send_webhook(
        &self,
        webhook: &WebhookConfig,
        event: &WebhookEvent,
        event_data: &WebhookEventData,
    ) -> Result<()> {
        let payload = WebhookPayload {
            event: event.clone(),
            timestamp: chrono::Utc::now().timestamp(),
            tenant_id: webhook.tenant_id.clone(),
            webhook_id: webhook.id.clone(),
            data: event_data.clone(),
            signature: None,
        };

        let mut payload_json = serde_json::to_string(&payload)?;

        // Add HMAC signature if secret is configured
        if let Some(secret) = &webhook.secret {
            let signature = self.generate_signature(&payload_json, secret)?;
            let mut payload_with_sig = payload;
            payload_with_sig.signature = Some(signature);
            payload_json = serde_json::to_string(&payload_with_sig)?;
        }

        // Build request
        let mut request = self.client
            .post(&webhook.url)
            .header("Content-Type", "application/json")
            .header("User-Agent", "VaulTLS-Webhook/1.0")
            .header("X-VaulTLS-Event", format!("{:?}", event))
            .header("X-VaulTLS-Webhook-ID", &webhook.id)
            .body(payload_json.clone());

        // Add custom headers
        if let Some(headers) = &webhook.headers {
            if let Some(headers_obj) = headers.as_object() {
                for (key, value) in headers_obj {
                    if let Some(value_str) = value.as_str() {
                        request = request.header(key, value_str);
                    }
                }
            }
        }

        let start_time = std::time::Instant::now();
        let mut attempt = 1;
        let mut last_error = None;

        // Retry logic
        while attempt <= webhook.retry_attempts + 1 {
            match timeout(
                Duration::from_secs(webhook.timeout_seconds as u64),
                request.try_clone().unwrap().send()
            ).await {
                Ok(Ok(response)) => {
                    let duration = start_time.elapsed();
                    let status = response.status().as_u16() as i32;
                    let response_body = response.text().await.unwrap_or_default();

                    // Log delivery
                    let delivery = WebhookDelivery {
                        id: uuid::Uuid::new_v4().to_string(),
                        webhook_id: webhook.id.clone(),
                        event: event.clone(),
                        payload: serde_json::from_str(&payload_json).unwrap(),
                        response_status: Some(status),
                        response_body: Some(response_body),
                        error_message: None,
                        attempt_number: attempt,
                        delivered_at: chrono::Utc::now().timestamp(),
                        duration_ms: duration.as_millis() as i64,
                        success: status >= 200 && status < 300,
                    };

                    let _ = self.db.log_webhook_delivery(&delivery).await;

                    if delivery.success {
                        let _ = self.db.increment_webhook_success(&webhook.id).await;
                        return Ok(());
                    } else {
                        last_error = Some(format!("HTTP {}: {}", status, delivery.response_body.unwrap_or_default()));
                    }
                },
                Ok(Err(e)) => {
                    last_error = Some(e.to_string());
                },
                Err(_) => {
                    last_error = Some("Request timeout".to_string());
                }
            }

            attempt += 1;
            if attempt <= webhook.retry_attempts + 1 {
                tokio::time::sleep(Duration::from_secs(2_u64.pow(attempt - 2))).await;
            }
        }

        // Log final failure
        let duration = start_time.elapsed();
        let delivery = WebhookDelivery {
            id: uuid::Uuid::new_v4().to_string(),
            webhook_id: webhook.id.clone(),
            event: event.clone(),
            payload: serde_json::from_str(&payload_json).unwrap(),
            response_status: None,
            response_body: None,
            error_message: last_error,
            attempt_number: attempt - 1,
            delivered_at: chrono::Utc::now().timestamp(),
            duration_ms: duration.as_millis() as i64,
            success: false,
        };

        let _ = self.db.log_webhook_delivery(&delivery).await;
        let _ = self.db.increment_webhook_failure(&webhook.id).await;

        Ok(())
    }

    /// Generate HMAC signature for webhook payload
    fn generate_signature(&self, payload: &str, secret: &str) -> Result<String> {
        let mut mac = HmacSha256::new_from_slice(secret.as_bytes())?;
        mac.update(payload.as_bytes());
        let result = mac.finalize();
        Ok(format!("sha256={}", hex::encode(result.into_bytes())))
    }

    /// Send test webhook
    pub async fn send_test_webhook(&self, webhook: &WebhookConfig) -> Result<Value> {
        let test_data = WebhookEventData::System(SystemEventData {
            alert_type: "test".to_string(),
            severity: "info".to_string(),
            message: "This is a test webhook from VaulTLS".to_string(),
            details: Some(serde_json::json!({
                "test": true,
                "webhook_id": webhook.id,
                "timestamp": chrono::Utc::now().timestamp()
            })),
        });

        let payload = WebhookPayload {
            event: WebhookEvent::SystemAlert,
            timestamp: chrono::Utc::now().timestamp(),
            tenant_id: webhook.tenant_id.clone(),
            webhook_id: webhook.id.clone(),
            data: test_data,
            signature: None,
        };

        let payload_json = serde_json::to_string(&payload)?;
        let start_time = std::time::Instant::now();

        match timeout(
            Duration::from_secs(webhook.timeout_seconds as u64),
            self.client
                .post(&webhook.url)
                .header("Content-Type", "application/json")
                .header("X-VaulTLS-Event", "SystemAlert")
                .header("X-VaulTLS-Webhook-ID", &webhook.id)
                .header("X-VaulTLS-Test", "true")
                .body(payload_json)
                .send()
        ).await {
            Ok(Ok(response)) => {
                let duration = start_time.elapsed();
                let status = response.status().as_u16();
                let response_body = response.text().await.unwrap_or_default();

                Ok(serde_json::json!({
                    "success": status >= 200 && status < 300,
                    "status_code": status,
                    "response_body": response_body,
                    "duration_ms": duration.as_millis(),
                    "error": null
                }))
            },
            Ok(Err(e)) => {
                Ok(serde_json::json!({
                    "success": false,
                    "status_code": null,
                    "response_body": null,
                    "duration_ms": start_time.elapsed().as_millis(),
                    "error": e.to_string()
                }))
            },
            Err(_) => {
                Ok(serde_json::json!({
                    "success": false,
                    "status_code": null,
                    "response_body": null,
                    "duration_ms": start_time.elapsed().as_millis(),
                    "error": "Request timeout"
                }))
            }
        }
    }
}
