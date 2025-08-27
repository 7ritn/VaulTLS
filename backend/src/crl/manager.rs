use crate::crl::generator::{CrlGenerator, CrlDistributionPoints};
use crate::data::crl::{
    CertificateStatusResponse, CrlFormat, CrlGenerationOptions, CrlInfo, CrlMetadata,
    RevocationReason, RevocationStatistics, RevocationStatus, RevokedCertificate,
    RevokeCertificateRequest, RevokeCertificateResponse,
};
use crate::db::VaulTLSDB;
use anyhow::{anyhow, Result};
use std::collections::HashMap;
use tracing::{debug, info, warn};

/// CRL Manager handles certificate revocation and CRL generation
pub struct CrlManager {
    db: VaulTLSDB,
    base_url: String,
}

impl CrlManager {
    /// Create a new CRL manager
    pub fn new(db: VaulTLSDB, base_url: String) -> Self {
        Self { db, base_url }
    }

    /// Revoke a certificate
    pub async fn revoke_certificate(
        &self,
        certificate_id: i64,
        request: RevokeCertificateRequest,
        revoked_by_user_id: i64,
    ) -> Result<RevokeCertificateResponse> {
        info!("Revoking certificate {} by user {}", certificate_id, revoked_by_user_id);

        // Get certificate details
        let cert = self.db.get_user_cert(certificate_id).await?;
        
        // Check if already revoked
        if cert.status == "revoked" {
            return Err(anyhow!("Certificate {} is already revoked", certificate_id));
        }

        let revocation_date = request.effective_date.unwrap_or_else(|| chrono::Utc::now().timestamp());
        let reason = request.reason.unwrap_or_default();

        // Update certificate status in database
        self.db.revoke_certificate(
            certificate_id,
            revocation_date,
            reason,
            revoked_by_user_id,
        ).await?;

        // Add to revoked certificates table
        let revoked_cert = RevokedCertificate {
            id: -1, // Will be set by database
            certificate_id,
            serial_number: cert.serial_number.clone().unwrap_or_else(|| format!("{:x}", certificate_id)),
            revocation_date,
            revocation_reason: reason,
            ca_id: cert.ca_id,
            tenant_id: cert.tenant_id.clone(),
            revoked_by_user_id: Some(revoked_by_user_id),
            created_at: chrono::Utc::now().timestamp(),
        };

        self.db.insert_revoked_certificate(revoked_cert).await?;

        // Update CRL metadata
        self.update_crl_metadata(cert.ca_id, &cert.tenant_id).await?;

        // Generate new CRL
        let crl_updated = self.generate_crl_for_ca(cert.ca_id, &cert.tenant_id).await.is_ok();

        Ok(RevokeCertificateResponse {
            certificate_id,
            serial_number: cert.serial_number.unwrap_or_else(|| format!("{:x}", certificate_id)),
            revocation_date,
            reason,
            crl_updated,
        })
    }

    /// Generate CRL for a specific CA
    pub async fn generate_crl_for_ca(&self, ca_id: i64, tenant_id: &str) -> Result<Vec<u8>> {
        debug!("Generating CRL for CA {} in tenant {}", ca_id, tenant_id);

        // Get CA certificate
        let ca = self.db.get_ca_by_id(ca_id).await?;

        // Get revoked certificates for this CA
        let revoked_certs = self.db.get_revoked_certificates_by_ca(ca_id, tenant_id).await?;

        // Get or create CRL metadata
        let crl_metadata = self.get_or_create_crl_metadata(ca_id, tenant_id).await?;

        // Generate CRL
        let options = CrlGenerationOptions::default();
        let generator = CrlGenerator::new(ca, Some(options));
        let crl_der = generator.generate_crl(revoked_certs, &crl_metadata)?;

        // Store CRL in database (optional - could be generated on-demand)
        self.db.store_crl(ca_id, tenant_id, &crl_der).await?;

        Ok(crl_der)
    }

    /// Get CRL for a CA in the specified format
    pub async fn get_crl(&self, ca_id: i64, tenant_id: &str, format: CrlFormat) -> Result<Vec<u8>> {
        // Try to get cached CRL first
        if let Ok(crl_der) = self.db.get_stored_crl(ca_id, tenant_id).await {
            // Check if CRL is still valid
            if self.is_crl_current(&crl_der, ca_id, tenant_id).await? {
                return CrlGenerator::format_crl(crl_der, format);
            }
        }

        // Generate new CRL
        let crl_der = self.generate_crl_for_ca(ca_id, tenant_id).await?;
        CrlGenerator::format_crl(crl_der, format)
    }

    /// Check certificate status
    pub async fn check_certificate_status(
        &self,
        serial_number: &str,
        ca_id: Option<i64>,
    ) -> Result<CertificateStatusResponse> {
        // Find certificate by serial number
        let cert = if let Some(ca_id) = ca_id {
            self.db.get_certificate_by_serial_and_ca(serial_number, ca_id).await?
        } else {
            self.db.get_certificate_by_serial(serial_number).await?
        };

        let status = RevocationStatus::from_str(&cert.status).unwrap_or_default();
        
        let (revocation_date, revocation_reason) = if status == RevocationStatus::Revoked {
            (cert.revoked_at, cert.revocation_reason.and_then(|r| RevocationReason::from_u8(r as u8)))
        } else {
            (None, None)
        };

        Ok(CertificateStatusResponse {
            serial_number: serial_number.to_string(),
            status,
            revocation_date,
            revocation_reason,
            valid_until: cert.valid_until,
            ca_id: cert.ca_id,
            tenant_id: cert.tenant_id,
        })
    }

    /// Get CRL information
    pub async fn get_crl_info(&self, ca_id: i64, tenant_id: &str) -> Result<CrlInfo> {
        let crl_metadata = self.get_or_create_crl_metadata(ca_id, tenant_id).await?;
        let total_certificates = self.db.count_certificates_by_ca(ca_id, tenant_id).await?;

        Ok(CrlInfo {
            ca_id,
            tenant_id: tenant_id.to_string(),
            crl_number: crl_metadata.crl_number,
            this_update: crl_metadata.this_update,
            next_update: crl_metadata.next_update,
            revoked_count: crl_metadata.revoked_count,
            total_certificates,
            last_generated: crl_metadata.created_at,
        })
    }

    /// Get revocation statistics
    pub async fn get_revocation_statistics(&self, ca_id: i64, tenant_id: &str) -> Result<RevocationStatistics> {
        let total_certificates = self.db.count_certificates_by_ca(ca_id, tenant_id).await?;
        let active_certificates = self.db.count_active_certificates_by_ca(ca_id, tenant_id).await?;
        let revoked_certificates = self.db.count_revoked_certificates_by_ca(ca_id, tenant_id).await?;
        let expired_certificates = self.db.count_expired_certificates_by_ca(ca_id, tenant_id).await?;
        
        let revocations_by_reason = self.db.get_revocations_by_reason(ca_id, tenant_id).await?;
        let revocations_last_30_days = self.db.count_recent_revocations(ca_id, tenant_id, 30).await?;

        Ok(RevocationStatistics {
            total_certificates,
            active_certificates,
            revoked_certificates,
            expired_certificates,
            revocations_by_reason,
            revocations_last_30_days,
            tenant_id: tenant_id.to_string(),
            ca_id,
        })
    }

    /// Update CRL metadata after revocation
    async fn update_crl_metadata(&self, ca_id: i64, tenant_id: &str) -> Result<()> {
        let revoked_count = self.db.count_revoked_certificates_by_ca(ca_id, tenant_id).await?;
        let next_crl_number = self.db.get_next_crl_number(ca_id, tenant_id).await?;
        
        let now = chrono::Utc::now().timestamp();
        let next_update = now + (7 * 24 * 60 * 60); // 7 days from now

        let metadata = CrlMetadata {
            id: -1,
            ca_id,
            tenant_id: tenant_id.to_string(),
            crl_number: next_crl_number,
            this_update: now,
            next_update,
            revoked_count,
            created_at: now,
        };

        self.db.update_crl_metadata(metadata).await?;
        Ok(())
    }

    /// Get or create CRL metadata
    async fn get_or_create_crl_metadata(&self, ca_id: i64, tenant_id: &str) -> Result<CrlMetadata> {
        match self.db.get_crl_metadata(ca_id, tenant_id).await {
            Ok(metadata) => Ok(metadata),
            Err(_) => {
                // Create initial metadata
                let now = chrono::Utc::now().timestamp();
                let metadata = CrlMetadata {
                    id: -1,
                    ca_id,
                    tenant_id: tenant_id.to_string(),
                    crl_number: 1,
                    this_update: now,
                    next_update: now + (7 * 24 * 60 * 60), // 7 days
                    revoked_count: 0,
                    created_at: now,
                };
                
                self.db.insert_crl_metadata(metadata.clone()).await?;
                Ok(metadata)
            }
        }
    }

    /// Check if CRL is still current
    async fn is_crl_current(&self, _crl_der: &[u8], ca_id: i64, tenant_id: &str) -> Result<bool> {
        let metadata = self.db.get_crl_metadata(ca_id, tenant_id).await?;
        let now = chrono::Utc::now().timestamp();
        
        // Check if CRL has expired
        if now > metadata.next_update {
            return Ok(false);
        }

        // Check if revocation count has changed
        let current_revoked_count = self.db.count_revoked_certificates_by_ca(ca_id, tenant_id).await?;
        if current_revoked_count != metadata.revoked_count {
            return Ok(false);
        }

        Ok(true)
    }

    /// Generate CRL distribution points for a CA
    pub fn generate_distribution_points(&self, ca_id: i64, tenant_id: &str) -> Vec<String> {
        let cdp = CrlDistributionPoints::new(self.base_url.clone());
        cdp.generate_urls(ca_id, tenant_id)
    }

    /// Restore a certificate from revocation (remove from CRL)
    pub async fn restore_certificate(&self, certificate_id: i64, restored_by_user_id: i64) -> Result<()> {
        info!("Restoring certificate {} by user {}", certificate_id, restored_by_user_id);

        // Get certificate details
        let cert = self.db.get_user_cert(certificate_id).await?;
        
        if cert.status != "revoked" {
            return Err(anyhow!("Certificate {} is not revoked", certificate_id));
        }

        // Update certificate status
        self.db.restore_certificate(certificate_id, restored_by_user_id).await?;

        // Remove from revoked certificates table
        self.db.remove_revoked_certificate(certificate_id).await?;

        // Update CRL metadata
        self.update_crl_metadata(cert.ca_id, &cert.tenant_id).await?;

        // Generate new CRL
        let _ = self.generate_crl_for_ca(cert.ca_id, &cert.tenant_id).await;

        Ok(())
    }
}
