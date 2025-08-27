use crate::data::crl::{CrlFormat, CrlGenerationOptions, CrlMetadata, RevokedCertificate, RevocationReason};
use crate::cert::CA;
use anyhow::{anyhow, Result};
use openssl::asn1::{Asn1Integer, Asn1Time};
use openssl::bn::BigNum;
use openssl::hash::MessageDigest;
use openssl::pkey::PKey;
use openssl::x509::extension::{AuthorityKeyIdentifier, CrlNumber};
use openssl::x509::{X509Crl, X509CrlBuilder, X509Revoked, X509RevokedBuilder, X509};
use std::collections::HashMap;
use tracing::{debug, info, warn};

/// CRL Generator for creating Certificate Revocation Lists
pub struct CrlGenerator {
    ca: CA,
    options: CrlGenerationOptions,
}

impl CrlGenerator {
    /// Create a new CRL generator
    pub fn new(ca: CA, options: Option<CrlGenerationOptions>) -> Self {
        Self {
            ca,
            options: options.unwrap_or_default(),
        }
    }

    /// Generate a CRL with the given revoked certificates
    pub fn generate_crl(
        &self,
        revoked_certs: Vec<RevokedCertificate>,
        crl_metadata: &CrlMetadata,
    ) -> Result<Vec<u8>> {
        debug!("Generating CRL for CA {} with {} revoked certificates", 
               self.ca.id, revoked_certs.len());

        // Parse CA certificate and private key
        let ca_cert = X509::from_der(&self.ca.cert)?;
        let ca_key = PKey::private_key_from_der(&self.ca.key)?;

        // Create CRL builder
        let mut crl_builder = X509CrlBuilder::new()?;

        // Set issuer name (same as CA certificate subject)
        crl_builder.set_issuer_name(ca_cert.subject_name())?;

        // Set this update time
        let this_update = Asn1Time::from_unix(crl_metadata.this_update)?;
        crl_builder.set_this_update(&this_update)?;

        // Set next update time
        let next_update = Asn1Time::from_unix(crl_metadata.next_update)?;
        crl_builder.set_next_update(&next_update)?;

        // Add revoked certificates
        for revoked_cert in revoked_certs {
            if let Ok(revoked_entry) = self.create_revoked_entry(&revoked_cert) {
                crl_builder.add_revoked(revoked_entry)?;
            } else {
                warn!("Failed to create revoked entry for certificate {}", revoked_cert.certificate_id);
            }
        }

        // Add CRL extensions if enabled
        if self.options.crl_extensions.unwrap_or(true) {
            self.add_crl_extensions(&mut crl_builder, &ca_cert, crl_metadata)?;
        }

        // Sign the CRL
        crl_builder.sign(&ca_key, MessageDigest::sha256())?;

        // Build the CRL
        let crl = crl_builder.build();

        // Convert to DER format
        let crl_der = crl.to_der()?;

        info!("Generated CRL for CA {} with {} revoked certificates, size: {} bytes", 
              self.ca.id, crl_metadata.revoked_count, crl_der.len());

        Ok(crl_der)
    }

    /// Create a revoked certificate entry
    fn create_revoked_entry(&self, revoked_cert: &RevokedCertificate) -> Result<X509Revoked> {
        let mut revoked_builder = X509RevokedBuilder::new()?;

        // Set serial number
        let serial_bn = BigNum::from_hex_str(&revoked_cert.serial_number)?;
        let serial_asn1 = Asn1Integer::from_bn(&serial_bn)?;
        revoked_builder.set_serial_number(&serial_asn1)?;

        // Set revocation date
        let revocation_time = Asn1Time::from_unix(revoked_cert.revocation_date)?;
        revoked_builder.set_revocation_date(&revocation_time)?;

        // Add revocation reason extension if not unspecified
        if revoked_cert.revocation_reason != RevocationReason::Unspecified {
            // Note: OpenSSL Rust bindings don't have direct support for CRL reason codes
            // This would need to be implemented using raw ASN.1 if needed
            debug!("Revocation reason: {:?} (extension not yet implemented)", 
                   revoked_cert.revocation_reason);
        }

        Ok(revoked_builder.build())
    }

    /// Add CRL extensions
    fn add_crl_extensions(
        &self,
        crl_builder: &mut X509CrlBuilder,
        ca_cert: &X509,
        crl_metadata: &CrlMetadata,
    ) -> Result<()> {
        // Add Authority Key Identifier
        let auth_key_id = AuthorityKeyIdentifier::new()
            .keyid(false)
            .issuer(false)
            .build(&crl_builder.x509v3_context(Some(ca_cert), None))?;
        crl_builder.add_extension(auth_key_id)?;

        // Add CRL Number
        let crl_number_bn = BigNum::from_u32(crl_metadata.crl_number as u32)?;
        let crl_number = CrlNumber::new().num(&crl_number_bn).build()?;
        crl_builder.add_extension(crl_number)?;

        Ok(())
    }

    /// Convert CRL from DER to PEM format
    pub fn der_to_pem(crl_der: &[u8]) -> Result<String> {
        let crl = X509Crl::from_der(crl_der)?;
        let pem = crl.to_pem()?;
        Ok(String::from_utf8(pem)?)
    }

    /// Format CRL according to the requested format
    pub fn format_crl(crl_der: Vec<u8>, format: CrlFormat) -> Result<Vec<u8>> {
        match format {
            CrlFormat::Der => Ok(crl_der),
            CrlFormat::Pem => {
                let pem_string = Self::der_to_pem(&crl_der)?;
                Ok(pem_string.into_bytes())
            }
        }
    }

    /// Validate CRL before generation
    pub fn validate_options(&self) -> Result<()> {
        if let Some(validity_hours) = self.options.validity_hours {
            if validity_hours <= 0 || validity_hours > 8760 { // Max 1 year
                return Err(anyhow!("Invalid validity hours: {}", validity_hours));
            }
        }

        Ok(())
    }
}

/// CRL Distribution Point URL generator
pub struct CrlDistributionPoints {
    base_url: String,
}

impl CrlDistributionPoints {
    pub fn new(base_url: String) -> Self {
        Self { base_url }
    }

    /// Generate CRL distribution point URLs for a CA
    pub fn generate_urls(&self, ca_id: i64, tenant_id: &str) -> Vec<String> {
        vec![
            format!("{}/api/crl/ca/{}/download", self.base_url, ca_id),
            format!("{}/api/crl/tenant/{}/ca/{}/download", self.base_url, tenant_id, ca_id),
        ]
    }

    /// Generate CRL distribution points extension value
    pub fn generate_extension_value(&self, ca_id: i64, tenant_id: &str) -> String {
        let urls = self.generate_urls(ca_id, tenant_id);
        urls.join(",")
    }
}

/// CRL validation utilities
pub struct CrlValidator;

impl CrlValidator {
    /// Validate a CRL against its issuing CA
    pub fn validate_crl(crl_der: &[u8], ca_cert: &X509) -> Result<bool> {
        let crl = X509Crl::from_der(crl_der)?;
        
        // Get CA public key
        let ca_public_key = ca_cert.public_key()?;
        
        // Verify CRL signature
        let is_valid = crl.verify(&ca_public_key)?;
        
        if !is_valid {
            return Ok(false);
        }

        // Check if CRL is current (not expired)
        let now = Asn1Time::days_from_now(0)?;
        if let Some(next_update) = crl.next_update() {
            if next_update.compare(&now)? < 0 {
                warn!("CRL has expired");
                return Ok(false);
            }
        }

        Ok(true)
    }

    /// Check if a certificate serial number is in the CRL
    pub fn is_certificate_revoked(crl_der: &[u8], serial_number: &str) -> Result<bool> {
        let crl = X509Crl::from_der(crl_der)?;
        
        // Parse the serial number
        let serial_bn = BigNum::from_hex_str(serial_number)?;
        let serial_asn1 = Asn1Integer::from_bn(&serial_bn)?;
        
        // Check if the certificate is in the revoked list
        if let Some(revoked_list) = crl.get_revoked() {
            for revoked in revoked_list {
                if revoked.serial_number().compare(&serial_asn1) == 0 {
                    return Ok(true);
                }
            }
        }
        
        Ok(false)
    }

    /// Get revocation information for a certificate
    pub fn get_revocation_info(crl_der: &[u8], serial_number: &str) -> Result<Option<(i64, Option<i32>)>> {
        let crl = X509Crl::from_der(crl_der)?;
        
        // Parse the serial number
        let serial_bn = BigNum::from_hex_str(serial_number)?;
        let serial_asn1 = Asn1Integer::from_bn(&serial_bn)?;
        
        // Find the certificate in the revoked list
        if let Some(revoked_list) = crl.get_revoked() {
            for revoked in revoked_list {
                if revoked.serial_number().compare(&serial_asn1) == 0 {
                    let revocation_date = revoked.revocation_date().to_unix()?;
                    // Note: Reason code extraction would need additional implementation
                    return Ok(Some((revocation_date, None)));
                }
            }
        }
        
        Ok(None)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::data::crl::RevocationReason;

    #[test]
    fn test_crl_distribution_points() {
        let cdp = CrlDistributionPoints::new("https://vaultls.example.com".to_string());
        let urls = cdp.generate_urls(1, "tenant-123");
        
        assert_eq!(urls.len(), 2);
        assert!(urls[0].contains("/api/crl/ca/1/download"));
        assert!(urls[1].contains("/tenant/tenant-123/ca/1/download"));
    }

    #[test]
    fn test_crl_format_content_types() {
        assert_eq!(CrlFormat::Der.content_type(), "application/pkix-crl");
        assert_eq!(CrlFormat::Pem.content_type(), "application/x-pem-file");
    }

    #[test]
    fn test_revocation_reason_descriptions() {
        assert_eq!(RevocationReason::KeyCompromise.description(), "Key Compromise");
        assert_eq!(RevocationReason::CessationOfOperation.description(), "Cessation of Operation");
    }
}
