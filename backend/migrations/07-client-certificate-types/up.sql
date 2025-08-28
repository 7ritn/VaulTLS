-- Migration 07: Add Client Certificate Type Classification
-- Add support for User/Device classification for Client certificates

-- Add client_certificate_type column to user_certificates table
-- This field is only relevant for Client certificates (not Server certificates)
ALTER TABLE user_certificates ADD COLUMN client_certificate_type TEXT;

-- Create index for performance on client certificate type queries
CREATE INDEX IF NOT EXISTS idx_user_certificates_client_type ON user_certificates(client_certificate_type) 
WHERE certificate_type = 'Client';

-- Create composite index for efficient statistics queries
CREATE INDEX IF NOT EXISTS idx_user_certificates_type_client_type ON user_certificates(certificate_type, client_certificate_type);

-- Update existing Client certificates to have a default classification
-- This is optional - existing certificates can remain NULL until explicitly classified
-- UPDATE user_certificates SET client_certificate_type = 'User' 
-- WHERE certificate_type = 'Client' AND client_certificate_type IS NULL;

-- Add check constraint to ensure client_certificate_type is only set for Client certificates
-- SQLite doesn't support adding constraints to existing tables, so we document this as a business rule:
-- client_certificate_type should only be set when certificate_type = 'Client'

-- Add audit event for migration
INSERT INTO audit_events (
    event_type, resource_type, resource_id, user_id, token_prefix, tenant_id, 
    endpoint, method, status_code, duration_ms, ip_address, user_agent, 
    request_body, response_body, created_at
)
SELECT 
    'system.migration',
    'database',
    '07-client-certificate-types',
    NULL,
    NULL,
    t.id,
    '/system/migration',
    'POST',
    200,
    0,
    '127.0.0.1',
    'VaulTLS-Migration/1.0',
    '{"migration": "07-client-certificate-types", "description": "Add Client Certificate Type Classification"}',
    '{"column_added": "client_certificate_type", "indexes_created": 2, "classification_types": ["User", "Device"]}',
    strftime('%s', 'now')
FROM tenants t;
