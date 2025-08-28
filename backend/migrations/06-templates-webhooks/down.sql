-- Migration 06 Rollback: Remove Certificate Templates and Webhook Notifications

-- Drop indexes first
DROP INDEX IF EXISTS idx_user_certificates_template;
DROP INDEX IF EXISTS idx_webhook_deliveries_success;
DROP INDEX IF EXISTS idx_webhook_deliveries_delivered_at;
DROP INDEX IF EXISTS idx_webhook_deliveries_event;
DROP INDEX IF EXISTS idx_webhook_deliveries_webhook;
DROP INDEX IF EXISTS idx_webhooks_events;
DROP INDEX IF EXISTS idx_webhooks_active;
DROP INDEX IF EXISTS idx_webhooks_tenant;
DROP INDEX IF EXISTS idx_certificate_templates_name;
DROP INDEX IF EXISTS idx_certificate_templates_profile;
DROP INDEX IF EXISTS idx_certificate_templates_tenant;

-- Remove template_id column from user_certificates
-- SQLite doesn't support DROP COLUMN, so we need to recreate the table
CREATE TABLE user_certificates_backup AS SELECT 
    id, name, user_id, certificate_type, valid_until, status, 
    serial_number, subject, issuer, ca_id, profile_id, metadata, 
    created_at, updated_at, tenant_id
FROM user_certificates;

DROP TABLE user_certificates;

CREATE TABLE user_certificates (
    id INTEGER PRIMARY KEY,
    name TEXT NOT NULL,
    user_id INTEGER NOT NULL,
    certificate_type TEXT NOT NULL,
    valid_until INTEGER NOT NULL,
    status TEXT NOT NULL DEFAULT 'active',
    serial_number TEXT NOT NULL UNIQUE,
    subject TEXT NOT NULL,
    issuer TEXT NOT NULL,
    ca_id INTEGER NOT NULL,
    profile_id TEXT,
    metadata TEXT,
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL,
    tenant_id TEXT NOT NULL,
    FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE,
    FOREIGN KEY(ca_id) REFERENCES certificate_authorities(id) ON DELETE CASCADE,
    FOREIGN KEY(profile_id) REFERENCES certificate_profiles(id) ON DELETE SET NULL,
    FOREIGN KEY(tenant_id) REFERENCES tenants(id) ON DELETE CASCADE
);

INSERT INTO user_certificates SELECT * FROM user_certificates_backup;
DROP TABLE user_certificates_backup;

-- Recreate indexes for user_certificates
CREATE INDEX idx_user_certificates_user ON user_certificates(user_id);
CREATE INDEX idx_user_certificates_status ON user_certificates(status);
CREATE INDEX idx_user_certificates_valid_until ON user_certificates(valid_until);
CREATE INDEX idx_user_certificates_serial ON user_certificates(serial_number);
CREATE INDEX idx_user_certificates_tenant ON user_certificates(tenant_id);
CREATE INDEX idx_user_certificates_ca ON user_certificates(ca_id);
CREATE INDEX idx_user_certificates_profile ON user_certificates(profile_id);
CREATE INDEX idx_user_certificates_type ON user_certificates(certificate_type);

-- Drop webhook tables
DROP TABLE IF EXISTS webhook_deliveries;
DROP TABLE IF EXISTS webhooks;

-- Drop certificate templates table
DROP TABLE IF EXISTS certificate_templates;

-- Remove migration audit events
DELETE FROM audit_events 
WHERE event_type = 'system.migration' 
AND resource_id = '06-templates-webhooks';
