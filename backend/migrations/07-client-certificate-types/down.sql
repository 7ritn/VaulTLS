-- Migration 07 Rollback: Remove Client Certificate Type Classification

-- Drop indexes
DROP INDEX IF EXISTS idx_user_certificates_client_type;
DROP INDEX IF EXISTS idx_user_certificates_type_client_type;

-- Remove client_certificate_type column from user_certificates
-- SQLite doesn't support DROP COLUMN, so we need to recreate the table
CREATE TABLE user_certificates_backup AS SELECT 
    id, name, created_on, valid_until, certificate_type, user_id, renew_method, 
    tenant_id, profile_id, serial_number, issuer, subject, algorithm, key_size, 
    sans, metadata, status, revoked_at, revoked_by_user_id, revocation_reason, 
    ca_id, pkcs12, pkcs12_password
FROM user_certificates;

DROP TABLE user_certificates;

CREATE TABLE user_certificates (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    created_on INTEGER NOT NULL,
    valid_until INTEGER NOT NULL,
    certificate_type TEXT NOT NULL DEFAULT 'Client',
    user_id INTEGER NOT NULL,
    renew_method INTEGER NOT NULL DEFAULT 0,
    tenant_id TEXT NOT NULL,
    profile_id TEXT,
    serial_number TEXT,
    issuer TEXT,
    subject TEXT,
    algorithm TEXT,
    key_size INTEGER,
    sans TEXT, -- JSON string
    metadata TEXT, -- JSON string
    status TEXT NOT NULL DEFAULT 'active',
    revoked_at INTEGER,
    revoked_by_user_id INTEGER,
    revocation_reason INTEGER,
    ca_id INTEGER NOT NULL,
    pkcs12 BLOB NOT NULL,
    pkcs12_password TEXT NOT NULL,
    FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE,
    FOREIGN KEY(tenant_id) REFERENCES tenants(id) ON DELETE CASCADE,
    FOREIGN KEY(ca_id) REFERENCES certificate_authorities(id) ON DELETE CASCADE,
    UNIQUE(name, tenant_id)
);

INSERT INTO user_certificates SELECT * FROM user_certificates_backup;
DROP TABLE user_certificates_backup;

-- Recreate original indexes
CREATE INDEX idx_user_certificates_tenant ON user_certificates(tenant_id);
CREATE INDEX idx_user_certificates_user ON user_certificates(user_id);
CREATE INDEX idx_user_certificates_status ON user_certificates(status);
CREATE INDEX idx_user_certificates_valid_until ON user_certificates(valid_until);
CREATE INDEX idx_user_certificates_type ON user_certificates(certificate_type);
CREATE INDEX idx_user_certificates_ca ON user_certificates(ca_id);

-- Remove migration audit events
DELETE FROM audit_events 
WHERE event_type = 'system.migration' 
AND resource_id = '07-client-certificate-types';
