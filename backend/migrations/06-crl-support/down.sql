-- Rollback CRL support migration
-- WARNING: This will remove all revocation tracking data

-- Drop views
DROP VIEW IF EXISTS revoked_certificates_view;
DROP VIEW IF EXISTS active_certificates;

-- Drop indexes
DROP INDEX IF EXISTS idx_crl_cache_created_at;
DROP INDEX IF EXISTS idx_user_certificates_revoked_at;
DROP INDEX IF EXISTS idx_user_certificates_revocation_status;
DROP INDEX IF EXISTS idx_crl_metadata_tenant;
DROP INDEX IF EXISTS idx_crl_metadata_ca;
DROP INDEX IF EXISTS idx_revoked_certificates_date;
DROP INDEX IF EXISTS idx_revoked_certificates_tenant;
DROP INDEX IF EXISTS idx_revoked_certificates_ca;
DROP INDEX IF EXISTS idx_revoked_certificates_serial;

-- Drop new tables
DROP TABLE IF EXISTS crl_cache;
DROP TABLE IF EXISTS crl_metadata;
DROP TABLE IF EXISTS revoked_certificates;

-- Remove columns from user_certificates table
-- SQLite doesn't support DROP COLUMN directly, so we need to recreate the table
CREATE TABLE user_certificates_backup AS 
SELECT id, name, created_on, valid_until, pkcs12, ca_id, user_id, type, renew_method, 
       tenant_id, profile_id, serial_number, issuer, subject, algorithm, key_size, 
       sans, metadata, status
FROM user_certificates;

DROP TABLE user_certificates;

CREATE TABLE user_certificates (
    id INTEGER PRIMARY KEY,
    name TEXT NOT NULL,
    created_on INTEGER NOT NULL,
    valid_until INTEGER NOT NULL,
    pkcs12 BLOB,
    ca_id INTEGER,
    user_id INTEGER,
    type INTEGER DEFAULT 0,
    renew_method INTEGER DEFAULT 0,
    tenant_id TEXT NOT NULL DEFAULT '00000000-0000-0000-0000-000000000000',
    profile_id TEXT,
    serial_number TEXT,
    issuer TEXT,
    subject TEXT,
    algorithm TEXT,
    key_size INTEGER,
    sans TEXT,
    metadata TEXT,
    status TEXT DEFAULT 'active',
    FOREIGN KEY(ca_id) REFERENCES ca_certificates(id) ON DELETE CASCADE,
    FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
);

INSERT INTO user_certificates 
SELECT id, name, created_on, valid_until, pkcs12, ca_id, user_id, type, renew_method,
       tenant_id, profile_id, serial_number, issuer, subject, algorithm, key_size,
       sans, metadata, status
FROM user_certificates_backup;

DROP TABLE user_certificates_backup;

-- Recreate original indexes
CREATE INDEX idx_user_certificates_serial ON user_certificates(serial_number);
CREATE INDEX idx_user_certificates_profile ON user_certificates(profile_id);
CREATE INDEX idx_user_certificates_algorithm ON user_certificates(algorithm);
CREATE INDEX idx_user_certificates_valid_until ON user_certificates(valid_until);
CREATE INDEX idx_user_certificates_status ON user_certificates(status);
CREATE INDEX idx_user_certificates_tenant ON user_certificates(tenant_id);
