-- Migration 07 Rollback: Remove User and Device Certificate Types

-- Remove User and Device certificate templates
DELETE FROM certificate_templates 
WHERE certificate_type IN ('User', 'Device');

-- Remove User and Device certificate profiles
DELETE FROM certificate_profiles 
WHERE certificate_type IN ('User', 'Device');

-- Update any existing User/Device certificates back to Client type
UPDATE user_certificates 
SET certificate_type = 'Client' 
WHERE certificate_type IN ('User', 'Device');

-- Drop indexes
DROP INDEX IF EXISTS idx_certificate_profiles_type;
DROP INDEX IF EXISTS idx_user_certificates_type;

-- Remove certificate_type column from certificate_profiles
-- SQLite doesn't support DROP COLUMN, so we need to recreate the table
CREATE TABLE certificate_profiles_backup AS SELECT 
    id, name, eku, key_usage, san_rules, default_days, max_days, 
    renewal_window_pct, key_alg_options, tenant_id, created_at, profile_data
FROM certificate_profiles;

DROP TABLE certificate_profiles;

CREATE TABLE certificate_profiles (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    eku TEXT NOT NULL, -- JSON array of Extended Key Usage values
    key_usage TEXT NOT NULL, -- JSON array of Key Usage values
    san_rules TEXT, -- JSON object with SAN validation rules
    default_days INTEGER NOT NULL,
    max_days INTEGER NOT NULL,
    renewal_window_pct INTEGER NOT NULL DEFAULT 80,
    key_alg_options TEXT NOT NULL, -- JSON array of allowed key algorithms
    tenant_id TEXT NOT NULL,
    created_at INTEGER NOT NULL,
    profile_data TEXT NOT NULL, -- JSON blob with full profile data
    FOREIGN KEY(tenant_id) REFERENCES tenants(id) ON DELETE CASCADE,
    UNIQUE(name, tenant_id)
);

INSERT INTO certificate_profiles SELECT * FROM certificate_profiles_backup;
DROP TABLE certificate_profiles_backup;

-- Recreate indexes for certificate_profiles
CREATE INDEX idx_certificate_profiles_tenant ON certificate_profiles(tenant_id);
CREATE INDEX idx_certificate_profiles_name ON certificate_profiles(name);

-- Remove migration audit events
DELETE FROM audit_events 
WHERE event_type = 'system.migration' 
AND resource_id = '07-user-device-types';
