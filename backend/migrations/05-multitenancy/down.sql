-- Rollback multi-tenancy migration
-- WARNING: This will remove all multi-tenant data and API tokens

-- Drop indexes
DROP INDEX IF EXISTS idx_role_scope_map_role;
DROP INDEX IF EXISTS idx_role_scope_map_tenant;
DROP INDEX IF EXISTS idx_profiles_tenant;
DROP INDEX IF EXISTS idx_audit_events_token;
DROP INDEX IF EXISTS idx_audit_events_user;
DROP INDEX IF EXISTS idx_audit_events_resource;
DROP INDEX IF EXISTS idx_audit_events_created;
DROP INDEX IF EXISTS idx_audit_events_tenant;
DROP INDEX IF EXISTS idx_user_certificates_serial;
DROP INDEX IF EXISTS idx_user_certificates_profile;
DROP INDEX IF EXISTS idx_user_certificates_algorithm;
DROP INDEX IF EXISTS idx_user_certificates_valid_until;
DROP INDEX IF EXISTS idx_user_certificates_status;
DROP INDEX IF EXISTS idx_user_certificates_tenant;
DROP INDEX IF EXISTS idx_ca_certificates_active;
DROP INDEX IF EXISTS idx_ca_certificates_tenant;
DROP INDEX IF EXISTS idx_users_tenant;
DROP INDEX IF EXISTS idx_api_tokens_expires;
DROP INDEX IF EXISTS idx_api_tokens_enabled;
DROP INDEX IF EXISTS idx_api_tokens_tenant;
DROP INDEX IF EXISTS idx_api_tokens_prefix;

-- Drop new tables
DROP TABLE IF EXISTS audit_events;
DROP TABLE IF EXISTS profiles;
DROP TABLE IF EXISTS endpoint_scope_map;
DROP TABLE IF EXISTS role_scope_map;
DROP TABLE IF EXISTS api_tokens;
DROP TABLE IF EXISTS tenants;

-- Remove columns from existing tables (SQLite doesn't support DROP COLUMN directly)
-- We need to recreate the tables without the new columns

-- Recreate users table without tenant_id
CREATE TABLE users_backup AS SELECT id, name, email, password_hash, oidc_id, role FROM users;
DROP TABLE users;
CREATE TABLE users (
    id INTEGER PRIMARY KEY,
    name TEXT NOT NULL,
    email TEXT NOT NULL,
    password_hash TEXT,
    oidc_id TEXT,
    role INTEGER NOT NULL
);
INSERT INTO users SELECT * FROM users_backup;
DROP TABLE users_backup;

-- Recreate ca_certificates table without new columns
CREATE TABLE ca_certificates_backup AS SELECT id, created_on, valid_until, certificate, key FROM ca_certificates;
DROP TABLE ca_certificates;
CREATE TABLE ca_certificates (
    id INTEGER PRIMARY KEY,
    created_on INTEGER NOT NULL,
    valid_until INTEGER NOT NULL,
    certificate BLOB,
    key BLOB
);
INSERT INTO ca_certificates SELECT * FROM ca_certificates_backup;
DROP TABLE ca_certificates_backup;

-- Recreate user_certificates table without new columns
CREATE TABLE user_certificates_backup AS SELECT id, name, created_on, valid_until, pkcs12, ca_id, user_id, type, renew_method FROM user_certificates;
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
    FOREIGN KEY(ca_id) REFERENCES ca_certificates(id) ON DELETE CASCADE,
    FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
);
INSERT INTO user_certificates SELECT * FROM user_certificates_backup;
DROP TABLE user_certificates_backup;
