-- Multi-tenancy and API tokens migration
-- This migration adds support for multiple tenants and API token authentication

-- Create tenants table
CREATE TABLE tenants (
    id TEXT PRIMARY KEY,  -- UUID v4
    name TEXT NOT NULL,
    created_at INTEGER NOT NULL,
    is_active BOOLEAN DEFAULT TRUE
);

-- Create API tokens table
CREATE TABLE api_tokens (
    id TEXT PRIMARY KEY,  -- UUID v4
    prefix TEXT NOT NULL UNIQUE,  -- Short display ID (e.g., "vlt_abc123")
    hash TEXT NOT NULL,  -- HMAC-SHA256 hash
    salt TEXT NOT NULL,  -- Per-token salt (hex encoded)
    scopes TEXT NOT NULL,  -- JSON array of scopes
    description TEXT NOT NULL,
    is_enabled BOOLEAN DEFAULT TRUE,
    revoked_at INTEGER,
    last_used_at INTEGER,
    expires_at INTEGER,
    created_at INTEGER NOT NULL,
    created_by_user_id INTEGER NOT NULL,
    tenant_id TEXT NOT NULL,
    rate_limit_per_minute INTEGER,
    FOREIGN KEY(created_by_user_id) REFERENCES users(id) ON DELETE CASCADE,
    FOREIGN KEY(tenant_id) REFERENCES tenants(id) ON DELETE CASCADE
);

-- Create role-scope mapping table
CREATE TABLE role_scope_map (
    id INTEGER PRIMARY KEY,
    role INTEGER NOT NULL,  -- UserRole enum value
    scope TEXT NOT NULL,
    tenant_id TEXT,
    FOREIGN KEY(tenant_id) REFERENCES tenants(id) ON DELETE CASCADE
);

-- Create endpoint-scope mapping table
CREATE TABLE endpoint_scope_map (
    id INTEGER PRIMARY KEY,
    endpoint_pattern TEXT NOT NULL,
    method TEXT NOT NULL,
    required_scopes TEXT NOT NULL,  -- JSON array of required scopes
    description TEXT
);

-- Create certificate profiles table
CREATE TABLE profiles (
    id TEXT PRIMARY KEY,  -- UUID v4
    name TEXT NOT NULL,
    eku TEXT NOT NULL,  -- JSON array of Extended Key Usage
    key_usage TEXT NOT NULL,  -- JSON array of Key Usage
    san_rules TEXT,  -- JSON object with regex rules per type
    default_days INTEGER NOT NULL,
    max_days INTEGER NOT NULL,
    renewal_window_pct INTEGER DEFAULT 30,
    key_alg_options TEXT NOT NULL,  -- JSON array of allowed algorithms
    tenant_id TEXT NOT NULL,
    created_at INTEGER NOT NULL,
    FOREIGN KEY(tenant_id) REFERENCES tenants(id) ON DELETE CASCADE
);

-- Create audit events table
CREATE TABLE audit_events (
    id INTEGER PRIMARY KEY,
    event_type TEXT NOT NULL,
    resource_type TEXT NOT NULL,
    resource_id TEXT,
    user_id INTEGER,
    token_prefix TEXT,
    tenant_id TEXT,
    endpoint TEXT NOT NULL,
    method TEXT NOT NULL,
    status_code INTEGER NOT NULL,
    duration_ms INTEGER,
    ip_address TEXT,
    user_agent TEXT,
    request_body TEXT,  -- Sanitized request body
    response_body TEXT,  -- Sanitized response body
    created_at INTEGER NOT NULL,
    FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE SET NULL,
    FOREIGN KEY(tenant_id) REFERENCES tenants(id) ON DELETE CASCADE
);

-- Add tenant_id to existing tables
ALTER TABLE users ADD COLUMN tenant_id TEXT;
ALTER TABLE ca_certificates ADD COLUMN tenant_id TEXT;
ALTER TABLE ca_certificates ADD COLUMN name TEXT;
ALTER TABLE ca_certificates ADD COLUMN key_algorithm TEXT DEFAULT 'rsa-2048';
ALTER TABLE ca_certificates ADD COLUMN path_len INTEGER;
ALTER TABLE ca_certificates ADD COLUMN basic_constraints TEXT;
ALTER TABLE ca_certificates ADD COLUMN crl_distribution_points TEXT;  -- JSON
ALTER TABLE ca_certificates ADD COLUMN authority_info_access TEXT;  -- JSON
ALTER TABLE ca_certificates ADD COLUMN is_active BOOLEAN DEFAULT TRUE;

-- Enhance user_certificates table
ALTER TABLE user_certificates ADD COLUMN tenant_id TEXT;
ALTER TABLE user_certificates ADD COLUMN profile_id TEXT;
ALTER TABLE user_certificates ADD COLUMN serial_number TEXT;
ALTER TABLE user_certificates ADD COLUMN issuer TEXT;
ALTER TABLE user_certificates ADD COLUMN subject TEXT;
ALTER TABLE user_certificates ADD COLUMN algorithm TEXT;
ALTER TABLE user_certificates ADD COLUMN key_size INTEGER;
ALTER TABLE user_certificates ADD COLUMN sans TEXT;  -- JSON object with SANs
ALTER TABLE user_certificates ADD COLUMN metadata TEXT;  -- JSON object for additional data
ALTER TABLE user_certificates ADD COLUMN status TEXT DEFAULT 'valid';

-- Create default tenant for existing installation
INSERT INTO tenants (id, name, created_at, is_active) 
VALUES ('00000000-0000-0000-0000-000000000000', 'Default Tenant', strftime('%s', 'now'), TRUE);

-- Migrate existing data to default tenant
UPDATE users SET tenant_id = '00000000-0000-0000-0000-000000000000' WHERE tenant_id IS NULL;
UPDATE ca_certificates SET tenant_id = '00000000-0000-0000-0000-000000000000' WHERE tenant_id IS NULL;
UPDATE user_certificates SET tenant_id = '00000000-0000-0000-0000-000000000000' WHERE tenant_id IS NULL;

-- Add foreign key constraints for tenant_id (SQLite doesn't support adding FK constraints to existing columns)
-- These will be enforced in the application layer

-- Create indexes for performance
CREATE INDEX idx_api_tokens_prefix ON api_tokens(prefix);
CREATE INDEX idx_api_tokens_tenant ON api_tokens(tenant_id);
CREATE INDEX idx_api_tokens_enabled ON api_tokens(is_enabled);
CREATE INDEX idx_api_tokens_expires ON api_tokens(expires_at);

CREATE INDEX idx_users_tenant ON users(tenant_id);
CREATE INDEX idx_ca_certificates_tenant ON ca_certificates(tenant_id);
CREATE INDEX idx_ca_certificates_active ON ca_certificates(is_active);

CREATE INDEX idx_user_certificates_tenant ON user_certificates(tenant_id);
CREATE INDEX idx_user_certificates_status ON user_certificates(status);
CREATE INDEX idx_user_certificates_valid_until ON user_certificates(valid_until);
CREATE INDEX idx_user_certificates_algorithm ON user_certificates(algorithm);
CREATE INDEX idx_user_certificates_profile ON user_certificates(profile_id);
CREATE INDEX idx_user_certificates_serial ON user_certificates(serial_number);

CREATE INDEX idx_audit_events_tenant ON audit_events(tenant_id);
CREATE INDEX idx_audit_events_created ON audit_events(created_at);
CREATE INDEX idx_audit_events_resource ON audit_events(resource_type, resource_id);
CREATE INDEX idx_audit_events_user ON audit_events(user_id);
CREATE INDEX idx_audit_events_token ON audit_events(token_prefix);

CREATE INDEX idx_profiles_tenant ON profiles(tenant_id);

CREATE INDEX idx_role_scope_map_tenant ON role_scope_map(tenant_id);
CREATE INDEX idx_role_scope_map_role ON role_scope_map(role);
