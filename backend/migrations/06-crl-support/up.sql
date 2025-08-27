-- Add CRL (Certificate Revocation List) support
-- This migration adds proper certificate revocation tracking

-- Create revoked certificates table
CREATE TABLE revoked_certificates (
    id INTEGER PRIMARY KEY,
    certificate_id INTEGER NOT NULL,
    serial_number TEXT NOT NULL,
    revocation_date INTEGER NOT NULL,
    revocation_reason INTEGER NOT NULL DEFAULT 0,
    ca_id INTEGER NOT NULL,
    tenant_id TEXT NOT NULL DEFAULT '00000000-0000-0000-0000-000000000000',
    revoked_by_user_id INTEGER,
    created_at INTEGER NOT NULL,
    FOREIGN KEY(ca_id) REFERENCES ca_certificates(id) ON DELETE CASCADE,
    FOREIGN KEY(revoked_by_user_id) REFERENCES users(id) ON DELETE SET NULL
);

-- Create indexes for performance
CREATE INDEX idx_revoked_certificates_serial ON revoked_certificates(serial_number);
CREATE INDEX idx_revoked_certificates_ca ON revoked_certificates(ca_id);
CREATE INDEX idx_revoked_certificates_tenant ON revoked_certificates(tenant_id);
CREATE INDEX idx_revoked_certificates_date ON revoked_certificates(revocation_date);

-- Create CRL metadata table to track CRL generation
CREATE TABLE crl_metadata (
    id INTEGER PRIMARY KEY,
    ca_id INTEGER NOT NULL,
    tenant_id TEXT NOT NULL DEFAULT '00000000-0000-0000-0000-000000000000',
    crl_number INTEGER NOT NULL DEFAULT 1,
    this_update INTEGER NOT NULL,
    next_update INTEGER NOT NULL,
    revoked_count INTEGER NOT NULL DEFAULT 0,
    created_at INTEGER NOT NULL,
    FOREIGN KEY(ca_id) REFERENCES ca_certificates(id) ON DELETE CASCADE
);

-- Create index for CRL metadata
CREATE INDEX idx_crl_metadata_ca ON crl_metadata(ca_id);
CREATE INDEX idx_crl_metadata_tenant ON crl_metadata(tenant_id);

-- Add revocation status to user_certificates table
ALTER TABLE user_certificates ADD COLUMN revocation_status TEXT DEFAULT 'active';
ALTER TABLE user_certificates ADD COLUMN revoked_at INTEGER;
ALTER TABLE user_certificates ADD COLUMN revoked_by_user_id INTEGER;
ALTER TABLE user_certificates ADD COLUMN revocation_reason INTEGER;

-- Create index for revocation status
CREATE INDEX idx_user_certificates_revocation_status ON user_certificates(revocation_status);
CREATE INDEX idx_user_certificates_revoked_at ON user_certificates(revoked_at);

-- Add foreign key constraint for revoked_by_user_id
-- Note: SQLite doesn't support adding foreign keys to existing tables,
-- so we'll handle this constraint in the application layer

-- Update existing certificates to have active status
UPDATE user_certificates SET revocation_status = 'active' WHERE revocation_status IS NULL;

-- Add CRL distribution points to CA certificates (already exists in our multi-tenancy migration)
-- This is handled by the existing crl_distribution_points column

-- Create a view for active certificates
CREATE VIEW active_certificates AS
SELECT * FROM user_certificates 
WHERE revocation_status = 'active' OR revocation_status IS NULL;

-- Create a view for revoked certificates with details
CREATE VIEW revoked_certificates_view AS
SELECT 
    uc.id as certificate_id,
    uc.name as certificate_name,
    uc.serial_number,
    uc.revoked_at,
    uc.revocation_reason,
    uc.revoked_by_user_id,
    uc.ca_id,
    uc.tenant_id,
    uc.user_id as owner_user_id,
    u.name as owner_name,
    ru.name as revoked_by_name
FROM user_certificates uc
LEFT JOIN users u ON uc.user_id = u.id
LEFT JOIN users ru ON uc.revoked_by_user_id = ru.id
WHERE uc.revocation_status = 'revoked';

-- Create CRL cache table for storing generated CRLs
CREATE TABLE crl_cache (
    ca_id INTEGER NOT NULL,
    tenant_id TEXT NOT NULL DEFAULT '00000000-0000-0000-0000-000000000000',
    crl_data BLOB NOT NULL,
    created_at INTEGER NOT NULL,
    PRIMARY KEY (ca_id, tenant_id),
    FOREIGN KEY(ca_id) REFERENCES ca_certificates(id) ON DELETE CASCADE
);

-- Create index for CRL cache
CREATE INDEX idx_crl_cache_created_at ON crl_cache(created_at);

-- Insert initial CRL metadata for existing CAs
INSERT INTO crl_metadata (ca_id, tenant_id, crl_number, this_update, next_update, revoked_count, created_at)
SELECT
    id,
    tenant_id,
    1,
    strftime('%s', 'now'),
    strftime('%s', 'now', '+7 days'),
    0,
    strftime('%s', 'now')
FROM ca_certificates;
