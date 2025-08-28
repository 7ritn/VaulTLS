-- Migration 07: Add User and Device Certificate Types
-- Extend certificate type support to distinguish between User and Device certificates

-- Add certificate_type column to certificate_profiles table if it doesn't exist
-- This allows profiles to be specific to certificate types
ALTER TABLE certificate_profiles ADD COLUMN certificate_type TEXT DEFAULT 'Client';

-- Update existing profiles to have appropriate certificate types
UPDATE certificate_profiles SET certificate_type = 'Server' 
WHERE name LIKE '%server%' OR name LIKE '%Server%' OR name LIKE '%web%' OR name LIKE '%Web%';

UPDATE certificate_profiles SET certificate_type = 'Client' 
WHERE certificate_type = 'Client' AND (name LIKE '%client%' OR name LIKE '%Client%');

-- Create default profiles for User and Device certificate types
INSERT INTO certificate_profiles (
    id, name, certificate_type, eku, key_usage, san_rules, default_days, max_days, 
    renewal_window_pct, key_alg_options, tenant_id, created_at, profile_data
)
SELECT 
    'user-auth-' || t.id,
    'User Authentication Profile',
    'User',
    '["clientAuth", "emailProtection"]',
    '["digitalSignature"]',
    '{"email_addresses": [{"pattern": "*@*", "required": true, "max_count": 1}]}',
    365,
    730,
    80,
    '["RSA-2048", "RSA-4096", "ECDSA-P256"]',
    t.id,
    strftime('%s', 'now'),
    json_object(
        'id', 'user-auth-' || t.id,
        'name', 'User Authentication Profile',
        'certificate_type', 'User',
        'eku', json('["clientAuth", "emailProtection"]'),
        'key_usage', json('["digitalSignature"]'),
        'san_rules', json('{"email_addresses": [{"pattern": "*@*", "required": true, "max_count": 1}]}'),
        'default_days', 365,
        'max_days', 730,
        'renewal_window_pct', 80,
        'key_alg_options', json('["RSA-2048", "RSA-4096", "ECDSA-P256"]'),
        'tenant_id', t.id,
        'created_at', strftime('%s', 'now')
    )
FROM tenants t;

INSERT INTO certificate_profiles (
    id, name, certificate_type, eku, key_usage, san_rules, default_days, max_days, 
    renewal_window_pct, key_alg_options, tenant_id, created_at, profile_data
)
SELECT 
    'device-auth-' || t.id,
    'Device Authentication Profile',
    'Device',
    '["clientAuth"]',
    '["digitalSignature", "keyEncipherment"]',
    '{"dns_names": [{"pattern": "*.local", "required": false, "max_count": 5}]}',
    180,
    365,
    80,
    '["RSA-2048", "RSA-4096", "ECDSA-P256"]',
    t.id,
    strftime('%s', 'now'),
    json_object(
        'id', 'device-auth-' || t.id,
        'name', 'Device Authentication Profile',
        'certificate_type', 'Device',
        'eku', json('["clientAuth"]'),
        'key_usage', json('["digitalSignature", "keyEncipherment"]'),
        'san_rules', json('{"dns_names": [{"pattern": "*.local", "required": false, "max_count": 5}]}'),
        'default_days', 180,
        'max_days', 365,
        'renewal_window_pct', 80,
        'key_alg_options', json('["RSA-2048", "RSA-4096", "ECDSA-P256"]'),
        'tenant_id', t.id,
        'created_at', strftime('%s', 'now')
    )
FROM tenants t;

-- Update certificate templates to support User and Device types
INSERT INTO certificate_templates (
    id, name, description, certificate_type, profile_id, default_validity_years, 
    default_key_algorithm, san_template, metadata_template, tenant_id, created_at, template_data
)
SELECT 
    'user-cert-' || t.id,
    'User Certificate Template',
    'Standard template for user authentication certificates',
    'User',
    'user-auth-' || t.id,
    1,
    'RSA-2048',
    '{{email}}',
    '{"certificate_purpose": "user_authentication", "template_type": "user"}',
    t.id,
    strftime('%s', 'now'),
    json_object(
        'id', 'user-cert-' || t.id,
        'name', 'User Certificate Template',
        'description', 'Standard template for user authentication certificates',
        'certificate_type', 'User',
        'profile_id', 'user-auth-' || t.id,
        'default_validity_years', 1,
        'default_key_algorithm', 'RSA-2048',
        'san_template', '{{email}}',
        'metadata_template', json('{"certificate_purpose": "user_authentication", "template_type": "user"}'),
        'tenant_id', t.id,
        'created_at', strftime('%s', 'now')
    )
FROM tenants t;

INSERT INTO certificate_templates (
    id, name, description, certificate_type, profile_id, default_validity_years, 
    default_key_algorithm, san_template, metadata_template, tenant_id, created_at, template_data
)
SELECT 
    'device-cert-' || t.id,
    'Device Certificate Template',
    'Standard template for device authentication certificates',
    'Device',
    'device-auth-' || t.id,
    1,
    'RSA-2048',
    '{{device_name}}.{{domain}}',
    '{"certificate_purpose": "device_authentication", "template_type": "device"}',
    t.id,
    strftime('%s', 'now'),
    json_object(
        'id', 'device-cert-' || t.id,
        'name', 'Device Certificate Template',
        'description', 'Standard template for device authentication certificates',
        'certificate_type', 'Device',
        'profile_id', 'device-auth-' || t.id,
        'default_validity_years', 1,
        'default_key_algorithm', 'RSA-2048',
        'san_template', '{{device_name}}.{{domain}}',
        'metadata_template', json('{"certificate_purpose": "device_authentication", "template_type": "device"}'),
        'tenant_id', t.id,
        'created_at', strftime('%s', 'now')
    )
FROM tenants t;

-- Add indexes for performance
CREATE INDEX IF NOT EXISTS idx_certificate_profiles_type ON certificate_profiles(certificate_type);
CREATE INDEX IF NOT EXISTS idx_user_certificates_type ON user_certificates(certificate_type);

-- Add audit event for migration
INSERT INTO audit_events (
    event_type, resource_type, resource_id, user_id, token_prefix, tenant_id, 
    endpoint, method, status_code, duration_ms, ip_address, user_agent, 
    request_body, response_body, created_at
)
SELECT 
    'system.migration',
    'database',
    '07-user-device-types',
    NULL,
    NULL,
    t.id,
    '/system/migration',
    'POST',
    200,
    0,
    '127.0.0.1',
    'VaulTLS-Migration/1.0',
    '{"migration": "07-user-device-types", "description": "Add User and Device Certificate Types"}',
    '{"profiles_created": 2, "templates_created": 2, "certificate_types_added": ["User", "Device"]}',
    strftime('%s', 'now')
FROM tenants t;
