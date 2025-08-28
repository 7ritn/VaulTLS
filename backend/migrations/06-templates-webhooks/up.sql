-- Migration 06: Certificate Templates and Webhook Notifications
-- Add certificate template system and webhook notification infrastructure

-- Certificate Templates Table
CREATE TABLE certificate_templates (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    description TEXT NOT NULL,
    certificate_type TEXT NOT NULL,
    profile_id TEXT NOT NULL,
    default_validity_years INTEGER NOT NULL,
    default_key_algorithm TEXT NOT NULL,
    san_template TEXT,
    metadata_template TEXT,
    tenant_id TEXT NOT NULL,
    created_at INTEGER NOT NULL,
    template_data TEXT NOT NULL, -- JSON blob with full template data
    FOREIGN KEY(profile_id) REFERENCES certificate_profiles(id) ON DELETE CASCADE,
    FOREIGN KEY(tenant_id) REFERENCES tenants(id) ON DELETE CASCADE,
    UNIQUE(name, tenant_id)
);

-- Webhooks Configuration Table
CREATE TABLE webhooks (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    url TEXT NOT NULL,
    events TEXT NOT NULL, -- JSON array of webhook events
    secret TEXT, -- HMAC secret for signature verification
    headers TEXT, -- JSON object with custom headers
    timeout_seconds INTEGER NOT NULL DEFAULT 30,
    retry_attempts INTEGER NOT NULL DEFAULT 3,
    is_active BOOLEAN NOT NULL DEFAULT 1,
    tenant_id TEXT NOT NULL,
    created_at INTEGER NOT NULL,
    last_triggered INTEGER,
    success_count INTEGER NOT NULL DEFAULT 0,
    failure_count INTEGER NOT NULL DEFAULT 0,
    webhook_data TEXT NOT NULL, -- JSON blob with full webhook config
    FOREIGN KEY(tenant_id) REFERENCES tenants(id) ON DELETE CASCADE,
    UNIQUE(name, tenant_id)
);

-- Webhook Deliveries Log Table
CREATE TABLE webhook_deliveries (
    id TEXT PRIMARY KEY,
    webhook_id TEXT NOT NULL,
    event TEXT NOT NULL,
    payload TEXT NOT NULL, -- JSON payload sent
    response_status INTEGER,
    response_body TEXT,
    error_message TEXT,
    attempt_number INTEGER NOT NULL,
    delivered_at INTEGER NOT NULL,
    duration_ms INTEGER NOT NULL,
    success BOOLEAN NOT NULL,
    delivery_data TEXT NOT NULL, -- JSON blob with full delivery data
    FOREIGN KEY(webhook_id) REFERENCES webhooks(id) ON DELETE CASCADE
);

-- Add template_id column to user_certificates table
ALTER TABLE user_certificates ADD COLUMN template_id TEXT;
ALTER TABLE user_certificates ADD FOREIGN KEY(template_id) REFERENCES certificate_templates(id) ON DELETE SET NULL;

-- Indexes for performance
CREATE INDEX idx_certificate_templates_tenant ON certificate_templates(tenant_id);
CREATE INDEX idx_certificate_templates_profile ON certificate_templates(profile_id);
CREATE INDEX idx_certificate_templates_name ON certificate_templates(name);

CREATE INDEX idx_webhooks_tenant ON webhooks(tenant_id);
CREATE INDEX idx_webhooks_active ON webhooks(is_active);
CREATE INDEX idx_webhooks_events ON webhooks(events);

CREATE INDEX idx_webhook_deliveries_webhook ON webhook_deliveries(webhook_id);
CREATE INDEX idx_webhook_deliveries_event ON webhook_deliveries(event);
CREATE INDEX idx_webhook_deliveries_delivered_at ON webhook_deliveries(delivered_at);
CREATE INDEX idx_webhook_deliveries_success ON webhook_deliveries(success);

CREATE INDEX idx_user_certificates_template ON user_certificates(template_id);

-- Insert default certificate templates for existing tenants
INSERT INTO certificate_templates (id, name, description, certificate_type, profile_id, default_validity_years, default_key_algorithm, san_template, metadata_template, tenant_id, created_at, template_data)
SELECT 
    'default-server-' || t.id,
    'Default Server Certificate',
    'Standard server certificate template with 1-year validity',
    'Server',
    COALESCE((SELECT id FROM certificate_profiles WHERE tenant_id = t.id LIMIT 1), 'default-profile'),
    1,
    'RSA-2048',
    '{{hostname}}.{{domain}}',
    '{"auto_generated": true, "template_type": "server"}',
    t.id,
    strftime('%s', 'now'),
    json_object(
        'id', 'default-server-' || t.id,
        'name', 'Default Server Certificate',
        'description', 'Standard server certificate template with 1-year validity',
        'certificate_type', 'Server',
        'profile_id', COALESCE((SELECT id FROM certificate_profiles WHERE tenant_id = t.id LIMIT 1), 'default-profile'),
        'default_validity_years', 1,
        'default_key_algorithm', 'RSA-2048',
        'san_template', '{{hostname}}.{{domain}}',
        'metadata_template', json('{"auto_generated": true, "template_type": "server"}'),
        'tenant_id', t.id,
        'created_at', strftime('%s', 'now')
    )
FROM tenants t
WHERE EXISTS (SELECT 1 FROM certificate_profiles WHERE tenant_id = t.id);

INSERT INTO certificate_templates (id, name, description, certificate_type, profile_id, default_validity_years, default_key_algorithm, san_template, metadata_template, tenant_id, created_at, template_data)
SELECT 
    'default-client-' || t.id,
    'Default Client Certificate',
    'Standard client certificate template with 6-month validity',
    'Client',
    COALESCE((SELECT id FROM certificate_profiles WHERE tenant_id = t.id LIMIT 1), 'default-profile'),
    1,
    'RSA-2048',
    NULL,
    '{"auto_generated": true, "template_type": "client"}',
    t.id,
    strftime('%s', 'now'),
    json_object(
        'id', 'default-client-' || t.id,
        'name', 'Default Client Certificate',
        'description', 'Standard client certificate template with 6-month validity',
        'certificate_type', 'Client',
        'profile_id', COALESCE((SELECT id FROM certificate_profiles WHERE tenant_id = t.id LIMIT 1), 'default-profile'),
        'default_validity_years', 1,
        'default_key_algorithm', 'RSA-2048',
        'san_template', NULL,
        'metadata_template', json('{"auto_generated": true, "template_type": "client"}'),
        'tenant_id', t.id,
        'created_at', strftime('%s', 'now')
    )
FROM tenants t
WHERE EXISTS (SELECT 1 FROM certificate_profiles WHERE tenant_id = t.id);

-- Add webhook event types to audit events for tracking
INSERT INTO audit_events (event_type, resource_type, resource_id, user_id, token_prefix, tenant_id, endpoint, method, status_code, duration_ms, ip_address, user_agent, request_body, response_body, created_at)
SELECT 
    'system.migration',
    'database',
    '06-templates-webhooks',
    NULL,
    NULL,
    t.id,
    '/system/migration',
    'POST',
    200,
    0,
    '127.0.0.1',
    'VaulTLS-Migration/1.0',
    '{"migration": "06-templates-webhooks", "description": "Certificate Templates and Webhook Notifications"}',
    '{"templates_created": 2, "tables_created": 3}',
    strftime('%s', 'now')
FROM tenants t;
