ALTER TABLE ca_certificates ADD COLUMN predecessor_id INTEGER REFERENCES ca_certificates(id) ON DELETE SET NULL;
CREATE UNIQUE INDEX idx_ca_certificates_predecessor_id ON ca_certificates(predecessor_id) WHERE predecessor_id IS NOT NULL;
ALTER TABLE user_certificates ADD COLUMN renewal_error TEXT;
