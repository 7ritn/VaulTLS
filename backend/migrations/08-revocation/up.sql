ALTER TABLE user_certificates ADD COLUMN revoked_at INTEGER;
ALTER TABLE ca_certificates ADD COLUMN crl_number INTEGER DEFAULT 0;
UPDATE ca_certificates SET crl_number = 0 where crl_number IS NULL;