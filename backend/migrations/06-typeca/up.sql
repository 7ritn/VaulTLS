ALTER TABLE ca_certificates ADD COLUMN type INTEGER DEFAULT 0;
UPDATE ca_certificates SET type = 0 where type IS NULL;