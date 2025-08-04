ALTER TABLE user_certificates ADD COLUMN renew_method INTEGER DEFAULT 0;
UPDATE user_certificates SET renew_method = 0 where renew_method IS NULL;