ALTER TABLE user_certificates RENAME COLUMN pkcs12 TO data;
ALTER TABLE user_certificates RENAME COLUMN pkcs12_password TO password;
