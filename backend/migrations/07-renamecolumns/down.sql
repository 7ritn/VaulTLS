ALTER TABLE user_certificates RENAME COLUMN data TO pkcs12;
ALTER TABLE user_certificates RENAME COLUMN password TO pkcs12_password;