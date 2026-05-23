CREATE TABLE acme_accounts (
    id INTEGER PRIMARY KEY,
    name TEXT NOT NULL,
    allowed_domains TEXT NOT NULL DEFAULT '',
    eab_kid TEXT NOT NULL UNIQUE,
    eab_hmac_key BLOB NOT NULL,
    acme_jwk TEXT,
    jwk_thumbprint TEXT,
    status TEXT NOT NULL DEFAULT 'pending',
    ca_id INTEGER,
    contacts TEXT NOT NULL DEFAULT '',
    created_on INTEGER NOT NULL,
    user_id INTEGER NOT NULL,
    auto_validate INTEGER NOT NULL DEFAULT 0,
    FOREIGN KEY(ca_id) REFERENCES ca_certificates(id) ON DELETE SET NULL,
    FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE TABLE acme_orders (
    id INTEGER PRIMARY KEY,
    account_id INTEGER NOT NULL,
    status TEXT NOT NULL DEFAULT 'pending',
    identifiers TEXT NOT NULL,
    not_after INTEGER NOT NULL,
    expires INTEGER NOT NULL,
    certificate_id INTEGER,
    created_on INTEGER NOT NULL,
    client_ip TEXT,
    error TEXT,
    FOREIGN KEY(account_id) REFERENCES acme_accounts(id) ON DELETE CASCADE,
    FOREIGN KEY(certificate_id) REFERENCES user_certificates(id) ON DELETE SET NULL
);

CREATE TABLE acme_nonces (
    nonce TEXT PRIMARY KEY,
    created_on INTEGER NOT NULL
);

ALTER TABLE user_certificates ADD COLUMN acme_account_id INTEGER REFERENCES acme_accounts(id) ON DELETE SET NULL;
ALTER TABLE user_certificates ADD COLUMN serial_hex TEXT;

CREATE INDEX idx_acme_orders_account_created ON acme_orders(account_id, created_on);
CREATE INDEX idx_acme_nonces_created_on ON acme_nonces(created_on);
CREATE INDEX idx_user_certificates_serial_hex ON user_certificates(serial_hex);
