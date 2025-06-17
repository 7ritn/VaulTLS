CREATE TABLE ca_certificates (
    id INTEGER PRIMARY KEY,
    created_on INTEGER NOT NULL,
    valid_until INTEGER NOT NULL,
    certificate BLOB,
    key BLOB
);

CREATE TABLE users (
    id INTEGER PRIMARY KEY,
    name TEXT NOT NULL,
    email TEXT NOT NULL,
    password_hash TEXT,
    oidc_id TEXT,
    role INTEGER NOT NULL
);

CREATE TABLE user_certificates (
    id INTEGER PRIMARY KEY,
    name TEXT NOT NULL,
    created_on INTEGER NOT NULL,
    valid_until INTEGER NOT NULL,
    pkcs12 BLOB,
    ca_id INTEGER,
    user_id INTEGER,
    FOREIGN KEY(ca_id) REFERENCES ca_certificates(id) ON DELETE CASCADE,
    FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
);