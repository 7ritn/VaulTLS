-- Entries on the CRL/KRL of the CA in ca_id. Deleting the revoked certificate (revoked_user_cert_id) or
-- revoked intermediate CA (revoked_ca_id) keeps the entry. Deleting the issuing CA removes its entries.
CREATE TABLE revocations (
    id INTEGER PRIMARY KEY,
    ca_id INTEGER NOT NULL REFERENCES ca_certificates(id) ON DELETE CASCADE,
    serial BLOB NOT NULL,
    revoked_at INTEGER NOT NULL,
    revoked_user_cert_id INTEGER UNIQUE REFERENCES user_certificates(id) ON DELETE SET NULL,
    revoked_ca_id INTEGER UNIQUE REFERENCES ca_certificates(id) ON DELETE SET NULL
);

CREATE INDEX idx_revocations_ca_id ON revocations(ca_id);
