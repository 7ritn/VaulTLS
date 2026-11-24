-- Entries on the CRL/KRL of a CA. Rows outlive the revoked certificate or CA, so deleting
-- either never removes it from the revocation list.
CREATE TABLE revocations (
    id INTEGER PRIMARY KEY,
    ca_id INTEGER NOT NULL REFERENCES ca_certificates(id) ON DELETE CASCADE,
    serial BLOB NOT NULL,
    revoked_at INTEGER NOT NULL,
    user_cert_id INTEGER UNIQUE REFERENCES user_certificates(id) ON DELETE SET NULL,
    revoked_ca_id INTEGER UNIQUE REFERENCES ca_certificates(id) ON DELETE SET NULL
);

CREATE INDEX idx_revocations_ca_id ON revocations(ca_id);
