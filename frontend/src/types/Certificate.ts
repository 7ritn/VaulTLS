export interface Certificate {
    id: number;                // Unique identifier for the certificate
    name: string;              // Certificate name
    subject_alt_name?: string; // Subject Alternative Name (SAN) for the certificate
    created_on: string;        // Date when the certificate was created (UNIX timestamp in ms)
    valid_until: string;       // Expiration date of the certificate (UNIX timestamp in ms)
    user_id: number;           // User ID who owns the certificate
}
