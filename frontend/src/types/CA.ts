export enum CAType {
    TLS = 0,
    SSH = 1
}

export interface CA {
    id: number;                           // Unique identifier for the CA
    name: string;                         // CA name
    created_on: string;                   // Date when the CA was created (UNIX timestamp in ms)
    valid_until: string;                  // Expiration date of the CA (UNIX timestamp in ms)
    ca_type: CAType;                      // CA type
}

export interface CARequirements {
    ca_name: string;                    // CA name
    ca_type: CAType;                    // CA type
    validity_in_years?: number;          // Validity of CA in years
}