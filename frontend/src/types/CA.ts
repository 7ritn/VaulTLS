export interface CA {
    id: number;                           // Unique identifier for the CA
    name: string;                         // CA name
    created_on: string;                   // Date when the CA was created (UNIX timestamp in ms)
    valid_until: string;                  // Expiration date of the CA (UNIX timestamp in ms)
}

export interface CARequirements {
    name: string;                         // CA name
    validity_in_years: number             // Validity of CA in years
}