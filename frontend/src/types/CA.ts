import {ValidityUnit} from "@/types/ValidityUnit.ts";
import type {Name} from "@/types/Name.ts";

export enum CAType {
    TLS = 0,
    SSH = 1
}

export interface CA {
    id: number;                           // Unique identifier for the CA
    name: Name;                           // CA name
    created_on: number;                   // Date when the CA was created (UNIX timestamp in ms)
    valid_until: number;                  // Expiration date of the CA (UNIX timestamp in ms)
    ca_type: CAType;                      // CA type
    parent_id?: number | null;            // Parent CA identifier, when this is an intermediate CA
    revoked_at?: number | null;           // Date when the CA was revoked (UNIX timestamp in s)
    predecessor_id?: number | null;       // CA that this CA succeeds
}

export interface CARequirements {
    ca_name: Name;                      // CA name
    ca_type: CAType;                    // CA type
    validity_duration?: number;         // Validity duration
    validity_unit?: ValidityUnit;       // Validity unit (hours, days, months, years)
    parent_id?: number;                 // Parent CA identifier, when creating an intermediate CA
    predecessor_id?: number;            // CA that the new CA succeeds, renewals of its certificates move to the new CA
}

export enum DataFormat {
    DER = 'der',
    PEM = 'pem'
}

export interface ImportCARequest {
    cert: string;
    key: string;
    crl?: string;
    format: DataFormat;
    parent_id?: number;                 // Parent CA identifier, when importing an intermediate CA
    predecessor_id?: number;            // CA that the imported CA succeeds
}