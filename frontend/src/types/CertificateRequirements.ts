import {CertificateRenewMethod, type CertificateType} from "@/types/Certificate.ts";
import {ValidityUnit} from "@/types/ValidityUnit.ts";
import type {Name} from "@/types/Name.ts";
import type {DataFormat} from "@/types/CA.ts";
import type {KeyAlgorithm} from "@/types/KeyAlgorithm.ts";

export interface CertificateRequirements {
    cert_name: Name;
    user_id: number;
    validity_duration: number;
    validity_unit: ValidityUnit;
    system_generated_password: boolean;
    cert_password: string;
    notify_user: boolean;
    cert_type: CertificateType;
    usage_limit: string[];
    renew_method: CertificateRenewMethod;
    ca_id?: number;
    key_algorithm?: KeyAlgorithm;       // TLS only; defaults to the issuing CA's algorithm
}

export interface ImportUserCertificateRequest {
    p12: string;
    password: string;
    user_id: number;
    ca_id: number;
    renew_method: CertificateRenewMethod;
    cert_type: CertificateType;
    format: DataFormat;
}
