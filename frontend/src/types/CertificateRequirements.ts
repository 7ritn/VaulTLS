import {CertificateRenewMethod, type CertificateType} from "@/types/Certificate.ts";

export interface CertificateRequirements {
    cert_name: string;
    user_id: number;
    validity_in_years: number;
    system_generated_password: boolean;
    pkcs12_password: string;
    notify_user: boolean;
    cert_type: CertificateType;
    dns_names: string[];
    renew_method: CertificateRenewMethod;
    ca_id?: number;
}
