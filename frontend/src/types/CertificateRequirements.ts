import {CertificateRenewMethod, type CertificateType} from "@/types/Certificate.ts";
import {ValidityUnit} from "@/types/ValidityUnit.ts";

export interface CertificateRequirements {
    cert_name: string;
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
}
