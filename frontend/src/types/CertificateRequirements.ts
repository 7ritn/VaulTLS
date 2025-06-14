export interface CertificateRequirements {
    cert_name: string;
    user_id: number;
    validity_in_years: number;
    notify_user: boolean;
    subject_alt_name?: string;
}
