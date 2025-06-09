export interface SetupReq {
    name: string,
    email: string,
    ca_name: string,
    ca_validity_in_years: number,
    password: string | null;
}

export interface IsSetupResponse {
    setup: boolean,
    password: boolean,
    oidc: string;
}

export interface ChangePasswordReq {
    old_password: string | null,
    new_password: string;
}