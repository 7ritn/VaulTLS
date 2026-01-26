import {ValidityUnit} from "@/types/ValidityUnit.ts";

export interface SetupReq {
    name: string,
    email: string,
    ca_name: string,
    validity_duration: number,
    validity_unit: ValidityUnit,
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