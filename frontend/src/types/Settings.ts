export enum Encryption {
    None = 0,
    TLS = 1,
    STARTTLS = 2
}
export enum PasswordRule {
    Optional = 0,
    Required = 1,
    System = 2
}
export interface Settings {
    common: {
        password_enabled: boolean;
        password_rule: PasswordRule;
        vaultls_url: string;
    },
    mail: {
        smtp_host: string,
        smtp_port: number,
        encryption: Encryption,
        username?: string,
        password?: string,
        from: string,
    };
    oidc: {
        id: string,
        secret: string,
        auth_url: string,
        callback_url: string;
    }
}
