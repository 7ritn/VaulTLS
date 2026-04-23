export interface AcmeIdentifier {
  type: string;
  value: string;
}

export interface AcmeOrder {
  id: number;
  account_id: number;
  account_name: string;
  status: string;
  identifiers: AcmeIdentifier[];
  not_after: number;
  expires: number;
  certificate_id: number | null;
  created_on: number;
  client_ip: string | null;
  error: string | null;
}

export interface AcmeAccount {
  id: number;
  name: string;
  allowed_domains: string;
  eab_kid: string;
  status: string;
  ca_id: number | null;
  contacts: string;
  created_on: number;
  user_id: number;
  auto_validate: boolean;
}

export interface CreateAcmeAccountRequest {
  name: string;
  allowed_domains: string[];
  ca_id: number | null;
  auto_validate?: boolean;
}

export interface UpdateAcmeAccountRequest {
  name?: string;
  allowed_domains?: string[];
  ca_id?: number;
  status?: string;
  auto_validate?: boolean;
}

export interface CreateAcmeAccountResponse {
  id: number;
  name: string;
  eab_kid: string;
  eab_hmac_key: string;
}
