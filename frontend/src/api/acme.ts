import ApiClient from '@/api/ApiClient.ts';
import type { AcmeAccount, AcmeOrder, CreateAcmeAccountRequest, CreateAcmeAccountResponse, UpdateAcmeAccountRequest } from '@/types/Acme';

export const fetchAcmeOrders = async (): Promise<AcmeOrder[]> => {
    return await ApiClient.get<AcmeOrder[]>('/acme/orders');
};

export const fetchAcmeAccounts = async (): Promise<AcmeAccount[]> => {
    return await ApiClient.get<AcmeAccount[]>('/acme/accounts');
};

export const createAcmeAccount = async (req: CreateAcmeAccountRequest): Promise<CreateAcmeAccountResponse> => {
    return await ApiClient.post<CreateAcmeAccountResponse>('/acme/accounts', req);
};

export const updateAcmeAccount = async (id: number, req: UpdateAcmeAccountRequest): Promise<AcmeAccount> => {
    return await ApiClient.put<AcmeAccount>(`/acme/accounts/${id}`, req);
};

export const deleteAcmeAccount = async (id: number): Promise<void> => {
    await ApiClient.delete(`/acme/accounts/${id}`);
};
