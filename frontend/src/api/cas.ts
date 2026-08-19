import ApiClient from "@/api/ApiClient.ts";
import type {CA, CARequirements, ImportCARequest} from "@/types/CA.ts";

export const fetchCAs = async (): Promise<CA[]> => {
    return await ApiClient.get<CA[]>(`/certificates/ca`);
};

export const createCA = async (certReq: CARequirements): Promise<number> => {
    return await ApiClient.post<number>('/certificates/ca', certReq);
};

export const importCA = async (importReq: ImportCARequest): Promise<number> => {
    return await ApiClient.post<number>('/certificates/ca/import', importReq);
};

export const downloadCAByID = async (id: number): Promise<void> => {
    return await ApiClient.download(`/certificates/ca/${id}/download`);
};

export const downloadAllTLSCAs = async (): Promise<void> => {
    return await ApiClient.download(`/certificates/ca/all/download`);
};

export const deleteCA = async (id: number): Promise<void> => {
    await ApiClient.delete<void>(`/certificates/ca/${id}`);
};

export const downloadCRL = async (id: number, format: string = 'der'): Promise<void> => {
    await ApiClient.download(`/certificates/ca/${id}/crl?format=${format}`);
};