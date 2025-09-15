import ApiClient from "@/api/ApiClient.ts";
import type {CA, CARequirements} from "@/types/CA.ts";

export const fetchCAs = async (): Promise<CA[]> => {
    return await ApiClient.get<CA[]>(`/certificates/ca`);
};

export const downloadCurrentCA = async (): Promise<void> => {
    return await ApiClient.download(`/certificates/ca/download`);
};

export const createCA = async (certReq: CARequirements): Promise<number> => {
    return await ApiClient.post<number>('/certificates/ca', certReq);
};

export const downloadCAByID = async (id: number): Promise<void> => {
    return await ApiClient.download(`/certificates/ca/${id}/download`);
};