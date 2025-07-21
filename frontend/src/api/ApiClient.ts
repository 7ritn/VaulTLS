import axios from 'axios';
import type { AxiosInstance, AxiosRequestConfig, AxiosResponse } from 'axios';
import {useAuthStore} from "@/stores/auth.ts";
const API_URL = `${window.location.origin}/api`;

class ApiClient {
    private client: AxiosInstance;

    constructor(baseURL: string) {
        this.client = axios.create({
            baseURL,
            withCredentials: true,
            headers: {
                'Content-Type': 'application/json',
            },
        });

        this.client.interceptors.response.use(
            (response) => response,
            (error) => {
                if (error.response?.status === 401) {
                    const authStore = useAuthStore();
                    authStore.logout();
                }
                return Promise.reject(error);
            }
        );

    }

    async get<T>(url: string, params: Record<string, any> = {}): Promise<T> {
        try {
            const response: AxiosResponse<T> = await this.client.get(url, { params });
            return response.data;
        } catch (error) {
            console.error(`GET ${url} failed:`, error);
            throw error;
        }
    }

    async download(url: string, params: Record<string, any> = {}): Promise<void> {
        try {
            const response: AxiosResponse<BlobPart> = await this.client.get(url, {
                params,
                responseType: 'blob',
            });

            const disposition = response.headers['content-disposition'];
            let filename = 'certificate.crt';
            if (disposition && disposition.includes('filename=')) {
                filename = disposition
                    .split('filename=')[1]
                    .replace(/['"]/g, '')
                    .trim();
            }

            const blob = new Blob([response.data]);
            const blobUrl = URL.createObjectURL(blob);
            const link = document.createElement('a');
            link.href = blobUrl;
            link.download = filename;
            document.body.appendChild(link);
            link.click();
            link.remove();
            URL.revokeObjectURL(blobUrl);
        } catch (error) {
            console.error(`GET ${url} download failed:`, error);
            throw error;
        }
    }


    async post<T>(url: string, data: Record<string, any> = {}): Promise<T> {
        try {
            const response: AxiosResponse<T> = await this.client.post(url, data);
            return response.data;
        } catch (error) {
            console.error(`POST ${url} failed:`, error);
            throw error;
        }
    }

    async put<T>(url: string, data: Record<string, any> = {}): Promise<T> {
        try {
            const response: AxiosResponse<T> = await this.client.put(url, data);
            return response.data;
        } catch (error) {
            console.error(`PUT ${url} failed:`, error);
            throw error;
        }
    }

    async delete<T>(url: string, config: AxiosRequestConfig = {}): Promise<T> {
        try {
            const response: AxiosResponse<T> = await this.client.delete(url, config);
            return response.data;
        } catch (error) {
            console.error(`DELETE ${url} failed:`, error);
            throw error;
        }
    }
}

export default new ApiClient(API_URL);
