import { defineStore } from 'pinia';
import type { Certificate, CertificateType, ClientCertificateType } from '@/types/Certificate';
import {
    fetchCertificates,
    fetchCertificatePassword,
    downloadCertificate,
    createCertificate,
    deleteCertificate,
} from '../api/certificates';
import type {CertificateRequirements} from "@/types/CertificateRequirements.ts";
import { apiClient } from '@/api/client';

export interface CertificateSearchParams {
  page?: number
  per_page?: number
  search?: string
  sort?: string
  certificateType?: CertificateType | ''
  clientCertificateType?: ClientCertificateType | ''
  status?: string
  expiresIn?: string
  caId?: string
  createdAfter?: string
  algorithm?: string
}

export interface CertificateSearchResponse {
  certificates: Certificate[]
  total: number
  page: number
  per_page: number
  total_pages: number
}

export const useCertificateStore = defineStore('certificate', {
    state: () => ({
        certificates: new Map<number, Certificate>(),
        certificatesList: [] as Certificate[], // For search results
        totalCount: 0,
        currentPage: 1,
        totalPages: 0,
        loading: false,
        error: null as string | null,
    }),

    actions: {
        // Fetch certificates and update the state
        async fetchCertificates(): Promise<void> {
            this.loading = true;
            this.error = null;
            try {
                const new_certs = await fetchCertificates();
                for (const cert of new_certs) {
                    if (!this.certificates.has(cert.id)) {
                        this.certificates.set(cert.id, cert);
                    }
                }

                const newIds = new Set<number>(new_certs.map(cert => cert.id));
                for (const existingId of this.certificates.keys()) {
                    if (!newIds.has(existingId)) {
                        this.certificates.delete(existingId);
                    }
                }

            } catch (err) {
                this.error = 'Failed to fetch certificates.';
                console.error(err);
            } finally {
                this.loading = false;
            }
        },

        async fetchCertificatePassword(id: number): Promise<void> {
            try {
                const pkcs12_password = await fetchCertificatePassword(id);
                const current_cert = this.certificates.get(id);
                if (current_cert) {
                    current_cert.pkcs12_password = pkcs12_password;
                }
            } catch (err) {
                this.error = 'Failed to fetch certificates.';
                console.error(err);
            } finally {
                this.loading = false;
            }
        },

        // Trigger the download of a certificate by ID
        async downloadCertificate(id: number): Promise<void> {
            try {
                this.error = null;
                await downloadCertificate(id);
            } catch (err) {
                this.error = 'Failed to download the certificate.';
                console.error(err);
            }
        },

        // Create a new certificate and fetch the updated list
        async createCertificate(certReq: CertificateRequirements): Promise<void> {
            this.loading = true;
            this.error = null;
            try {
                await createCertificate(certReq);
                await this.fetchCertificates();
            } catch (err) {
                this.error = 'Failed to create the certificate.';
                console.error(err);
            } finally {
                this.loading = false;
            }
        },

        // Delete a certificate by ID and fetch the updated list
        async deleteCertificate(id: number): Promise<void> {
            this.loading = true;
            this.error = null;
            try {
                await deleteCertificate(id);
                await this.fetchCertificates();
            } catch (err) {
                this.error = 'Failed to delete the certificate.';
                console.error(err);
            } finally {
                this.loading = false;
            }
        },

        // Modern API: Search certificates with filters and pagination
        async searchCertificates(params: CertificateSearchParams = {}): Promise<void> {
            this.loading = true;
            this.error = null;

            try {
                const response = await apiClient.post<CertificateSearchResponse>('/api/certificates/search', {
                    page: params.page || 1,
                    per_page: params.per_page || 25,
                    filters: {
                        search: params.search || '',
                        certificate_type: params.certificateType || '',
                        client_certificate_type: params.clientCertificateType || '',
                        status: params.status || '',
                        expires_in_days: params.expiresIn ? parseInt(params.expiresIn) : undefined,
                        ca_id: params.caId ? parseInt(params.caId) : undefined,
                        created_after: params.createdAfter || '',
                        algorithm: params.algorithm || ''
                    },
                    sort: params.sort ? [{
                        field: params.sort.split(':')[0],
                        direction: params.sort.split(':')[1] as 'asc' | 'desc'
                    }] : [{ field: 'created_at', direction: 'desc' }]
                });

                this.certificatesList = response.data.certificates;
                this.totalCount = response.data.total;
                this.currentPage = response.data.page;
                this.totalPages = response.data.total_pages;

                // Also update the certificates map for compatibility
                for (const cert of response.data.certificates) {
                    this.certificates.set(cert.id, cert);
                }
            } catch (err: any) {
                this.error = err.response?.data?.detail || 'Failed to search certificates';
                console.error('Error searching certificates:', err);
            } finally {
                this.loading = false;
            }
        },

        // Modern API: Bulk download certificates
        async bulkDownloadCertificates(certificateIds: number[], format: string = 'pem'): Promise<void> {
            this.loading = true;
            this.error = null;

            try {
                const response = await apiClient.post('/api/certificates/bulk-download', {
                    certificate_ids: certificateIds,
                    format,
                    include_chain: true,
                    include_private_key: false,
                    archive_format: 'zip'
                }, {
                    responseType: 'blob'
                });

                // Create download link
                const blob = new Blob([response.data]);
                const url = window.URL.createObjectURL(blob);
                const link = document.createElement('a');
                link.href = url;
                link.download = `certificates-${Date.now()}.zip`;
                document.body.appendChild(link);
                link.click();
                document.body.removeChild(link);
                window.URL.revokeObjectURL(url);
            } catch (err: any) {
                this.error = err.response?.data?.detail || 'Failed to download certificates';
                console.error('Error downloading certificates:', err);
            } finally {
                this.loading = false;
            }
        },

        // Modern API: Revoke certificate
        async revokeCertificate(id: number, reason: string): Promise<void> {
            this.loading = true;
            this.error = null;

            try {
                await apiClient.post(`/api/certificates/${id}/revoke`, { reason });

                // Update local state
                const cert = this.certificates.get(id);
                if (cert) {
                    cert.status = 'revoked';
                }

                const listIndex = this.certificatesList.findIndex(cert => cert.id === id);
                if (listIndex !== -1) {
                    this.certificatesList[listIndex].status = 'revoked';
                }
            } catch (err: any) {
                this.error = err.response?.data?.detail || 'Failed to revoke certificate';
                console.error('Error revoking certificate:', err);
                throw err;
            } finally {
                this.loading = false;
            }
        },

        // Clear error state
        clearError(): void {
            this.error = null;
        },
    },

    getters: {
        // Get certificates as array for compatibility
        certificatesArray: (state) => Array.from(state.certificates.values()),

        // Get active certificates
        activeCertificates: (state) => state.certificatesList.filter(cert => cert.status === 'active'),

        // Get expired certificates
        expiredCertificates: (state) => state.certificatesList.filter(cert => cert.status === 'expired'),

        // Get certificates expiring soon (30 days)
        expiringSoonCertificates: (state) => {
            const thirtyDaysFromNow = Date.now() + (30 * 24 * 60 * 60 * 1000);
            return state.certificatesList.filter(cert => {
                const expiryDate = new Date(cert.valid_until).getTime();
                return cert.status === 'active' && expiryDate <= thirtyDaysFromNow;
            });
        },

        // Get server certificates
        serverCertificates: (state) => state.certificatesList.filter(cert => cert.certificate_type === 'Server'),

        // Get client certificates
        clientCertificates: (state) => state.certificatesList.filter(cert => cert.certificate_type === 'Client'),

        // Get user certificates
        userCertificates: (state) => state.certificatesList.filter(cert =>
            cert.certificate_type === 'Client' && cert.client_certificate_type === 'User'
        ),

        // Get device certificates
        deviceCertificates: (state) => state.certificatesList.filter(cert =>
            cert.certificate_type === 'Client' && cert.client_certificate_type === 'Device'
        ),
    },
});
