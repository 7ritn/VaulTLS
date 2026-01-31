import { defineStore } from 'pinia';
import type { Certificate } from '@/types/Certificate';
import {
    fetchCertificates,
    fetchCertificatePassword,
    downloadCertificate,
    createCertificate,
    deleteCertificate,
} from '../api/certificates';
import type {CertificateRequirements} from "@/types/CertificateRequirements.ts";
import axios from 'axios';

export const useCertificateStore = defineStore('certificate', {
    state: () => ({
        certificates: new Map<number, Certificate>(),
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
                if (axios.isAxiosError(err)) {
                    this.error = 'Failed to fetch certificates: ' + err.response?.data?.error;
                } else {
                    this.error = 'Failed to fetch certificates';
                }
                console.error(err);
            } finally {
                this.loading = false;
            }
        },

        async fetchCertificatePassword(id: number): Promise<void> {
            try {
                const cert_password = await fetchCertificatePassword(id);
                const current_cert = this.certificates.get(id);
                if (current_cert) {
                    current_cert.password = cert_password;
                }
            } catch (err) {
                if (axios.isAxiosError(err)) {
                    this.error = 'Failed to fetch the certificate password: ' + err.response?.data?.error;
                } else {
                    this.error = 'Failed to fetch the certificate password';
                }
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
                if (axios.isAxiosError(err)) {
                    this.error = 'Failed to download the certificate: ' + err.response?.data?.error;
                } else {
                    this.error = 'Failed to download the certificate';
                }
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
                if (axios.isAxiosError(err)) {
                    this.error = 'Failed to create the certificate: ' + err.response?.data?.error;
                } else {
                    this.error = 'Failed to create the certificate';
                }
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
                if (axios.isAxiosError(err)) {
                    this.error = 'Failed to delete the certificate: ' + err.response?.data?.error;
                } else {
                    this.error = 'Failed to delete the certificate';
                }
                console.error(err);
            } finally {
                this.loading = false;
            }
        },
    },
});
