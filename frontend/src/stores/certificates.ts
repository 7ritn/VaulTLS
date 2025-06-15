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

export const useCertificateStore = defineStore('certificate', {
    state: () => ({
        certificates: [] as Certificate[],
        loading: false,
        error: null as string | null,
    }),

    actions: {
        // Fetch certificates and update the state
        async fetchCertificates(): Promise<void> {
            this.loading = true;
            this.error = null;
            try {
                this.certificates = await fetchCertificates();
                for (const cert of this.certificates) {
                    cert.password_shown = false
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
                const certificate = await fetchCertificatePassword(id);
                for (const cert of this.certificates) {
                    if (cert.id == id) {
                        cert.pkcs12_password = certificate.pkcs12_password
                        return
                    }
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
                const { filename, blob } = await downloadCertificate(id);
                const url = URL.createObjectURL(blob);
                const link = document.createElement('a');
                link.href = url;
                link.download = filename;
                document.body.appendChild(link);
                link.click();
                link.remove();
                URL.revokeObjectURL(url);
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
                this.certificates = await fetchCertificates();
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
                this.certificates = await fetchCertificates();
            } catch (err) {
                this.error = 'Failed to delete the certificate.';
                console.error(err);
            } finally {
                this.loading = false;
            }
        },
    },
});
