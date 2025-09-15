import { defineStore } from 'pinia';
import type {CA, CARequirements} from '@/types/CA';
import {createCA, downloadCAByID, fetchCAs} from "@/api/cas.ts";

export const useCertificateStore = defineStore('certificate', {
    state: () => ({
        cas: new Map<number, CA>(),
        loading: false,
        error: null as string | null,
    }),

    actions: {
        // Fetch certificates and update the state
        async fetchCAs(): Promise<void> {
            this.loading = true;
            this.error = null;
            try {
                const new_cas = await fetchCAs();
                for (const ca of new_cas) {
                    if (!this.cas.has(ca.id)) {
                        this.cas.set(ca.id, ca);
                    }
                }

                const newIds = new Set<number>(new_cas.map(ca => ca.id));
                for (const existingId of this.cas.keys()) {
                    if (!newIds.has(existingId)) {
                        this.cas.delete(existingId);
                    }
                }

            } catch (err) {
                this.error = 'Failed to fetch CA.';
                console.error(err);
            } finally {
                this.loading = false;
            }
        },

        // Trigger the download of a certificate by ID
        async downloadCA(id: number): Promise<void> {
            try {
                this.error = null;
                await downloadCAByID(id);
            } catch (err) {
                this.error = 'Failed to download the CA.';
                console.error(err);
            }
        },

        // Create a new CA and fetch the updated list
        async createCA(certReq: CARequirements): Promise<void> {
            this.loading = true;
            this.error = null;
            try {
                await createCA(certReq);
                await this.fetchCAs();
            } catch (err) {
                this.error = 'Failed to create the CA.';
                console.error(err);
            } finally {
                this.loading = false;
            }
        },
    },
});
