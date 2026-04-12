import { defineStore } from 'pinia';
import type { AcmeAccount, AcmeOrder, CreateAcmeAccountRequest, CreateAcmeAccountResponse, UpdateAcmeAccountRequest } from '@/types/Acme';
import { fetchAcmeAccounts, fetchAcmeOrders, createAcmeAccount, updateAcmeAccount, deleteAcmeAccount } from '@/api/acme.ts';
import axios from 'axios';

export const useAcmeStore = defineStore('acme', {
    state: () => ({
        accounts: new Map<number, AcmeAccount>(),
        orders: new Map<number, AcmeOrder>(),
        loading: false,
        error: null as string | null,
    }),

    actions: {
        async fetchOrders(): Promise<void> {
            this.loading = true;
            this.error = null;
            try {
                const newOrders = await fetchAcmeOrders();
                for (const order of newOrders) {
                    this.orders.set(order.id, order);
                }
                const newIds = new Set<number>(newOrders.map(o => o.id));
                for (const existingId of this.orders.keys()) {
                    if (!newIds.has(existingId)) {
                        this.orders.delete(existingId);
                    }
                }
            } catch (err) {
                if (axios.isAxiosError(err)) {
                    this.error = 'Failed to fetch ACME orders: ' + err.response?.data?.error;
                } else {
                    this.error = 'Failed to fetch ACME orders';
                }
                console.error(err);
            } finally {
                this.loading = false;
            }
        },

        async fetchAccounts(): Promise<void> {
            this.loading = true;
            this.error = null;
            try {
                const newAccounts = await fetchAcmeAccounts();
                for (const account of newAccounts) {
                    this.accounts.set(account.id, account);
                }

                const newIds = new Set<number>(newAccounts.map(a => a.id));
                for (const existingId of this.accounts.keys()) {
                    if (!newIds.has(existingId)) {
                        this.accounts.delete(existingId);
                    }
                }
            } catch (err) {
                if (axios.isAxiosError(err)) {
                    this.error = 'Failed to fetch ACME accounts: ' + err.response?.data?.error;
                } else {
                    this.error = 'Failed to fetch ACME accounts';
                }
                console.error(err);
            } finally {
                this.loading = false;
            }
        },

        async createAccount(req: CreateAcmeAccountRequest): Promise<CreateAcmeAccountResponse | null> {
            this.loading = true;
            this.error = null;
            try {
                const response = await createAcmeAccount(req);
                await this.fetchAccounts();
                return response;
            } catch (err) {
                if (axios.isAxiosError(err)) {
                    this.error = 'Failed to create ACME account: ' + err.response?.data?.error;
                } else {
                    this.error = 'Failed to create ACME account';
                }
                console.error(err);
                return null;
            } finally {
                this.loading = false;
            }
        },

        async updateAccount(id: number, req: UpdateAcmeAccountRequest): Promise<void> {
            this.loading = true;
            this.error = null;
            try {
                const updated = await updateAcmeAccount(id, req);
                this.accounts.set(updated.id, updated);
            } catch (err) {
                if (axios.isAxiosError(err)) {
                    this.error = 'Failed to update ACME account: ' + err.response?.data?.error;
                } else {
                    this.error = 'Failed to update ACME account';
                }
                console.error(err);
            } finally {
                this.loading = false;
            }
        },

        async deleteAccount(id: number): Promise<void> {
            this.loading = true;
            this.error = null;
            try {
                await deleteAcmeAccount(id);
                this.accounts.delete(id);
            } catch (err) {
                if (axios.isAxiosError(err)) {
                    this.error = 'Failed to delete ACME account: ' + err.response?.data?.error;
                } else {
                    this.error = 'Failed to delete ACME account';
                }
                console.error(err);
            } finally {
                this.loading = false;
            }
        },
    },
});
