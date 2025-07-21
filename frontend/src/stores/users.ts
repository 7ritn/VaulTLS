import { defineStore } from 'pinia';
import type {CreateUserRequest, User} from "@/types/User.ts";
import {createUser, deleteUser, fetchUsers, updateUser} from "@/api/users.ts";
import {hashPassword} from "@/utils/hash.ts";

export const useUserStore = defineStore('user', {
    state: () => ({
        users: [] as User[],
        loading: false,
        error: null as string | null,
    }),

    actions: {
        // Fetch certificates and update the state
        async fetchUsers(force: boolean = false): Promise<void> {
            if (this.users.length == 0 || force) {
                this.loading = true;
                this.error = null;
                try {
                    this.users = await fetchUsers();
                } catch (err) {
                    this.error = 'Failed to fetch users.';
                    console.error(err);
                } finally {
                    this.loading = false;
                }
            }
        },

        // Create a new certificate and fetch the updated list
        async createUser(createUserReq: CreateUserRequest): Promise<void> {
            this.loading = true;
            this.error = null;
            try {
                if (createUserReq.password) {
                    createUserReq.password = await hashPassword(createUserReq.password);
                }
                await createUser(createUserReq);
                this.users = await fetchUsers();
            } catch (err) {
                this.error = 'Failed to create user.';
                console.error(err);
            } finally {
                this.loading = false;
            }
        },

        // Update user details
        async updateUser(user: User): Promise<boolean> {
            this.loading = true;
            this.error = null;
            try {
                await updateUser(user);
                this.loading = false;
                return true;
            } catch (err) {
                this.loading = false;
                this.error = 'Failed to create user.';
                return false;
            }
        },

        // Delete a certificate by ID and fetch the updated list
        async deleteUser(id: number): Promise<void> {
            this.loading = true;
            this.error = null;
            try {
                await deleteUser(id); // This handles API deletion and fetch internally
                this.users = await fetchUsers(); // Refresh the local state
            } catch (err) {
                this.error = 'Failed to delete the certificate.';
                console.error(err);
            } finally {
                this.loading = false;
            }
        },

        // Convert a user ID to a user name
        idToName(id: number): string {
            for (const user of this.users) {
                if (user.id == id) {
                    return user.name;
                }
            }
            return "Unknown User #" + id;
        }
    },
});
