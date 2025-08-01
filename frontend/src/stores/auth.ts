import { defineStore } from 'pinia';
import {change_password, current_user, login, logout} from "@/api/auth.ts";
import type {ChangePasswordReq} from "@/types/Login.ts";
import {type User, UserRole} from "@/types/User.ts";
import {argon2Verify} from 'hash-wasm';
import {hashPassword} from "@/utils/hash.ts";

export const useAuthStore = defineStore('auth', {
    state: () => ({
        isAuthenticated: false as boolean,
        current_user: null as User | null,
        error: null as string | null,
    }),
    getters: {
        isAdmin(state): boolean {
            return state.current_user?.role === UserRole.Admin;
        }
    },
    actions: {
        async init() {
            this.isAuthenticated = localStorage.getItem('is_authenticated') === 'true';
            if (this.isAuthenticated) {
                await this.fetchCurrentUser();
            }
        },

        // Trigger the login of a user by email and password
        async login(email: string, password: string) {
            this.error = null;

            try {
                // Hash password with argon2id using hash-wasm
                const hash = await hashPassword(password);

                await login({ email, password: hash }).catch(async err => {
                    if (err.response.status === 409) {
                        // Need to log in with plaintext password
                        const server_hash = err.response.data.error;

                        const split = server_hash.split('$');
                        const server_salt = split[4];
                        if (server_salt === "VmF1bFRMU1ZhdWxUTFNWYXVsVExTVmF1bFRMUw") {
                            // Replay attack
                            console.log('Server hash is same.');
                            return false;
                        }

                        // Verify password against server hash
                        const isValid = await argon2Verify({
                            password,
                            hash: server_hash,
                        });

                        if (isValid) {
                            // Password matches server's old hash
                            await login({ email, password }).catch(err => {
                                this.error = 'Failed to login.';
                                console.error(err);
                                return false;
                            });
                            return true;
                        } else {
                            console.log('Invalid password.');
                        }
                    }
                });

                this.current_user = await current_user();
                this.setAuthentication(true);
                return true;
            } catch (err) {
                this.error = 'Failed to login.';
                console.error(err);
                return false;
            }
        },

        // Change the password of the current user
        async changePassword(oldPassword: string, newPassword: string) {
            try {
                this.error = null;
                const oldHash = await hashPassword(oldPassword);
                const newHash = await hashPassword(newPassword);
                const changePasswordReq: ChangePasswordReq = {
                    old_password: oldHash,
                    new_password: newHash,
                };
                await change_password(changePasswordReq);
                return true;
            } catch (err) {
                this.error = 'Failed to change password.';
                console.error(err);
                return false;
            }
        },

        // Fetch current user and update the state
        async fetchCurrentUser() {
            try {
                this.error = null;
                this.current_user = (await current_user());
                this.setAuthentication(true);
            } catch (err) {
                this.error = 'Failed to fetch current user.';
                console.error(err);
                await this.logout();
            }
        },

        // Trigger the login of a user by OIDC
        async finishOIDC() {
            await this.fetchCurrentUser()
            this.setAuthentication(true);
        },

        // Set the authentication state and store it in local storage
        setAuthentication(isAuthenticated: boolean) {
            if (isAuthenticated) {
                this.isAuthenticated = true;
                localStorage.setItem('is_authenticated', String(true));
            } else {
                this.isAuthenticated = false;
                localStorage.removeItem('is_authenticated');
            }
        },

        // Log out the user and clear the authentication state
        async logout() {
            try {
                this.error = null;
                await logout()
                this.setAuthentication(false);
            } catch (err) {
                // Can't fail
                this.error = 'Failed to logout.';
                console.error(err);
            }
        },
    },
});
