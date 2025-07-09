import { defineStore } from 'pinia';
import {change_password, current_user, login, logout} from "@/api/auth.ts";
import type {ChangePasswordReq} from "@/types/Login.ts";
import {type User, UserRole} from "@/types/User.ts";

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
        // Trigger the login of a user by email and password
        async login(email: string | undefined, password: string | undefined) {
            try {
                this.error = null;
                await login({email, password});
                this.current_user = (await current_user());
                this.setAuthentication(true);

                return true;
            } catch (err) {
                this.error = 'Failed to login.';
                console.error(err);
                return false;
            }
        },

        // Change the password of the current user
        async changePassword(changePasswordReq: ChangePasswordReq) {
            try {
                this.error = null;
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
