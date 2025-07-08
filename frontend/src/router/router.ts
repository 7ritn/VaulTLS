import {createRouter, createWebHistory} from 'vue-router';
import { useAuthStore } from '@/stores/auth';
import { useSetupStore } from '@/stores/setup';

import LoginView from '@/views/LoginView.vue';
import FirstSetupView from '@/views/FirstSetupView.vue';

import MainLayout from '@/layouts/MainLayout.vue';
import OverviewTab from '@/components/OverviewTab.vue';
import SettingsTab from '@/components/SettingsTab.vue';
import UserTab from "@/components/UserTab.vue";

const router = createRouter({
    history: createWebHistory(),
    routes: [
        {
            path: '/login',
            name: 'Login',
            component: LoginView,
        },
        {
            path: '/first-setup',
            name: 'FirstSetup',
            component: FirstSetupView,
        },
        {
            path: '/',
            component: MainLayout,
            // Child routes for the main app
            children: [
                {
                    path: '',
                    redirect: '/overview', // default child route
                },
                {
                    path: 'overview',
                    name: 'Overview',
                    component: OverviewTab,
                },
                {
                    path: 'users',
                    name: 'Users',
                    component: UserTab,
                },
                {
                    path: 'settings',
                    name: 'Settings',
                    component: SettingsTab,
                },
            ],
            // A guard to check if the app is set up and user is authenticated
            beforeEnter: async (to, from, next) => {
                const authStore = useAuthStore();
                const setupStore = useSetupStore();

                try {
                    if (!setupStore.isSetup) {
                        return next({ name: 'FirstSetup' });
                    }
                    let urlParams = new URLSearchParams(window.location.search);
                    if (urlParams.has('oidc', 'success')) {
                        await authStore.finishOIDC();
                    }

                    if (!authStore.isAuthenticated) {
                        console.log('Not authenticated');
                        return next({ name: 'Login' });
                    }

                    next();
                } catch (error) {
                    console.error('Error checking setup or auth:', error);
                    next({ name: 'Login' });
                }
            },
        },
    ],
});

export default router;
