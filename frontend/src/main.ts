import 'bootstrap/dist/css/bootstrap.min.css';
import './assets/styles/variables.css'
import './assets/styles/theme.css'

import { createApp } from 'vue'
import { createPinia } from 'pinia'
import router from './router/router';

import App from './App.vue'
import {useSetupStore} from "@/stores/setup.ts";
import {useAuthStore} from "@/stores/auth.ts";
import {useThemeStore} from "@/stores/theme.ts";


async function initApp() {
    const pinia = createPinia();
    const app = createApp(App);

    // Initialize Pinia before mounting
    app.use(pinia);

    // Initialize the store
    const setupStore = useSetupStore();
    await setupStore.init()

    const authStore = useAuthStore();
    await authStore.init();

    // Initialize theme store
    const themeStore = useThemeStore();
    themeStore.initializeTheme();

    app.use(router);

    app.mount('#app');
}

initApp().catch((err) => {
    console.error('Failed to initialize app:', err);
});
