import {defineStore} from "pinia";
import {is_setup} from "@/api/auth.ts";
import {fetchVersion} from "@/api/settings.ts";
import { i18n, SUPPORTED_LOCALES, resolveBrowserLocale } from '@/plugins/i18n';

function applyDefaultLanguage(lang: string) {
    if (!localStorage.getItem('locale') && !resolveBrowserLocale() && lang in SUPPORTED_LOCALES) {
        (i18n.global.locale as { value: string }).value = lang;
        localStorage.setItem('locale', lang);
    }
}

export const useSetupStore = defineStore('setup',  {
    state: () => ({
        isSetup: false as boolean,
        oidcUrl: null as string | null,
        passwordAuthEnabled: false as boolean,
        version: null as string | null,
        isInitialized: false as boolean
    }),
    actions: {
        async init() {
            if (!this.isInitialized) {
                const [isSetupResponse, versionResponse] = await Promise.all([
                    is_setup(),
                    fetchVersion()
                ]);

                this.isSetup = isSetupResponse.setup;
                this.oidcUrl = isSetupResponse.oidc;
                this.passwordAuthEnabled = isSetupResponse.password;
                this.version = versionResponse;
                this.isInitialized = true;
                applyDefaultLanguage(isSetupResponse.default_language);
            }
        },

        async reload() {
            const isSetupResponse = await is_setup();
            this.isSetup = isSetupResponse.setup;
            this.oidcUrl = isSetupResponse.oidc;
            this.passwordAuthEnabled = isSetupResponse.password;
            applyDefaultLanguage(isSetupResponse.default_language);
        }
    },
});