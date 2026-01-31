import { defineStore } from 'pinia';
import {type Settings} from '@/types/Settings';
import {
    fetchSettings,
    putSettings
} from '@/api/settings';
import axios from 'axios';

export const useSettingsStore = defineStore('settings', {
    state: () => ({
        settings: null as Settings | null,
        error: null as string | null,
    }),
    actions: {
        // Fetch certificates and update the state
        async fetchSettings(): Promise<void> {
            this.error = null;
            try {
                this.settings = await fetchSettings();
            } catch (err) {
                if (axios.isAxiosError(err)) {
                    this.error = 'Failed to fetch the settings: ' + err.response?.data?.error;
                } else {
                    this.error = 'Failed to fetch the settings';
                }
                console.error(err);
            }
        },

        // Trigger the download of a certificate by ID
        async saveSettings(): Promise<boolean> {
            if (this.settings) {
                try {
                    this.error = null;
                    await putSettings(this.settings);
                    return true;
                } catch (err) {
                    if (axios.isAxiosError(err)) {
                        this.error = 'Failed to save the settings: ' + err.response?.data?.error;
                    } else {
                        this.error = 'Failed to save the settings';
                    }
                    console.error(err);
                    return false;
                }
            }
            return false;
        },
    },
});
