import { defineStore } from 'pinia';
import { ref, watch } from 'vue';

export type Theme = 'light' | 'dark' | 'auto';

export const useThemeStore = defineStore('theme', () => {
    const theme = ref<Theme>((localStorage.getItem('theme') as Theme) || 'auto');

    const setTheme = (newTheme: Theme) => {
        theme.value = newTheme;
        localStorage.setItem('theme', newTheme);
    };

    const applyTheme = () => {
        let actualTheme: 'light' | 'dark' = 'light';
        if (theme.value === 'auto') {
            actualTheme = window.matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light';
        } else {
            actualTheme = theme.value;
        }
        document.documentElement.setAttribute('data-bs-theme', actualTheme);
    };

    // Watch for theme changes and apply
    watch(theme, () => {
        applyTheme();
    }, { immediate: true });

    // Watch for system preference changes if 'auto' is selected
    window.matchMedia('(prefers-color-scheme: dark)').addEventListener('change', () => {
        if (theme.value === 'auto') {
            applyTheme();
        }
    });

    return {
        theme,
        setTheme,
        applyTheme,
    };
});
