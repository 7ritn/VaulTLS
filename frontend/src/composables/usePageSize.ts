import { ref, watch } from 'vue';
import { useSettingsStore } from '@/stores/settings';

const COOKIE_NAME = 'vaultls_page_size';
export const PAGE_SIZE_OPTIONS = [10, 20, 50, 100];

function getCookie(name: string): string | null {
    const match = document.cookie.match(
        new RegExp('(?:^|; )' + name.replace(/[.*+?^${}()|[\]\\]/g, '\\$&') + '=([^;]*)')
    );
    return match ? decodeURIComponent(match[1]) : null;
}

function setCookie(name: string, value: string, days = 365) {
    const expires = new Date(Date.now() + days * 864e5).toUTCString();
    document.cookie = `${name}=${encodeURIComponent(value)}; expires=${expires}; path=/; SameSite=Strict`;
}

export function usePageSize() {
    const settingsStore = useSettingsStore();

    const cookieVal = getCookie(COOKIE_NAME);
    const initialSize = cookieVal && PAGE_SIZE_OPTIONS.includes(Number(cookieVal))
        ? Number(cookieVal)
        : (settingsStore.settings?.common.default_page_size ?? 20);

    const pageSize = ref<number>(initialSize);

    // If settings load after composable init and no cookie is set, adopt the server default
    watch(() => settingsStore.settings?.common.default_page_size, (newDefault) => {
        if (!getCookie(COOKIE_NAME) && newDefault != null) {
            pageSize.value = newDefault;
        }
    });

    const setPageSize = (size: number) => {
        pageSize.value = size;
        setCookie(COOKIE_NAME, String(size));
    };

    return { pageSize, setPageSize, PAGE_SIZE_OPTIONS };
}
