import { createI18n } from 'vue-i18n';
import en from '@/locales/en.json';
import es from '@/locales/es.json';
import fr from '@/locales/fr.json';

export const SUPPORTED_LOCALES: Record<string, string> = {
  en: 'English',
  es: 'Español',
  fr: 'French',
};

export function resolveBrowserLocale(): string | null {
  const langs = navigator.languages?.length ? navigator.languages : [navigator.language];
  for (const l of langs) {
    const code = l.split('-')[0];
    if (code in SUPPORTED_LOCALES) return code;
  }
  return null;
}

function resolveLocale(): string {
  const saved = localStorage.getItem('locale');
  if (saved && saved in SUPPORTED_LOCALES) return saved;
  return resolveBrowserLocale() ?? 'en';
}

export const i18n = createI18n({
  legacy: false,
  locale: resolveLocale(),
  fallbackLocale: 'en',
  messages: { en, es, fr },
});
