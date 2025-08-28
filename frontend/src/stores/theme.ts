import { defineStore } from 'pinia'
import { ref, computed, watch } from 'vue'

export type ThemeMode = 'light' | 'dark' | 'system'

export interface ThemeConfig {
  mode: ThemeMode
  systemPreference: 'light' | 'dark'
  effectiveTheme: 'light' | 'dark'
}

export const useThemeStore = defineStore('theme', () => {
  // State
  const mode = ref<ThemeMode>('system')
  const systemPreference = ref<'light' | 'dark'>('light')

  // Computed
  const effectiveTheme = computed(() => {
    if (mode.value === 'system') {
      return systemPreference.value
    }
    return mode.value as 'light' | 'dark'
  })

  const isDark = computed(() => effectiveTheme.value === 'dark')
  const isLight = computed(() => effectiveTheme.value === 'light')

  // Actions
  const setMode = (newMode: ThemeMode) => {
    mode.value = newMode
    localStorage.setItem('vaultls-theme-mode', newMode)
    applyTheme()
  }

  const setSystemPreference = (preference: 'light' | 'dark') => {
    systemPreference.value = preference
    if (mode.value === 'system') {
      applyTheme()
    }
  }

  const applyTheme = () => {
    const root = document.documentElement
    const theme = effectiveTheme.value

    // Remove existing theme classes
    root.classList.remove('light', 'dark')
    
    // Add current theme class
    root.classList.add(theme)
    
    // Update meta theme-color for mobile browsers
    const metaThemeColor = document.querySelector('meta[name="theme-color"]')
    if (metaThemeColor) {
      const color = theme === 'dark' ? '#1f2937' : '#3b82f6'
      metaThemeColor.setAttribute('content', color)
    }

    // Dispatch custom event for components that need to react to theme changes
    window.dispatchEvent(new CustomEvent('theme-changed', { 
      detail: { theme, mode: mode.value } 
    }))
  }

  const toggleTheme = () => {
    if (mode.value === 'light') {
      setMode('dark')
    } else if (mode.value === 'dark') {
      setMode('system')
    } else {
      setMode('light')
    }
  }

  const initializeTheme = () => {
    // Load saved theme mode
    const savedMode = localStorage.getItem('vaultls-theme-mode') as ThemeMode
    if (savedMode && ['light', 'dark', 'system'].includes(savedMode)) {
      mode.value = savedMode
    }

    // Detect system preference
    const mediaQuery = window.matchMedia('(prefers-color-scheme: dark)')
    systemPreference.value = mediaQuery.matches ? 'dark' : 'light'

    // Listen for system preference changes
    mediaQuery.addEventListener('change', (e) => {
      setSystemPreference(e.matches ? 'dark' : 'light')
    })

    // Apply initial theme
    applyTheme()
  }

  // Watch for mode changes to apply theme
  watch(mode, applyTheme)
  watch(systemPreference, () => {
    if (mode.value === 'system') {
      applyTheme()
    }
  })

  return {
    // State
    mode,
    systemPreference,
    
    // Computed
    effectiveTheme,
    isDark,
    isLight,
    
    // Actions
    setMode,
    setSystemPreference,
    applyTheme,
    toggleTheme,
    initializeTheme,
  }
})
