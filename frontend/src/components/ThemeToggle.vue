<template>
  <div class="theme-toggle">
    <button
      @click="toggleTheme"
      class="theme-toggle-button"
      :title="getButtonTitle()"
      :aria-label="getButtonTitle()"
    >
      <component :is="getCurrentIcon()" class="theme-icon" />
      <span class="theme-label">{{ getCurrentLabel() }}</span>
    </button>
    
    <!-- Dropdown for detailed theme selection -->
    <div v-if="showDropdown" class="theme-dropdown" @click.stop>
      <div class="theme-option" @click="setTheme('light')">
        <SunIcon class="theme-option-icon" />
        <span>Light</span>
        <CheckIcon v-if="themeStore.mode === 'light'" class="check-icon" />
      </div>
      <div class="theme-option" @click="setTheme('dark')">
        <MoonIcon class="theme-option-icon" />
        <span>Dark</span>
        <CheckIcon v-if="themeStore.mode === 'dark'" class="check-icon" />
      </div>
      <div class="theme-option" @click="setTheme('system')">
        <MonitorIcon class="theme-option-icon" />
        <span>System</span>
        <CheckIcon v-if="themeStore.mode === 'system'" class="check-icon" />
      </div>
    </div>
  </div>
</template>

<script setup lang="ts">
import { ref, computed, onMounted, onUnmounted } from 'vue'
import { useThemeStore } from '@/stores/theme'
import SunIcon from '@/components/icons/SunIcon.vue'
import MoonIcon from '@/components/icons/MoonIcon.vue'
import MonitorIcon from '@/components/icons/MonitorIcon.vue'
import CheckIcon from '@/components/icons/CheckIcon.vue'

interface Props {
  showLabel?: boolean
  showDropdown?: boolean
  size?: 'sm' | 'md' | 'lg'
}

const props = withDefaults(defineProps<Props>(), {
  showLabel: true,
  showDropdown: false,
  size: 'md'
})

const themeStore = useThemeStore()
const showDropdown = ref(false)

const getCurrentIcon = () => {
  switch (themeStore.mode) {
    case 'light':
      return SunIcon
    case 'dark':
      return MoonIcon
    case 'system':
      return MonitorIcon
    default:
      return SunIcon
  }
}

const getCurrentLabel = () => {
  if (!props.showLabel) return ''
  
  switch (themeStore.mode) {
    case 'light':
      return 'Light'
    case 'dark':
      return 'Dark'
    case 'system':
      return 'System'
    default:
      return 'Theme'
  }
}

const getButtonTitle = () => {
  const current = getCurrentLabel()
  const next = getNextTheme()
  return `Current: ${current}. Click to switch to ${next}.`
}

const getNextTheme = () => {
  switch (themeStore.mode) {
    case 'light':
      return 'Dark'
    case 'dark':
      return 'System'
    case 'system':
      return 'Light'
    default:
      return 'Light'
  }
}

const toggleTheme = () => {
  if (props.showDropdown) {
    showDropdown.value = !showDropdown.value
  } else {
    themeStore.toggleTheme()
  }
}

const setTheme = (mode: 'light' | 'dark' | 'system') => {
  themeStore.setMode(mode)
  showDropdown.value = false
}

const handleClickOutside = (event: Event) => {
  const target = event.target as Element
  if (!target.closest('.theme-toggle')) {
    showDropdown.value = false
  }
}

onMounted(() => {
  if (props.showDropdown) {
    document.addEventListener('click', handleClickOutside)
  }
})

onUnmounted(() => {
  if (props.showDropdown) {
    document.removeEventListener('click', handleClickOutside)
  }
})
</script>

<style scoped>
.theme-toggle {
  position: relative;
  display: inline-block;
}

.theme-toggle-button {
  display: flex;
  align-items: center;
  gap: var(--spacing-sm);
  padding: var(--spacing-sm) var(--spacing-md);
  background: var(--color-surface);
  border: 1px solid var(--color-border);
  border-radius: var(--radius-md);
  color: var(--color-text-primary);
  cursor: pointer;
  transition: all var(--transition-fast);
  font-size: 0.875rem;
  font-weight: 500;
}

.theme-toggle-button:hover {
  background: var(--color-hover);
  border-color: var(--color-border-secondary);
}

.theme-toggle-button:focus {
  outline: none;
  border-color: var(--color-border-focus);
  box-shadow: 0 0 0 3px var(--color-focus);
}

.theme-icon {
  width: 1.25rem;
  height: 1.25rem;
  transition: transform var(--transition-fast);
}

.theme-toggle-button:hover .theme-icon {
  transform: scale(1.1);
}

.theme-label {
  font-weight: 500;
  user-select: none;
}

.theme-dropdown {
  position: absolute;
  top: 100%;
  right: 0;
  margin-top: var(--spacing-xs);
  background: var(--color-card);
  border: 1px solid var(--color-border);
  border-radius: var(--radius-md);
  box-shadow: var(--shadow-lg);
  z-index: 1000;
  min-width: 140px;
  overflow: hidden;
}

.theme-option {
  display: flex;
  align-items: center;
  gap: var(--spacing-sm);
  padding: var(--spacing-sm) var(--spacing-md);
  cursor: pointer;
  transition: background-color var(--transition-fast);
  font-size: 0.875rem;
}

.theme-option:hover {
  background: var(--color-hover);
}

.theme-option-icon {
  width: 1rem;
  height: 1rem;
  color: var(--color-text-secondary);
}

.check-icon {
  width: 1rem;
  height: 1rem;
  color: var(--brand-primary);
  margin-left: auto;
}

/* Size variants */
.theme-toggle-button.size-sm {
  padding: var(--spacing-xs) var(--spacing-sm);
  font-size: 0.75rem;
}

.theme-toggle-button.size-sm .theme-icon {
  width: 1rem;
  height: 1rem;
}

.theme-toggle-button.size-lg {
  padding: var(--spacing-md) var(--spacing-lg);
  font-size: 1rem;
}

.theme-toggle-button.size-lg .theme-icon {
  width: 1.5rem;
  height: 1.5rem;
}

/* Animation for theme transitions */
@media (prefers-reduced-motion: no-preference) {
  .theme-icon {
    animation: theme-change 0.3s ease-in-out;
  }
}

@keyframes theme-change {
  0% { transform: rotate(0deg) scale(1); }
  50% { transform: rotate(180deg) scale(1.1); }
  100% { transform: rotate(360deg) scale(1); }
}
</style>
