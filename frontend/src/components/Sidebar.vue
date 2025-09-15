<template>
  <div>
    <!-- Always visible toggle button when sidebar is hidden -->
    <button
        v-if="!visible"
        class="sidebar-toggle btn btn-primary d-lg-none"
        @click="toggleSidebar"
        :style="{ left: '10px' }"
    >
      <i class="bi bi-list"></i>
    </button>

    <!-- Sidebar Backdrop (Mobile Only) -->
    <div
        class="sidebar-backdrop"
        :class="{ 'd-block': visible && isMobile }"
        @click="toggleSidebar"
    ></div>

    <!-- Sidebar Content -->
    <div
        class="sidebar shadow-lg rounded-end d-flex flex-column"
        :class="{ 'sidebar-visible': visible, 'sidebar-hidden': !visible }"
    >
      <ProfileCard />

      <div class="flex-grow-1 overflow-auto mt-4">
        <ul class="nav flex-column flex-grow-1">
          <li class="nav-item mb-2">
            <a
                href="#"
                class="nav-link d-flex align-items-center gap-2"
                :class="{ active: activeRouteName === 'Overview' }"
                @click.prevent="goToRoute('Overview')"
            >
              Overview
            </a>
          </li>
          <li class="nav-item mb-2">
            <a
                href="#"
                class="nav-link d-flex align-items-center gap-2"
                :class="{ active: activeRouteName === 'CA' }"
                @click.prevent="goToRoute('CA')"
            >
              Certificate Authorities
            </a>
          </li>
          <li v-if="isAdmin" class="nav-item mb-2">
            <a
                href="#"
                class="nav-link d-flex align-items-center gap-2"
                :class="{ active: activeRouteName === 'Users' }"
                @click.prevent="goToRoute('Users')"
            >
              Users
            </a>
          </li>
          <li class="nav-item">
            <a
                href="#"
                class="nav-link d-flex align-items-center gap-2"
                :class="{ active: activeRouteName === 'Settings' }"
                @click.prevent="goToRoute('Settings')"
            >
              Settings
            </a>
          </li>
        </ul>
      </div>
      <div class="p-3">
        <a
            href="#"
            class="nav-link d-flex align-items-center gap-2"
            @click="handleLogout"
        >
          Logout
        </a>
      </div>
      <div class="text-center text-muted small p-2">
        {{ "Version: " + setupStore.version }}
      </div>
    </div>
  </div>
</template>

<script setup lang="ts">
import { computed, ref, onMounted } from 'vue';
import { useRoute, useRouter } from 'vue-router';
import ProfileCard from './ProfileCard.vue';
import { UserRole } from "@/types/User.ts";
import { useAuthStore } from "@/stores/auth.ts";
import {useSettingsStore} from "@/stores/settings.ts";
import {useSetupStore} from "@/stores/setup.ts";
defineProps({
  currentTab: String,
  visible: Boolean
});
const emit = defineEmits(['change-tab', 'toggle-sidebar']);

const route = useRoute();
const router = useRouter();
const authStore = useAuthStore();
const setupStore = useSetupStore();
const isMobile = ref(false);

const activeRouteName = computed(() => route.name);
const isAdmin = computed(() => authStore.current_user?.role === UserRole.Admin);

const goToRoute = (name: string) => {
  emit('change-tab', name);
  router.push({ name });
};

const handleLogout = async () => {
  await authStore.logout();
  goToRoute('Login');
};

const toggleSidebar = () => {
  emit('toggle-sidebar');
};

const checkIfMobile = () => {
  isMobile.value = window.innerWidth < 992;
};

onMounted(async () => {
  checkIfMobile();
  window.addEventListener('resize', checkIfMobile);
});
</script>

<style scoped>
.sidebar {
  position: fixed;
  top: 0;
  left: 0;
  bottom: 0;
  width: 250px;
  height: 100vh;
  overflow-y: auto;
  z-index: 1000;
  background-color: var(--color-background);
  transition: transform 0.3s ease;
}

.sidebar-toggle {
  position: fixed;
  bottom: 10px;
  width: 40px;
  height: 40px;
  border-radius: 50%;
  display: flex;
  align-items: center;
  justify-content: center;
  z-index: 1001;
}

.sidebar-visible {
  transform: translateX(0);
}

.sidebar-hidden {
  transform: translateX(-100%);
}

.sidebar-backdrop {
  display: none;
  position: fixed;
  top: 0;
  left: 0;
  width: 100%;
  height: 100%;
  background-color: rgba(0, 0, 0, 0.5);
  z-index: 999;
}

@media (min-width: 992px) {
  .sidebar {
    transform: translateX(0) !important;
  }
  .sidebar-toggle {
    display: none !important;
  }
}

.nav-link {
  color: #000;
  text-decoration: none;
}

.nav-link:hover {
  background-color: var(--color-hover);
}

.nav-link.active {
  font-weight: bold;
  background-color: var(--color-active);
  border-radius: 4px;
}

button.nav-link {
  background: none;
  cursor: pointer;
}
</style>