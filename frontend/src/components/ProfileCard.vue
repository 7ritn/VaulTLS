<template>
  <div class="card text-center shadow-sm">
    <div class="card-body">
      <Avatar
          :size="100"
          :name="authStore.current_user?.name || 'User'"
          variant="bauhaus"
          :colors=avatarColors
          class="rounded-circle img-thumbnail mb-3"
      />
      <h5 class="card-title">{{ authStore.current_user?.name }}</h5>
      <p class="card-text text-muted email">{{ formatEmail(authStore.current_user?.email) }}</p>
    </div>
  </div>
</template>

<script setup lang="ts">
import { useAuthStore } from "@/stores/auth.ts";
import Avatar from 'vue-boring-avatars';

const formatEmail = (email?: string) => {
  return email?.replace('@', '\u200B@');
};

const avatarColors = [
  '#264653', // Dark blue
  '#2a9d8f', // Teal
  '#e9c46a', // Yellow
  '#f4a261', // Orange
  '#e76f51'  // Coral
];

const authStore = useAuthStore();
</script>

<style scoped>
.card {
  max-width: 300px;
  margin: 3%;
  background-color: var(--color-card);
  border: none;
  border-radius: 12px;
  padding: 1.5rem;
  box-shadow: 0 2px 8px var(--shadow-color);
}
</style>
