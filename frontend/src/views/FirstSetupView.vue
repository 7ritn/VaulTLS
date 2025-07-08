<template>
  <div class="container d-flex justify-content-center align-items-center vh-100">
    <div class="card p-4 shadow" style="max-width: 400px; width: 100%;">
      <h1 class="text-center mb-4">Hello</h1>

      <!-- Show notice if OIDC is enabled -->
      <div v-if="setupStore.oidcUrl" class="alert alert-info text-center">
        OAuth (OIDC) is configured. You can still set a password for local login if desired.
      </div>

      <form @submit.prevent="setupPassword">
        <div class="mb-3">
          <label for="username" class="form-label">Username</label>
          <input
              id="username"
              type="text"
              v-model="username"
              class="form-control"
              required
          />
        </div>

        <div class="mb-3">
          <label for="email" class="form-label">E-Mail</label>
          <input
              id="email"
              type="text"
              v-model="email"
              class="form-control"
              required
          />
        </div>

        <div class="mb-3">
          <label for="ca_name" class="form-label">Name of CA entity</label>
          <input
              id="ca_name"
              type="text"
              v-model="ca_name"
              class="form-control"
              required
          />
        </div>

        <div class="mb-3">
          <label for="ca_validity_in_years" class="form-label">Validity of CA in years</label>
          <input
              id="ca_validity_in_years"
              type="number"
              v-model="ca_validity_in_years"
              class="form-control"
              required
          />
        </div>

        <!-- Password field is always available, but not required if OIDC is enabled -->
        <div class="mb-3">
          <label for="password" class="form-label">Password</label>
          <input
              id="password"
              type="password"
              v-model="password"
              class="form-control"
              autocomplete="new-password"
              :required="!setupStore.oidcUrl"
          />
          <small class="text-muted">
            {{ setupStore.oidcUrl ? "You can leave this empty if using OAuth (OIDC)." : "Required for local login." }}
          </small>
        </div>

        <button type="submit" class="btn btn-primary w-100">
          Complete Setup
        </button>

        <p v-if="errorMessage" class="text-danger mt-3">
          {{ errorMessage }}
        </p>
      </form>
    </div>
  </div>
</template>

<script setup lang="ts">
import { ref } from 'vue';
import router from '../router/router';
import { setup } from "@/api/auth.ts";
import {useSetupStore} from "@/stores/setup.ts";

const setupStore = useSetupStore();

const username = ref('');
const email = ref('');
const ca_name = ref('');
const ca_validity_in_years = ref(10);
const password = ref('');
const errorMessage = ref('');

const setupPassword = async () => {
  try {
    await setup({
      name: username.value,
      email: email.value,
      ca_name: ca_name.value,
      ca_validity_in_years: ca_validity_in_years.value,
      password: password.value || null,
    });
    await setupStore.reload();
    await router.replace({ name: 'Login' });
  } catch (err) {
    errorMessage.value = 'Failed to set up.';
  }
};
</script>
