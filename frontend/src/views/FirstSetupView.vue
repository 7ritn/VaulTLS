<template>
  <div class="container d-flex justify-content-center align-items-center vh-100">
    <div class="card p-4 shadow" style="max-width: 400px; width: 100%;">
      <div class="d-flex justify-content-end mb-2">
        <select
            class="form-select form-select-sm"
            style="max-width: 120px"
            :value="locale"
            @change="changeLocale(($event.target as HTMLSelectElement).value)"
        >
          <option v-for="(label, code) in SUPPORTED_LOCALES" :key="code" :value="code">
            {{ label }}
          </option>
        </select>
      </div>

      <h1 class="text-center mb-4">{{ $t('setup.hello') }}</h1>

      <!-- Show notice if OIDC is enabled -->
      <div v-if="setupStore.oidcUrl" class="alert alert-info text-center">
        {{ $t('setup.oidcNotice') }}
      </div>

      <form @submit.prevent="setupPassword">
        <div class="mb-3">
          <label for="username" class="form-label">{{ $t('common.username') }}</label>
          <input
              id="username"
              type="text"
              v-model="username"
              class="form-control"
              required
          />
        </div>

        <div class="mb-3">
          <label for="email" class="form-label">{{ $t('common.email') }}</label>
          <input
              id="email"
              type="text"
              v-model="email"
              class="form-control"
              required
          />
        </div>

        <div class="mb-3">
          <label for="ca_name" class="form-label">{{ $t('setup.caName') }}</label>
          <input
              id="ca_name"
              type="text"
              v-model="ca_name"
              class="form-control"
              required
          />
        </div>

        <div class="mb-3">
          <label for="ca_validity_duration" class="form-label">{{ $t('setup.caValidity') }}</label>
          <div class="input-group">
            <input
                id="ca_validity_duration"
                type="number"
                v-model="ca_validity_duration"
                class="form-control"
                required
            />
            <select
                id="ca_validity_unit"
                v-model="ca_validity_unit"
                class="form-select"
                style="max-width: 120px"
                required
            >
              <option :value="ValidityUnit.Hour">{{ $t('common.hours') }}</option>
              <option :value="ValidityUnit.Day">{{ $t('common.days') }}</option>
              <option :value="ValidityUnit.Month">{{ $t('common.months') }}</option>
              <option :value="ValidityUnit.Year">{{ $t('common.years') }}</option>
            </select>
          </div>
        </div>

        <!-- Password field is always available, but not required if OIDC is enabled -->
        <div class="mb-3">
          <label for="password" class="form-label">{{ $t('common.password') }}</label>
          <input
              id="password"
              type="password"
              v-model="password"
              class="form-control"
              autocomplete="new-password"
              :required="!setupStore.oidcUrl"
          />
          <small class="text-muted">
            {{ setupStore.oidcUrl ? $t('setup.passwordHintOidc') : $t('setup.passwordHintRequired') }}
          </small>
        </div>

        <button type="submit" class="btn btn-primary w-100">
          {{ $t('setup.completeSetup') }}
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
import { useI18n } from 'vue-i18n';
import { SUPPORTED_LOCALES } from '@/plugins/i18n';
import router from '../router/router';
import { setup } from "@/api/auth.ts";
import {useSetupStore} from "@/stores/setup.ts";
import {hashPassword} from "@/utils/hash.ts";
import {ValidityUnit} from "@/types/ValidityUnit.ts";

const { t, locale } = useI18n();

const changeLocale = (lang: string) => {
  locale.value = lang;
  localStorage.setItem('locale', lang);
};
const setupStore = useSetupStore();

const username = ref('');
const email = ref('');
const ca_name = ref('');
const ca_validity_duration = ref(10);
const ca_validity_unit = ref(ValidityUnit.Year);
const password = ref('');
const errorMessage = ref('');

const setupPassword = async () => {
  try {
    let hash = password.value ? await hashPassword(password.value) : null;

    await setup({
      name: username.value,
      email: email.value,
      ca_name: ca_name.value,
      validity_duration: ca_validity_duration.value,
      validity_unit: ca_validity_unit.value,
      password: password.value || null,
      default_language: locale.value,
    });
    await setupStore.reload();
    await router.replace({ name: 'Login' });
  } catch (err) {
    errorMessage.value = t('setup.setupFailed');
  }
};
</script>
