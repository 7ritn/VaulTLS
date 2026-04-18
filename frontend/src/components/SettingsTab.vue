<template>
  <div class="settings-tab">
    <h1>{{ $t('settings.title') }}</h1>
    <hr />
    <!-- Application Section -->
    <div v-if="authStore.isAdmin && settings" class="mb-3">
      <!-- Common Section -->
      <h3>{{ $t('settings.common.heading') }}</h3>
      <div class="card mt-3 mb-3">
        <div class="card-body">
          <div class="mb-3 form-check form-switch">
            <input
                type="checkbox"
                class="form-check-input"
                id="common-password-enabled"
                v-model="settings.common.password_enabled"
                role="switch"
            />
            <label class="form-check-label" for="common-password-enabled">
              {{ $t('settings.common.passwordEnabled') }}
            </label>
          </div>
          <div class="mb-3">
            <label for="common-vaultls-url" class="form-label">{{ $t('settings.common.vaultlsUrl') }}</label>
            <input
                id="common-vaultls-url"
                v-model="settings.common.vaultls_url"
                type="text"
                class="form-control"
            />
          </div>
          <div class="mb-3">
            <label for="common-password-rule" class="form-label">{{ $t('settings.common.passwordRule') }}</label>
            <select
                id="common-password-rule"
                v-model="settings.common.password_rule"
                class="form-select"
            >
              <option :value="PasswordRule.Optional">{{ $t('settings.common.passwordRuleOptional') }}</option>
              <option :value="PasswordRule.Required">{{ $t('settings.common.passwordRuleRequired') }}</option>
              <option :value="PasswordRule.System">{{ $t('settings.common.passwordRuleSystem') }}</option>
            </select>
          </div>
          <div class="mb-3">
            <label for="crl-next-update" class="form-label">{{ $t('settings.common.crlValidity') }}</label>
            <div class="input-group">
              <input
                  id="crl-next-update"
                  v-model="crlNextUpdateValue"
                  type="number"
                  class="form-control"
                  @input="updateCrlNextUpdate"
              />
              <select
                  v-model="crlNextUpdateUnit"
                  class="form-select"
                  @change="updateCrlNextUpdate"
              >
                <option value="hours">{{ $t('settings.common.crlHours') }}</option>
                <option value="days">{{ $t('settings.common.crlDays') }}</option>
                <option value="weeks">{{ $t('settings.common.crlWeeks') }}</option>
              </select>
            </div>
          </div>
          <div class="mb-3">
            <label for="common-default-language" class="form-label">{{ $t('settings.common.defaultLanguage') }}</label>
            <select
                id="common-default-language"
                v-model="settings.common.default_language"
                class="form-select"
            >
              <option v-for="(label, code) in SUPPORTED_LOCALES" :key="code" :value="code">
                {{ label }}
              </option>
            </select>
          </div>
        </div>
      </div>

      <!-- Mail Section -->
      <h3>{{ $t('settings.mail.heading') }}</h3>
      <div class="card mt-3 mb-3">
        <div class="card-body">
          <div class="mb-3 row">
            <div class="col-9">
              <label for="mail-smtp-host" class="form-label">{{ $t('settings.mail.smtpHost') }}</label>
              <input
                  id="mail-smtp-host"
                  v-model="settings.mail.smtp_host"
                  type="text"
                  class="form-control"
              />
            </div>
            <div class="col-3">
              <label for="mail-smtp-port" class="form-label">{{ $t('settings.mail.port') }}</label>
              <input
                  id="mail-smtp-port"
                  v-model="settings.mail.smtp_port"
                  type="number"
                  class="form-control"
              />
            </div>
          </div>
          <div class="mb-3">
            <label for="mail-encryption" class="form-label">{{ $t('settings.mail.encryption') }}</label>
            <select
                id="mail-encryption"
                v-model="settings.mail.encryption"
                class="form-select"
            >
              <option :value="Encryption.None">{{ $t('settings.mail.encryptionNone') }}</option>
              <option :value="Encryption.TLS">{{ $t('settings.mail.encryptionTls') }}</option>
              <option :value="Encryption.STARTTLS">{{ $t('settings.mail.encryptionStarttls') }}</option>
            </select>
          </div>
          <div class="mb-3">
            <label for="mail-username" class="form-label">{{ $t('common.username') }}</label>
            <input
                id="mail-username"
                v-model="settings.mail.username"
                type="text"
                class="form-control"
            />
          </div>
          <div class="mb-3">
            <label for="mail-password" class="form-label">{{ $t('common.password') }}</label>
            <input
                id="mail-password"
                v-model="settings.mail.password"
                type="password"
                class="form-control"
            />
          </div>
          <div class="mb-3">
            <label for="mail-from" class="form-label">{{ $t('settings.mail.from') }}</label>
            <input
                id="mail-from"
                v-model="settings.mail.from"
                type="email"
                class="form-control"
            />
          </div>
        </div>
      </div>

      <!-- OIDC Section -->
      <h3>{{ $t('settings.oidc.heading') }}</h3>
      <div class="card mt-3 mb-3">
        <div class="card-body">
          <div class="mb-3">
            <label for="oidc-id" class="form-label">{{ $t('settings.oidc.clientId') }}</label>
            <input
                id="oidc-id"
                v-model="settings.oidc.id"
                type="text"
                class="form-control"
            />
          </div>
          <div class="mb-3">
            <label for="oidc-secret" class="form-label">{{ $t('settings.oidc.clientSecret') }}</label>
            <input
                id="oidc-secret"
                v-model="settings.oidc.secret"
                type="password"
                class="form-control"
            />
          </div>
          <div class="mb-3">
            <label for="oidc-auth-url" class="form-label">{{ $t('settings.oidc.authUrl') }}</label>
            <input
                id="oidc-auth-url"
                v-model="settings.oidc.auth_url"
                type="text"
                class="form-control"
            />
          </div>
          <div class="mb-3">
            <label for="oidc-callback-url" class="form-label">{{ $t('settings.oidc.callbackUrl') }}</label>
            <input
                id="oidc-callback-url"
                v-model="settings.oidc.callback_url"
                type="text"
                class="form-control"
            />
          </div>
        </div>
      </div>
    </div>

    <h2>{{ $t('settings.user.heading') }}</h2>
    <div class="card mt-3 mb-3">
      <div class="card-body">
        <h4 class="card-header">{{ $t('settings.user.changePassword') }}</h4>
        <form @submit.prevent="changePassword">
          <div v-if="authStore.current_user?.has_password" class="mb-3">
            <label for="old-password" class="form-label">{{ $t('settings.user.oldPassword') }}</label>
            <input
                id="old-password"
                v-model="changePasswordReq.oldPassword"
                type="password"
                class="form-control"
            />
          </div>
          <div class="mb-3">
            <label for="new-password" class="form-label">{{ $t('settings.user.newPassword') }}</label>
            <input
                id="new-password"
                v-model="changePasswordReq.newPassword"
                type="password"
                class="form-control"
            />
          </div>
          <div class="mb-3">
            <label for="confirm-password" class="form-label">{{ $t('settings.user.confirmPassword') }}</label>
            <input
                id="confirm-password"
                v-model="confirmPassword"
                type="password"
                class="form-control"
            />
          </div>
          <div v-if="password_error" class="alert alert-danger mt-3">
            {{ password_error }}
          </div>

          <button
              type="submit"
              class="btn btn-primary"
              :disabled="!canChangePassword"
          >
            {{ $t('settings.user.changePassword') }}
          </button>
        </form>
      </div>
      <div v-if="editableUser" class="card-body">
        <h4 class="card-header">{{ $t('settings.user.profile') }}</h4>
        <div class="mb-3">
          <label for="user_name" class="form-label">{{ $t('common.username') }}</label>
          <input
              id="user_name"
              v-model="editableUser.name"
              type="text"
              class="form-control"
          />
        </div>
        <div class="mb-3">
          <label for="user_email" class="form-label">{{ $t('common.email') }}</label>
          <input
              id="user_email"
              v-model="editableUser.email"
              type="email"
              class="form-control"
          />
        </div>
      </div>
    </div>

    <!-- Error Messages -->
    <div v-if="settings_error" class="alert alert-danger mt-3">
      {{ settings_error }}
    </div>
    <div v-if="user_error" class="alert alert-danger mt-3">
      {{ user_error }}
    </div>
    <div v-if="saved_successfully" class="alert alert-success mt-3">
      {{ $t('settings.savedSuccessfully') }}
    </div>

    <!-- Save Button -->
    <button class="btn btn-primary mt-3" @click="saveSettings">{{ $t('common.save') }}</button>
  </div>
</template>

<script setup lang="ts">
import { computed, ref, onMounted } from 'vue';
import { useSettingsStore } from '@/stores/settings';
import { useAuthStore } from '@/stores/auth';
import { type User, UserRole } from "@/types/User.ts";
import { useUserStore } from "@/stores/users.ts";
import { useSetupStore } from "@/stores/setup.ts";
import { Encryption, PasswordRule } from "@/types/Settings.ts";
import { SUPPORTED_LOCALES } from '@/plugins/i18n';

// Stores
const settingsStore = useSettingsStore();
const authStore = useAuthStore();
const userStore = useUserStore();
const setupStore = useSetupStore();

// Computed state
const settings = computed(() => settingsStore.settings);
const current_user = computed(() => authStore.current_user);
const settings_error = computed(() => settingsStore.error);
const user_error = computed(() => userStore.error);
const password_error = computed(() => authStore.error);

const canChangePassword = computed(() =>
    changePasswordReq.value.newPassword === confirmPassword.value &&
    changePasswordReq.value.newPassword.length > 0
);

// Local state
const showPasswordDialog = ref(false);
const changePasswordReq = ref({ oldPassword: '', newPassword: '' });
const confirmPassword = ref('');
const editableUser = ref<User | null>(null);
const saved_successfully = ref(false);

const crlNextUpdateValue = ref(7);
const crlNextUpdateUnit = ref('days');

const updateCrlNextUpdate = () => {
  if (settings.value) {
    let multiplier = 1;
    if (crlNextUpdateUnit.value === 'days') multiplier = 24;
    else if (crlNextUpdateUnit.value === 'weeks') multiplier = 168;
    settings.value.common.crl_next_update_hours = crlNextUpdateValue.value * multiplier;
  }
};

// Methods
const changePassword = async () => {
  await authStore.changePassword(changePasswordReq.value.oldPassword, changePasswordReq.value.newPassword);
  showPasswordDialog.value = false;
  changePasswordReq.value = { oldPassword: '', newPassword: '' };
  confirmPassword.value = '';
};

const saveSettings = async () => {
  saved_successfully.value = false;
  let success = true;

  if (current_user.value?.role === UserRole.Admin) {
    success &&= await settingsStore.saveSettings();
    await setupStore.reload();
  }

  if (editableUser.value) {
    success &&= await userStore.updateUser(editableUser.value);
    await authStore.fetchCurrentUser();
  }

  saved_successfully.value = success;
};

onMounted(async () => {
  if (authStore.isAdmin) {
    await settingsStore.fetchSettings();
    if (settings.value) {
      const hours = settings.value.common.crl_next_update_hours;
      if (hours % 168 === 0) {
        crlNextUpdateUnit.value = 'weeks';
        crlNextUpdateValue.value = hours / 168;
      } else if (hours % 24 === 0) {
        crlNextUpdateUnit.value = 'days';
        crlNextUpdateValue.value = hours / 24;
      } else {
        crlNextUpdateUnit.value = 'hours';
        crlNextUpdateValue.value = hours;
      }
    }
  }
  if (current_user.value) {
    editableUser.value = { ...current_user.value };
  }
});

</script>
