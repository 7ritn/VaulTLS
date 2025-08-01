<template>
  <div class="settings-tab">
    <h1>Settings</h1>
    <hr />
    <!-- Application Section -->
    <div v-if="authStore.isAdmin && settings" class="mb-3">
      <!-- Common Section -->
      <h3>Common</h3>
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
              Password Login enabled
            </label>
          </div>
          <div class="mb-3">
            <label for="common-vaultls-url" class="form-label">VaulTLS URL</label>
            <input
                id="common-vaultls-url"
                v-model="settings.common.vaultls_url"
                type="text"
                class="form-control"
            />
          </div>
          <div class="mb-3">
            <label for="common-password-rule" class="form-label">PKCS12 Password Rules</label>
            <select
                id="common-password-rule"
                v-model="settings.common.password_rule"
                class="form-select"
            >
              <option :value="PasswordRule.Optional">Optional</option>
              <option :value="PasswordRule.Required">Required</option>
              <option :value="PasswordRule.System">System Generated</option>
            </select>
          </div>
        </div>
      </div>

      <!-- Mail Section -->
      <h3>Mail</h3>
      <div class="card mt-3 mb-3">
        <div class="card-body">
          <div class="mb-3 row">
            <div class="col-9">
              <label for="mail-smtp-host" class="form-label">SMTP Host</label>
              <input
                  id="mail-smtp-host"
                  v-model="settings.mail.smtp_host"
                  type="text"
                  class="form-control"
              />
            </div>
            <div class="col-3">
              <label for="mail-smtp-port" class="form-label">Port</label>
              <input
                  id="mail-smtp-port"
                  v-model="settings.mail.smtp_port"
                  type="number"
                  class="form-control"
              />
            </div>
          </div>
          <div class="mb-3">
            <label for="mail-encryption" class="form-label">Role</label>
            <select
                id="mail-encryption"
                v-model="settings.mail.encryption"
                class="form-select"
            >
              <option :value="Encryption.None">None</option>
              <option :value="Encryption.TLS">TLS</option>
              <option :value="Encryption.STARTTLS">STARTTLS</option>
            </select>
          </div>
          <div class="mb-3">
            <label for="mail-username" class="form-label">Username</label>
            <input
                id="mail-username"
                v-model="settings.mail.username"
                type="text"
                class="form-control"
            />
          </div>
          <div class="mb-3">
            <label for="mail-password" class="form-label">Password</label>
            <input
                id="mail-password"
                v-model="settings.mail.password"
                type="password"
                class="form-control"
            />
          </div>
          <div class="mb-3">
            <label for="mail-from" class="form-label">From</label>
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
      <h3>OIDC</h3>
      <div class="card mt-3 mb-3">
        <div class="card-body">
          <div class="mb-3">
            <label for="oidc-id" class="form-label">Client ID</label>
            <input
                id="oidc-id"
                v-model="settings.oidc.id"
                type="text"
                class="form-control"
            />
          </div>
          <div class="mb-3">
            <label for="oidc-secret" class="form-label">Client Secret</label>
            <input
                id="oidc-secret"
                v-model="settings.oidc.secret"
                type="password"
                class="form-control"
            />
          </div>
          <div class="mb-3">
            <label for="oidc-auth-url" class="form-label">Authorization URL</label>
            <input
                id="oidc-auth-url"
                v-model="settings.oidc.auth_url"
                type="text"
                class="form-control"
            />
          </div>
          <div class="mb-3">
            <label for="oidc-callback-url" class="form-label">Callback URL</label>
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

    <h2>User</h2>
    <div class="card mt-3 mb-3">
      <div class="card-body">
        <h4 class="card-header">Change Password</h4>
        <form @submit.prevent="changePassword">
          <div v-if="authStore.current_user?.has_password" class="mb-3">
            <label for="old-password" class="form-label">Old Password</label>
            <input
                id="old-password"
                v-model="changePasswordReq.oldPassword"
                type="password"
                class="form-control"
            />
          </div>
          <div class="mb-3">
            <label for="new-password" class="form-label">New Password</label>
            <input
                id="new-password"
                v-model="changePasswordReq.newPassword"
                type="password"
                class="form-control"
            />
          </div>
          <div class="mb-3">
            <label for="confirm-password" class="form-label">Confirm New Password</label>
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
            Change Password
          </button>
        </form>
      </div>
      <div v-if="editableUser" class="card-body">
        <h4 class="card-header">Profile</h4>
        <div class="mb-3">
          <label for="user_name" class="form-label">Username</label>
          <input
              id="user_name"
              v-model="editableUser.name"
              type="text"
              class="form-control"
          />
        </div>
        <div class="mb-3">
          <label for="user_email" class="form-label">E-Mail</label>
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
      Settings saved successfully
    </div>

    <!-- Save Button -->
    <button class="btn btn-primary mt-3" @click="saveSettings">Save</button>
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
  }
  if (current_user.value) {
    editableUser.value = { ...current_user.value };
  }
});

</script>
