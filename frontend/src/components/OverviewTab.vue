<template>
  <div>
    <h1>{{ $t('overview.title') }}</h1>
    <hr />
    <div class="table-responsive">
      <table class="table table-striped active-certs">
        <thead>
          <tr>
            <th v-if="authStore.isAdmin">{{ $t('overview.colUser') }}</th>
            <th>{{ $t('common.colName') }}</th>
            <th v-if="hasAnyOU">{{ $t('common.colGroup') }}</th>
            <th class="d-none d-md-table-cell">{{ $t('common.colType') }}</th>
            <th class="d-none d-md-table-cell">{{ $t('common.colCreatedOn') }}</th>
            <th>{{ $t('common.colValidUntil') }}</th>
            <th>{{ $t('common.password') }}</th>
            <th class="d-none d-md-table-cell">{{ $t('overview.colRenewMethod') }}</th>
            <th class="d-none d-md-table-cell">{{ $t('common.colCaId') }}</th>
            <th>{{ $t('common.actions') }}</th>
          </tr>
        </thead>
        <tbody>
          <tr v-for="cert in activeCertificates" :key="cert.id">
            <td :id="'UserId-' + cert.id" v-if="authStore.isAdmin">{{ userStore.idToName(cert.user_id) }}</td>
            <td :id="'CertName-' + cert.id" >{{ cert.name.cn }}</td>
            <td :id="'CertGroup-' + cert.id" v-if="hasAnyOU">{{ cert.name.ou ?? '' }}</td>
            <td :id="'CertType-' + cert.id" class="d-none d-md-table-cell">{{ CertificateType[cert.certificate_type] }}</td>
            <td :id="'CreatedOn-' + cert.id" class="d-none d-md-table-cell">{{ new Date(cert.created_on).toLocaleDateString() }}</td>
            <td :id="'ValidUntil-' + cert.id" >{{ new Date(cert.valid_until).toLocaleDateString() }}</td>
            <td :id="'Password-' + cert.id"  class="password-cell">
              <div class="d-flex align-items-center">
                <template v-if="shownCerts.has(cert.id)">
                  <input
                      :id="'PasswordInput-' + cert.id"
                      type="text"
                      :value="cert.password"
                      readonly
                      class="form-control form-control-sm"
                      placeholder="(Blank)"
                      style="font-family: monospace; max-width: 100px; min-width: 70px;"
                  />
                </template>
                <template v-else>
                  <input
                      type="text"
                      value="•••••••••••"
                      readonly
                      class="form-control form-control-sm"
                      style="font-family: monospace; min-width: 70px; max-width: 100px; overflow-x: hidden; pointer-events: none;"
                  />
                </template>
                <svg
                  :id="'PasswordButton-' + cert.id"
                  style="width: 20px; height: 20px; cursor: pointer; flex-shrink: 0;"
                  @click="togglePasswordShown(cert)"
                  alt="Button to show / hide password"
                  class="ms-2"
                >
                  <use
                    :href="shownCerts.has(cert.id) ? 'images/eye-icons.svg#eye-open' : 'images/eye-icons.svg#eye-closed'"
                  ></use>
                </svg>
                <svg
                  :id="'PasswordCopyButton-' + cert.id"
                  style="width: 20px; height: 20px; cursor: pointer; flex-shrink: 0;"
                  @click="copyPasswordtoClipboard(cert)"
                  alt="Button to copy password"
                  class="ms-2"
                >
                  <use
                    :href="copiedCerts.has(cert.id) ? 'images/copy-icons.svg#checkmark' : 'images/copy-icons.svg#copy'"
                  ></use>
                </svg>
              </div>
            </td>
            <td :id="'RenewMethod-' + cert.id" class="d-none d-md-table-cell">{{ CertificateRenewMethod[cert.renew_method] }}</td>
            <td :id="'CaId-' + cert.id" class="d-none d-md-table-cell">{{ cert.ca_id }}</td>
            <td>
              <div class="d-flex flex-sm-row flex-column gap-1">
                <button
                    :id="'DownloadButton-' + cert.id"
                    class="btn btn-primary btn-sm flex-grow-1"
                    @click="downloadCertificate(cert.id)"
                >
                  {{ $t('common.download') }}
                </button>
                <button
                    v-if="cert.certificate_type === CertificateType.TLSClient || cert.certificate_type === CertificateType.TLSServer"
                    class="btn btn-warning btn-sm flex-grow-1"
                    @click="confirmRevocation(cert)"
                >
                  {{ $t('overview.revoke') }}
                </button>
              </div>
            </td>
          </tr>
        </tbody>
      </table>
    </div>

    <button
        id="CreateCertificateButton"
        v-if="authStore.isAdmin"
        class="btn btn-primary mx-1"
        @click="showGenerateModal"
    >
      {{ $t('overview.createCertificate') }}
    </button>

    <div v-if="loading" class="text-center mt-3">{{ $t('overview.loadingCerts') }}</div>
    <div v-if="error" class="alert alert-danger mt-3">{{ error }}</div>

    <div class="mt-5 pt-3 border-top">
      <div
          class="d-flex align-items-center text-muted"
          style="cursor: pointer; user-select: none;"
          @click="showRevoked = !showRevoked"
      >
        <h6 class="mb-0 text-uppercase fw-bold" style="font-size: 0.85rem; letter-spacing: 0.05rem;">
          {{ $t('overview.revokedSection') }}
        </h6>
        <span class="ms-2 small">{{ showRevoked ? '−' : '+' }}</span>
      </div>

      <div v-if="showRevoked" class="mt-3">
        <div class="table-responsive">
          <table class="table table-sm table-borderless align-middle revoked-certificates-table">
            <thead>
            <tr class="text-muted border-bottom" style="font-size: 0.8rem;">
              <th v-if="authStore.isAdmin">{{ $t('overview.colUser') }}</th>
              <th>{{ $t('common.colName') }}</th>
              <th v-if="hasAnyOU">{{ $t('common.colGroup') }}</th>
              <th class="d-none d-md-table-cell">{{ $t('common.colType') }}</th>
              <th class="d-none d-md-table-cell">{{ $t('overview.colCreated') }}</th>
              <th class="d-none d-md-table-cell">{{ $t('overview.colValidity') }}</th>
              <th>{{ $t('overview.colRevoked') }}</th>
              <th class="d-none d-md-table-cell text-end">{{ $t('common.colCaId') }}</th>
              <th class="text-end">{{ $t('common.actions') }}</th>
            </tr>
            </thead>
            <tbody class="text-muted" style="font-size: 0.85rem;">
            <tr v-for="cert in revokedCertificates" :key="cert.id" class="opacity-75">
              <td v-if="authStore.isAdmin">{{ userStore.idToName(cert.user_id) }}</td>
              <td class="fw-medium">{{ cert.name.cn }}</td>
              <td v-if="hasAnyOU">{{ cert.name.ou ?? '' }}</td>
              <td class="d-none d-md-table-cell">{{ CertificateType[cert.certificate_type] }}</td>
              <td class="d-none d-md-table-cell">{{ new Date(cert.created_on).toLocaleDateString() }}</td>
              <td class="d-none d-md-table-cell">{{ new Date(cert.valid_until).toLocaleDateString() }}</td>
              <td>{{ cert.revoked_at ? new Date(cert.revoked_at * 1000).toLocaleDateString() : 'Unknown' }}</td>
              <td class="d-none d-md-table-cell text-end">{{ cert.ca_id }}</td>
              <td class="text-end">
                <button
                    class="btn btn-link btn-sm text-decoration-none text-secondary p-0"
                    :title="$t('common.delete')"
                    @click="confirmDeletion(cert)"
                >
                  <small>{{ $t('common.delete') }}</small>
                </button>
              </td>
            </tr>
            <tr v-if="revokedCertificates.length === 0">
              <td colspan="7" class="text-center py-4 text-muted italic">
                <small>{{ $t('overview.noRevokedCerts') }}</small>
              </td>
            </tr>
            </tbody>
          </table>
        </div>
      </div>
    </div>

    <!-- Generate Certificate Modal -->
    <div
        v-if="isGenerateModalVisible"
        class="modal show d-block"
        tabindex="-1"
        style="background: rgba(0, 0, 0, 0.5)"
    >
      <div class="modal-dialog">
        <div class="modal-content">
          <div class="modal-header">
            <h5 class="modal-title">{{ $t('overview.generateModal.title') }}</h5>
            <button type="button" class="btn-close" @click="closeGenerateModal"></button>
          </div>
          <div class="modal-body">
            <div class="mb-3">
              <label for="certName" class="form-label">{{ $t('overview.generateModal.commonName') }}</label>
              <div class="input-group">
                <input
                    id="certName"
                    v-model="certReq.cert_name.cn"
                    type="text"
                    class="form-control"
                    placeholder="Enter certificate common name"
                />
                <button
                    class="btn btn-outline-secondary"
                    type="button"
                    @click="showOUField = !showOUField"
                    :title="showOUField ? $t('common.hideOu') : $t('common.addOu')"
                >
                  {{ showOUField ? '−' : '+' }}
                </button>
              </div>
            </div>
            <div class="mb-3" v-if="showOUField && (certReq.cert_type === CertificateType.TLSClient || certReq.cert_type === CertificateType.TLSServer)">
              <label for="certOU" class="form-label">{{ $t('common.ouGroup') }}</label>
              <input
                  id="certOU"
                  v-model="certReq.cert_name.ou"
                  type="text"
                  class="form-control"
                  placeholder="Enter organizational unit (optional)"
              />
            </div>
            <div class="mb-3">
              <label for="certType" class="form-label">{{ $t('overview.generateModal.certType') }}</label>
              <select
                  class="form-select"
                  id="certType"
                  v-model="certReq.cert_type"
                  required
              >
                <option :value="CertificateType.TLSClient">{{ $t('overview.generateModal.tlsClient') }}</option>
                <option :value="CertificateType.TLSServer">{{ $t('overview.generateModal.tlsServer') }}</option>
                <option :value="CertificateType.SSHClient">{{ $t('overview.generateModal.sshClient') }}</option>
                <option :value="CertificateType.SSHServer">{{ $t('overview.generateModal.sshServer') }}</option>
              </select>
            </div>
            <div class="mb-3" v-if="certReq.cert_type == CertificateType.TLSServer || certReq.cert_type == CertificateType.SSHClient || certReq.cert_type == CertificateType.SSHServer">
              <label class="form-label" v-if="certReq.cert_type == CertificateType.TLSServer">{{ $t('overview.generateModal.dnsNames') }}</label>
              <label class="form-label" v-if="certReq.cert_type == CertificateType.SSHClient || certReq.cert_type == CertificateType.SSHServer">{{ $t('overview.generateModal.principals') }}</label>
              <div v-for="(_, index) in certReq.usage_limit" :key="index" class="input-group mb-2">
                <input
                    type="text"
                    class="form-control"
                    v-model="certReq.usage_limit[index]"
                    :placeholder="$t('overview.generateModal.usagePlaceholder', { n: index + 1 })"
                />
                <button
                    v-if="index === certReq.usage_limit.length - 1"
                    type="button"
                    class="btn btn-outline-secondary"
                    @click="addUsageField"
                >
                  +
                </button>
                <button
                    v-if="certReq.usage_limit.length > 1"
                    type="button"
                    class="btn btn-outline-danger"
                    @click="removeUsageField(index)"
                >
                  −
                </button>
              </div>
            </div>
            <div class="mb-3">
              <label for="userId" class="form-label">{{ $t('overview.generateModal.user') }}</label>
              <select
                  id="userId"
                  v-model="certReq.user_id"
                  class="form-control"
              >
                <option value="" disabled>{{ $t('overview.generateModal.selectUser') }}</option>
                <option v-for="user in userStore.users" :key="user.id" :value="user.id">
                  {{ user.name }}
                </option>
              </select>
            </div>
            <div class="mb-3">
              <label for="caId" class="form-label">{{ $t('overview.generateModal.ca') }}</label>
              <select
                  id="caId"
                  v-model="certReq.ca_id"
                  class="form-control"
                  required
              >
                <option :value="undefined" disabled>{{ $t('overview.generateModal.selectCa') }}</option>
                <option v-for="ca in availableCAs" :key="ca.id" :value="ca.id">
                  {{ ca.name.cn }} (ID: {{ ca.id }})
                </option>
              </select>
            </div>

            <div class="mb-3">
              <label for="validity" class="form-label">{{ $t('common.validity') }}</label>
              <div class="input-group">
                <input
                    id="validity"
                    v-model.number="certReq.validity_duration"
                    type="number"
                    class="form-control"
                    min="0"
                    placeholder="Enter validity period"
                />
                <select
                    id="validity_unit"
                    v-model="certReq.validity_unit"
                    class="form-select"
                    style="max-width: 120px"
                >
                  <option :value="ValidityUnit.Hour">{{ $t('common.hours') }}</option>
                  <option :value="ValidityUnit.Day">{{ $t('common.days') }}</option>
                  <option :value="ValidityUnit.Month">{{ $t('common.months') }}</option>
                  <option :value="ValidityUnit.Year">{{ $t('common.years') }}</option>
                </select>
              </div>
            </div>
            <div class="mb-3 form-check form-switch">
              <input
                  type="checkbox"
                  class="form-check-input"
                  id="systemGeneratedPassword"
                  v-model="certReq.system_generated_password"
                  :disabled="passwordRule == PasswordRule.System"
                  role="switch"
              />
              <label class="form-check-label" for="system_generated_password">
                {{ $t('overview.generateModal.systemPassword') }}
              </label>
            </div>
            <div class="mb-3" v-if="!certReq.system_generated_password">
              <label for="certPassword" class="form-label">{{ $t('common.password') }}</label>
              <input
                  id="certPassword"
                  v-model="certReq.cert_password"
                  type="text"
                  class="form-control"
                  placeholder="Enter password"
              />
            </div>
            <div class="mb-3">
              <label for="renewMethod" class="form-label">{{ $t('overview.generateModal.renewMethod') }}</label>
              <select
                  class="form-select"
                  id="renewMethod"
                  v-model="certReq.renew_method"
                  required
              >
                <option :value="CertificateRenewMethod.None">{{ $t('overview.generateModal.renewNone') }}</option>
                <option :value="CertificateRenewMethod.Notify">{{ $t('overview.generateModal.renewRemind') }}</option>
                <option :value="CertificateRenewMethod.Renew" v-if="certReq.cert_type == CertificateType.TLSServer || certReq.cert_type == CertificateType.TLSClient">{{ $t('overview.generateModal.renewRenew') }}</option>
                <option :value="CertificateRenewMethod.RenewAndNotify" v-if="certReq.cert_type == CertificateType.TLSServer || certReq.cert_type == CertificateType.TLSClient">{{ $t('overview.generateModal.renewAndNotify') }}</option>
              </select>
            </div>
            <div v-if="isMailValid" class="mb-3 form-check form-switch">
              <input
                  type="checkbox"
                  class="form-check-input"
                  id="notify-user"
                  v-model="certReq.notify_user"
                  role="switch"
              />
              <label class="form-check-label" for="notify-user">
                {{ $t('overview.generateModal.notifyUser') }}
              </label>
            </div>
          </div>
          <div class="modal-footer">
            <button type="button" class="btn btn-secondary" @click="closeGenerateModal">
              {{ $t('common.cancel') }}
            </button>
            <button
                type="button"
                class="btn btn-primary"
                :disabled="loading || ((!certReq.system_generated_password && certReq.cert_password.length == 0) && passwordRule == PasswordRule.Required)"
                @click="createCertificate"
            >
              <span v-if="loading">{{ $t('common.creating') }}</span>
              <span v-else>{{ $t('overview.generateModal.create') }}</span>
            </button>
          </div>
        </div>
      </div>
    </div>

    <!-- Revocation Confirmation Modal -->
    <div
        v-if="isRevokeModalVisible"
        class="modal show d-block"
        tabindex="-1"
        style="background: rgba(0, 0, 0, 0.5)"
    >
      <div class="modal-dialog">
        <div class="modal-content">
          <div class="modal-header">
            <h5 class="modal-title">{{ $t('overview.revokeModal.title') }}</h5>
            <button type="button" class="btn-close" @click="closeRevokeModal"></button>
          </div>
          <div class="modal-body">
            <p>
              {{ $t('overview.revokeModal.confirm', { name: certToRevoke?.name.cn }) }}
            </p>
          </div>
          <div class="modal-footer">
            <button type="button" class="btn btn-secondary" @click="closeRevokeModal">
              {{ $t('common.cancel') }}
            </button>
            <button type="button" class="btn btn-warning" @click="revokeCertificate">
              {{ $t('overview.revokeModal.revoke') }}
            </button>
          </div>
        </div>
      </div>
    </div>

    <!-- Delete Confirmation Modal -->
    <div
        v-if="isDeleteModalVisible"
        class="modal show d-block"
        tabindex="-1"
        style="background: rgba(0, 0, 0, 0.5)"
    >
      <div class="modal-dialog">
        <div class="modal-content">
          <div class="modal-header">
            <h5 class="modal-title">{{ $t('overview.deleteModal.title') }}</h5>
            <button type="button" class="btn-close" @click="closeDeleteModal"></button>
          </div>
          <div class="modal-body">
            <p>
              {{ $t('overview.deleteModal.confirm', { name: certToDelete?.name.cn }) }}
            </p>
            <p class="text-warning">
              <small>{{ $t('overview.deleteModal.disclaimer') }}</small>
            </p>
          </div>
          <div class="modal-footer">
            <button type="button" class="btn btn-secondary" @click="closeDeleteModal">
              {{ $t('common.cancel') }}
            </button>
            <button type="button" class="btn btn-danger" @click="deleteCertificate">
              {{ $t('common.delete') }}
            </button>
          </div>
        </div>
      </div>
    </div>
  </div>
</template>
<script setup lang="ts">
import {computed, onMounted, reactive, ref, watch} from 'vue';
import {useCertificateStore} from '@/stores/certificates';
import {type Certificate, CertificateRenewMethod, CertificateType} from "@/types/Certificate";
import type {CertificateRequirements} from "@/types/CertificateRequirements";
import {useAuthStore} from "@/stores/auth.ts";
import {useUserStore} from "@/stores/users.ts";
import {useSettingsStore} from "@/stores/settings.ts";
import {PasswordRule} from "@/types/Settings.ts";
import {useCAStore} from "@/stores/cas.ts";
import {CAType} from "@/types/CA.ts";
import {ValidityUnit} from "@/types/ValidityUnit.ts";

// stores
const certificateStore = useCertificateStore();
const authStore = useAuthStore();
const userStore = useUserStore();
const settingStore = useSettingsStore();
const caStore = useCAStore();

// local state
const shownCerts = ref(new Set<number>());
const copiedCerts = ref(new Set<number>());

const certificates = computed(() => certificateStore.certificates);
const activeCertificates = computed(() => {
  return Array.from(certificates.value.values()).filter(cert => !cert.revoked_at);
});
const revokedCertificates = computed(() => {
  return Array.from(certificates.value.values()).filter(cert => !!cert.revoked_at);
});
const settings = computed(() => settingStore.settings);
const loading = computed(() => certificateStore.loading);
const error = computed(() => certificateStore.error);
const hasAnyOU = computed(() => Array.from(certificates.value.values()).some(cert => cert.name.ou));

const isDeleteModalVisible = ref(false);
const isGenerateModalVisible = ref(false);
const isRevokeModalVisible = ref(false);
const showRevoked = ref(false);

const certToDelete = ref<Certificate | null>(null);
const certToRevoke = ref<Certificate | null>(null);

const passwordRule = computed(() => {
  return settings.value?.common.password_rule ?? PasswordRule.Optional;
});

const certReq = reactive<CertificateRequirements>({
  cert_name: { cn: '', ou: undefined },
  user_id: 0,
  validity_duration: 1,
  validity_unit: ValidityUnit.Year,
  system_generated_password: passwordRule.value == PasswordRule.System,
  cert_password: '',
  notify_user: false,
  cert_type: CertificateType.TLSClient,
  usage_limit: [''],
  renew_method: CertificateRenewMethod.None,
  ca_id: undefined
});

const showOUField = ref(false);

const isMailValid = computed(() => {
  return (settings.value?.mail.smtp_host.length ?? 0) > 0 && (settings.value?.mail.smtp_port ?? 0) > 0;
});

const availableCAs = computed(() => {
  const cas = Array.from(caStore.cas.values());

  // Map certificate types to allowed CA types
  const allowedCATypes = {
    [CertificateType.TLSClient]: [CAType.TLS],
    [CertificateType.TLSServer]: [CAType.TLS],
    [CertificateType.SSHClient]: [CAType.SSH],
    [CertificateType.SSHServer]: [CAType.SSH],
  };

  const allowedType = allowedCATypes[certReq.cert_type];
  if (!allowedType) return cas;

  return cas.filter(ca => allowedType.includes(ca.ca_type)).sort((a, b) => b.id - a.id);
});


watch(passwordRule, (newVal) => {
  certReq.system_generated_password = (newVal === PasswordRule.System);
}, { immediate: true });

onMounted(async () => {
  await certificateStore.fetchCertificates();
  await settingStore.fetchSettings();
  if (authStore.isAdmin) {
    await userStore.fetchUsers();
  }
});

const showGenerateModal = async () => {
  await userStore.fetchUsers();
  await caStore.fetchCAs();

  isGenerateModalVisible.value = true;
};

const closeGenerateModal = () => {
  isGenerateModalVisible.value = false;
  certReq.cert_name = { cn: '', ou: undefined };
  certReq.user_id = 0;
  certReq.validity_duration = 1;
  certReq.validity_unit = ValidityUnit.Year;
  certReq.cert_password = '';
  certReq.notify_user = false;
  certReq.ca_id = undefined;
  showOUField.value = false;
};

const createCertificate = async () => {
    await certificateStore.createCertificate(certReq);
    closeGenerateModal();
};

const confirmDeletion = (cert: Certificate) => {
  certToDelete.value = cert;
  isDeleteModalVisible.value = true;
};

const closeDeleteModal = () => {
  certToDelete.value = null;
  isDeleteModalVisible.value = false;
};

const downloadCertificate = async (certId: number) => {
  await certificateStore.downloadCertificate(certId);
}

const deleteCertificate = async () => {
  if (certToDelete.value) {
    await certificateStore.deleteCertificate(certToDelete.value.id);
    closeDeleteModal();
  }
};

const confirmRevocation = (cert: Certificate) => {
  certToRevoke.value = cert;
  isRevokeModalVisible.value = true;
};

const closeRevokeModal = () => {
  certToRevoke.value = null;
  isRevokeModalVisible.value = false;
};

const revokeCertificate = async () => {
  if (certToRevoke.value) {
    const certId = certToRevoke.value.id;
    await certificateStore.revokeCertificate(certId);
    closeRevokeModal();
  }
};

const togglePasswordShown = async (cert: Certificate) => {
  if (!cert.password) {
    await certificateStore.fetchCertificatePassword(cert.id);
  }

  if (shownCerts.value.has(cert.id)) {
    shownCerts.value.delete(cert.id);
  } else {
    shownCerts.value.add(cert.id);
  }
};

const copyPasswordtoClipboard = async (cert: Certificate) => {
    if (!cert.password) {
      await certificateStore.fetchCertificatePassword(cert.id);
    }

    try {
      await navigator.clipboard.writeText(cert.password);

      copiedCerts.value.add(cert.id);
      setTimeout(() => copiedCerts.value.delete(cert.id), 1500);

    } catch (err) {
      console.error("Failed to copy to clipboard: ", err);
    }
};

const addUsageField = () => {
  certReq.usage_limit.push('');
};

const removeUsageField = (index: number) => {
  certReq.usage_limit.splice(index, 1);
};
</script>


<style scoped>
.modal {
  z-index: 1050;
  display: flex;
  align-items: center;
  justify-content: center;
}

/* When multiple modals are present, we want to stack them properly */
.modal + .modal {
  z-index: 1051;
}
</style>
