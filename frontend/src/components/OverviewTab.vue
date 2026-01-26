<template>
  <div>
    <h1>Certificates</h1>
    <hr />
    <div class="table-responsive">
      <table class="table table-striped">
        <thead>
          <tr>
            <th v-if="authStore.isAdmin">User</th>
            <th>Name</th>
            <th class="d-none d-md-table-cell">Type</th>
            <th class="d-none d-md-table-cell">Created on</th>
            <th>Valid until</th>
            <th>Password</th>
            <th class="d-none d-md-table-cell">Renew Method</th>
            <th class="d-none d-md-table-cell">CA ID</th>
            <th>Actions</th>
          </tr>
        </thead>
        <tbody>
          <tr v-for="cert in certificates.values()" :key="cert.id">
            <td :id="'UserId-' + cert.id" v-if="authStore.isAdmin">{{ userStore.idToName(cert.user_id) }}</td>
            <td :id="'CertName-' + cert.id" >{{ cert.name }}</td>
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
                      class="form-control form-control-sm me-2"
                      style="font-family: monospace; max-width: 100px;"
                  />
                </template>
                <template v-else>
                  <span>•••••••</span>
                </template>
                <img
                    :id="'PasswordButton-' + cert.id"
                    :src="shownCerts.has(cert.id) ? '/images/eye-open.png' : '/images/eye-hidden.png'"
                    class="ms-2"
                    style="width: 20px; cursor: pointer;"
                    @click="togglePasswordShown(cert)"
                    alt="Button to show / hide password"
                />
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
                  Download
                </button>
                <button
                    :id="'DeleteButton-' + cert.id"
                    v-if="authStore.isAdmin"
                    class="btn btn-danger btn-sm flex-grow-1"
                    @click="confirmDeletion(cert)"
                >
                  Delete
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
      Create New Certificate
    </button>

    <div v-if="loading" class="text-center mt-3">Loading certificates...</div>
    <div v-if="error" class="alert alert-danger mt-3">{{ error }}</div>

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
            <h5 class="modal-title">Generate New Certificate</h5>
            <button type="button" class="btn-close" @click="closeGenerateModal"></button>
          </div>
          <div class="modal-body">
            <div class="mb-3">
              <label for="certName" class="form-label">Common Name</label>
              <input
                  id="certName"
                  v-model="certReq.cert_name"
                  type="text"
                  class="form-control"
                  placeholder="Enter certificate name"
              />
            </div>
            <div class="mb-3">
              <label for="certType" class="form-label">Certificate Type</label>
              <select
                  class="form-select"
                  id="certType"
                  v-model="certReq.cert_type"
                  required
              >
                <option :value="CertificateType.TLSClient">TLS Client</option>
                <option :value="CertificateType.TLSServer">TLS Server</option>
                <option :value="CertificateType.SSHClient">SSH Client</option>
                <option :value="CertificateType.SSHServer">SSH Server</option>
              </select>
            </div>
            <div class="mb-3" v-if="certReq.cert_type == CertificateType.TLSServer || certReq.cert_type == CertificateType.SSHClient || certReq.cert_type == CertificateType.SSHServer">
              <label class="form-label" v-if="certReq.cert_type == CertificateType.TLSServer">DNS Names</label>
              <label class="form-label" v-if="certReq.cert_type == CertificateType.SSHClient || certReq.cert_type == CertificateType.SSHServer">Principals</label>
              <div v-for="(_, index) in certReq.usage_limit" :key="index" class="input-group mb-2">
                <input
                    type="text"
                    class="form-control"
                    v-model="certReq.usage_limit[index]"
                    :placeholder="'Usage ' + (index + 1)"
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
              <label for="userId" class="form-label">User</label>
              <select
                  id="userId"
                  v-model="certReq.user_id"
                  class="form-control"
              >
                <option value="" disabled>Select a user</option>
                <option v-for="user in userStore.users" :key="user.id" :value="user.id">
                  {{ user.name }}
                </option>
              </select>
            </div>
            <div class="mb-3">
              <label for="caId" class="form-label">Certificate Authority</label>
              <select
                  id="caId"
                  v-model="certReq.ca_id"
                  class="form-control"
                  required
              >
                <option :value="undefined" disabled>Select a CA</option>
                <option v-for="ca in availableCAs" :key="ca.id" :value="ca.id">
                  {{ ca.name }} (ID: {{ ca.id }})
                </option>
              </select>
            </div>

            <div class="mb-3">
              <label for="validity" class="form-label">Validity</label>
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
                  <option :value="ValidityUnit.Hour">Hours</option>
                  <option :value="ValidityUnit.Day">Days</option>
                  <option :value="ValidityUnit.Month">Months</option>
                  <option :value="ValidityUnit.Year">Years</option>
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
                System Generated Password
              </label>
            </div>
            <div class="mb-3" v-if="!certReq.system_generated_password">
              <label for="certPassword" class="form-label">Password</label>
              <input
                  id="certPassword"
                  v-model="certReq.cert_password"
                  type="text"
                  class="form-control"
                  placeholder="Enter password"
              />
            </div>
            <div class="mb-3">
              <label for="renewMethod" class="form-label">Certificate Renew Method</label>
              <select
                  class="form-select"
                  id="renewMethod"
                  v-model="certReq.renew_method"
                  required
              >
                <option :value="CertificateRenewMethod.None">None</option>
                <option :value="CertificateRenewMethod.Notify">Remind</option>
                <option :value="CertificateRenewMethod.Renew" v-if="certReq.cert_type == CertificateType.TLSServer || certReq.cert_type == CertificateType.TLSClient">Renew</option>
                <option :value="CertificateRenewMethod.RenewAndNotify" v-if="certReq.cert_type == CertificateType.TLSServer || certReq.cert_type == CertificateType.TLSClient">Renew and Notify</option>
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
                Notify User
              </label>
            </div>
          </div>
          <div class="modal-footer">
            <button type="button" class="btn btn-secondary" @click="closeGenerateModal">
              Cancel
            </button>
            <button
                type="button"
                class="btn btn-primary"
                :disabled="loading || ((!certReq.system_generated_password && certReq.cert_password.length == 0) && passwordRule == PasswordRule.Required)"
                @click="createCertificate"
            >
              <span v-if="loading">Creating...</span>
              <span v-else>Create Certificate</span>
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
            <h5 class="modal-title">Delete Certificate</h5>
            <button type="button" class="btn-close" @click="closeDeleteModal"></button>
          </div>
          <div class="modal-body">
            <p>
              Are you sure you want to delete the certificate
              <strong>{{ certToDelete?.name }}</strong>?
            </p>
            <p class="text-warning">
              <small>
                Disclaimer: Deleting the certificate will not revoke it. The certificate will remain
                valid until its expiration date.
              </small>
            </p>
          </div>
          <div class="modal-footer">
            <button type="button" class="btn btn-secondary" @click="closeDeleteModal">
              Cancel
            </button>
            <button type="button" class="btn btn-danger" @click="deleteCertificate">
              Delete
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

const certificates = computed(() => certificateStore.certificates);
const settings = computed(() => settingStore.settings);
const loading = computed(() => certificateStore.loading);
const error = computed(() => certificateStore.error);

const isDeleteModalVisible = ref(false);
const isGenerateModalVisible = ref(false);
const certToDelete = ref<Certificate | null>(null);

const passwordRule = computed(() => {
  return settings.value?.common.password_rule ?? PasswordRule.Optional;
});

const certReq = reactive<CertificateRequirements>({
  cert_name: '',
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
  certReq.cert_name = '';
  certReq.user_id = 0;
  certReq.validity_duration = 1;
  certReq.validity_unit = ValidityUnit.Year;
  certReq.cert_password = '';
  certReq.notify_user = false;
  certReq.ca_id = undefined;
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