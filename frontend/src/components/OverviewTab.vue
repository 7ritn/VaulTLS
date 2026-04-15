<template>
  <div>
    <h1>Certificates</h1>
    <hr />
    <div class="form-check mb-2">
      <input
          id="hideAcmeCerts"
          v-model="hideAcmeCerts"
          type="checkbox"
          class="form-check-input"
      />
      <label class="form-check-label" for="hideAcmeCerts">Hide ACME certificates</label>
    </div>

    <div class="table-responsive">
      <table class="table table-striped active-certs">
        <thead>
          <tr>
            <th v-if="authStore.isAdmin">User</th>
            <th>Name</th>
            <th v-if="hasAnyOU">Group</th>
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
          <tr v-for="cert in paginatedActiveCerts" :key="cert.id">
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
                    v-if="cert.certificate_type === CertificateType.TLSClient || cert.certificate_type === CertificateType.TLSServer"
                    class="btn btn-warning btn-sm flex-grow-1"
                    @click="confirmRevocation(cert)"
                >
                  Revoke
                </button>
              </div>
            </td>
          </tr>
        </tbody>
      </table>
      <PaginationControls
          :current-page="activeCurrentPage"
          :total-pages="activeTotalPages"
          :total-items="filteredActiveCertificates.length"
          :start-item="activeStartItem"
          :end-item="activeEndItem"
          :page-size="pageSize"
          @prev="activePrev"
          @next="activeNext"
          @update:page-size="setPageSize"
      />
    </div>

    <button
        id="CreateCertificateButton"
        v-if="authStore.isAdmin"
        class="btn btn-primary mx-1 mt-3"
        @click="showGenerateModal"
    >
      Create New Certificate
    </button>

    <div v-if="loading" class="text-center mt-3">Loading certificates...</div>
    <div v-if="error" class="alert alert-danger mt-3">{{ error }}</div>

    <div class="mt-5 pt-3 border-top">
      <div
          class="d-flex align-items-center text-muted"
          style="cursor: pointer; user-select: none;"
          @click="showRevoked = !showRevoked"
      >
        <h6 class="mb-0 text-uppercase fw-bold" style="font-size: 0.85rem; letter-spacing: 0.05rem;">
          Revoked Certificates
        </h6>
        <span class="ms-2 small">{{ showRevoked ? '−' : '+' }}</span>
      </div>

      <div v-if="showRevoked" class="mt-3">
        <div class="table-responsive">
          <table class="table table-sm table-borderless align-middle revoked-certificates-table">
            <thead>
            <tr class="text-muted border-bottom" style="font-size: 0.8rem;">
              <th v-if="authStore.isAdmin">User</th>
              <th>Name</th>
              <th v-if="hasAnyOU">Group</th>
              <th class="d-none d-md-table-cell">Type</th>
              <th class="d-none d-md-table-cell">Created</th>
              <th class="d-none d-md-table-cell">Validity</th>
              <th>Revoked</th>
              <th class="d-none d-md-table-cell text-end">CA ID</th>
              <th class="text-end">Actions</th>
            </tr>
            </thead>
            <tbody class="text-muted" style="font-size: 0.85rem;">
            <tr v-for="cert in paginatedRevokedCerts" :key="cert.id" class="opacity-75">
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
                    title="Delete Record"
                    @click="confirmDeletion(cert)"
                >
                  <small>Delete</small>
                </button>
              </td>
            </tr>
            <tr v-if="revokedCertificates.length === 0">
              <td colspan="7" class="text-center py-4 text-muted italic">
                <small>No revoked certificates found.</small>
              </td>
            </tr>
            </tbody>
          </table>
          <PaginationControls
              :current-page="revokedCurrentPage"
              :total-pages="revokedTotalPages"
              :total-items="revokedCertificates.length"
              :start-item="revokedStartItem"
              :end-item="revokedEndItem"
              :page-size="pageSize"
              @prev="revokedPrev"
              @next="revokedNext"
              @update:page-size="setPageSize"
          />
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
            <h5 class="modal-title">Generate New Certificate</h5>
            <button type="button" class="btn-close" @click="closeGenerateModal"></button>
          </div>
          <div class="modal-body">
            <div class="mb-3">
              <label for="certName" class="form-label">Common Name</label>
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
                    :title="showOUField ? 'Hide OU field' : 'Add OU (Group)'"
                >
                  {{ showOUField ? '−' : '+' }}
                </button>
              </div>
            </div>
            <div class="mb-3" v-if="showOUField && (certReq.cert_type === CertificateType.TLSClient || certReq.cert_type === CertificateType.TLSServer)">
              <label for="certOU" class="form-label">OU (Group)</label>
              <input
                  id="certOU"
                  v-model="certReq.cert_name.ou"
                  type="text"
                  class="form-control"
                  placeholder="Enter organizational unit (optional)"
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
                  {{ ca.name.cn }} (ID: {{ ca.id }})
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
            <h5 class="modal-title">Revoke Certificate</h5>
            <button type="button" class="btn-close" @click="closeRevokeModal"></button>
          </div>
          <div class="modal-body">
            <p>
              Are you sure you want to revoke the certificate
              <strong>{{ certToRevoke?.name.cn }}</strong>?
            </p>
          </div>
          <div class="modal-footer">
            <button type="button" class="btn btn-secondary" @click="closeRevokeModal">
              Cancel
            </button>
            <button type="button" class="btn btn-warning" @click="revokeCertificate">
              Revoke
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
              <strong>{{ certToDelete?.name.cn }}</strong>?
            </p>
            <p class="text-warning">
              <small>
                Disclaimer: Deleting the certificate will remove it from CRL creation since no information on deleted certificates is kept.
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
import {usePagination} from "@/composables/usePagination.ts";
import {usePageSize} from "@/composables/usePageSize.ts";
import PaginationControls from "@/components/PaginationControls.vue";

// stores
const certificateStore = useCertificateStore();
const authStore = useAuthStore();
const userStore = useUserStore();
const settingStore = useSettingsStore();
const caStore = useCAStore();

// local state
const shownCerts = ref(new Set<number>());
const hideAcmeCerts = ref(false);

const certificates = computed(() => certificateStore.certificates);

const filteredActiveCertificates = computed(() => {
    const all = Array.from(certificates.value.values()).filter(cert => !cert.revoked_at);
    if (!hideAcmeCerts.value) return all;
    return all.filter(cert => cert.name.ou != 'ACME');
});

const revokedCertificates = computed(() => {
    return Array.from(certificates.value.values()).filter(cert => !!cert.revoked_at);
});

const { pageSize, setPageSize } = usePageSize();

const {
    currentPage: activeCurrentPage,
    totalPages: activeTotalPages,
    paginated: paginatedActiveCerts,
    startItem: activeStartItem,
    endItem: activeEndItem,
    prev: activePrev,
    next: activeNext,
} = usePagination(filteredActiveCertificates, pageSize);

const {
    currentPage: revokedCurrentPage,
    totalPages: revokedTotalPages,
    paginated: paginatedRevokedCerts,
    startItem: revokedStartItem,
    endItem: revokedEndItem,
    prev: revokedPrev,
    next: revokedNext,
} = usePagination(revokedCertificates, pageSize);
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