<template>
  <div>
    <h1>{{ $t('acme.title') }}</h1>
    <hr />
    <div class="form-check mb-2">
      <input
          id="hideDeactivatedAccounts"
          v-model="hideDeactivated"
          type="checkbox"
          class="form-check-input"
      />
      <label class="form-check-label" for="hideDeactivatedAccounts">{{ $t('acme.hideDeactivated') }}</label>
    </div>
    <div class="table-responsive">
      <table class="table table-striped">
        <thead>
        <tr>
          <th>{{ $t('acme.colId') }}</th>
          <th>{{ $t('common.colName') }}</th>
          <th>{{ $t('acme.colAllowedDomains') }}</th>
          <th>{{ $t('acme.colStatus') }}</th>
          <th>{{ $t('acme.colValidation') }}</th>
          <th>{{ $t('common.colCaId') }}</th>
          <th>{{ $t('users.title') }}</th>
          <th class="d-none d-lg-table-cell">{{ $t('acme.colCreated') }}</th>
          <th>{{ $t('common.actions') }}</th>
        </tr>
        </thead>
        <tbody>
        <tr v-for="account in accountsArray" :key="account.id">
          <td :id="'AcmeId-' + account.id">{{ account.id }}</td>
          <td :id="'AcmeName-' + account.id">{{ account.name }}</td>
          <td :id="'AcmeDomains-' + account.id">
            <span :title="account.allowed_domains">
              {{ truncateDomains(account.allowed_domains) }}
            </span>
          </td>
          <td :id="'AcmeStatus-' + account.id">
            <span
                class="badge"
                :class="statusBadgeClass(account.status)"
            >{{ $te(`acme.${account.status}`) ? $t(`acme.${account.status}`) : account.status }}</span>
          </td>
          <td :id="'AcmeAutoValidate-' + account.id">
            <span v-if="account.auto_validate" class="badge bg-warning text-dark" :title="$t('acme.autoValidateTitle')">{{ $t(`acme.autoApproved`) }}</span>
            <span v-else class="badge bg-success" :title="$t('acme.http01ValidateTitle')">HTTP-01 / DNS-01</span>
          </td>
          <td :id="'AcmeCA-' + account.id">
            {{ account.ca_id }}
          </td>
          <td :id="'AcmeUser-' + account.id">{{ userStore.idToName(account.user_id) }}</td>
          <td :id="'AcmeCreated-' + account.id" class="d-none d-lg-table-cell">
            {{ new Date(account.created_on).toLocaleDateString() }}
          </td>
          <td>
            <div class="d-flex flex-sm-row flex-column gap-1">
              <button
                  :id="'EditButton-' + account.id"
                  v-if="authStore.isAdmin"
                  class="btn btn-outline-primary btn-sm flex-grow-1"
                  @click="openEditModal(account)"
              >
                {{ $t('acme.edit') }}
              </button>
              <button
                  :id="'DeleteButton-' + account.id"
                  v-if="authStore.isAdmin && account.status !== 'deactivated'"
                  class="btn btn-danger btn-sm flex-grow-1"
                  @click="confirmDeletion(account)"
              >
                {{ $t('acme.deactivate') }}
              </button>
            </div>
          </td>
        </tr>
        </tbody>
      </table>
    </div>

    <button
        id="CreateAcmeAccountButton"
        v-if="authStore.isAdmin"
        class="btn btn-primary mx-1"
        @click="openCreateModal"
    >
      {{ $t('acme.createAccount') }}
    </button>

    <div v-if="loading" class="text-center mt-3">{{ $t('acme.loadingAccounts') }}</div>
    <div v-if="error" class="alert alert-danger mt-3">{{ error }}</div>

    <hr class="mt-4" />
    <h1>{{ $t('acme.ordersTitle') }}</h1>
    <hr />
    <div class="table-responsive">
      <table class="table table-striped">
        <thead>
        <tr>
          <th>{{ $t('acme.colId') }}</th>
          <th>{{ $t('acme.colAccount') }}</th>
          <th>{{ $t('acme.colStatus') }}</th>
          <th>{{ $t('acme.colDomains') }}</th>
          <th class="d-none d-lg-table-cell">{{ $t('acme.colExpires') }}</th>
          <th>{{ $t('acme.colCertId') }}</th>
          <th class="d-none d-lg-table-cell">{{ $t('acme.colClientIp') }}</th>
          <th>{{ $t('acme.colError') }}</th>
        </tr>
        </thead>
        <tbody>
        <tr v-for="order in acmeStore.orders.values()" :key="order.id">
          <td>{{ order.id }}</td>
          <td>{{ order.account_name }}</td>
          <td>
            <span class="badge" :class="orderStatusBadgeClass(order.status)">{{ $t(`acme.${order.status}`) }}</span>
          </td>
          <td>{{ order.identifiers.map(i => i.value).join(', ') }}</td>
          <td class="d-none d-lg-table-cell">{{ new Date(order.expires).toLocaleDateString() }}</td>
          <td>{{ order.certificate_id !== null ? order.certificate_id : '—' }}</td>
          <td class="d-none d-lg-table-cell">{{ order.client_ip ?? '—' }}</td>
          <td>
            <span v-if="order.error" :title="order.error" class="text-danger" style="cursor: help;">
              {{ order.error.length > 40 ? order.error.slice(0, 40) + '…' : order.error }}
            </span>
            <span v-else class="text-muted">—</span>
          </td>
        </tr>
        <tr v-if="acmeStore.orders.size === 0">
          <td colspan="8" class="text-center text-muted">{{ $t('acme.noOrders') }}</td>
        </tr>
        </tbody>
      </table>
    </div>

    <!-- Create Modal -->
    <div
        v-if="isCreateModalVisible"
        class="modal show d-block"
        tabindex="-1"
        style="background: rgba(0, 0, 0, 0.5)"
    >
      <div class="modal-dialog">
        <div class="modal-content">
          <div class="modal-header">
            <h5 class="modal-title">{{ $t('acme.createModal.title') }}</h5>
            <button type="button" class="btn-close" @click="closeCreateModal"></button>
          </div>
          <div class="modal-body">
            <div class="mb-3">
              <label for="acmeName" class="form-label">{{ $t('common.colName') }}</label>
              <input
                  id="acmeName"
                  v-model="createForm.name"
                  type="text"
                  class="form-control"
                  :placeholder="$t('acme.createModal.namePlaceholder')"
                  required
              />
            </div>
            <div class="mb-3">
              <label class="form-label">{{ $t('acme.createModal.allowedDomains') }}</label>
              <div class="input-group mb-2">
                <input
                    id="acmeDomainInput"
                    v-model="domainInput"
                    type="text"
                    class="form-control"
                    :placeholder="$t('acme.createModal.domainPlaceholder')"
                    @keydown.enter.prevent="addDomain"
                />
                <button
                    class="btn btn-outline-secondary"
                    type="button"
                    @click="addDomain"
                >
                  {{ $t('acme.createModal.addDomain') }}
                </button>
              </div>
              <div class="d-flex flex-wrap gap-1">
                <span
                    v-for="(domain, index) in createForm.allowed_domains"
                    :key="index"
                    class="badge bg-secondary d-flex align-items-center gap-1"
                >
                  {{ domain }}
                  <button
                      type="button"
                      class="btn-close btn-close-white"
                      style="font-size: 0.6em;"
                      @click="removeDomain(index)"
                  ></button>
                </span>
              </div>
              <div v-if="createForm.allowed_domains.length === 0" class="text-muted small mt-1">
                {{ $t('acme.createModal.noDomainsAdded') }}
              </div>
            </div>
            <div class="mb-3">
              <label for="acmeCA" class="form-label">{{ $t('overview.generateModal.ca') }}</label>
              <select
                  id="acmeCA"
                  v-model="createForm.ca_id"
                  class="form-select"
                  required
              >
                <option :value="undefined" disabled>{{ $t('acme.createModal.selectCa') }}</option>
                <option v-for="ca in availableCAs" :key="ca.id" :value="ca.id">
                  {{ ca.name.cn }} (ID: {{ ca.id }})
                </option>
              </select>
            </div>
            <div class="mb-3 form-check">
              <input
                  id="acmeAutoValidate"
                  v-model="createForm.auto_validate"
                  type="checkbox"
                  class="form-check-input"
              />
              <label for="acmeAutoValidate" class="form-check-label">
                {{ $t('acme.createModal.autoValidate') }}
              </label>
              <div class="form-text text-warning">
                {{ $t('acme.createModal.autoValidateHelp') }}
              </div>
            </div>
          </div>
          <div class="modal-footer">
            <button type="button" class="btn btn-secondary" @click="closeCreateModal">
              {{ $t('common.cancel') }}
            </button>
            <button
                type="button"
                class="btn btn-primary"
                :disabled="loading || !createForm.name || !createForm.ca_id"
                @click="createAccount"
            >
              <span v-if="loading">{{ $t('common.creating') }}</span>
              <span v-else>{{ $t('acme.createModal.create') }}</span>
            </button>
          </div>
        </div>
      </div>
    </div>

    <!-- Credentials Modal -->
    <div
        v-if="isCredentialsModalVisible && createdCredentials"
        class="modal show d-block"
        tabindex="-1"
        style="background: rgba(0, 0, 0, 0.5)"
    >
      <div class="modal-dialog modal-lg">
        <div class="modal-content">
          <div class="modal-header">
            <h5 class="modal-title">{{ $t('acme.credentialsModal.title') }}</h5>
            <button type="button" class="btn-close" @click="closeCredentialsModal"></button>
          </div>
          <div class="modal-body">
            <div class="alert alert-warning">
              <strong>{{ $t('acme.credentialsModal.hmacWarning') }}</strong>
            </div>
            <div class="mb-3">
              <label class="form-label">{{ $t('acme.credentialsModal.eabKeyId') }}</label>
              <div class="input-group">
                <input
                    type="text"
                    class="form-control font-monospace"
                    :value="createdCredentials.eab_kid"
                    readonly
                />
                <button
                    class="btn btn-outline-secondary"
                    type="button"
                    @click="copyToClipboard(createdCredentials!.eab_kid)"
                    :title="$t('acme.credentialsModal.copy')"
                >
                  {{ $t('acme.credentialsModal.copy') }}
                </button>
              </div>
            </div>
            <div class="mb-3">
              <label class="form-label">{{ $t('acme.credentialsModal.eabHmacKey') }}</label>
              <div class="input-group">
                <input
                    type="text"
                    class="form-control font-monospace"
                    :value="createdCredentials.eab_hmac_key"
                    readonly
                />
                <button
                    class="btn btn-outline-secondary"
                    type="button"
                    @click="copyToClipboard(createdCredentials!.eab_hmac_key)"
                    :title="$t('acme.credentialsModal.copy')"
                >
                  {{ $t('acme.credentialsModal.copy') }}
                </button>
              </div>
            </div>
            <div class="mt-4">
              <h6>{{ $t('acme.credentialsModal.exampleUsage') }}</h6>
              <div class="mb-2">
                <label class="form-label small text-muted">certbot</label>
                <pre class="bg-body-secondary p-2 rounded small">certbot certonly \
  --server {{ acmeDirectoryUrl }} \
  --eab-kid {{ createdCredentials.eab_kid }} \
  --eab-hmac-key {{ createdCredentials.eab_hmac_key }} \
  -d your.domain.com</pre>
              </div>
              <div>
                <label class="form-label small text-muted">acme.sh</label>
                <pre class="bg-body-secondary p-2 rounded small">acme.sh --register-account \
  --server {{ acmeDirectoryUrl }} \
  --eab-kid {{ createdCredentials.eab_kid }} \
  --eab-hmac-key {{ createdCredentials.eab_hmac_key }}</pre>
              </div>
              <div class="mt-3">
                <h6 class="text-muted small">{{ $t('acme.credentialsModal.dns01Examples') }}</h6>
                <div class="mb-2">
                  <label class="form-label small text-muted">certbot (DNS-01)</label>
                  <pre class="bg-body-secondary p-2 rounded small">certbot certonly \
  --server {{ acmeDirectoryUrl }} \
  --eab-kid {{ createdCredentials.eab_kid }} \
  --eab-hmac-key {{ createdCredentials.eab_hmac_key }} \
  --preferred-challenges dns \
  -d your.domain.com</pre>
                </div>
                <div>
                  <label class="form-label small text-muted">acme.sh (DNS-01)</label>
                  <pre class="bg-body-secondary p-2 rounded small">acme.sh --issue \
  --server {{ acmeDirectoryUrl }} \
  --dns dns_provider \
  -d your.domain.com</pre>
                </div>
              </div>
            </div>
          </div>
          <div class="modal-footer">
            <button type="button" class="btn btn-primary" @click="closeCredentialsModal">
              {{ $t('acme.credentialsModal.close') }}
            </button>
          </div>
        </div>
      </div>
    </div>

    <!-- Edit Modal -->
    <div
        v-if="isEditModalVisible && accountToEdit"
        class="modal show d-block"
        tabindex="-1"
        style="background: rgba(0, 0, 0, 0.5)"
    >
      <div class="modal-dialog">
        <div class="modal-content">
          <div class="modal-header">
            <h5 class="modal-title">{{ $t('acme.editModal.title') }}</h5>
            <button type="button" class="btn-close" @click="closeEditModal"></button>
          </div>
          <div class="modal-body">
            <div class="mb-3">
              <label for="editAcmeName" class="form-label">{{ $t('common.colName') }}</label>
              <input
                  id="editAcmeName"
                  v-model="editForm.name"
                  type="text"
                  class="form-control"
                  :placeholder="$t('acme.editModal.namePlaceholder')"
                  required
              />
            </div>
            <div class="mb-3">
              <label for="editAcmeCA" class="form-label">{{ $t('overview.generateModal.ca') }}</label>
              <select
                  id="editAcmeCA"
                  v-model="editForm.ca_id"
                  class="form-select"
              >
                <option :value="undefined" disabled>{{ $t('acme.editModal.selectCa') }}</option>
                <option v-for="ca in availableCAs" :key="ca.id" :value="ca.id">
                  {{ ca.name.cn }} (ID: {{ ca.id }})
                </option>
              </select>
            </div>
            <div class="mb-3">
              <label class="form-label">{{ $t('acme.editModal.allowedDomains') }}</label>
              <div class="input-group mb-2">
                <input
                    id="editDomainInput"
                    v-model="editDomainInput"
                    type="text"
                    class="form-control"
                    :placeholder="$t('acme.editModal.domainPlaceholder')"
                    @keydown.enter.prevent="addEditDomain"
                />
                <button
                    class="btn btn-outline-secondary"
                    type="button"
                    @click="addEditDomain"
                >
                  {{ $t('acme.editModal.addDomain') }}
                </button>
              </div>
              <div class="d-flex flex-wrap gap-1">
                <span
                    v-for="(domain, index) in editForm.allowed_domains"
                    :key="index"
                    class="badge bg-secondary d-flex align-items-center gap-1"
                >
                  {{ domain }}
                  <button
                      type="button"
                      class="btn-close btn-close-white"
                      style="font-size: 0.6em;"
                      @click="removeEditDomain(index)"
                  ></button>
                </span>
              </div>
              <div v-if="editForm.allowed_domains.length === 0" class="text-muted small mt-1">
                {{ $t('acme.editModal.noDomainsAdded') }}
              </div>
            </div>
            <div class="mb-3 form-check">
              <input
                  id="editAcmeAutoValidate"
                  v-model="editForm.auto_validate"
                  type="checkbox"
                  class="form-check-input"
              />
              <label for="editAcmeAutoValidate" class="form-check-label">
                {{ $t('acme.editModal.autoValidate') }}
              </label>
              <div class="form-text text-warning">
                {{ $t('acme.editModal.autoValidateHelp') }}
              </div>
            </div>
          </div>
          <div class="modal-footer">
            <button type="button" class="btn btn-secondary" @click="closeEditModal">
              {{ $t('common.cancel') }}
            </button>
            <button
                type="button"
                class="btn btn-primary"
                :disabled="loading || !editForm.name"
                @click="saveEdit"
            >
              <span v-if="loading">{{ $t('acme.editModal.saving') }}</span>
              <span v-else>{{ $t('common.save') }}</span>
            </button>
          </div>
        </div>
      </div>
    </div>

    <!-- Deactivate Confirmation Modal -->
    <div
        v-if="isDeleteModalVisible"
        class="modal show d-block"
        tabindex="-1"
        style="background: rgba(0, 0, 0, 0.5)"
    >
      <div class="modal-dialog">
        <div class="modal-content">
          <div class="modal-header">
            <h5 class="modal-title">{{ $t('acme.deactivateModal.title') }}</h5>
            <button type="button" class="btn-close" @click="closeDeleteModal"></button>
          </div>
          <div class="modal-body">
            <p>{{ $t('acme.deactivateModal.confirm', { name: accountToDelete?.name }) }}</p>
          </div>
          <div class="modal-footer">
            <button type="button" class="btn btn-secondary" @click="closeDeleteModal">
              {{ $t('common.cancel') }}
            </button>
            <button id="ConfirmDeleteButton" type="button" class="btn btn-danger" @click="deleteAccount">
              {{ $t('acme.deactivateModal.deactivate') }}
            </button>
          </div>
        </div>
      </div>
    </div>
  </div>
</template>

<script setup lang="ts">
import { computed, onMounted, reactive, ref } from 'vue';
import { useAcmeStore } from '@/stores/acme';
import { useCAStore } from '@/stores/cas';
import { useAuthStore } from '@/stores/auth';
import { useUserStore } from '@/stores/users';
import type { AcmeAccount, CreateAcmeAccountResponse } from '@/types/Acme';
import { CAType } from '@/types/CA';

// stores
const acmeStore = useAcmeStore();
const caStore = useCAStore();
const authStore = useAuthStore();
const userStore = useUserStore();

// local state
const loading = computed(() => acmeStore.loading);
const error = computed(() => acmeStore.error);
const cas = computed(() => caStore.cas);
const availableCAs = computed(() =>
  Array.from(caStore.cas.values()).filter(ca => ca.ca_type === CAType.TLS).sort((a, b) => b.id - a.id)
);

const hideDeactivated = ref(true);
const accountsArray = computed(() => {
  const all = Array.from(acmeStore.accounts.values());
  return hideDeactivated.value ? all.filter(a => a.status !== 'deactivated') : all;
});
const acmeDirectoryUrl = window.location.origin + '/api/acme/directory';

// create modal
const isCreateModalVisible = ref(false);
const domainInput = ref('');
const createForm = reactive<{ name: string; allowed_domains: string[]; ca_id: number | undefined; auto_validate: boolean }>({
  name: '',
  allowed_domains: [],
  ca_id: undefined,
  auto_validate: false,
});

// credentials modal
const isCredentialsModalVisible = ref(false);
const createdCredentials = ref<CreateAcmeAccountResponse | null>(null);

// edit modal
const isEditModalVisible = ref(false);
const accountToEdit = ref<AcmeAccount | null>(null);
const editDomainInput = ref('');
const editForm = reactive<{ name: string; allowed_domains: string[]; ca_id: number | undefined; auto_validate: boolean }>({
  name: '',
  allowed_domains: [],
  ca_id: undefined,
  auto_validate: false,
});

// delete modal
const isDeleteModalVisible = ref(false);
const accountToDelete = ref<AcmeAccount | null>(null);

onMounted(async () => {
  await Promise.all([acmeStore.fetchAccounts(), acmeStore.fetchOrders(), caStore.fetchCAs(), userStore.fetchUsers()]);
});

// helpers
const truncateDomains = (domains: string): string => {
  if (domains.length <= 40) return domains;
  return domains.slice(0, 40) + '...';
};

const orderStatusBadgeClass = (status: string): string => {
  switch (status) {
    case 'valid':
      return 'bg-success';
    case 'ready':
      return 'bg-primary';
    case 'pending':
      return 'bg-secondary';
    case 'invalid':
      return 'bg-danger';
    default:
      return 'bg-secondary';
  }
};

const statusBadgeClass = (status: string): string => {
  switch (status) {
    case 'valid':
      return 'bg-success';
    case 'pending':
      return 'bg-secondary';
    case 'deactivated':
      return 'bg-danger';
    default:
      return 'bg-secondary';
  }
};

const copyToClipboard = async (text: string) => {
  try {
    await navigator.clipboard.writeText(text);
  } catch (err) {
    console.error('Failed to copy to clipboard', err);
  }
};

// create modal actions
const openCreateModal = () => {
  isCreateModalVisible.value = true;
};

const closeCreateModal = () => {
  isCreateModalVisible.value = false;
  createForm.name = '';
  createForm.allowed_domains = [];
  createForm.ca_id = undefined;
  createForm.auto_validate = false;
  domainInput.value = '';
};

const addDomain = () => {
  const d = domainInput.value.trim();
  if (d && !createForm.allowed_domains.includes(d)) {
    createForm.allowed_domains.push(d);
  }
  domainInput.value = '';
};

const removeDomain = (index: number) => {
  createForm.allowed_domains.splice(index, 1);
};

const createAccount = async () => {
  const result = await acmeStore.createAccount({
    name: createForm.name,
    allowed_domains: createForm.allowed_domains,
    ca_id: createForm.ca_id!,
    auto_validate: createForm.auto_validate,
  });
  closeCreateModal();
  if (result) {
    createdCredentials.value = result;
    isCredentialsModalVisible.value = true;
  }
};

// credentials modal actions
const closeCredentialsModal = () => {
  isCredentialsModalVisible.value = false;
  createdCredentials.value = null;
};

// edit modal actions
const openEditModal = (account: AcmeAccount) => {
  accountToEdit.value = account;
  editForm.name = account.name;
  editForm.allowed_domains = account.allowed_domains
      ? account.allowed_domains.split(',').map(d => d.trim()).filter(d => d.length > 0)
      : [];
  editForm.ca_id = account.ca_id;
  editForm.auto_validate = account.auto_validate;
  editDomainInput.value = '';
  isEditModalVisible.value = true;
};

const closeEditModal = () => {
  isEditModalVisible.value = false;
  accountToEdit.value = null;
  editForm.ca_id = undefined;
  editDomainInput.value = '';
};

const addEditDomain = () => {
  const d = editDomainInput.value.trim();
  if (d && !editForm.allowed_domains.includes(d)) {
    editForm.allowed_domains.push(d);
  }
  editDomainInput.value = '';
};

const removeEditDomain = (index: number) => {
  editForm.allowed_domains.splice(index, 1);
};

const saveEdit = async () => {
  if (accountToEdit.value) {
    await acmeStore.updateAccount(accountToEdit.value.id, {
      name: editForm.name,
      allowed_domains: editForm.allowed_domains,
      ca_id: editForm.ca_id,
      auto_validate: editForm.auto_validate,
    });
    closeEditModal();
  }
};

// delete modal actions
const confirmDeletion = (account: AcmeAccount) => {
  accountToDelete.value = account;
  isDeleteModalVisible.value = true;
};

const closeDeleteModal = () => {
  accountToDelete.value = null;
  isDeleteModalVisible.value = false;
};

const deleteAccount = async () => {
  if (accountToDelete.value) {
    await acmeStore.deleteAccount(accountToDelete.value.id);
    closeDeleteModal();
  }
};
</script>

<style scoped>
.modal {
  z-index: 1050;
  display: flex;
  align-items: center;
  justify-content: center;
}

.modal + .modal {
  z-index: 1051;
}

pre {
  white-space: pre-wrap;
  word-break: break-all;
}
</style>
