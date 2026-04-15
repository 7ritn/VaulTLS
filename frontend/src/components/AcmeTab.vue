<template>
  <div>
    <h1>ACME Accounts</h1>
    <hr />
    <div class="table-responsive">
      <table class="table table-striped">
        <thead>
        <tr>
          <th>ID</th>
          <th>Name</th>
          <th>Allowed Domains</th>
          <th>Status</th>
          <th>Validation</th>
          <th>CA</th>
          <th>User</th>
          <th class="d-none d-lg-table-cell">Created</th>
          <th>Actions</th>
        </tr>
        </thead>
        <tbody>
        <tr v-for="account in paginatedAccounts" :key="account.id">
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
            >{{ account.status }}</span>
          </td>
          <td :id="'AcmeAutoValidate-' + account.id">
            <span v-if="account.auto_validate" class="badge bg-warning text-dark" title="Challenge validation is skipped for this account">Auto</span>
            <span v-else class="badge bg-success" title="HTTP-01 and DNS-01 challenge validation is enforced">HTTP-01 / DNS-01</span>
          </td>
          <td :id="'AcmeCA-' + account.id">
            {{ account.ca_id !== null ? account.ca_id : 'Default' }}
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
                Edit
              </button>
              <button
                  :id="'DeleteButton-' + account.id"
                  v-if="authStore.isAdmin"
                  class="btn btn-danger btn-sm flex-grow-1"
                  @click="confirmDeletion(account)"
              >
                Delete
              </button>
            </div>
          </td>
        </tr>
        </tbody>
      </table>
      <PaginationControls
          :current-page="accountsCurrentPage"
          :total-pages="accountsTotalPages"
          :total-items="accountsArray.length"
          :start-item="accountsStartItem"
          :end-item="accountsEndItem"
          :page-size="pageSize"
          @prev="accountsPrev"
          @next="accountsNext"
          @update:page-size="setPageSize"
      />
    </div>

    <button
        id="CreateAcmeAccountButton"
        v-if="authStore.isAdmin"
        class="btn btn-primary mx-1"
        @click="openCreateModal"
    >
      Create ACME Account
    </button>

    <div v-if="loading" class="text-center mt-3">Loading ACME accounts...</div>
    <div v-if="error" class="alert alert-danger mt-3">{{ error }}</div>

    <hr class="mt-4" />
    <h1>ACME Orders</h1>
    <hr />
    <div class="table-responsive">
      <table class="table table-striped">
        <thead>
        <tr>
          <th>ID</th>
          <th>Account</th>
          <th>Status</th>
          <th>Domains</th>
          <th class="d-none d-lg-table-cell">Expires</th>
          <th>Certificate ID</th>
          <th class="d-none d-lg-table-cell">Client IP</th>
          <th>Error</th>
        </tr>
        </thead>
        <tbody>
        <tr v-for="order in paginatedOrders" :key="order.id">
          <td>{{ order.id }}</td>
          <td>{{ order.account_name }}</td>
          <td>
            <span class="badge" :class="orderStatusBadgeClass(order.status)">{{ order.status }}</span>
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
          <td colspan="8" class="text-center text-muted">No orders yet.</td>
        </tr>
        </tbody>
      </table>
      <PaginationControls
          :current-page="ordersCurrentPage"
          :total-pages="ordersTotalPages"
          :total-items="ordersArray.length"
          :start-item="ordersStartItem"
          :end-item="ordersEndItem"
          :page-size="pageSize"
          @prev="ordersPrev"
          @next="ordersNext"
          @update:page-size="setPageSize"
      />
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
            <h5 class="modal-title">Create ACME Account</h5>
            <button type="button" class="btn-close" @click="closeCreateModal"></button>
          </div>
          <div class="modal-body">
            <div class="mb-3">
              <label for="acmeName" class="form-label">Name</label>
              <input
                  id="acmeName"
                  v-model="createForm.name"
                  type="text"
                  class="form-control"
                  placeholder="Enter account name"
                  required
              />
            </div>
            <div class="mb-3">
              <label class="form-label">Allowed Domains</label>
              <div class="input-group mb-2">
                <input
                    id="acmeDomainInput"
                    v-model="domainInput"
                    type="text"
                    class="form-control"
                    placeholder="e.g. *.example.com or api.internal"
                    @keydown.enter.prevent="addDomain"
                />
                <button
                    class="btn btn-outline-secondary"
                    type="button"
                    @click="addDomain"
                >
                  Add
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
                No domains added yet.
              </div>
            </div>
            <div class="mb-3">
              <label for="acmeCA" class="form-label">CA (optional)</label>
              <select
                  id="acmeCA"
                  v-model="createForm.ca_id"
                  class="form-select"
              >
                <option :value="null">Default (Latest TLS CA)</option>
                <option v-for="ca in cas.values()" :key="ca.id" :value="ca.id">
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
                Auto-validate challenges
              </label>
              <div class="form-text text-warning">
                When enabled, challenge validation (HTTP-01 and DNS-01) is skipped. The allowed domains
                allowlist above becomes the sole access control for certificate issuance.
              </div>
            </div>
          </div>
          <div class="modal-footer">
            <button type="button" class="btn btn-secondary" @click="closeCreateModal">
              Cancel
            </button>
            <button
                type="button"
                class="btn btn-primary"
                :disabled="loading || !createForm.name"
                @click="createAccount"
            >
              <span v-if="loading">Creating...</span>
              <span v-else>Create Account</span>
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
            <h5 class="modal-title">Account Created Successfully!</h5>
            <button type="button" class="btn-close" @click="closeCredentialsModal"></button>
          </div>
          <div class="modal-body">
            <div class="alert alert-warning">
              <strong>Save the HMAC key now — it won't be shown again.</strong>
            </div>
            <div class="mb-3">
              <label class="form-label">EAB Key ID</label>
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
                    title="Copy to clipboard"
                >
                  Copy
                </button>
              </div>
            </div>
            <div class="mb-3">
              <label class="form-label">EAB HMAC Key</label>
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
                    title="Copy to clipboard"
                >
                  Copy
                </button>
              </div>
            </div>
            <div class="mt-4">
              <h6>Example Usage</h6>
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
                <h6 class="text-muted small">DNS-01 examples</h6>
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
              Close
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
            <h5 class="modal-title">Edit ACME Account</h5>
            <button type="button" class="btn-close" @click="closeEditModal"></button>
          </div>
          <div class="modal-body">
            <div class="mb-3">
              <label for="editAcmeName" class="form-label">Name</label>
              <input
                  id="editAcmeName"
                  v-model="editForm.name"
                  type="text"
                  class="form-control"
                  placeholder="Enter account name"
                  required
              />
            </div>
            <div class="mb-3">
              <label class="form-label">Allowed Domains</label>
              <div class="input-group mb-2">
                <input
                    id="editDomainInput"
                    v-model="editDomainInput"
                    type="text"
                    class="form-control"
                    placeholder="e.g. *.example.com or api.internal"
                    @keydown.enter.prevent="addEditDomain"
                />
                <button
                    class="btn btn-outline-secondary"
                    type="button"
                    @click="addEditDomain"
                >
                  Add
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
                No domains added yet.
              </div>
            </div>
            <div class="mb-3">
              <label for="editAcmeStatus" class="form-label">Status</label>
              <select
                  id="editAcmeStatus"
                  v-model="editForm.status"
                  class="form-select"
              >
                <option value="valid">valid</option>
                <option value="deactivated">deactivated</option>
              </select>
            </div>
            <div class="mb-3 form-check">
              <input
                  id="editAcmeAutoValidate"
                  v-model="editForm.auto_validate"
                  type="checkbox"
                  class="form-check-input"
              />
              <label for="editAcmeAutoValidate" class="form-check-label">
                Auto-validate challenges
              </label>
              <div class="form-text text-warning">
                When enabled, challenge validation (HTTP-01 and DNS-01) is skipped. The allowed domains
                allowlist becomes the sole access control for certificate issuance.
              </div>
            </div>
          </div>
          <div class="modal-footer">
            <button type="button" class="btn btn-secondary" @click="closeEditModal">
              Cancel
            </button>
            <button
                type="button"
                class="btn btn-primary"
                :disabled="loading || !editForm.name"
                @click="saveEdit"
            >
              <span v-if="loading">Saving...</span>
              <span v-else>Save</span>
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
            <h5 class="modal-title">Delete ACME Account</h5>
            <button type="button" class="btn-close" @click="closeDeleteModal"></button>
          </div>
          <div class="modal-body">
            <p>
              Are you sure you want to delete the ACME account
              <strong>{{ accountToDelete?.name }}</strong>?
            </p>
          </div>
          <div class="modal-footer">
            <button type="button" class="btn btn-secondary" @click="closeDeleteModal">
              Cancel
            </button>
            <button type="button" class="btn btn-danger" @click="deleteAccount">
              Delete
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
import { usePagination } from '@/composables/usePagination.ts';
import { usePageSize } from '@/composables/usePageSize.ts';
import PaginationControls from '@/components/PaginationControls.vue';

// stores
const acmeStore = useAcmeStore();
const caStore = useCAStore();
const authStore = useAuthStore();
const userStore = useUserStore();

// local state
const loading = computed(() => acmeStore.loading);
const error = computed(() => acmeStore.error);
const cas = computed(() => caStore.cas);

const accountsArray = computed(() => Array.from(acmeStore.accounts.values()));
const ordersArray = computed(() => Array.from(acmeStore.orders.values()));

const { pageSize, setPageSize } = usePageSize();

const {
    currentPage: accountsCurrentPage,
    totalPages: accountsTotalPages,
    paginated: paginatedAccounts,
    startItem: accountsStartItem,
    endItem: accountsEndItem,
    prev: accountsPrev,
    next: accountsNext,
} = usePagination(accountsArray, pageSize);

const {
    currentPage: ordersCurrentPage,
    totalPages: ordersTotalPages,
    paginated: paginatedOrders,
    startItem: ordersStartItem,
    endItem: ordersEndItem,
    prev: ordersPrev,
    next: ordersNext,
} = usePagination(ordersArray, pageSize);

const acmeDirectoryUrl = window.location.origin + '/api/acme/directory';

// create modal
const isCreateModalVisible = ref(false);
const domainInput = ref('');
const createForm = reactive<{ name: string; allowed_domains: string[]; ca_id: number | null; auto_validate: boolean }>({
  name: '',
  allowed_domains: [],
  ca_id: null,
  auto_validate: false,
});

// credentials modal
const isCredentialsModalVisible = ref(false);
const createdCredentials = ref<CreateAcmeAccountResponse | null>(null);

// edit modal
const isEditModalVisible = ref(false);
const accountToEdit = ref<AcmeAccount | null>(null);
const editDomainInput = ref('');
const editForm = reactive<{ name: string; allowed_domains: string[]; status: string; auto_validate: boolean }>({
  name: '',
  allowed_domains: [],
  status: 'valid',
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
  createForm.ca_id = null;
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
    ca_id: createForm.ca_id,
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
  editForm.status = account.status;
  editForm.auto_validate = account.auto_validate;
  editDomainInput.value = '';
  isEditModalVisible.value = true;
};

const closeEditModal = () => {
  isEditModalVisible.value = false;
  accountToEdit.value = null;
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
      status: editForm.status,
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
