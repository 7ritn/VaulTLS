<template>
  <div>
    <h1>{{ $t('ca.title') }}</h1>
    <hr />
    <div class="table-responsive">
      <table class="table table-striped">
        <thead>
        <tr>
          <th>{{ $t('common.colCaId') }}</th>
          <th>{{ $t('common.colName') }}</th>
          <th v-if="hasAnyOU">{{ $t('common.colGroup') }}</th>
          <th>{{ $t('common.colType') }}</th>
          <th class="d-none d-lg-table-cell">{{ $t('common.colCreatedOn') }}</th>
          <th>{{ $t('common.colValidUntil') }}</th>
          <th>{{ $t('common.actions') }}</th>
        </tr>
        </thead>
        <tbody>
        <tr v-for="ca in cas.values()" :key="ca.id">
          <td :id="'CaId-' + ca.id">{{ ca.id }}</td>
          <td :id="'CAName-' + ca.id">{{ ca.name.cn }}</td>
          <td :id="'CAGroup-' + ca.id" v-if="hasAnyOU">{{ ca.name.ou ?? '' }}</td>
          <td :id="'CAType-' + ca.id">{{ CAType[ca.ca_type] }}</td>
          <td :id="'CreatedOn-' + ca.id" class="d-none d-lg-table-cell">{{ new Date(ca.created_on).toLocaleDateString() }}</td>
          <td :id="'ValidUntil-' + ca.id">
            <span v-if="ca.valid_until != -1">
              {{ new Date(ca.valid_until).toLocaleDateString() }}
            </span>
          </td>
          <td>
            <div class="d-flex flex-sm-row flex-column gap-1">
              <button
                  :id="'DownloadButton-' + ca.id"
                  class="btn btn-primary btn-sm flex-grow-1"
                  @click="downloadCA(ca.id)"
              >
                {{ $t('common.download') }}
              </button>
              <div v-if="ca.ca_type === CAType.TLS" class="btn-group flex-grow-1">
                <button
                    type="button"
                    class="btn btn-outline-primary btn-sm"
                    @click="downloadCRL(ca.id, 'der')"
                    :id="'CRLButton-' + ca.id"
                >
                  {{ $t('ca.crl') }}
                </button>
                <button
                    type="button"
                    class="btn btn-outline-primary btn-sm dropdown-toggle dropdown-toggle-split"
                    data-bs-toggle="dropdown"
                    data-bs-popper-config='{"strategy":"fixed"}'
                    aria-expanded="false"
                    :id="'CRLDropdown-' + ca.id"
                >
                  <span class="visually-hidden">{{ $t('ca.toggle_dropdown') }}</span>
                </button>
                <ul class="dropdown-menu" :aria-labelledby="'CRLDropdown-' + ca.id">
                  <li><a class="dropdown-item" href="#" @click.prevent="downloadCRL(ca.id, 'der')">{{ $t('ca.der_format') }}</a></li>
                  <li><a class="dropdown-item" href="#" @click.prevent="downloadCRL(ca.id, 'pem')">{{ $t('ca.pem_format') }}</a></li>
                </ul>
              </div>
              <button
                  v-if="ca.ca_type === CAType.SSH"
                  :id="'KRLButton-' + ca.id"
                  class="btn btn-outline-primary btn-sm flex-grow-1"
                  @click="downloadCRL(ca.id)"
              >
                {{ $t('ca.krl') }}
              </button>
              <button
                  :id="'DeleteButton-' + ca.id"
                  v-if="authStore.isAdmin"
                  class="btn btn-danger btn-sm flex-grow-1"
                  @click="confirmDeletion(ca)"
              >
                {{ $t('common.delete') }}
              </button>
            </div>
          </td>
        </tr>
        </tbody>
      </table>
    </div>

    <button
        id="CreateCAButton"
        v-if="authStore.isAdmin"
        class="btn btn-primary mx-1"
        @click="showCreateModal"
    >
      {{ $t('ca.createCa') }}
    </button>

    <button
        id="ImportCAButton"
        v-if="authStore.isAdmin"
        class="btn btn-outline-primary mx-1"
        @click="showImportModal"
    >
      {{ $t('ca.importCa') }}
    </button>

    <div v-if="loading" class="text-center mt-3">{{ $t('ca.loadingCas') }}</div>
    <div v-if="error" class="alert alert-danger mt-3">{{ error }}</div>

    <!-- Create CA Modal -->
    <div
        v-if="isCreateModalVisible"
        class="modal show d-block"
        tabindex="-1"
        style="background: rgba(0, 0, 0, 0.5)"
    >
      <div class="modal-dialog">
        <div class="modal-content">
          <div class="modal-header">
            <h5 class="modal-title">{{ $t('ca.createModal.title') }}</h5>
            <button type="button" class="btn-close" @click="closeCreateModal"></button>
          </div>
          <div class="modal-body">
            <div class="mb-3">
              <label for="caName" class="form-label">{{ $t('ca.createModal.caName') }}</label>
              <div class="input-group">
                <input
                    id="caName"
                    v-model="caReq.ca_name.cn"
                    type="text"
                    class="form-control"
                    :placeholder="$t('ca.enterCaCommonName')"
                    required
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
            <div class="mb-3" v-if="showOUField && caReq.ca_type === CAType.TLS">
              <label for="caOU" class="form-label">{{ $t('common.ouGroup') }}</label>
              <input
                  id="caOU"
                  v-model="caReq.ca_name.ou"
                  type="text"
                  class="form-control"
                  placeholder="Enter organizational unit (optional)"
              />
            </div>
            <div class="mb-3">
              <label for="caType" class="form-label">{{ $t('ca.createModal.caType') }}</label>
              <select
                  class="form-select"
                  id="caType"
                  v-model="caReq.ca_type"
                  required
              >
                <option :value="CAType.TLS">TLS</option>
                <option :value="CAType.SSH">SSH</option>
              </select>
            </div>
            <div class="mb-3" v-if="caReq.ca_type === CAType.TLS">
              <label for="validity" class="form-label">{{ $t('common.validity') }}</label>
              <div class="input-group">
                <input
                    id="validity"
                    v-model.number="caReq.validity_duration"
                    type="number"
                    class="form-control"
                    min="1"
                    :placeholder="$t('common.enterValidityPeriod')"
                />
                <select
                    id="validity_unit"
                    v-model="caReq.validity_unit"
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
          </div>
          <div class="modal-footer">
            <button type="button" class="btn btn-secondary" @click="closeCreateModal">
              {{ $t('common.cancel') }}
            </button>
            <button
                type="button"
                class="btn btn-primary"
                :disabled="loading || !caReq.ca_name.cn || (!caReq.validity_duration && caReq.ca_type == CAType.TLS)"
                @click="createCA"
            >
              <span v-if="loading">{{ $t('common.creating') }}</span>
              <span v-else>{{ $t('ca.createModal.create') }}</span>
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
            <h5 class="modal-title">{{ $t('ca.deleteModal.title') }}</h5>
            <button type="button" class="btn-close" @click="closeDeleteModal"></button>
          </div>
          <div class="modal-body">
            <p>
              {{ $t('ca.deleteModal.confirm', { name: caToDelete?.name.cn }) }}
            </p>
          </div>
          <div class="modal-footer">
            <button type="button" class="btn btn-secondary" @click="closeDeleteModal">
              {{ $t('common.cancel') }}
            </button>
            <button type="button" class="btn btn-danger" @click="deleteCA">
              {{ $t('common.delete') }}
            </button>
          </div>
        </div>
      </div>
    </div>

    <!-- Import CA Modal -->
    <div
        v-if="isImportModalVisible"
        class="modal show d-block"
        tabindex="-1"
        style="background: rgba(0, 0, 0, 0.5)"
    >
      <div class="modal-dialog">
        <div class="modal-content">
          <div class="modal-header">
            <h5 class="modal-title">{{ $t('ca.importModal.title') }}</h5>
            <button type="button" class="btn-close" @click="closeImportModal"></button>
          </div>
          <div class="modal-body">
            <div class="mb-3">
              <label for="importFormat" class="form-label">{{ $t('common.format') }}</label>
              <select class="form-select" id="importFormat" v-model="importReq.format">
                <option :value="DataFormat.PEM">PEM</option>
                <option :value="DataFormat.DER">DER (Base64)</option>
              </select>
            </div>
            <div class="mb-3">
              <label for="importCert" class="form-label">{{ $t('ca.importModal.cert') }}</label>
              <textarea
                  id="importCert"
                  v-model="importReq.cert"
                  class="form-control"
                  rows="3"
                  :placeholder="importReq.format === DataFormat.PEM ? '-----BEGIN CERTIFICATE-----...' : 'Base64 encoded DER...'"
                  required
              ></textarea>
            </div>
            <div class="mb-3">
              <label for="importKey" class="form-label">{{ $t('ca.importModal.key') }}</label>
              <textarea
                  id="importKey"
                  v-model="importReq.key"
                  class="form-control"
                  rows="3"
                  :placeholder="importReq.format === DataFormat.PEM ? '-----BEGIN PRIVATE KEY-----...' : 'Base64 encoded DER...'"
                  required
              ></textarea>
            </div>
            <div class="mb-3">
              <label for="importCrl" class="form-label">{{ $t('ca.importModal.crl') }} ({{ $t('common.optional') }})</label>
              <textarea
                  id="importCrl"
                  v-model="importReq.crl"
                  class="form-control"
                  rows="2"
                  :placeholder="importReq.format === DataFormat.PEM ? '-----BEGIN X509 CRL-----...' : 'Base64 encoded DER...'"
              ></textarea>
            </div>
          </div>
          <div class="modal-footer">
            <button type="button" class="btn btn-secondary" @click="closeImportModal">
              {{ $t('common.cancel') }}
            </button>
            <button
                type="button"
                class="btn btn-primary"
                :disabled="loading || !importReq.cert || !importReq.key"
                @click="doImportCA"
            >
              <span v-if="loading">{{ $t('common.importing') }}</span>
              <span v-else>{{ $t('common.import') }}</span>
            </button>
          </div>
        </div>
      </div>
    </div>
  </div>
</template>

<script setup lang="ts">
import {computed, onMounted, reactive, ref} from 'vue';
import {useCAStore} from '@/stores/cas';
import {type CA, type CARequirements, CAType, DataFormat, type ImportCARequest} from '@/types/CA';
import {useAuthStore} from '@/stores/auth';
import {ValidityUnit} from "@/types/ValidityUnit.ts";

// stores
const caStore = useCAStore();
const authStore = useAuthStore();

// local state
const cas = computed(() => caStore.cas);
const loading = computed(() => caStore.loading);
const error = computed(() => caStore.error);
const hasAnyOU = computed(() => Array.from(cas.value.values()).some(ca => ca.name.ou));

const isDeleteModalVisible = ref(false);
const isCreateModalVisible = ref(false);
const isImportModalVisible = ref(false);
const caToDelete = ref<CA | null>(null);

const caReq = reactive<CARequirements>({
  ca_name: { cn: '', ou: undefined },
  ca_type: CAType.TLS,
  validity_duration: undefined,
  validity_unit: ValidityUnit.Year
});

const importReq = reactive<ImportCARequest>({
  cert: '',
  key: '',
  crl: '',
  format: DataFormat.PEM
});

const showOUField = ref(false);

onMounted(async () => {
  await caStore.fetchCAs();
});

const showCreateModal = () => {
  isCreateModalVisible.value = true;
};

const closeCreateModal = () => {
  isCreateModalVisible.value = false;
  caReq.ca_name = { cn: '', ou: undefined };
  caReq.validity_duration = 10;
  caReq.validity_unit = ValidityUnit.Year;
  showOUField.value = false;
};

const showImportModal = () => {
  isImportModalVisible.value = true;
};

const closeImportModal = () => {
  isImportModalVisible.value = false;
  importReq.cert = '';
  importReq.key = '';
  importReq.crl = '';
  importReq.format = DataFormat.PEM;
};

const createCA = async () => {
  await caStore.createCA(caReq);
  closeCreateModal();
};

const doImportCA = async () => {
  await caStore.importCA(importReq);
  closeImportModal();
};

const confirmDeletion = (ca: CA) => {
  caToDelete.value = ca;
  isDeleteModalVisible.value = true;
};

const closeDeleteModal = () => {
  caToDelete.value = null;
  isDeleteModalVisible.value = false;
};

const deleteCA = async () => {
  if (caToDelete.value) {
    await caStore.deleteCA(caToDelete.value.id);
    closeDeleteModal();
  }
};

const downloadCA = async (caId: number) => {
  await caStore.downloadCA(caId);
};

const downloadCRL = async (caId: number, format: string = 'der') => {
  await caStore.downloadCRL(caId, format);
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

.dropdown-toggle-split {
  max-width: 40px;
  min-width: 20px;
}
</style>