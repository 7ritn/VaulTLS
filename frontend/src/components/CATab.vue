<template>
  <div>
    <h1>Certificate Authorities</h1>
    <hr />
    <div class="table-responsive">
      <table class="table table-striped">
        <thead>
        <tr>
          <th>CA ID</th>
          <th>Name</th>
          <th class="d-none d-lg-table-cell">Created on</th>
          <th>Valid until</th>
          <th>Actions</th>
        </tr>
        </thead>
        <tbody>
        <tr v-for="ca in cas.values()" :key="ca.id">
          <td :id="'CaId-' + ca.id">{{ ca.id }}</td>
          <td :id="'CAName-' + ca.id">{{ ca.name }}</td>
          <td :id="'CreatedOn-' + ca.id" class="d-none d-lg-table-cell">{{ new Date(ca.created_on).toLocaleDateString() }}</td>
          <td :id="'ValidUntil-' + ca.id">{{ new Date(ca.valid_until).toLocaleDateString() }}</td>
          <td>
            <div class="d-flex flex-sm-row flex-column gap-1">
              <button
                  :id="'DownloadButton-' + ca.id"
                  class="btn btn-primary btn-sm flex-grow-1"
                  @click="downloadCA(ca.id)"
              >
                Download
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
      Create New CA
    </button>

    <div v-if="loading" class="text-center mt-3">Loading CAs...</div>
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
            <h5 class="modal-title">Create New Certificate Authority</h5>
            <button type="button" class="btn-close" @click="closeCreateModal"></button>
          </div>
          <div class="modal-body">
            <div class="mb-3">
              <label for="caName" class="form-label">CA Name</label>
              <input
                  id="caName"
                  v-model="caReq.ca_name"
                  type="text"
                  class="form-control"
                  placeholder="Enter CA name"
                  required
              />
            </div>
            <div class="mb-3">
              <label for="validity" class="form-label">Validity (years)</label>
              <input
                  id="validity"
                  v-model.number="caReq.validity_in_years"
                  type="number"
                  class="form-control"
                  min="1"
                  max="30"
                  placeholder="Enter validity period"
                  required
              />
            </div>
          </div>
          <div class="modal-footer">
            <button type="button" class="btn btn-secondary" @click="closeCreateModal">
              Cancel
            </button>
            <button
                type="button"
                class="btn btn-primary"
                :disabled="loading || !caReq.ca_name || !caReq.validity_in_years"
                @click="createCA"
            >
              <span v-if="loading">Creating...</span>
              <span v-else>Create CA</span>
            </button>
          </div>
        </div>
      </div>
    </div>
  </div>
</template>

<script setup lang="ts">
import {computed, onMounted, reactive, ref} from 'vue';
import {useCAStore} from '@/stores/ca';
import type {CARequirements} from '@/types/CA';
import {useAuthStore} from '@/stores/auth';

// stores
const caStore = useCAStore();
const authStore = useAuthStore();

// local state
const cas = computed(() => caStore.cas);
const loading = computed(() => caStore.loading);
const error = computed(() => caStore.error);

const isCreateModalVisible = ref(false);

const caReq = reactive<CARequirements>({
  ca_name: '',
  validity_in_years: 10,
});

onMounted(async () => {
  await caStore.fetchCAs();
});

const showCreateModal = () => {
  isCreateModalVisible.value = true;
};

const closeCreateModal = () => {
  isCreateModalVisible.value = false;
  caReq.ca_name = '';
  caReq.validity_in_years = 10;
};

const createCA = async () => {
  await caStore.createCA(caReq);
  closeCreateModal();
};

const downloadCA = async (caId: number) => {
  await caStore.downloadCA(caId);
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