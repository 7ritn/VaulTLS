<template>
  <div>
    <h1>Certificates</h1>
    <hr />
    <div class="table-responsive">
      <table class="table table-striped">
        <thead>
          <tr>
            <th v-if="isAdmin">User</th>
            <th>Name</th>
            <th>SAN</th>
            <th>Created on</th>
            <th>Valid until</th>
            <th>Actions</th>
          </tr>
        </thead>
        <tbody>
          <tr v-for="cert in certificates" :key="cert.id">
            <td v-if="isAdmin">{{ userStore.idToName(cert.user_id) }}</td>
            <td>{{ cert.name }}</td>
            <td>{{ cert.subject_alt_name }}</td>
            <td>{{ new Date(cert.created_on).toLocaleDateString() }}</td>
            <td>{{ new Date(cert.valid_until).toLocaleDateString() }}</td>
            <td>
              <button class="btn btn-primary btn-sm" @click="downloadCertificate(cert.id)">
                Download
              </button>
              <button v-if="isAdmin" class="btn btn-danger btn-sm ms-2" @click="confirmDeletion(cert)">
                Delete
              </button>
            </td>
          </tr>
        </tbody>
      </table>
    </div>

    <button
        v-if="isAdmin"
        class="btn btn-primary mb-3"
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
              <label for="certName" class="form-label">Certificate Name</label>
              <input
                  id="certName"
                  v-model="certReq.cert_name"
                  type="text"
                  class="form-control"
                  placeholder="Enter certificate name"
              />
            </div>
            <div class="mb-3">
              <label for="san" class="form-label">Subject Alternative Name (DNS Name only)</label>
              <input
                  id="san"
                  v-model="certReq.subject_alt_name"
                  type="text"
                  class="form-control"
                  placeholder="e.g. example.lan"
              />
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
              <label for="validity" class="form-label">Validity (years)</label>
              <input
                  id="validity"
                  v-model.number="certReq.validity_in_years"
                  type="number"
                  class="form-control"
                  min="1"
                  placeholder="Enter validity period"
              />
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
                :disabled="loading"
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

<script lang="ts">
import { computed, defineComponent, ref, reactive, onMounted } from 'vue';
import { useCertificateStore } from '@/stores/certificates';
import type { Certificate } from "@/types/Certificate";
import type { CertificateRequirements } from "@/types/CertificateRequirements";
import {useAuthStore} from "@/stores/auth.ts";
import {UserRole} from "@/types/User.ts";
import {useUserStore} from "@/stores/users.ts";
import {useSettingsStore} from "@/stores/settings.ts";

export default defineComponent({
  name: 'OverviewTab',

  setup() {
    const certificateStore = useCertificateStore();
    const authStore = useAuthStore();
    const userStore = useUserStore();
    const settingStore = useSettingsStore();

    const certificates = computed(() => certificateStore.certificates);
    const loading = computed(() => certificateStore.loading);
    const error = computed(() => certificateStore.error);

    // Local state for the modals
    const isDeleteModalVisible = ref(false);
    const isGenerateModalVisible = ref(false);
    const certToDelete = ref<Certificate | null>(null);

    // Reactive form state for Generate
    const certReq = reactive<CertificateRequirements>({
      cert_name: '',
      subject_alt_name: '',
      user_id: 0,
      validity_in_years: 1,
      notify_user: false,
    });
    const isAdmin = computed(() => {
      return authStore.current_user !== null && authStore.current_user.role === UserRole.Admin;
    });
    const isMailValid = computed(() => {
      return settingStore.settings.mail.smtp_host.length > 0 && settingStore.settings.mail.smtp_port > 0;
    })


    // Fetch certificates when the component is mounted
    onMounted(() => {
      certificateStore.fetchCertificates();
      if (isAdmin.value) {
        userStore.fetchUsers();
      }
    });

    const showGenerateModal = () => {
      userStore.fetchUsers();
      isGenerateModalVisible.value = true;
    };

    const closeGenerateModal = () => {
      isGenerateModalVisible.value = false;
      certReq.cert_name = '';
      certReq.subject_alt_name = '';
      certReq.user_id = 0;
      certReq.validity_in_years = 1;
    };

    const createCertificate = async () => {
      try {
        await certificateStore.createCertificate(certReq);
        closeGenerateModal();
      } catch (error) {
        console.error('Error creating certificate:', error);
      }
    };

    const confirmDeletion = (cert: Certificate) => {
      certToDelete.value = cert;
      isDeleteModalVisible.value = true;
    };

    const closeDeleteModal = () => {
      certToDelete.value = null;
      isDeleteModalVisible.value = false;
    };

    const deleteCertificate = async () => {
      if (certToDelete.value) {
        await certificateStore.deleteCertificate(certToDelete.value.id);
        closeDeleteModal();
      }
    };

    return {
      certificates,
      userStore,
      loading,
      error,
      downloadCertificate: certificateStore.downloadCertificate,
      confirmDeletion,
      closeDeleteModal,
      deleteCertificate,
      isDeleteModalVisible,
      certToDelete,
      // Generate certificate related
      certReq,
      isAdmin,
      createCertificate,
      showGenerateModal,
      closeGenerateModal,
      isGenerateModalVisible,
      isMailValid
    };
  },
});
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