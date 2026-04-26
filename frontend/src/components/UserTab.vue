// src/components/UserTab.vue
<template>
  <div>
    <h1>{{ $t('users.title') }}</h1>
    <hr />
    <!-- Loading and Error states -->
    <div v-if="userStore.loading" class="alert alert-info">
      {{ $t('common.loading') }}
    </div>
    <div v-if="userStore.error" class="alert alert-danger">
      {{ userStore.error }}
    </div>

    <!-- Users Table -->
    <div class="table-responsive">
      <table class="table table-striped">
        <thead>
          <tr>
            <th>{{ $t('common.username') }}</th>
            <th>{{ $t('common.email') }}</th>
            <th>{{ $t('users.colRole') }}</th>
            <th>{{ $t('common.actions') }}</th>
          </tr>
        </thead>
        <tbody>
          <tr v-for="user in userStore.users" :key="user.id">
            <td :id="'UserName-' + user.id">{{ user.name }}</td>
            <td :id="'UserMail-' + user.id">{{ user.email }}</td>
            <td :id="'UserRole-' + user.id">{{ UserRole[user.role] }}</td>
            <td>
              <div class="d-flex flex-sm-row flex-column gap-1">
                <button
                    :id="'UserDeletebutton-' + user.id"
                    class="btn btn-danger btn-sm flex-grow-1"
                    @click="confirmDeleteUser(user)"
                >
                  {{ $t('common.delete') }}
                </button>
              </div>
            </td>
          </tr>
        </tbody>
      </table>
    </div>

    <!-- Create User Button -->
    <button
      class="btn btn-primary mb-3"
      @click="isCreateModalVisible = true"
    >
      {{ $t('users.createUser') }}
    </button>

    <!-- Create User Modal -->
    <div
      class="modal fade"
      :class="{ 'show d-block': isCreateModalVisible }"
      tabindex="-1"
      v-if="isCreateModalVisible"
    >
      <div class="modal-dialog">
        <div class="modal-content">
          <div class="modal-header">
            <h5 class="modal-title">{{ $t('users.createModal.title') }}</h5>
            <button
              type="button"
              class="btn-close"
              @click="isCreateModalVisible = false"
            ></button>
          </div>
          <div class="modal-body">
            <form @submit.prevent="handleCreateUser">
              <div class="mb-3">
                <label for="user_name" class="form-label">{{ $t('common.username') }}</label>
                <input
                  type="text"
                  class="form-control"
                  id="user_name"
                  v-model="newUser.user_name"
                  required
                >
              </div>
              <div class="mb-3">
                <label for="user_email" class="form-label">{{ $t('common.email') }}</label>
                <input
                    type="text"
                    class="form-control"
                    id="user_email"
                    v-model="newUser.user_email"
                    required
                >
              </div>
              <div class="mb-3">
                <label for="password" class="form-label">{{ $t('common.password') }}</label>
                <input
                  type="password"
                  class="form-control"
                  id="password"
                  v-model="newUser.password"
                >
              </div>
              <div class="mb-3">
                <label for="user_role" class="form-label">{{ $t('users.createModal.role') }}</label>
                <select
                    class="form-select"
                    id="user_role"
                    v-model="newUser.role"
                    required
                >
                  <option :value="UserRole.User">User</option>
                  <option :value="UserRole.Admin">Admin</option>
                </select>
              </div>

              <div class="modal-footer">
                <button
                  type="button"
                  class="btn btn-secondary"
                  @click="isCreateModalVisible = false"
                >
                  {{ $t('common.cancel') }}
                </button>
                <button type="submit" class="btn btn-primary">
                  {{ $t('users.createModal.create') }}
                </button>
              </div>
            </form>
          </div>
        </div>
      </div>
    </div>
    <!-- Modal Backdrop -->
    <div
      class="modal-backdrop fade show"
      v-if="isCreateModalVisible"
    ></div>

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
            <h5 class="modal-title">{{ $t('users.deleteModal.title') }}</h5>
            <button type="button" class="btn-close" @click="closeDeleteModal"></button>
          </div>
          <div class="modal-body">
            <p>
              {{ $t('users.deleteModal.confirm', { name: userToDelete?.name }) }}
            </p>
            <p class="text-warning">
              <small>{{ $t('users.deleteModal.disclaimer') }}</small>
            </p>
          </div>
          <div class="modal-footer">
            <button type="button" class="btn btn-secondary" @click="closeDeleteModal">
              {{ $t('common.cancel') }}
            </button>
            <button type="button" class="btn btn-danger" @click="deleteUser">
              {{ $t('common.delete') }}
            </button>
          </div>
        </div>
      </div>
    </div>
  </div>
</template>

<script setup lang="ts">
import { onMounted, ref } from 'vue';
import { type CreateUserRequest, UserRole, type User } from '@/types/User';
import { useUserStore } from '@/stores/users.ts';
import { useCertificateStore } from '@/stores/certificates.ts';

// Stores
const userStore = useUserStore();

// Local state
const isCreateModalVisible = ref(false);
const isDeleteModalVisible = ref(false);
const userToDelete = ref<User | null>(null);
const newUser = ref<CreateUserRequest>({
  user_name: '',
  user_email: '',
  password: '',
  role: UserRole.User,
});

// Lifecycle hook
onMounted(async () => {
  await userStore.fetchUsers();
});

// Methods
const handleCreateUser = async () => {
  await userStore.createUser(newUser.value);
  isCreateModalVisible.value = false;
  // Reset form
  newUser.value = {
    user_name: '',
    user_email: '',
    password: '',
    role: UserRole.User,
  };
};

const confirmDeleteUser = async (user: User) => {
  userToDelete.value = user;
  isDeleteModalVisible.value = true;
};

const closeDeleteModal = () => {
  userToDelete.value = null;
  isDeleteModalVisible.value = false;
};

const deleteUser = async () => {
  if (userToDelete.value) {
    await userStore.deleteUser(userToDelete.value.id);
    const certStore = useCertificateStore();
    await certStore.fetchCertificates();
    closeDeleteModal();
  }
};
</script>


<style scoped>

:deep(.modal.show) {
  background-color: rgba(0, 0, 0, 0.5);
}
</style>