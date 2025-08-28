<template>
  <div class="modal fade show d-block" tabindex="-1" role="dialog" @click.self="$emit('close')">
    <div class="modal-dialog modal-lg" role="document">
      <div class="modal-content">
        <!-- Modal Header -->
        <div class="modal-header">
          <h5 class="modal-title">
            <CertificateIcon class="me-2" />
            Create New Certificate
          </h5>
          <button type="button" class="btn-close" @click="$emit('close')"></button>
        </div>

        <!-- Modal Body -->
        <div class="modal-body">
          <form @submit.prevent="handleSubmit">
            <!-- Certificate Type Selection -->
            <div class="row mb-4">
              <div class="col-12">
                <label class="form-label">Certificate Type *</label>
                <div class="certificate-type-selector">
                  <div class="row g-3">
                    <div class="col-md-6">
                      <div 
                        class="certificate-type-card"
                        :class="{ active: form.certificate_type === 'Server' }"
                        @click="selectCertificateType('Server')"
                      >
                        <ServerIcon class="type-icon" />
                        <h6>Server Certificate</h6>
                        <p class="text-muted small">For web servers, APIs, and TLS/SSL endpoints</p>
                        <div class="type-features">
                          <span class="badge bg-light text-dark">Server Authentication</span>
                          <span class="badge bg-light text-dark">DNS Names</span>
                        </div>
                      </div>
                    </div>
                    <div class="col-md-6">
                      <div 
                        class="certificate-type-card"
                        :class="{ active: form.certificate_type === 'Client' }"
                        @click="selectCertificateType('Client')"
                      >
                        <UserIcon class="type-icon" />
                        <h6>Client Certificate</h6>
                        <p class="text-muted small">For user or device authentication</p>
                        <div class="type-features">
                          <span class="badge bg-light text-dark">Client Authentication</span>
                          <span class="badge bg-light text-dark">Email/UPN</span>
                        </div>
                      </div>
                    </div>
                  </div>
                </div>
              </div>
            </div>

            <!-- Client Certificate Type (only for Client certificates) -->
            <div v-if="form.certificate_type === 'Client'" class="row mb-4">
              <div class="col-12">
                <label class="form-label">Client Certificate Type *</label>
                <div class="btn-group w-100" role="group">
                  <input 
                    type="radio" 
                    class="btn-check" 
                    id="client-type-user" 
                    v-model="form.client_certificate_type" 
                    value="User"
                  >
                  <label class="btn btn-outline-primary" for="client-type-user">
                    <UserIcon class="me-2" />
                    User Certificate
                    <small class="d-block text-muted">For human authentication</small>
                  </label>

                  <input 
                    type="radio" 
                    class="btn-check" 
                    id="client-type-device" 
                    v-model="form.client_certificate_type" 
                    value="Device"
                  >
                  <label class="btn btn-outline-primary" for="client-type-device">
                    <DeviceIcon class="me-2" />
                    Device Certificate
                    <small class="d-block text-muted">For machine authentication</small>
                  </label>
                </div>
              </div>
            </div>

            <!-- Basic Information -->
            <div class="row mb-3">
              <div class="col-md-6">
                <label for="cert-name" class="form-label">Certificate Name *</label>
                <input
                  id="cert-name"
                  v-model="form.name"
                  type="text"
                  class="form-control"
                  :class="{ 'is-invalid': errors.name }"
                  placeholder="Enter certificate name"
                  required
                />
                <div v-if="errors.name" class="invalid-feedback">{{ errors.name }}</div>
              </div>
              <div class="col-md-6">
                <label for="validity-years" class="form-label">Validity Period *</label>
                <select
                  id="validity-years"
                  v-model="form.validity_years"
                  class="form-select"
                  :class="{ 'is-invalid': errors.validity_years }"
                  required
                >
                  <option value="">Select validity period</option>
                  <option value="1">1 Year</option>
                  <option value="2">2 Years</option>
                  <option value="3">3 Years</option>
                  <option value="5">5 Years</option>
                </select>
                <div v-if="errors.validity_years" class="invalid-feedback">{{ errors.validity_years }}</div>
              </div>
            </div>

            <!-- User Selection (for Client certificates) -->
            <div v-if="form.certificate_type === 'Client'" class="row mb-3">
              <div class="col-12">
                <label for="user-select" class="form-label">User *</label>
                <select
                  id="user-select"
                  v-model="form.user_id"
                  class="form-select"
                  :class="{ 'is-invalid': errors.user_id }"
                  required
                >
                  <option value="">Select user</option>
                  <option v-for="user in availableUsers" :key="user.id" :value="user.id">
                    {{ user.name }} ({{ user.email }})
                  </option>
                </select>
                <div v-if="errors.user_id" class="invalid-feedback">{{ errors.user_id }}</div>
              </div>
            </div>

            <!-- DNS Names (for Server certificates) -->
            <div v-if="form.certificate_type === 'Server'" class="row mb-3">
              <div class="col-12">
                <label class="form-label">DNS Names *</label>
                <div class="dns-names-input">
                  <div v-for="(dns, index) in form.dns_names" :key="index" class="input-group mb-2">
                    <input
                      v-model="form.dns_names[index]"
                      type="text"
                      class="form-control"
                      :placeholder="index === 0 ? 'example.com' : 'Additional DNS name'"
                      @input="validateDnsName(index)"
                    />
                    <button
                      v-if="form.dns_names.length > 1"
                      type="button"
                      class="btn btn-outline-danger"
                      @click="removeDnsName(index)"
                    >
                      <XIcon />
                    </button>
                  </div>
                  <button
                    type="button"
                    class="btn btn-outline-secondary btn-sm"
                    @click="addDnsName"
                  >
                    <PlusIcon class="me-1" />
                    Add DNS Name
                  </button>
                </div>
                <div class="form-text">
                  Enter the domain names this certificate will secure (e.g., example.com, *.example.com)
                </div>
              </div>
            </div>

            <!-- Certificate Authority Selection -->
            <div class="row mb-3">
              <div class="col-12">
                <label for="ca-select" class="form-label">Certificate Authority</label>
                <select
                  id="ca-select"
                  v-model="form.ca_selection"
                  class="form-select"
                >
                  <option value="auto">Auto-select CA</option>
                  <option v-for="ca in availableCAs" :key="ca.id" :value="ca.id">
                    {{ ca.name }} ({{ ca.key_algorithm }})
                  </option>
                </select>
                <div class="form-text">
                  Leave as "Auto-select" to use the most appropriate CA for this certificate type
                </div>
              </div>
            </div>

            <!-- Certificate Profile -->
            <div class="row mb-3">
              <div class="col-12">
                <label for="profile-select" class="form-label">Certificate Profile</label>
                <select
                  id="profile-select"
                  v-model="form.profile_id"
                  class="form-select"
                >
                  <option value="">Use default profile</option>
                  <option v-for="profile in availableProfiles" :key="profile.id" :value="profile.id">
                    {{ profile.name }}
                  </option>
                </select>
                <div class="form-text">
                  Profiles define certificate policies, key usage, and validity constraints
                </div>
              </div>
            </div>

            <!-- Advanced Options -->
            <div class="advanced-options">
              <div class="d-flex align-items-center mb-3">
                <h6 class="mb-0">Advanced Options</h6>
                <button
                  type="button"
                  class="btn btn-link btn-sm ms-auto"
                  @click="showAdvanced = !showAdvanced"
                >
                  {{ showAdvanced ? 'Hide' : 'Show' }} Advanced
                  <ChevronDownIcon v-if="!showAdvanced" class="ms-1" />
                  <ChevronUpIcon v-else class="ms-1" />
                </button>
              </div>

              <div v-if="showAdvanced" class="advanced-fields">
                <!-- Custom SAN -->
                <div class="row mb-3">
                  <div class="col-12">
                    <label for="custom-sans" class="form-label">Custom Subject Alternative Names</label>
                    <textarea
                      id="custom-sans"
                      v-model="form.sans"
                      class="form-control"
                      rows="3"
                      placeholder="DNS:example.com,IP:192.168.1.1,email:user@example.com"
                    ></textarea>
                    <div class="form-text">
                      Custom SAN entries in format: DNS:domain.com,IP:1.2.3.4,email:user@domain.com
                    </div>
                  </div>
                </div>

                <!-- Metadata -->
                <div class="row mb-3">
                  <div class="col-12">
                    <label for="metadata" class="form-label">Metadata (JSON)</label>
                    <textarea
                      id="metadata"
                      v-model="metadataText"
                      class="form-control"
                      rows="4"
                      placeholder='{"department": "IT", "project": "web-server"}'
                    ></textarea>
                    <div class="form-text">
                      Optional metadata in JSON format for certificate tracking and management
                    </div>
                  </div>
                </div>
              </div>
            </div>
          </form>
        </div>

        <!-- Modal Footer -->
        <div class="modal-footer">
          <button type="button" class="btn btn-secondary" @click="$emit('close')">
            Cancel
          </button>
          <button
            type="button"
            class="btn btn-primary"
            :disabled="!isFormValid || loading"
            @click="handleSubmit"
          >
            <span v-if="loading" class="spinner-border spinner-border-sm me-2"></span>
            <CertificateIcon v-else class="me-2" />
            {{ loading ? 'Creating...' : 'Create Certificate' }}
          </button>
        </div>
      </div>
    </div>
  </div>
</template>

<script setup lang="ts">
import { ref, computed, onMounted, watch } from 'vue'
import { useCertificateStore } from '@/stores/certificates'
import { useCAStore } from '@/stores/cas'
import { useUserStore } from '@/stores/users'
import type { CertificateType, ClientCertificateType } from '@/types/Certificate'

// Icons
import CertificateIcon from '@/components/icons/CertificateIcon.vue'
import ServerIcon from '@/components/icons/ServerIcon.vue'
import UserIcon from '@/components/icons/UserIcon.vue'
import DeviceIcon from '@/components/icons/DeviceIcon.vue'
import XIcon from '@/components/icons/XIcon.vue'
import PlusIcon from '@/components/icons/PlusIcon.vue'
import ChevronDownIcon from '@/components/icons/ChevronDownIcon.vue'
import ChevronUpIcon from '@/components/icons/ChevronUpIcon.vue'

// Stores
const certificateStore = useCertificateStore()
const caStore = useCAStore()
const userStore = useUserStore()

// Emits
const emit = defineEmits<{
  close: []
  created: [certificate: any]
}>()

// Reactive state
const loading = ref(false)
const showAdvanced = ref(false)
const metadataText = ref('')

const form = ref({
  name: '',
  certificate_type: '' as CertificateType | '',
  client_certificate_type: '' as ClientCertificateType | '',
  user_id: '',
  validity_years: '',
  dns_names: [''],
  ca_selection: 'auto',
  profile_id: '',
  sans: '',
})

const errors = ref<Record<string, string>>({})

// Computed properties
const availableCAs = computed(() => caStore.cas)
const availableUsers = computed(() => userStore.users)
const availableProfiles = computed(() => {
  // Filter profiles by certificate type
  return [] // TODO: Implement profile store
})

const isFormValid = computed(() => {
  return form.value.name &&
         form.value.certificate_type &&
         form.value.validity_years &&
         (form.value.certificate_type === 'Server' ? 
           form.value.dns_names.some(dns => dns.trim()) : 
           form.value.user_id) &&
         (form.value.certificate_type === 'Client' ? 
           form.value.client_certificate_type : true)
})

// Methods
const selectCertificateType = (type: CertificateType) => {
  form.value.certificate_type = type
  
  // Reset type-specific fields
  if (type === 'Server') {
    form.value.client_certificate_type = ''
    form.value.user_id = ''
    if (form.value.dns_names.length === 0) {
      form.value.dns_names = ['']
    }
  } else {
    form.value.dns_names = ['']
    if (!form.value.client_certificate_type) {
      form.value.client_certificate_type = 'User'
    }
  }
}

const addDnsName = () => {
  form.value.dns_names.push('')
}

const removeDnsName = (index: number) => {
  form.value.dns_names.splice(index, 1)
}

const validateDnsName = (index: number) => {
  const dns = form.value.dns_names[index]
  // Basic DNS validation
  const dnsRegex = /^(\*\.)?[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$/
  
  if (dns && !dnsRegex.test(dns)) {
    errors.value[`dns_${index}`] = 'Invalid DNS name format'
  } else {
    delete errors.value[`dns_${index}`]
  }
}

const validateForm = () => {
  errors.value = {}
  
  if (!form.value.name) {
    errors.value.name = 'Certificate name is required'
  }
  
  if (!form.value.certificate_type) {
    errors.value.certificate_type = 'Certificate type is required'
  }
  
  if (!form.value.validity_years) {
    errors.value.validity_years = 'Validity period is required'
  }
  
  if (form.value.certificate_type === 'Client') {
    if (!form.value.client_certificate_type) {
      errors.value.client_certificate_type = 'Client certificate type is required'
    }
    if (!form.value.user_id) {
      errors.value.user_id = 'User selection is required'
    }
  }
  
  if (form.value.certificate_type === 'Server') {
    const validDnsNames = form.value.dns_names.filter(dns => dns.trim())
    if (validDnsNames.length === 0) {
      errors.value.dns_names = 'At least one DNS name is required'
    }
  }
  
  return Object.keys(errors.value).length === 0
}

const handleSubmit = async () => {
  if (!validateForm()) {
    return
  }
  
  loading.value = true
  
  try {
    // Parse metadata if provided
    let metadata = undefined
    if (metadataText.value.trim()) {
      try {
        metadata = JSON.parse(metadataText.value)
      } catch (e) {
        errors.value.metadata = 'Invalid JSON format'
        loading.value = false
        return
      }
    }
    
    // Prepare request data
    const requestData = {
      name: form.value.name,
      certificate_type: form.value.certificate_type as CertificateType,
      client_certificate_type: form.value.client_certificate_type || undefined,
      user_id: form.value.user_id ? parseInt(form.value.user_id) : undefined,
      validity_years: parseInt(form.value.validity_years),
      dns_names: form.value.certificate_type === 'Server' ? 
        form.value.dns_names.filter(dns => dns.trim()) : undefined,
      ca_selection: form.value.ca_selection === 'auto' ? undefined : form.value.ca_selection,
      profile_id: form.value.profile_id || undefined,
      sans: form.value.sans || undefined,
      metadata,
    }
    
    const certificate = await certificateStore.createCertificate(requestData)
    emit('created', certificate)
  } catch (error: any) {
    console.error('Error creating certificate:', error)
    // Handle specific validation errors
    if (error.response?.data?.errors) {
      errors.value = error.response.data.errors
    }
  } finally {
    loading.value = false
  }
}

// Lifecycle
onMounted(async () => {
  await Promise.all([
    caStore.loadCAs(),
    userStore.loadUsers(),
  ])
})

// Watchers
watch(() => form.value.certificate_type, (newType) => {
  if (newType === 'Client' && !form.value.client_certificate_type) {
    form.value.client_certificate_type = 'User'
  }
})
</script>

<style scoped>
.modal {
  background-color: rgba(0, 0, 0, 0.5);
}

.certificate-type-selector {
  margin-bottom: 1rem;
}

.certificate-type-card {
  border: 2px solid var(--color-border);
  border-radius: var(--radius-lg);
  padding: 1.5rem;
  text-align: center;
  cursor: pointer;
  transition: all var(--transition-fast);
  background: var(--color-card);
}

.certificate-type-card:hover {
  border-color: var(--color-border-secondary);
  background: var(--color-hover);
}

.certificate-type-card.active {
  border-color: var(--color-button-primary);
  background: var(--color-focus);
}

.type-icon {
  width: 3rem;
  height: 3rem;
  margin-bottom: 1rem;
  color: var(--color-text-secondary);
}

.certificate-type-card.active .type-icon {
  color: var(--color-button-primary);
}

.type-features {
  display: flex;
  gap: 0.5rem;
  justify-content: center;
  flex-wrap: wrap;
}

.dns-names-input .input-group {
  margin-bottom: 0.5rem;
}

.advanced-options {
  border-top: 1px solid var(--color-border);
  padding-top: 1rem;
  margin-top: 1rem;
}

.advanced-fields {
  background: var(--color-background-secondary);
  border-radius: var(--radius-md);
  padding: 1rem;
  margin-top: 1rem;
}

.btn-check:checked + .btn {
  background-color: var(--color-button-primary);
  border-color: var(--color-button-primary);
  color: white;
}

.modal-content {
  background: var(--color-card);
  border: 1px solid var(--color-border);
}

.modal-header {
  border-bottom: 1px solid var(--color-border);
}

.modal-footer {
  border-top: 1px solid var(--color-border);
}
</style>
