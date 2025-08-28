<template>
  <div class="certificate-table">
    <div class="table-responsive">
      <table class="table table-hover">
        <thead>
          <tr>
            <th>
              <input 
                type="checkbox" 
                class="form-check-input"
                :checked="allSelected"
                @change="toggleSelectAll"
              />
            </th>
            <th>Certificate</th>
            <th>Type</th>
            <th>Status</th>
            <th>Expires</th>
            <th>Created</th>
            <th>Actions</th>
          </tr>
        </thead>
        <tbody>
          <tr 
            v-for="certificate in certificates" 
            :key="certificate.id"
            class="certificate-row"
            :class="{ 'table-warning': isExpiringSoon(certificate) }"
          >
            <td>
              <input 
                type="checkbox" 
                class="form-check-input"
                :checked="selectedCertificates.includes(certificate.id)"
                @change="toggleSelect(certificate.id)"
              />
            </td>
            
            <!-- Certificate Info -->
            <td>
              <div class="certificate-info">
                <div class="certificate-name">
                  <button 
                    class="btn btn-link p-0 text-start"
                    @click="$emit('select', certificate)"
                  >
                    {{ certificate.name }}
                  </button>
                </div>
                <div class="certificate-details">
                  <small class="text-muted">
                    <span v-if="certificate.certificate_type === 'Server'">
                      {{ certificate.sans?.[0] || certificate.subject_cn }}
                    </span>
                    <span v-else>
                      {{ certificate.user_name || certificate.subject_cn }}
                    </span>
                  </small>
                </div>
              </div>
            </td>
            
            <!-- Type -->
            <td>
              <div class="certificate-type">
                <span class="badge" :class="getTypeBadgeClass(certificate)">
                  {{ certificate.certificate_type }}
                </span>
                <div v-if="certificate.client_certificate_type" class="mt-1">
                  <small class="text-muted">{{ certificate.client_certificate_type }}</small>
                </div>
              </div>
            </td>
            
            <!-- Status -->
            <td>
              <span class="badge" :class="getStatusBadgeClass(certificate)">
                {{ certificate.status }}
              </span>
            </td>
            
            <!-- Expiry -->
            <td>
              <div class="expiry-info">
                <div :class="getExpiryTextClass(certificate)">
                  {{ formatExpiryDate(certificate.valid_until) }}
                </div>
                <small class="text-muted">
                  {{ getTimeUntilExpiry(certificate.valid_until) }}
                </small>
              </div>
            </td>
            
            <!-- Created -->
            <td>
              <div class="created-info">
                {{ formatDate(certificate.created_at) }}
              </div>
            </td>
            
            <!-- Actions -->
            <td>
              <div class="btn-group" role="group">
                <button 
                  class="btn btn-sm btn-outline-primary"
                  @click="$emit('download', certificate)"
                  title="Download"
                >
                  <DownloadIcon />
                </button>
                
                <div class="dropdown">
                  <button 
                    class="btn btn-sm btn-outline-secondary dropdown-toggle" 
                    type="button" 
                    data-bs-toggle="dropdown"
                    title="More actions"
                  >
                    <MoreIcon />
                  </button>
                  <ul class="dropdown-menu">
                    <li>
                      <a class="dropdown-item" href="#" @click="$emit('select', certificate)">
                        <EyeIcon class="me-2" />
                        View Details
                      </a>
                    </li>
                    <li v-if="certificate.status === 'active'">
                      <a class="dropdown-item" href="#" @click="$emit('renew', certificate)">
                        <RefreshIcon class="me-2" />
                        Renew
                      </a>
                    </li>
                    <li v-if="certificate.status === 'active'">
                      <a class="dropdown-item text-warning" href="#" @click="$emit('revoke', certificate)">
                        <XIcon class="me-2" />
                        Revoke
                      </a>
                    </li>
                    <li><hr class="dropdown-divider"></li>
                    <li>
                      <a class="dropdown-item" href="#" @click="downloadFormat(certificate, 'pem')">
                        <DownloadIcon class="me-2" />
                        Download PEM
                      </a>
                    </li>
                    <li>
                      <a class="dropdown-item" href="#" @click="downloadFormat(certificate, 'p12')">
                        <DownloadIcon class="me-2" />
                        Download PKCS#12
                      </a>
                    </li>
                  </ul>
                </div>
              </div>
            </td>
          </tr>
        </tbody>
      </table>
    </div>

    <!-- Bulk Actions Bar -->
    <div v-if="selectedCertificates.length > 0" class="bulk-actions-bar">
      <div class="d-flex align-items-center justify-content-between">
        <div class="selected-count">
          <strong>{{ selectedCertificates.length }}</strong> certificate(s) selected
        </div>
        <div class="bulk-actions">
          <button 
            class="btn btn-sm btn-primary me-2"
            @click="bulkDownload"
          >
            <DownloadIcon class="me-1" />
            Download Selected
          </button>
          <button 
            class="btn btn-sm btn-outline-danger"
            @click="bulkRevoke"
            :disabled="!canBulkRevoke"
          >
            <XIcon class="me-1" />
            Revoke Selected
          </button>
          <button 
            class="btn btn-sm btn-outline-secondary ms-2"
            @click="clearSelection"
          >
            Clear Selection
          </button>
        </div>
      </div>
    </div>

    <!-- Empty State -->
    <div v-if="certificates.length === 0" class="empty-state text-center py-5">
      <CertificateIcon class="empty-icon mb-3" />
      <h5>No certificates found</h5>
      <p class="text-muted">No certificates match your current search criteria.</p>
    </div>
  </div>
</template>

<script setup lang="ts">
import { ref, computed } from 'vue'
import { format, formatDistanceToNow } from 'date-fns'
import type { Certificate } from '@/types/Certificate'

// Icons
import DownloadIcon from '@/components/icons/DownloadIcon.vue'
import MoreIcon from '@/components/icons/MoreIcon.vue'
import EyeIcon from '@/components/icons/EyeIcon.vue'
import RefreshIcon from '@/components/icons/RefreshIcon.vue'
import XIcon from '@/components/icons/XIcon.vue'
import CertificateIcon from '@/components/icons/CertificateIcon.vue'

// Props
const props = defineProps<{
  certificates: Certificate[]
  loading?: boolean
}>()

// Emits
const emit = defineEmits<{
  select: [certificate: Certificate]
  download: [certificate: Certificate]
  revoke: [certificate: Certificate]
  renew: [certificate: Certificate]
}>()

// Reactive state
const selectedCertificates = ref<number[]>([])

// Computed properties
const allSelected = computed(() => {
  return props.certificates.length > 0 && 
         selectedCertificates.value.length === props.certificates.length
})

const canBulkRevoke = computed(() => {
  return selectedCertificates.value.some(id => {
    const cert = props.certificates.find(c => c.id === id)
    return cert?.status === 'active'
  })
})

// Methods
const toggleSelectAll = () => {
  if (allSelected.value) {
    selectedCertificates.value = []
  } else {
    selectedCertificates.value = props.certificates.map(cert => cert.id)
  }
}

const toggleSelect = (certificateId: number) => {
  const index = selectedCertificates.value.indexOf(certificateId)
  if (index > -1) {
    selectedCertificates.value.splice(index, 1)
  } else {
    selectedCertificates.value.push(certificateId)
  }
}

const clearSelection = () => {
  selectedCertificates.value = []
}

const isExpiringSoon = (certificate: Certificate) => {
  const expiryDate = new Date(certificate.valid_until)
  const now = new Date()
  const daysUntilExpiry = (expiryDate.getTime() - now.getTime()) / (1000 * 60 * 60 * 24)
  return certificate.status === 'active' && daysUntilExpiry <= 30 && daysUntilExpiry > 0
}

const getTypeBadgeClass = (certificate: Certificate) => {
  return certificate.certificate_type === 'Server' ? 'bg-primary' : 'bg-info'
}

const getStatusBadgeClass = (certificate: Certificate) => {
  switch (certificate.status) {
    case 'active': return 'bg-success'
    case 'expired': return 'bg-warning'
    case 'revoked': return 'bg-danger'
    default: return 'bg-secondary'
  }
}

const getExpiryTextClass = (certificate: Certificate) => {
  const expiryDate = new Date(certificate.valid_until)
  const now = new Date()
  const daysUntilExpiry = (expiryDate.getTime() - now.getTime()) / (1000 * 60 * 60 * 24)
  
  if (daysUntilExpiry < 0) return 'text-danger'
  if (daysUntilExpiry <= 30) return 'text-warning'
  return 'text-success'
}

const formatDate = (dateString: string) => {
  return format(new Date(dateString), 'MMM d, yyyy')
}

const formatExpiryDate = (dateString: string) => {
  return format(new Date(dateString), 'MMM d, yyyy')
}

const getTimeUntilExpiry = (dateString: string) => {
  const expiryDate = new Date(dateString)
  const now = new Date()
  
  if (expiryDate < now) {
    return 'Expired ' + formatDistanceToNow(expiryDate, { addSuffix: true })
  }
  
  return formatDistanceToNow(expiryDate, { addSuffix: true })
}

const downloadFormat = (certificate: Certificate, format: string) => {
  // TODO: Implement format-specific download
  console.log('Download certificate', certificate.id, 'in format', format)
}

const bulkDownload = () => {
  // TODO: Implement bulk download
  console.log('Bulk download certificates:', selectedCertificates.value)
}

const bulkRevoke = () => {
  // TODO: Implement bulk revoke
  console.log('Bulk revoke certificates:', selectedCertificates.value)
}
</script>

<style scoped>
.certificate-table {
  background: var(--color-card);
  border-radius: var(--radius-lg);
  overflow: hidden;
}

.table {
  margin-bottom: 0;
}

.table th {
  background: var(--color-background-secondary);
  border-bottom: 2px solid var(--color-border);
  font-weight: 600;
  color: var(--color-text-secondary);
  font-size: 0.875rem;
}

.table td {
  vertical-align: middle;
  border-bottom: 1px solid var(--color-border);
}

.certificate-row:hover {
  background: var(--color-hover);
}

.certificate-info {
  min-width: 200px;
}

.certificate-name {
  font-weight: 500;
}

.certificate-name .btn-link {
  color: var(--color-text-primary);
  text-decoration: none;
  font-weight: 500;
}

.certificate-name .btn-link:hover {
  color: var(--color-button-primary);
  text-decoration: underline;
}

.certificate-details {
  margin-top: 0.25rem;
}

.certificate-type {
  min-width: 100px;
}

.expiry-info,
.created-info {
  min-width: 120px;
}

.bulk-actions-bar {
  background: var(--color-focus);
  border-top: 1px solid var(--color-border);
  padding: 1rem;
}

.empty-state {
  padding: 3rem 1rem;
}

.empty-icon {
  width: 3rem;
  height: 3rem;
  color: var(--color-text-muted);
}

.btn-group .btn {
  border-radius: var(--radius-sm);
}

.btn-group .btn + .btn {
  margin-left: 0.25rem;
}

.dropdown-menu {
  background: var(--color-card);
  border: 1px solid var(--color-border);
  box-shadow: var(--shadow-lg);
}

.dropdown-item {
  color: var(--color-text-primary);
}

.dropdown-item:hover {
  background: var(--color-hover);
  color: var(--color-text-primary);
}

.table-warning {
  background-color: rgba(255, 193, 7, 0.1);
}

@media (max-width: 768px) {
  .certificate-table {
    font-size: 0.875rem;
  }
  
  .btn-group .btn {
    padding: 0.25rem 0.5rem;
  }
  
  .bulk-actions {
    flex-direction: column;
    gap: 0.5rem;
  }
}
</style>
