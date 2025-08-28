<template>
  <div class="certificate-grid">
    <!-- Grid View -->
    <div class="row g-3">
      <div 
        v-for="certificate in certificates" 
        :key="certificate.id"
        class="col-xl-3 col-lg-4 col-md-6"
      >
        <div 
          class="certificate-card"
          :class="{ 
            'border-warning': isExpiringSoon(certificate),
            'border-danger': isExpired(certificate)
          }"
        >
          <!-- Card Header -->
          <div class="card-header">
            <div class="d-flex justify-content-between align-items-start">
              <div class="certificate-type-icon">
                <ServerIcon v-if="certificate.certificate_type === 'Server'" />
                <UserIcon v-else />
              </div>
              <div class="card-actions">
                <input 
                  type="checkbox" 
                  class="form-check-input"
                  :checked="selectedCertificates.includes(certificate.id)"
                  @change="toggleSelect(certificate.id)"
                />
              </div>
            </div>
          </div>

          <!-- Card Body -->
          <div class="card-body">
            <!-- Certificate Name -->
            <h6 class="certificate-name">
              <button 
                class="btn btn-link p-0 text-start w-100"
                @click="$emit('select', certificate)"
              >
                {{ certificate.name }}
              </button>
            </h6>

            <!-- Certificate Details -->
            <div class="certificate-details mb-3">
              <div class="detail-item">
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

            <!-- Status and Type Badges -->
            <div class="badges mb-3">
              <span class="badge me-2" :class="getStatusBadgeClass(certificate)">
                {{ certificate.status }}
              </span>
              <span class="badge" :class="getTypeBadgeClass(certificate)">
                {{ certificate.certificate_type }}
                <span v-if="certificate.client_certificate_type" class="ms-1">
                  ({{ certificate.client_certificate_type }})
                </span>
              </span>
            </div>

            <!-- Expiry Information -->
            <div class="expiry-section">
              <div class="expiry-label">
                <CalendarIcon class="me-1" />
                <small class="text-muted">Expires</small>
              </div>
              <div class="expiry-date" :class="getExpiryTextClass(certificate)">
                {{ formatExpiryDate(certificate.valid_until) }}
              </div>
              <div class="expiry-countdown">
                <small :class="getExpiryTextClass(certificate)">
                  {{ getTimeUntilExpiry(certificate.valid_until) }}
                </small>
              </div>
            </div>

            <!-- Progress Bar for Validity -->
            <div class="validity-progress mb-3">
              <div class="progress" style="height: 4px;">
                <div 
                  class="progress-bar" 
                  :class="getValidityProgressClass(certificate)"
                  :style="{ width: getValidityPercentage(certificate) + '%' }"
                ></div>
              </div>
              <div class="d-flex justify-content-between mt-1">
                <small class="text-muted">{{ formatDate(certificate.valid_from) }}</small>
                <small class="text-muted">{{ formatDate(certificate.valid_until) }}</small>
              </div>
            </div>
          </div>

          <!-- Card Footer -->
          <div class="card-footer">
            <div class="d-flex justify-content-between align-items-center">
              <small class="text-muted">
                Created {{ formatDistanceToNow(new Date(certificate.created_at), { addSuffix: true }) }}
              </small>
              
              <div class="card-actions">
                <button 
                  class="btn btn-sm btn-outline-primary me-1"
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
                  <ul class="dropdown-menu dropdown-menu-end">
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
            </div>
          </div>
        </div>
      </div>
    </div>

    <!-- Bulk Actions Bar -->
    <div v-if="selectedCertificates.length > 0" class="bulk-actions-bar mt-4">
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
import ServerIcon from '@/components/icons/ServerIcon.vue'
import UserIcon from '@/components/icons/UserIcon.vue'
import CalendarIcon from '@/components/icons/CalendarIcon.vue'
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
const canBulkRevoke = computed(() => {
  return selectedCertificates.value.some(id => {
    const cert = props.certificates.find(c => c.id === id)
    return cert?.status === 'active'
  })
})

// Methods
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

const isExpired = (certificate: Certificate) => {
  const expiryDate = new Date(certificate.valid_until)
  const now = new Date()
  return expiryDate < now
}

const getStatusBadgeClass = (certificate: Certificate) => {
  switch (certificate.status) {
    case 'active': return 'bg-success'
    case 'expired': return 'bg-warning'
    case 'revoked': return 'bg-danger'
    default: return 'bg-secondary'
  }
}

const getTypeBadgeClass = (certificate: Certificate) => {
  return certificate.certificate_type === 'Server' ? 'bg-primary' : 'bg-info'
}

const getExpiryTextClass = (certificate: Certificate) => {
  const expiryDate = new Date(certificate.valid_until)
  const now = new Date()
  const daysUntilExpiry = (expiryDate.getTime() - now.getTime()) / (1000 * 60 * 60 * 24)
  
  if (daysUntilExpiry < 0) return 'text-danger'
  if (daysUntilExpiry <= 30) return 'text-warning'
  return 'text-success'
}

const getValidityPercentage = (certificate: Certificate) => {
  const validFrom = new Date(certificate.valid_from).getTime()
  const validUntil = new Date(certificate.valid_until).getTime()
  const now = Date.now()
  
  const totalDuration = validUntil - validFrom
  const elapsed = now - validFrom
  
  return Math.min(100, Math.max(0, (elapsed / totalDuration) * 100))
}

const getValidityProgressClass = (certificate: Certificate) => {
  const percentage = getValidityPercentage(certificate)
  if (percentage > 90) return 'bg-danger'
  if (percentage > 75) return 'bg-warning'
  return 'bg-success'
}

const formatDate = (dateString: string) => {
  return format(new Date(dateString), 'MMM d')
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
  console.log('Download certificate', certificate.id, 'in format', format)
}

const bulkDownload = () => {
  console.log('Bulk download certificates:', selectedCertificates.value)
}

const bulkRevoke = () => {
  console.log('Bulk revoke certificates:', selectedCertificates.value)
}
</script>

<style scoped>
.certificate-grid {
  padding: 0;
}

.certificate-card {
  background: var(--color-card);
  border: 1px solid var(--color-border);
  border-radius: var(--radius-lg);
  transition: all var(--transition-fast);
  height: 100%;
  display: flex;
  flex-direction: column;
}

.certificate-card:hover {
  box-shadow: var(--shadow-md);
  transform: translateY(-2px);
}

.certificate-card.border-warning {
  border-color: #ffc107;
  box-shadow: 0 0 0 0.1rem rgba(255, 193, 7, 0.25);
}

.certificate-card.border-danger {
  border-color: #dc3545;
  box-shadow: 0 0 0 0.1rem rgba(220, 53, 69, 0.25);
}

.card-header {
  background: var(--color-background-secondary);
  border-bottom: 1px solid var(--color-border);
  padding: 0.75rem 1rem;
}

.certificate-type-icon {
  width: 2rem;
  height: 2rem;
  color: var(--color-text-secondary);
}

.card-body {
  padding: 1rem;
  flex: 1;
}

.certificate-name {
  margin-bottom: 0.5rem;
  font-size: 1rem;
}

.certificate-name .btn-link {
  color: var(--color-text-primary);
  text-decoration: none;
  font-weight: 500;
  line-height: 1.2;
}

.certificate-name .btn-link:hover {
  color: var(--color-button-primary);
  text-decoration: underline;
}

.certificate-details {
  min-height: 1.5rem;
}

.badges {
  display: flex;
  flex-wrap: wrap;
  gap: 0.25rem;
}

.expiry-section {
  margin-bottom: 1rem;
}

.expiry-label {
  display: flex;
  align-items-center;
  margin-bottom: 0.25rem;
}

.expiry-date {
  font-weight: 500;
  margin-bottom: 0.25rem;
}

.validity-progress {
  margin-top: 1rem;
}

.card-footer {
  background: var(--color-background-secondary);
  border-top: 1px solid var(--color-border);
  padding: 0.75rem 1rem;
  margin-top: auto;
}

.card-actions {
  display: flex;
  gap: 0.25rem;
}

.bulk-actions-bar {
  background: var(--color-focus);
  border: 1px solid var(--color-border);
  border-radius: var(--radius-lg);
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

@media (max-width: 768px) {
  .bulk-actions {
    flex-direction: column;
    gap: 0.5rem;
  }
  
  .bulk-actions .btn {
    width: 100%;
  }
}
</style>
