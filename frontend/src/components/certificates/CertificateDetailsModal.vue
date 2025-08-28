<template>
  <div class="modal fade show d-block" tabindex="-1" role="dialog" @click.self="$emit('close')">
    <div class="modal-dialog modal-xl" role="document">
      <div class="modal-content">
        <!-- Modal Header -->
        <div class="modal-header">
          <h5 class="modal-title d-flex align-items-center">
            <CertificateIcon class="me-2" />
            Certificate Details
            <span class="badge ms-2" :class="statusBadgeClass">{{ certificate.status }}</span>
          </h5>
          <button type="button" class="btn-close" @click="$emit('close')"></button>
        </div>

        <!-- Modal Body -->
        <div class="modal-body">
          <div class="row">
            <!-- Left Column - Certificate Information -->
            <div class="col-lg-8">
              <!-- Basic Information -->
              <div class="card mb-4">
                <div class="card-header">
                  <h6 class="mb-0">Basic Information</h6>
                </div>
                <div class="card-body">
                  <div class="row">
                    <div class="col-md-6">
                      <div class="info-item">
                        <label>Certificate Name</label>
                        <p>{{ certificate.name }}</p>
                      </div>
                    </div>
                    <div class="col-md-6">
                      <div class="info-item">
                        <label>Certificate Type</label>
                        <p>
                          <TypeIcon class="me-1" />
                          {{ certificate.certificate_type }}
                          <span v-if="certificate.client_certificate_type" class="text-muted">
                            ({{ certificate.client_certificate_type }})
                          </span>
                        </p>
                      </div>
                    </div>
                    <div class="col-md-6">
                      <div class="info-item">
                        <label>Serial Number</label>
                        <p class="font-monospace">{{ certificate.serial_number }}</p>
                      </div>
                    </div>
                    <div class="col-md-6">
                      <div class="info-item">
                        <label>Fingerprint (SHA-256)</label>
                        <p class="font-monospace small">{{ certificate.fingerprint_sha256 }}</p>
                      </div>
                    </div>
                  </div>
                </div>
              </div>

              <!-- Validity Information -->
              <div class="card mb-4">
                <div class="card-header">
                  <h6 class="mb-0">Validity Period</h6>
                </div>
                <div class="card-body">
                  <div class="row">
                    <div class="col-md-6">
                      <div class="info-item">
                        <label>Valid From</label>
                        <p>
                          <CalendarIcon class="me-1" />
                          {{ formatDate(certificate.valid_from) }}
                        </p>
                      </div>
                    </div>
                    <div class="col-md-6">
                      <div class="info-item">
                        <label>Valid Until</label>
                        <p>
                          <CalendarIcon class="me-1" />
                          {{ formatDate(certificate.valid_until) }}
                          <span class="ms-2" :class="expiryWarningClass">
                            ({{ timeUntilExpiry }})
                          </span>
                        </p>
                      </div>
                    </div>
                    <div class="col-12">
                      <div class="validity-timeline">
                        <div class="progress">
                          <div 
                            class="progress-bar" 
                            :class="validityProgressClass"
                            :style="{ width: validityPercentage + '%' }"
                          ></div>
                        </div>
                        <div class="d-flex justify-content-between small text-muted mt-1">
                          <span>Issued</span>
                          <span>{{ validityPercentage.toFixed(1) }}% elapsed</span>
                          <span>Expires</span>
                        </div>
                      </div>
                    </div>
                  </div>
                </div>
              </div>

              <!-- Subject Information -->
              <div class="card mb-4">
                <div class="card-header">
                  <h6 class="mb-0">Subject Information</h6>
                </div>
                <div class="card-body">
                  <div class="row">
                    <div class="col-md-6">
                      <div class="info-item">
                        <label>Common Name (CN)</label>
                        <p>{{ certificate.subject_cn || 'N/A' }}</p>
                      </div>
                    </div>
                    <div class="col-md-6">
                      <div class="info-item">
                        <label>Organization (O)</label>
                        <p>{{ certificate.subject_o || 'N/A' }}</p>
                      </div>
                    </div>
                    <div class="col-md-6">
                      <div class="info-item">
                        <label>Organizational Unit (OU)</label>
                        <p>{{ certificate.subject_ou || 'N/A' }}</p>
                      </div>
                    </div>
                    <div class="col-md-6">
                      <div class="info-item">
                        <label>Country (C)</label>
                        <p>{{ certificate.subject_c || 'N/A' }}</p>
                      </div>
                    </div>
                  </div>
                </div>
              </div>

              <!-- Subject Alternative Names -->
              <div v-if="certificate.sans && certificate.sans.length > 0" class="card mb-4">
                <div class="card-header">
                  <h6 class="mb-0">Subject Alternative Names</h6>
                </div>
                <div class="card-body">
                  <div class="sans-list">
                    <span 
                      v-for="san in certificate.sans" 
                      :key="san"
                      class="badge bg-light text-dark me-2 mb-2"
                    >
                      {{ san }}
                    </span>
                  </div>
                </div>
              </div>

              <!-- Technical Details -->
              <div class="card mb-4">
                <div class="card-header d-flex justify-content-between align-items-center">
                  <h6 class="mb-0">Technical Details</h6>
                  <button 
                    class="btn btn-sm btn-outline-secondary"
                    @click="showTechnicalDetails = !showTechnicalDetails"
                  >
                    {{ showTechnicalDetails ? 'Hide' : 'Show' }} Details
                  </button>
                </div>
                <div v-if="showTechnicalDetails" class="card-body">
                  <div class="row">
                    <div class="col-md-6">
                      <div class="info-item">
                        <label>Key Algorithm</label>
                        <p>{{ certificate.key_algorithm || 'RSA-2048' }}</p>
                      </div>
                    </div>
                    <div class="col-md-6">
                      <div class="info-item">
                        <label>Signature Algorithm</label>
                        <p>{{ certificate.signature_algorithm || 'SHA256withRSA' }}</p>
                      </div>
                    </div>
                    <div class="col-md-6">
                      <div class="info-item">
                        <label>Key Usage</label>
                        <p>{{ certificate.key_usage || 'Digital Signature, Key Encipherment' }}</p>
                      </div>
                    </div>
                    <div class="col-md-6">
                      <div class="info-item">
                        <label>Extended Key Usage</label>
                        <p>{{ certificate.extended_key_usage || 'Server Authentication' }}</p>
                      </div>
                    </div>
                  </div>
                </div>
              </div>
            </div>

            <!-- Right Column - Actions and Metadata -->
            <div class="col-lg-4">
              <!-- Quick Actions -->
              <div class="card mb-4">
                <div class="card-header">
                  <h6 class="mb-0">Actions</h6>
                </div>
                <div class="card-body">
                  <div class="d-grid gap-2">
                    <button 
                      class="btn btn-primary"
                      @click="downloadCertificate"
                      :disabled="loading"
                    >
                      <DownloadIcon class="me-2" />
                      Download Certificate
                    </button>
                    
                    <div class="dropdown">
                      <button 
                        class="btn btn-outline-primary dropdown-toggle w-100" 
                        type="button" 
                        data-bs-toggle="dropdown"
                      >
                        <DownloadIcon class="me-2" />
                        Download Options
                      </button>
                      <ul class="dropdown-menu w-100">
                        <li><a class="dropdown-item" href="#" @click="downloadFormat('pem')">PEM Format</a></li>
                        <li><a class="dropdown-item" href="#" @click="downloadFormat('der')">DER Format</a></li>
                        <li><a class="dropdown-item" href="#" @click="downloadFormat('p12')">PKCS#12 Bundle</a></li>
                        <li><hr class="dropdown-divider"></li>
                        <li><a class="dropdown-item" href="#" @click="downloadChain">Certificate Chain</a></li>
                      </ul>
                    </div>

                    <button 
                      v-if="certificate.status === 'active'"
                      class="btn btn-success"
                      @click="renewCertificate"
                      :disabled="loading"
                    >
                      <RefreshIcon class="me-2" />
                      Renew Certificate
                    </button>

                    <button 
                      v-if="certificate.status === 'active'"
                      class="btn btn-warning"
                      @click="showRevokeModal = true"
                      :disabled="loading"
                    >
                      <XIcon class="me-2" />
                      Revoke Certificate
                    </button>
                  </div>
                </div>
              </div>

              <!-- Certificate Authority -->
              <div class="card mb-4">
                <div class="card-header">
                  <h6 class="mb-0">Certificate Authority</h6>
                </div>
                <div class="card-body">
                  <div class="info-item">
                    <label>Issuer</label>
                    <p>{{ certificate.issuer_cn || 'VaulTLS CA' }}</p>
                  </div>
                  <div class="info-item">
                    <label>CA Serial</label>
                    <p class="font-monospace small">{{ certificate.ca_serial || 'N/A' }}</p>
                  </div>
                </div>
              </div>

              <!-- User Information (for Client certificates) -->
              <div v-if="certificate.certificate_type === 'Client'" class="card mb-4">
                <div class="card-header">
                  <h6 class="mb-0">User Information</h6>
                </div>
                <div class="card-body">
                  <div class="info-item">
                    <label>User</label>
                    <p>
                      <UserIcon class="me-1" />
                      {{ certificate.user_name || 'Unknown User' }}
                    </p>
                  </div>
                  <div class="info-item">
                    <label>Email</label>
                    <p>{{ certificate.user_email || 'N/A' }}</p>
                  </div>
                </div>
              </div>

              <!-- Metadata -->
              <div v-if="certificate.metadata" class="card mb-4">
                <div class="card-header">
                  <h6 class="mb-0">Metadata</h6>
                </div>
                <div class="card-body">
                  <pre class="metadata-json">{{ JSON.stringify(certificate.metadata, null, 2) }}</pre>
                </div>
              </div>

              <!-- Audit Trail -->
              <div class="card">
                <div class="card-header">
                  <h6 class="mb-0">Recent Activity</h6>
                </div>
                <div class="card-body">
                  <div class="timeline">
                    <div class="timeline-item">
                      <div class="timeline-marker bg-success"></div>
                      <div class="timeline-content">
                        <small class="text-muted">{{ formatDate(certificate.created_at) }}</small>
                        <p class="mb-0">Certificate created</p>
                      </div>
                    </div>
                    <div v-if="certificate.last_downloaded_at" class="timeline-item">
                      <div class="timeline-marker bg-info"></div>
                      <div class="timeline-content">
                        <small class="text-muted">{{ formatDate(certificate.last_downloaded_at) }}</small>
                        <p class="mb-0">Last downloaded</p>
                      </div>
                    </div>
                    <div v-if="certificate.revoked_at" class="timeline-item">
                      <div class="timeline-marker bg-danger"></div>
                      <div class="timeline-content">
                        <small class="text-muted">{{ formatDate(certificate.revoked_at) }}</small>
                        <p class="mb-0">Certificate revoked</p>
                      </div>
                    </div>
                  </div>
                </div>
              </div>
            </div>
          </div>
        </div>

        <!-- Modal Footer -->
        <div class="modal-footer">
          <button type="button" class="btn btn-secondary" @click="$emit('close')">
            Close
          </button>
        </div>
      </div>
    </div>
  </div>

  <!-- Revoke Confirmation Modal -->
  <div v-if="showRevokeModal" class="modal fade show d-block" tabindex="-1">
    <div class="modal-dialog">
      <div class="modal-content">
        <div class="modal-header">
          <h5 class="modal-title">Revoke Certificate</h5>
          <button type="button" class="btn-close" @click="showRevokeModal = false"></button>
        </div>
        <div class="modal-body">
          <p>Are you sure you want to revoke this certificate?</p>
          <p class="text-warning">
            <strong>Warning:</strong> This action cannot be undone. The certificate will be immediately invalid.
          </p>
          <div class="mb-3">
            <label for="revoke-reason" class="form-label">Revocation Reason</label>
            <select id="revoke-reason" v-model="revokeReason" class="form-select">
              <option value="unspecified">Unspecified</option>
              <option value="keyCompromise">Key Compromise</option>
              <option value="superseded">Superseded</option>
              <option value="cessationOfOperation">Cessation of Operation</option>
              <option value="privilegeWithdrawn">Privilege Withdrawn</option>
            </select>
          </div>
        </div>
        <div class="modal-footer">
          <button type="button" class="btn btn-secondary" @click="showRevokeModal = false">
            Cancel
          </button>
          <button 
            type="button" 
            class="btn btn-danger"
            @click="confirmRevoke"
            :disabled="loading"
          >
            <span v-if="loading" class="spinner-border spinner-border-sm me-2"></span>
            Revoke Certificate
          </button>
        </div>
      </div>
    </div>
  </div>
</template>

<script setup lang="ts">
import { ref, computed } from 'vue'
import { useCertificateStore } from '@/stores/certificates'
import { formatDistanceToNow, format } from 'date-fns'
import type { Certificate } from '@/types/Certificate'

// Icons
import CertificateIcon from '@/components/icons/CertificateIcon.vue'
import TypeIcon from '@/components/icons/TypeIcon.vue'
import CalendarIcon from '@/components/icons/CalendarIcon.vue'
import DownloadIcon from '@/components/icons/DownloadIcon.vue'
import RefreshIcon from '@/components/icons/RefreshIcon.vue'
import XIcon from '@/components/icons/XIcon.vue'
import UserIcon from '@/components/icons/UserIcon.vue'

// Props
const props = defineProps<{
  certificate: Certificate
}>()

// Emits
const emit = defineEmits<{
  close: []
  updated: [certificate: Certificate]
}>()

// Store
const certificateStore = useCertificateStore()

// Reactive state
const loading = ref(false)
const showTechnicalDetails = ref(false)
const showRevokeModal = ref(false)
const revokeReason = ref('unspecified')

// Computed properties
const statusBadgeClass = computed(() => {
  switch (props.certificate.status) {
    case 'active': return 'bg-success'
    case 'expired': return 'bg-warning'
    case 'revoked': return 'bg-danger'
    default: return 'bg-secondary'
  }
})

const timeUntilExpiry = computed(() => {
  const expiryDate = new Date(props.certificate.valid_until)
  const now = new Date()
  
  if (expiryDate < now) {
    return 'Expired ' + formatDistanceToNow(expiryDate, { addSuffix: true })
  }
  
  return 'Expires ' + formatDistanceToNow(expiryDate, { addSuffix: true })
})

const expiryWarningClass = computed(() => {
  const expiryDate = new Date(props.certificate.valid_until)
  const now = new Date()
  const daysUntilExpiry = (expiryDate.getTime() - now.getTime()) / (1000 * 60 * 60 * 24)
  
  if (daysUntilExpiry < 0) return 'text-danger'
  if (daysUntilExpiry < 30) return 'text-warning'
  return 'text-success'
})

const validityPercentage = computed(() => {
  const validFrom = new Date(props.certificate.valid_from).getTime()
  const validUntil = new Date(props.certificate.valid_until).getTime()
  const now = Date.now()
  
  const totalDuration = validUntil - validFrom
  const elapsed = now - validFrom
  
  return Math.min(100, Math.max(0, (elapsed / totalDuration) * 100))
})

const validityProgressClass = computed(() => {
  const percentage = validityPercentage.value
  if (percentage > 90) return 'bg-danger'
  if (percentage > 75) return 'bg-warning'
  return 'bg-success'
})

// Methods
const formatDate = (dateString: string) => {
  return format(new Date(dateString), 'PPP p')
}

const downloadCertificate = async () => {
  loading.value = true
  try {
    await certificateStore.downloadCertificate(props.certificate.id)
  } catch (error) {
    console.error('Download failed:', error)
  } finally {
    loading.value = false
  }
}

const downloadFormat = async (format: string) => {
  loading.value = true
  try {
    await certificateStore.bulkDownloadCertificates([props.certificate.id], format)
  } catch (error) {
    console.error('Download failed:', error)
  } finally {
    loading.value = false
  }
}

const downloadChain = async () => {
  // TODO: Implement chain download
  console.log('Download chain for certificate:', props.certificate.id)
}

const renewCertificate = async () => {
  loading.value = true
  try {
    const newCertificate = await certificateStore.renewCertificate(props.certificate.id)
    emit('updated', newCertificate)
  } catch (error) {
    console.error('Renewal failed:', error)
  } finally {
    loading.value = false
  }
}

const confirmRevoke = async () => {
  loading.value = true
  try {
    await certificateStore.revokeCertificate(props.certificate.id, revokeReason.value)
    showRevokeModal.value = false
    emit('updated', { ...props.certificate, status: 'revoked' })
  } catch (error) {
    console.error('Revocation failed:', error)
  } finally {
    loading.value = false
  }
}
</script>

<style scoped>
.info-item {
  margin-bottom: 1rem;
}

.info-item label {
  font-weight: 600;
  color: var(--color-text-secondary);
  font-size: 0.875rem;
  margin-bottom: 0.25rem;
  display: block;
}

.info-item p {
  margin: 0;
  color: var(--color-text-primary);
}

.validity-timeline {
  margin-top: 1rem;
}

.sans-list {
  max-height: 200px;
  overflow-y: auto;
}

.metadata-json {
  background: var(--color-background-secondary);
  border: 1px solid var(--color-border);
  border-radius: var(--radius-sm);
  padding: 0.75rem;
  font-size: 0.75rem;
  max-height: 200px;
  overflow-y: auto;
}

.timeline {
  position: relative;
  padding-left: 1.5rem;
}

.timeline::before {
  content: '';
  position: absolute;
  left: 0.5rem;
  top: 0;
  bottom: 0;
  width: 2px;
  background: var(--color-border);
}

.timeline-item {
  position: relative;
  margin-bottom: 1rem;
}

.timeline-marker {
  position: absolute;
  left: -1.5rem;
  top: 0.25rem;
  width: 0.75rem;
  height: 0.75rem;
  border-radius: 50%;
  border: 2px solid var(--color-card);
}

.timeline-content {
  padding-left: 0.5rem;
}

.modal-xl {
  max-width: 1200px;
}

.card {
  background: var(--color-card);
  border: 1px solid var(--color-border);
}

.card-header {
  background: var(--color-background-secondary);
  border-bottom: 1px solid var(--color-border);
}
</style>
