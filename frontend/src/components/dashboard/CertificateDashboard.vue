<template>
  <div class="certificate-dashboard">
    <!-- Dashboard Header -->
    <div class="dashboard-header mb-4">
      <div class="row align-items-center">
        <div class="col-md-6">
          <h2 class="mb-0">Certificate Dashboard</h2>
          <p class="text-muted mb-0">Overview of your certificate infrastructure</p>
        </div>
        <div class="col-md-6 text-end">
          <button class="btn btn-outline-secondary me-2" @click="refreshData">
            <RefreshIcon class="me-2" />
            Refresh
          </button>
          <button class="btn btn-primary" @click="$router.push('/certificates/create')">
            <PlusIcon class="me-2" />
            Create Certificate
          </button>
        </div>
      </div>
    </div>

    <!-- Statistics Cards -->
    <div class="row g-4 mb-4">
      <div class="col-xl-3 col-md-6">
        <div class="stat-card">
          <div class="stat-icon bg-primary">
            <CertificateIcon />
          </div>
          <div class="stat-content">
            <h3>{{ statistics?.total || 0 }}</h3>
            <p>Total Certificates</p>
          </div>
        </div>
      </div>
      
      <div class="col-xl-3 col-md-6">
        <div class="stat-card">
          <div class="stat-icon bg-success">
            <CheckIcon />
          </div>
          <div class="stat-content">
            <h3>{{ statistics?.active || 0 }}</h3>
            <p>Active Certificates</p>
          </div>
        </div>
      </div>
      
      <div class="col-xl-3 col-md-6">
        <div class="stat-card">
          <div class="stat-icon bg-warning">
            <AlertIcon />
          </div>
          <div class="stat-content">
            <h3>{{ statistics?.expiring_soon || 0 }}</h3>
            <p>Expiring Soon</p>
          </div>
        </div>
      </div>
      
      <div class="col-xl-3 col-md-6">
        <div class="stat-card">
          <div class="stat-icon bg-danger">
            <XIcon />
          </div>
          <div class="stat-content">
            <h3>{{ statistics?.expired || 0 }}</h3>
            <p>Expired</p>
          </div>
        </div>
      </div>
    </div>

    <!-- Charts Row -->
    <div class="row g-4 mb-4">
      <!-- Certificate Types Chart -->
      <div class="col-lg-6">
        <div class="chart-card">
          <div class="chart-header">
            <h5>Certificate Types</h5>
            <p class="text-muted">Distribution by certificate type</p>
          </div>
          <div class="chart-body">
            <canvas ref="typeChartCanvas" width="400" height="200"></canvas>
          </div>
        </div>
      </div>

      <!-- Expiry Timeline Chart -->
      <div class="col-lg-6">
        <div class="chart-card">
          <div class="chart-header">
            <h5>Expiry Timeline</h5>
            <p class="text-muted">Certificates expiring over time</p>
          </div>
          <div class="chart-body">
            <canvas ref="expiryChartCanvas" width="400" height="200"></canvas>
          </div>
        </div>
      </div>
    </div>

    <!-- Recent Activity and Alerts -->
    <div class="row g-4">
      <!-- Recent Certificates -->
      <div class="col-lg-8">
        <div class="activity-card">
          <div class="activity-header">
            <h5>Recent Certificates</h5>
            <router-link to="/certificates" class="btn btn-sm btn-outline-primary">
              View All
            </router-link>
          </div>
          <div class="activity-body">
            <div v-if="recentCertificates.length === 0" class="text-center py-4">
              <p class="text-muted">No recent certificates</p>
            </div>
            <div v-else class="certificate-list">
              <div 
                v-for="certificate in recentCertificates" 
                :key="certificate.id"
                class="certificate-item"
              >
                <div class="certificate-info">
                  <div class="certificate-name">{{ certificate.name }}</div>
                  <div class="certificate-details">
                    <span class="badge me-2" :class="getStatusBadgeClass(certificate)">
                      {{ certificate.status }}
                    </span>
                    <span class="text-muted">{{ certificate.certificate_type }}</span>
                  </div>
                </div>
                <div class="certificate-date">
                  <small class="text-muted">
                    {{ formatDistanceToNow(new Date(certificate.created_at), { addSuffix: true }) }}
                  </small>
                </div>
              </div>
            </div>
          </div>
        </div>
      </div>

      <!-- Alerts and Notifications -->
      <div class="col-lg-4">
        <div class="alerts-card">
          <div class="alerts-header">
            <h5>Alerts</h5>
          </div>
          <div class="alerts-body">
            <!-- Expiring Soon Alert -->
            <div v-if="expiringSoonCount > 0" class="alert alert-warning">
              <div class="alert-icon">
                <AlertIcon />
              </div>
              <div class="alert-content">
                <strong>{{ expiringSoonCount }}</strong> certificate(s) expiring within 30 days
                <router-link to="/certificates?filter=expiring" class="alert-link">
                  View Details
                </router-link>
              </div>
            </div>

            <!-- Expired Alert -->
            <div v-if="expiredCount > 0" class="alert alert-danger">
              <div class="alert-icon">
                <XIcon />
              </div>
              <div class="alert-content">
                <strong>{{ expiredCount }}</strong> certificate(s) have expired
                <router-link to="/certificates?filter=expired" class="alert-link">
                  View Details
                </router-link>
              </div>
            </div>

            <!-- No Alerts -->
            <div v-if="expiringSoonCount === 0 && expiredCount === 0" class="alert alert-success">
              <div class="alert-icon">
                <CheckIcon />
              </div>
              <div class="alert-content">
                All certificates are healthy
              </div>
            </div>

            <!-- Quick Actions -->
            <div class="quick-actions mt-3">
              <h6>Quick Actions</h6>
              <div class="d-grid gap-2">
                <router-link to="/certificates/create" class="btn btn-sm btn-primary">
                  <PlusIcon class="me-2" />
                  Create Certificate
                </router-link>
                <router-link to="/cas" class="btn btn-sm btn-outline-secondary">
                  <ServerIcon class="me-2" />
                  Manage CAs
                </router-link>
                <router-link to="/audit" class="btn btn-sm btn-outline-secondary">
                  <EyeIcon class="me-2" />
                  View Audit Log
                </router-link>
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  </div>
</template>

<script setup lang="ts">
import { ref, computed, onMounted, nextTick } from 'vue'
import { Chart, registerables } from 'chart.js'
import { formatDistanceToNow } from 'date-fns'
import { useCertificateStore } from '@/stores/certificates'
import type { Certificate } from '@/types/Certificate'

// Register Chart.js components
Chart.register(...registerables)

// Icons
import CertificateIcon from '@/components/icons/CertificateIcon.vue'
import CheckIcon from '@/components/icons/CheckIcon.vue'
import AlertIcon from '@/components/icons/AlertIcon.vue'
import XIcon from '@/components/icons/XIcon.vue'
import RefreshIcon from '@/components/icons/RefreshIcon.vue'
import PlusIcon from '@/components/icons/PlusIcon.vue'
import ServerIcon from '@/components/icons/ServerIcon.vue'
import EyeIcon from '@/components/icons/EyeIcon.vue'

// Store
const certificateStore = useCertificateStore()

// Reactive state
const typeChartCanvas = ref<HTMLCanvasElement>()
const expiryChartCanvas = ref<HTMLCanvasElement>()
const typeChart = ref<Chart>()
const expiryChart = ref<Chart>()

// Computed properties
const statistics = computed(() => certificateStore.statistics)
const recentCertificates = computed(() => 
  certificateStore.certificatesArray
    .sort((a, b) => new Date(b.created_at).getTime() - new Date(a.created_at).getTime())
    .slice(0, 5)
)

const expiringSoonCount = computed(() => 
  certificateStore.expiringSoonCertificates.length
)

const expiredCount = computed(() => 
  certificateStore.expiredCertificates.length
)

// Methods
const getStatusBadgeClass = (certificate: Certificate) => {
  switch (certificate.status) {
    case 'active': return 'bg-success'
    case 'expired': return 'bg-warning'
    case 'revoked': return 'bg-danger'
    default: return 'bg-secondary'
  }
}

const refreshData = async () => {
  await Promise.all([
    certificateStore.searchCertificates(),
    certificateStore.loadStatistics(),
  ])
  updateCharts()
}

const createTypeChart = () => {
  if (!typeChartCanvas.value || !statistics.value) return

  const ctx = typeChartCanvas.value.getContext('2d')
  if (!ctx) return

  typeChart.value = new Chart(ctx, {
    type: 'doughnut',
    data: {
      labels: ['Server', 'Client (User)', 'Client (Device)'],
      datasets: [{
        data: [
          statistics.value.by_type.server,
          statistics.value.by_type.client_breakdown.user,
          statistics.value.by_type.client_breakdown.device,
        ],
        backgroundColor: [
          '#0d6efd',
          '#20c997',
          '#6f42c1',
        ],
        borderWidth: 2,
        borderColor: '#ffffff',
      }]
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      plugins: {
        legend: {
          position: 'bottom',
        }
      }
    }
  })
}

const createExpiryChart = () => {
  if (!expiryChartCanvas.value) return

  const ctx = expiryChartCanvas.value.getContext('2d')
  if (!ctx) return

  // Generate sample data for expiry timeline
  const labels = ['Next 7 days', '8-30 days', '31-90 days', '91-365 days', '1+ years']
  const data = [2, 5, 12, 25, 45] // Sample data

  expiryChart.value = new Chart(ctx, {
    type: 'bar',
    data: {
      labels,
      datasets: [{
        label: 'Certificates',
        data,
        backgroundColor: [
          '#dc3545',
          '#fd7e14',
          '#ffc107',
          '#20c997',
          '#0d6efd',
        ],
        borderWidth: 1,
        borderColor: '#ffffff',
      }]
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      plugins: {
        legend: {
          display: false,
        }
      },
      scales: {
        y: {
          beginAtZero: true,
          ticks: {
            stepSize: 1,
          }
        }
      }
    }
  })
}

const updateCharts = () => {
  nextTick(() => {
    if (typeChart.value) {
      typeChart.value.destroy()
    }
    if (expiryChart.value) {
      expiryChart.value.destroy()
    }
    createTypeChart()
    createExpiryChart()
  })
}

// Lifecycle
onMounted(async () => {
  await refreshData()
  nextTick(() => {
    createTypeChart()
    createExpiryChart()
  })
})
</script>

<style scoped>
.certificate-dashboard {
  padding: 1.5rem;
}

.stat-card {
  background: var(--color-card);
  border: 1px solid var(--color-border);
  border-radius: var(--radius-lg);
  padding: 1.5rem;
  display: flex;
  align-items: center;
  gap: 1rem;
  transition: all var(--transition-fast);
}

.stat-card:hover {
  box-shadow: var(--shadow-md);
}

.stat-icon {
  width: 3rem;
  height: 3rem;
  border-radius: var(--radius-md);
  display: flex;
  align-items: center;
  justify-content: center;
  color: white;
}

.stat-content h3 {
  margin: 0;
  font-size: 2rem;
  font-weight: 700;
  color: var(--color-text-primary);
}

.stat-content p {
  margin: 0;
  color: var(--color-text-secondary);
  font-size: 0.875rem;
}

.chart-card,
.activity-card,
.alerts-card {
  background: var(--color-card);
  border: 1px solid var(--color-border);
  border-radius: var(--radius-lg);
  height: 100%;
}

.chart-header,
.activity-header,
.alerts-header {
  padding: 1.5rem 1.5rem 0;
  border-bottom: 1px solid var(--color-border);
  margin-bottom: 1.5rem;
}

.chart-header h5,
.activity-header h5,
.alerts-header h5 {
  margin: 0;
  color: var(--color-text-primary);
}

.chart-body,
.activity-body,
.alerts-body {
  padding: 0 1.5rem 1.5rem;
}

.chart-body {
  height: 250px;
}

.certificate-item {
  display: flex;
  justify-content: between;
  align-items: center;
  padding: 0.75rem 0;
  border-bottom: 1px solid var(--color-border);
}

.certificate-item:last-child {
  border-bottom: none;
}

.certificate-name {
  font-weight: 500;
  color: var(--color-text-primary);
  margin-bottom: 0.25rem;
}

.certificate-details {
  display: flex;
  align-items: center;
  gap: 0.5rem;
}

.alert {
  display: flex;
  align-items: flex-start;
  gap: 0.75rem;
  padding: 1rem;
  border-radius: var(--radius-md);
  margin-bottom: 1rem;
}

.alert:last-child {
  margin-bottom: 0;
}

.alert-icon {
  width: 1.25rem;
  height: 1.25rem;
  flex-shrink: 0;
}

.alert-content {
  flex: 1;
}

.alert-link {
  display: block;
  margin-top: 0.5rem;
  font-size: 0.875rem;
}

.quick-actions h6 {
  margin-bottom: 0.75rem;
  color: var(--color-text-secondary);
  font-size: 0.875rem;
  text-transform: uppercase;
  letter-spacing: 0.05em;
}

@media (max-width: 768px) {
  .certificate-dashboard {
    padding: 1rem;
  }
  
  .dashboard-header .col-md-6:last-child {
    text-align: start !important;
    margin-top: 1rem;
  }
  
  .stat-card {
    padding: 1rem;
  }
  
  .stat-content h3 {
    font-size: 1.5rem;
  }
}
</style>
