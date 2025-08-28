<template>
  <div class="certificate-list">
    <!-- Search and Filters Header -->
    <div class="certificate-list-header">
      <div class="row align-items-center mb-3">
        <div class="col-md-6">
          <h2 class="mb-0">Certificates</h2>
          <p class="text-muted mb-0">Manage your SSL/TLS certificates</p>
        </div>
        <div class="col-md-6 text-end">
          <button 
            class="btn btn-primary"
            @click="showCreateModal = true"
          >
            <PlusIcon class="me-2" />
            Create Certificate
          </button>
        </div>
      </div>

      <!-- Search and Filter Bar -->
      <div class="search-filter-bar card">
        <div class="card-body">
          <div class="row g-3">
            <!-- Search Input -->
            <div class="col-md-4">
              <div class="input-group">
                <span class="input-group-text">
                  <SearchIcon />
                </span>
                <input
                  v-model="searchQuery"
                  type="text"
                  class="form-control"
                  placeholder="Search certificates..."
                  @input="debouncedSearch"
                />
                <button 
                  v-if="searchQuery"
                  class="btn btn-outline-secondary"
                  type="button"
                  @click="clearSearch"
                >
                  <XIcon />
                </button>
              </div>
            </div>

            <!-- Certificate Type Filter -->
            <div class="col-md-2">
              <select v-model="filters.certificateType" class="form-select" @change="applyFilters">
                <option value="">All Types</option>
                <option value="Server">Server</option>
                <option value="Client">Client</option>
              </select>
            </div>

            <!-- Client Certificate Type Filter -->
            <div class="col-md-2" v-if="filters.certificateType === 'Client'">
              <select v-model="filters.clientCertificateType" class="form-select" @change="applyFilters">
                <option value="">All Client Types</option>
                <option value="User">User</option>
                <option value="Device">Device</option>
              </select>
            </div>

            <!-- Status Filter -->
            <div class="col-md-2">
              <select v-model="filters.status" class="form-select" @change="applyFilters">
                <option value="">All Status</option>
                <option value="active">Active</option>
                <option value="expired">Expired</option>
                <option value="revoked">Revoked</option>
                <option value="pending">Pending</option>
              </select>
            </div>

            <!-- Advanced Filters Toggle -->
            <div class="col-md-2">
              <button 
                class="btn btn-outline-secondary w-100"
                @click="showAdvancedFilters = !showAdvancedFilters"
              >
                <FilterIcon class="me-2" />
                Filters
                <ChevronDownIcon v-if="!showAdvancedFilters" class="ms-2" />
                <ChevronUpIcon v-else class="ms-2" />
              </button>
            </div>
          </div>

          <!-- Advanced Filters -->
          <div v-if="showAdvancedFilters" class="advanced-filters mt-3 pt-3 border-top">
            <div class="row g-3">
              <div class="col-md-3">
                <label class="form-label">Expires In</label>
                <select v-model="filters.expiresIn" class="form-select" @change="applyFilters">
                  <option value="">Any Time</option>
                  <option value="7">Next 7 days</option>
                  <option value="30">Next 30 days</option>
                  <option value="90">Next 90 days</option>
                  <option value="365">Next year</option>
                </select>
              </div>
              <div class="col-md-3">
                <label class="form-label">CA</label>
                <select v-model="filters.caId" class="form-select" @change="applyFilters">
                  <option value="">All CAs</option>
                  <option v-for="ca in availableCAs" :key="ca.id" :value="ca.id">
                    {{ ca.name }}
                  </option>
                </select>
              </div>
              <div class="col-md-3">
                <label class="form-label">Created Date</label>
                <input 
                  v-model="filters.createdAfter" 
                  type="date" 
                  class="form-control"
                  @change="applyFilters"
                />
              </div>
              <div class="col-md-3">
                <label class="form-label">Key Algorithm</label>
                <select v-model="filters.algorithm" class="form-select" @change="applyFilters">
                  <option value="">All Algorithms</option>
                  <option value="RSA-2048">RSA 2048</option>
                  <option value="RSA-4096">RSA 4096</option>
                  <option value="ECDSA-P256">ECDSA P-256</option>
                  <option value="ECDSA-P384">ECDSA P-384</option>
                </select>
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>

    <!-- Results Summary -->
    <div class="results-summary d-flex justify-content-between align-items-center mb-3">
      <div>
        <span class="text-muted">
          Showing {{ certificates.length }} of {{ totalCertificates }} certificates
        </span>
        <span v-if="hasActiveFilters" class="badge bg-primary ms-2">
          Filtered
        </span>
      </div>
      <div class="d-flex gap-2">
        <!-- View Toggle -->
        <div class="btn-group" role="group">
          <button 
            type="button" 
            class="btn btn-outline-secondary"
            :class="{ active: viewMode === 'table' }"
            @click="viewMode = 'table'"
          >
            <TableIcon />
          </button>
          <button 
            type="button" 
            class="btn btn-outline-secondary"
            :class="{ active: viewMode === 'grid' }"
            @click="viewMode = 'grid'"
          >
            <GridIcon />
          </button>
        </div>

        <!-- Sort Options -->
        <div class="dropdown">
          <button 
            class="btn btn-outline-secondary dropdown-toggle" 
            type="button" 
            data-bs-toggle="dropdown"
          >
            <SortIcon class="me-2" />
            Sort
          </button>
          <ul class="dropdown-menu">
            <li><a class="dropdown-item" href="#" @click="setSortBy('name')">Name</a></li>
            <li><a class="dropdown-item" href="#" @click="setSortBy('created_at')">Created Date</a></li>
            <li><a class="dropdown-item" href="#" @click="setSortBy('valid_until')">Expiry Date</a></li>
            <li><a class="dropdown-item" href="#" @click="setSortBy('certificate_type')">Type</a></li>
            <li><a class="dropdown-item" href="#" @click="setSortBy('status')">Status</a></li>
          </ul>
        </div>
      </div>
    </div>

    <!-- Loading State -->
    <div v-if="loading" class="text-center py-5">
      <div class="spinner-border text-primary" role="status">
        <span class="visually-hidden">Loading...</span>
      </div>
      <p class="mt-2 text-muted">Loading certificates...</p>
    </div>

    <!-- Error State -->
    <div v-else-if="error" class="alert alert-danger">
      <h5>Error Loading Certificates</h5>
      <p>{{ error }}</p>
      <button class="btn btn-outline-danger" @click="loadCertificates">
        <RefreshIcon class="me-2" />
        Retry
      </button>
    </div>

    <!-- Empty State -->
    <div v-else-if="certificates.length === 0" class="empty-state text-center py-5">
      <CertificateIcon class="empty-icon mb-3" />
      <h4>No Certificates Found</h4>
      <p class="text-muted">
        {{ hasActiveFilters ? 'No certificates match your current filters.' : 'You haven\'t created any certificates yet.' }}
      </p>
      <button 
        v-if="!hasActiveFilters"
        class="btn btn-primary"
        @click="showCreateModal = true"
      >
        Create Your First Certificate
      </button>
      <button 
        v-else
        class="btn btn-outline-secondary"
        @click="clearAllFilters"
      >
        Clear Filters
      </button>
    </div>

    <!-- Certificate Table View -->
    <CertificateTable 
      v-else-if="viewMode === 'table'"
      :certificates="certificates"
      :loading="loading"
      @select="handleCertificateSelect"
      @download="handleCertificateDownload"
      @revoke="handleCertificateRevoke"
      @renew="handleCertificateRenew"
    />

    <!-- Certificate Grid View -->
    <CertificateGrid 
      v-else
      :certificates="certificates"
      :loading="loading"
      @select="handleCertificateSelect"
      @download="handleCertificateDownload"
      @revoke="handleCertificateRevoke"
      @renew="handleCertificateRenew"
    />

    <!-- Pagination -->
    <nav v-if="totalPages > 1" class="mt-4">
      <ul class="pagination justify-content-center">
        <li class="page-item" :class="{ disabled: currentPage === 1 }">
          <a class="page-link" href="#" @click.prevent="goToPage(currentPage - 1)">
            <ChevronLeftIcon />
          </a>
        </li>
        <li 
          v-for="page in visiblePages" 
          :key="page"
          class="page-item" 
          :class="{ active: page === currentPage }"
        >
          <a class="page-link" href="#" @click.prevent="goToPage(page)">
            {{ page }}
          </a>
        </li>
        <li class="page-item" :class="{ disabled: currentPage === totalPages }">
          <a class="page-link" href="#" @click.prevent="goToPage(currentPage + 1)">
            <ChevronRightIcon />
          </a>
        </li>
      </ul>
    </nav>

    <!-- Create Certificate Modal -->
    <CreateCertificateModal 
      v-if="showCreateModal"
      @close="showCreateModal = false"
      @created="handleCertificateCreated"
    />
  </div>
</template>

<script setup lang="ts">
import { ref, computed, onMounted, watch } from 'vue'
import { useCertificateStore } from '@/stores/certificates'
import { useCAStore } from '@/stores/cas'
import { debounce } from '@/utils/debounce'

// Components
import CertificateTable from './CertificateTable.vue'
import CertificateGrid from './CertificateGrid.vue'
import CreateCertificateModal from './CreateCertificateModal.vue'

// Icons
import PlusIcon from '@/components/icons/PlusIcon.vue'
import SearchIcon from '@/components/icons/SearchIcon.vue'
import XIcon from '@/components/icons/XIcon.vue'
import FilterIcon from '@/components/icons/FilterIcon.vue'
import ChevronDownIcon from '@/components/icons/ChevronDownIcon.vue'
import ChevronUpIcon from '@/components/icons/ChevronUpIcon.vue'
import TableIcon from '@/components/icons/TableIcon.vue'
import GridIcon from '@/components/icons/GridIcon.vue'
import SortIcon from '@/components/icons/SortIcon.vue'
import RefreshIcon from '@/components/icons/RefreshIcon.vue'
import CertificateIcon from '@/components/icons/CertificateIcon.vue'
import ChevronLeftIcon from '@/components/icons/ChevronLeftIcon.vue'
import ChevronRightIcon from '@/components/icons/ChevronRightIcon.vue'

// Stores
const certificateStore = useCertificateStore()
const caStore = useCAStore()

// Reactive state
const searchQuery = ref('')
const showAdvancedFilters = ref(false)
const showCreateModal = ref(false)
const viewMode = ref<'table' | 'grid'>('table')
const currentPage = ref(1)
const pageSize = ref(25)

const filters = ref({
  certificateType: '',
  clientCertificateType: '',
  status: '',
  expiresIn: '',
  caId: '',
  createdAfter: '',
  algorithm: ''
})

const sortBy = ref('created_at')
const sortDirection = ref<'asc' | 'desc'>('desc')

// Computed properties
const certificates = computed(() => certificateStore.certificates)
const totalCertificates = computed(() => certificateStore.totalCount)
const loading = computed(() => certificateStore.loading)
const error = computed(() => certificateStore.error)
const availableCAs = computed(() => caStore.cas)

const totalPages = computed(() => Math.ceil(totalCertificates.value / pageSize.value))

const hasActiveFilters = computed(() => {
  return searchQuery.value || 
         Object.values(filters.value).some(filter => filter !== '')
})

const visiblePages = computed(() => {
  const pages = []
  const start = Math.max(1, currentPage.value - 2)
  const end = Math.min(totalPages.value, currentPage.value + 2)
  
  for (let i = start; i <= end; i++) {
    pages.push(i)
  }
  
  return pages
})

// Methods
const loadCertificates = async () => {
  const searchParams = {
    page: currentPage.value,
    per_page: pageSize.value,
    search: searchQuery.value,
    sort: `${sortBy.value}:${sortDirection.value}`,
    ...filters.value
  }
  
  await certificateStore.searchCertificates(searchParams)
}

const debouncedSearch = debounce(() => {
  currentPage.value = 1
  loadCertificates()
}, 300)

const clearSearch = () => {
  searchQuery.value = ''
  currentPage.value = 1
  loadCertificates()
}

const applyFilters = () => {
  currentPage.value = 1
  loadCertificates()
}

const clearAllFilters = () => {
  searchQuery.value = ''
  filters.value = {
    certificateType: '',
    clientCertificateType: '',
    status: '',
    expiresIn: '',
    caId: '',
    createdAfter: '',
    algorithm: ''
  }
  currentPage.value = 1
  loadCertificates()
}

const setSortBy = (field: string) => {
  if (sortBy.value === field) {
    sortDirection.value = sortDirection.value === 'asc' ? 'desc' : 'asc'
  } else {
    sortBy.value = field
    sortDirection.value = 'desc'
  }
  loadCertificates()
}

const goToPage = (page: number) => {
  if (page >= 1 && page <= totalPages.value) {
    currentPage.value = page
    loadCertificates()
  }
}

// Event handlers
const handleCertificateSelect = (certificate: any) => {
  // Navigate to certificate details
  console.log('Select certificate:', certificate)
}

const handleCertificateDownload = (certificate: any) => {
  certificateStore.downloadCertificate(certificate.id)
}

const handleCertificateRevoke = (certificate: any) => {
  // Show revoke confirmation modal
  console.log('Revoke certificate:', certificate)
}

const handleCertificateRenew = (certificate: any) => {
  // Show renew modal
  console.log('Renew certificate:', certificate)
}

const handleCertificateCreated = () => {
  showCreateModal.value = false
  loadCertificates()
}

// Lifecycle
onMounted(async () => {
  await caStore.loadCAs()
  await loadCertificates()
})

// Watchers
watch(currentPage, loadCertificates)
</script>

<style scoped>
.certificate-list-header {
  margin-bottom: 2rem;
}

.search-filter-bar {
  border: 1px solid var(--color-border);
  background: var(--color-card);
}

.advanced-filters {
  background: var(--color-background-secondary);
  border-radius: var(--radius-md);
  padding: 1rem;
}

.results-summary {
  padding: 0.75rem 0;
  border-bottom: 1px solid var(--color-border);
}

.empty-state {
  padding: 4rem 2rem;
}

.empty-icon {
  width: 4rem;
  height: 4rem;
  color: var(--color-text-muted);
}

.btn-group .btn.active {
  background-color: var(--color-button-primary);
  border-color: var(--color-button-primary);
  color: white;
}

.pagination .page-link {
  color: var(--color-text-primary);
  background-color: var(--color-card);
  border-color: var(--color-border);
}

.pagination .page-item.active .page-link {
  background-color: var(--color-button-primary);
  border-color: var(--color-button-primary);
}

.pagination .page-link:hover {
  background-color: var(--color-hover);
  border-color: var(--color-border-secondary);
}
</style>
