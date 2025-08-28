import axios, { AxiosInstance, AxiosRequestConfig, AxiosResponse } from 'axios'
import { useAuthStore } from '@/stores/auth'

// Create axios instance with default configuration
export const apiClient: AxiosInstance = axios.create({
  baseURL: import.meta.env.VITE_API_BASE_URL || '',
  timeout: 30000,
  headers: {
    'Content-Type': 'application/json',
  },
})

// Request interceptor to add authentication
apiClient.interceptors.request.use(
  (config) => {
    const authStore = useAuthStore()
    
    // Add Bearer token if available
    if (authStore.bearerToken) {
      config.headers.Authorization = `Bearer ${authStore.bearerToken}`
    }
    
    // Add session cookie for legacy endpoints
    if (authStore.isAuthenticated && !config.headers.Authorization) {
      // Session cookie will be sent automatically by browser
      config.withCredentials = true
    }
    
    return config
  },
  (error) => {
    return Promise.reject(error)
  }
)

// Response interceptor for error handling
apiClient.interceptors.response.use(
  (response: AxiosResponse) => {
    return response
  },
  (error) => {
    const authStore = useAuthStore()
    
    // Handle authentication errors
    if (error.response?.status === 401) {
      // Clear authentication state
      authStore.logout()
      
      // Redirect to login if not already there
      if (window.location.pathname !== '/login') {
        window.location.href = '/login'
      }
    }
    
    // Handle rate limiting
    if (error.response?.status === 429) {
      console.warn('Rate limit exceeded. Please try again later.')
    }
    
    // Handle server errors
    if (error.response?.status >= 500) {
      console.error('Server error occurred:', error.response.data)
    }
    
    return Promise.reject(error)
  }
)

// API client wrapper with typed responses
export class ApiClient {
  private client: AxiosInstance

  constructor(client: AxiosInstance) {
    this.client = client
  }

  async get<T>(url: string, config?: AxiosRequestConfig): Promise<AxiosResponse<T>> {
    return this.client.get<T>(url, config)
  }

  async post<T>(url: string, data?: any, config?: AxiosRequestConfig): Promise<AxiosResponse<T>> {
    return this.client.post<T>(url, data, config)
  }

  async put<T>(url: string, data?: any, config?: AxiosRequestConfig): Promise<AxiosResponse<T>> {
    return this.client.put<T>(url, data, config)
  }

  async patch<T>(url: string, data?: any, config?: AxiosRequestConfig): Promise<AxiosResponse<T>> {
    return this.client.patch<T>(url, data, config)
  }

  async delete<T>(url: string, config?: AxiosRequestConfig): Promise<AxiosResponse<T>> {
    return this.client.delete<T>(url, config)
  }
}

// Export typed client instance
export const api = new ApiClient(apiClient)

// Utility functions for common API patterns
export const createFormData = (data: Record<string, any>): FormData => {
  const formData = new FormData()
  
  Object.entries(data).forEach(([key, value]) => {
    if (value !== null && value !== undefined) {
      if (value instanceof File) {
        formData.append(key, value)
      } else if (Array.isArray(value)) {
        value.forEach((item, index) => {
          formData.append(`${key}[${index}]`, item)
        })
      } else if (typeof value === 'object') {
        formData.append(key, JSON.stringify(value))
      } else {
        formData.append(key, String(value))
      }
    }
  })
  
  return formData
}

export const downloadFile = (blob: Blob, filename: string): void => {
  const url = window.URL.createObjectURL(blob)
  const link = document.createElement('a')
  link.href = url
  link.download = filename
  document.body.appendChild(link)
  link.click()
  document.body.removeChild(link)
  window.URL.revokeObjectURL(url)
}

// Error handling utilities
export const getErrorMessage = (error: any): string => {
  if (error.response?.data?.detail) {
    return error.response.data.detail
  }
  
  if (error.response?.data?.message) {
    return error.response.data.message
  }
  
  if (error.message) {
    return error.message
  }
  
  return 'An unexpected error occurred'
}

export const isNetworkError = (error: any): boolean => {
  return !error.response && error.request
}

export const isServerError = (error: any): boolean => {
  return error.response?.status >= 500
}

export const isClientError = (error: any): boolean => {
  return error.response?.status >= 400 && error.response?.status < 500
}

// API endpoints constants
export const API_ENDPOINTS = {
  // Authentication
  LOGIN: '/api/auth/login',
  LOGOUT: '/api/auth/logout',
  REFRESH: '/api/auth/refresh',
  
  // Certificates
  CERTIFICATES: '/api/certificates',
  CERTIFICATE_SEARCH: '/api/certificates/search',
  CERTIFICATE_BULK_DOWNLOAD: '/api/certificates/bulk-download',
  CERTIFICATE_STATISTICS: '/api/certificates/statistics',
  
  // Certificate Authorities
  CAS: '/api/cas',
  
  // Users
  USERS: '/api/users',
  
  // API Tokens
  TOKENS: '/api/tokens',
  
  // Audit
  AUDIT_EVENTS: '/api/audit/events',
  
  // Server
  SERVER_HEALTH: '/api/server/health',
  SERVER_VERSION: '/api/server/version',
  SERVER_INFO: '/api/server/info',
  
  // Documentation
  API_DOCS: '/docs',
  OPENAPI_SPEC: '/api/openapi.json',
} as const

export default apiClient
