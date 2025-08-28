<template>
  <div class="login-container">
    <div class="login-card">
      <!-- Logo and Header -->
      <div class="login-header text-center mb-4">
        <div class="logo mb-3">
          <CertificateIcon class="logo-icon" />
        </div>
        <h2>VaulTLS</h2>
        <p class="text-muted">Certificate Management Platform</p>
      </div>

      <!-- Login Form -->
      <form @submit.prevent="handleLogin">
        <!-- Email Field -->
        <div class="mb-3">
          <label for="email" class="form-label">Email Address</label>
          <div class="input-group">
            <span class="input-group-text">
              <UserIcon />
            </span>
            <input
              id="email"
              v-model="form.email"
              type="email"
              class="form-control"
              :class="{ 'is-invalid': errors.email }"
              placeholder="Enter your email"
              required
              autocomplete="email"
            />
          </div>
          <div v-if="errors.email" class="invalid-feedback">{{ errors.email }}</div>
        </div>

        <!-- Password Field -->
        <div class="mb-3">
          <label for="password" class="form-label">Password</label>
          <div class="input-group">
            <span class="input-group-text">
              <LockIcon />
            </span>
            <input
              id="password"
              v-model="form.password"
              :type="showPassword ? 'text' : 'password'"
              class="form-control"
              :class="{ 'is-invalid': errors.password }"
              placeholder="Enter your password"
              required
              autocomplete="current-password"
            />
            <button
              type="button"
              class="btn btn-outline-secondary"
              @click="showPassword = !showPassword"
            >
              <EyeIcon v-if="!showPassword" />
              <EyeOffIcon v-else />
            </button>
          </div>
          <div v-if="errors.password" class="invalid-feedback">{{ errors.password }}</div>
        </div>

        <!-- Remember Me -->
        <div class="mb-3">
          <div class="form-check">
            <input
              id="remember"
              v-model="form.remember"
              type="checkbox"
              class="form-check-input"
            />
            <label for="remember" class="form-check-label">
              Remember me
            </label>
          </div>
        </div>

        <!-- Error Message -->
        <div v-if="loginError" class="alert alert-danger">
          <AlertIcon class="me-2" />
          {{ loginError }}
        </div>

        <!-- Submit Button -->
        <div class="d-grid mb-3">
          <button
            type="submit"
            class="btn btn-primary"
            :disabled="loading || !isFormValid"
          >
            <span v-if="loading" class="spinner-border spinner-border-sm me-2"></span>
            <LockIcon v-else class="me-2" />
            {{ loading ? 'Signing In...' : 'Sign In' }}
          </button>
        </div>

        <!-- Forgot Password Link -->
        <div class="text-center">
          <a href="#" class="text-decoration-none" @click="showForgotPassword = true">
            Forgot your password?
          </a>
        </div>
      </form>

      <!-- API Token Login Option -->
      <div class="api-login-section mt-4 pt-4 border-top">
        <div class="text-center mb-3">
          <small class="text-muted">Or authenticate with API token</small>
        </div>
        <button
          class="btn btn-outline-secondary w-100"
          @click="showApiTokenLogin = !showApiTokenLogin"
        >
          <KeyIcon class="me-2" />
          Use API Token
        </button>
        
        <div v-if="showApiTokenLogin" class="api-token-form mt-3">
          <div class="mb-3">
            <label for="apiToken" class="form-label">API Token</label>
            <div class="input-group">
              <span class="input-group-text">
                <KeyIcon />
              </span>
              <input
                id="apiToken"
                v-model="apiTokenForm.token"
                type="password"
                class="form-control"
                placeholder="Enter your API token"
              />
            </div>
          </div>
          <button
            type="button"
            class="btn btn-primary w-100"
            @click="handleApiTokenLogin"
            :disabled="!apiTokenForm.token || loading"
          >
            <span v-if="loading" class="spinner-border spinner-border-sm me-2"></span>
            Authenticate with Token
          </button>
        </div>
      </div>
    </div>

    <!-- Forgot Password Modal -->
    <div v-if="showForgotPassword" class="modal fade show d-block" tabindex="-1">
      <div class="modal-dialog">
        <div class="modal-content">
          <div class="modal-header">
            <h5 class="modal-title">Reset Password</h5>
            <button type="button" class="btn-close" @click="showForgotPassword = false"></button>
          </div>
          <div class="modal-body">
            <p>Enter your email address and we'll send you a link to reset your password.</p>
            <div class="mb-3">
              <label for="resetEmail" class="form-label">Email Address</label>
              <input
                id="resetEmail"
                v-model="resetEmail"
                type="email"
                class="form-control"
                placeholder="Enter your email"
              />
            </div>
          </div>
          <div class="modal-footer">
            <button type="button" class="btn btn-secondary" @click="showForgotPassword = false">
              Cancel
            </button>
            <button
              type="button"
              class="btn btn-primary"
              @click="handlePasswordReset"
              :disabled="!resetEmail || loading"
            >
              Send Reset Link
            </button>
          </div>
        </div>
      </div>
    </div>
  </div>
</template>

<script setup lang="ts">
import { ref, computed } from 'vue'
import { useRouter } from 'vue-router'
import { useAuthStore } from '@/stores/auth'

// Icons
import CertificateIcon from '@/components/icons/CertificateIcon.vue'
import UserIcon from '@/components/icons/UserIcon.vue'
import LockIcon from '@/components/icons/LockIcon.vue'
import EyeIcon from '@/components/icons/EyeIcon.vue'
import EyeOffIcon from '@/components/icons/EyeOffIcon.vue'
import AlertIcon from '@/components/icons/AlertIcon.vue'
import KeyIcon from '@/components/icons/KeyIcon.vue'

// Router and Store
const router = useRouter()
const authStore = useAuthStore()

// Reactive state
const loading = ref(false)
const showPassword = ref(false)
const showApiTokenLogin = ref(false)
const showForgotPassword = ref(false)
const resetEmail = ref('')
const loginError = ref('')

const form = ref({
  email: '',
  password: '',
  remember: false,
})

const apiTokenForm = ref({
  token: '',
})

const errors = ref<Record<string, string>>({})

// Computed properties
const isFormValid = computed(() => {
  return form.value.email && form.value.password
})

// Methods
const validateForm = () => {
  errors.value = {}
  
  if (!form.value.email) {
    errors.value.email = 'Email is required'
  } else if (!/\S+@\S+\.\S+/.test(form.value.email)) {
    errors.value.email = 'Please enter a valid email address'
  }
  
  if (!form.value.password) {
    errors.value.password = 'Password is required'
  } else if (form.value.password.length < 6) {
    errors.value.password = 'Password must be at least 6 characters'
  }
  
  return Object.keys(errors.value).length === 0
}

const handleLogin = async () => {
  if (!validateForm()) {
    return
  }
  
  loading.value = true
  loginError.value = ''
  
  try {
    await authStore.login({
      email: form.value.email,
      password: form.value.password,
      remember: form.value.remember,
    })
    
    // Redirect to dashboard or intended route
    const redirectTo = router.currentRoute.value.query.redirect as string || '/dashboard'
    router.push(redirectTo)
  } catch (error: any) {
    loginError.value = error.response?.data?.message || 'Login failed. Please check your credentials.'
  } finally {
    loading.value = false
  }
}

const handleApiTokenLogin = async () => {
  loading.value = true
  loginError.value = ''
  
  try {
    await authStore.loginWithToken(apiTokenForm.value.token)
    
    // Redirect to dashboard
    router.push('/dashboard')
  } catch (error: any) {
    loginError.value = error.response?.data?.message || 'Invalid API token.'
  } finally {
    loading.value = false
  }
}

const handlePasswordReset = async () => {
  if (!resetEmail.value) {
    return
  }
  
  loading.value = true
  
  try {
    // TODO: Implement password reset
    console.log('Password reset for:', resetEmail.value)
    showForgotPassword.value = false
    resetEmail.value = ''
    // Show success message
  } catch (error) {
    console.error('Password reset failed:', error)
  } finally {
    loading.value = false
  }
}
</script>

<style scoped>
.login-container {
  min-height: 100vh;
  display: flex;
  align-items: center;
  justify-content: center;
  background: linear-gradient(135deg, var(--color-background) 0%, var(--color-background-secondary) 100%);
  padding: 2rem;
}

.login-card {
  background: var(--color-card);
  border: 1px solid var(--color-border);
  border-radius: var(--radius-xl);
  padding: 3rem;
  width: 100%;
  max-width: 400px;
  box-shadow: var(--shadow-xl);
}

.logo-icon {
  width: 4rem;
  height: 4rem;
  color: var(--color-button-primary);
}

.login-header h2 {
  color: var(--color-text-primary);
  font-weight: 700;
  margin-bottom: 0.5rem;
}

.input-group-text {
  background: var(--color-background-secondary);
  border-color: var(--color-border);
  color: var(--color-text-secondary);
}

.form-control {
  background: var(--color-background);
  border-color: var(--color-border);
  color: var(--color-text-primary);
}

.form-control:focus {
  background: var(--color-background);
  border-color: var(--color-button-primary);
  box-shadow: 0 0 0 0.2rem rgba(13, 110, 253, 0.25);
  color: var(--color-text-primary);
}

.form-check-input:checked {
  background-color: var(--color-button-primary);
  border-color: var(--color-button-primary);
}

.btn-primary {
  background-color: var(--color-button-primary);
  border-color: var(--color-button-primary);
  font-weight: 500;
}

.btn-outline-secondary {
  border-color: var(--color-border);
  color: var(--color-text-secondary);
}

.btn-outline-secondary:hover {
  background-color: var(--color-hover);
  border-color: var(--color-border-secondary);
  color: var(--color-text-primary);
}

.api-login-section {
  border-top-color: var(--color-border) !important;
}

.modal {
  background-color: rgba(0, 0, 0, 0.5);
}

.modal-content {
  background: var(--color-card);
  border: 1px solid var(--color-border);
}

.modal-header {
  border-bottom-color: var(--color-border);
}

.modal-footer {
  border-top-color: var(--color-border);
}

.alert-danger {
  background-color: rgba(220, 53, 69, 0.1);
  border-color: rgba(220, 53, 69, 0.2);
  color: #dc3545;
}

@media (max-width: 576px) {
  .login-container {
    padding: 1rem;
  }
  
  .login-card {
    padding: 2rem;
  }
}
</style>
