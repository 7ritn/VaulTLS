<template>
  <div v-if="totalItems > 0" class="d-flex align-items-center justify-content-between mt-2 px-1">
    <div class="d-flex align-items-center gap-2">
      <template v-if="totalPages > 1">
        <button
            class="btn btn-outline-secondary btn-sm"
            :disabled="currentPage <= 1"
            @click="$emit('prev')"
        >
          &lsaquo;
        </button>
        <span class="small text-muted">Page {{ currentPage }} of {{ totalPages }}</span>
        <button
            class="btn btn-outline-secondary btn-sm"
            :disabled="currentPage >= totalPages"
            @click="$emit('next')"
        >
          &rsaquo;
        </button>
      </template>
    </div>
    <div class="d-flex align-items-center gap-3">
      <span class="small text-muted">Showing {{ startItem }}–{{ endItem }} of {{ totalItems }}</span>
      <div class="d-flex align-items-center gap-1">
        <label class="small text-muted mb-0" for="page-size-select">Rows:</label>
        <select
            id="page-size-select"
            class="form-select form-select-sm"
            style="width: auto;"
            :value="pageSize"
            @change="$emit('update:pageSize', Number(($event.target as HTMLSelectElement).value))"
        >
          <option v-for="size in pageSizeOptions" :key="size" :value="size">{{ size }}</option>
        </select>
      </div>
    </div>
  </div>
</template>

<script setup lang="ts">
import { PAGE_SIZE_OPTIONS } from '@/composables/usePageSize';

defineProps<{
    currentPage: number;
    totalPages: number;
    totalItems: number;
    startItem: number;
    endItem: number;
    pageSize: number;
}>();

defineEmits<{
    prev: [];
    next: [];
    'update:pageSize': [size: number];
}>();

const pageSizeOptions = PAGE_SIZE_OPTIONS;
</script>
