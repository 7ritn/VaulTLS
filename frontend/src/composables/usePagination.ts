import { ref, computed, watch, isRef } from 'vue';
import type { ComputedRef, Ref } from 'vue';

export function usePagination<T>(items: ComputedRef<T[]>, pageSize: Ref<number> | number = 20) {
    const currentPage = ref(1);

    const pageSizeRef = isRef(pageSize) ? pageSize : ref(pageSize);

    const totalPages = computed(() => Math.max(1, Math.ceil(items.value.length / pageSizeRef.value)));

    const paginated = computed(() => {
        const start = (currentPage.value - 1) * pageSizeRef.value;
        return items.value.slice(start, start + pageSizeRef.value);
    });

    const startItem = computed(() => items.value.length === 0 ? 0 : (currentPage.value - 1) * pageSizeRef.value + 1);
    const endItem = computed(() => Math.min(currentPage.value * pageSizeRef.value, items.value.length));

    watch(() => items.value.length, () => {
        currentPage.value = 1;
    });

    watch(pageSizeRef, () => {
        currentPage.value = 1;
    });

    const prev = () => {
        if (currentPage.value > 1) currentPage.value--;
    };

    const next = () => {
        if (currentPage.value < totalPages.value) currentPage.value++;
    };

    return { currentPage, totalPages, paginated, startItem, endItem, prev, next };
}
