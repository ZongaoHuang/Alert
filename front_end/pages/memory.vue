<script lang="ts" setup>
import { useRouter } from 'vue-router';
import Id from './investigations/[id].vue';

const router = useRouter();

const columns = [{
  key: 'memo_id',
  label: 'ID'
}, {
    key:'title',
    label: '标题'
},
{
  key: 'content',
  label: '内容'
}, {
    key: 'date',
    label: '日期'
},{
    key: 'invest_id',
    label: '关联告警id'
},{
  key: 'actions',
  label: '处理',
  sortable: false
}]



// Pagination
const sort = ref({ column: 'id', direction: 'asc' as const })
const page = ref(1)
const pageCount = ref(10)
const pageTotal = ref(200) // This value should be dynamic coming from the API
const pageFrom = computed(() => (page.value - 1) * pageCount.value + 1)
const pageTo = computed(() => Math.min(page.value * pageCount.value, pageTotal.value))

// Data
// const { data: todos, pending } = await useLazyAsyncData<{
//   id: number
//   title: string
//   completed: string
// }[]>('todos', () => ($fetch as any)(`https://jsonplaceholder.typicode.com/todos${searchStatus.value}`, {
//   query: {
//     q: search.value,
//     '_page': page.value,
//     '_limit': pageCount.value,
//     '_sort': sort.value.column,
//     '_order': sort.value.direction
//   }
// }), {
//   default: () => [],
//   watch: [page, search, searchStatus, pageCount, sort]
// })

const memo_item=[
  {
    memo_id:  1,
    title: "sql业务",
    content: "该sql语句为业务行为，其他机器会访问10.0.0.1来...",
    date: "2023-10-22 21:49:23",
    invest_id: 1
  }

]

const items = (row) => [
  [{
    label: '编辑',
    icon: 'i-heroicons-pencil-square-20-solid',
    click: () => console.log('Edit', row.memo_id)
  }, {
    label: '删除',
    icon: 'i-heroicons-trash-20-solid'
  }]
]

</script>

<template>
    <div class="flex justify-center mt-8 mb-4">
  <UCard
    class="w-[90%]"
    :ui="{
      base: '',
      ring: '',
      divide: 'divide-y divide-gray-200 dark:divide-gray-700',
      header: { padding: 'px-4 py-5' },
      body: { padding: '', base: 'divide-y divide-gray-200 dark:divide-gray-700' },
      footer: { padding: 'p-4' }
    }"
  >
    <template #header>
      <h2 class="font-semibold text-xl text-gray-900 dark:text-white leading-tight">
        上下文记忆管理
      </h2>
    </template>


    <!-- Header and Action buttons -->
    <div class="flex justify-between items-center w-full px-4 py-3">
      <div class="flex items-center gap-1.5">
        <span class="text-sm leading-5">每页:</span>

        <USelect
          v-model="pageCount"
          :options="[3, 5, 10, 20, 30, 40]"
          class="me-2 w-20"
          size="xs"
        />
      </div>
    </div>

    <!-- Table -->
    <UTable
      v-model:sort="sort"
      :rows="memo_item"
      :columns="columns"
      sort-asc-icon="i-heroicons-arrow-up"
      sort-desc-icon="i-heroicons-arrow-down"
      sort-mode="manual"
      class="w-full"
      :ui="{ td: { base: ' truncate' }, default: { checkbox: { color: 'gray' } } }"
    >
      <template #completed-data="{ row }">
        <UBadge size="xs" :label="row.completed ? '处理完成' : '待处理'" :color="row.completed ? 'emerald' : 'orange'" variant="subtle" />
      </template>

      <template #actions-data="{ row }">
      <UDropdown :items="items(row)">
        <UButton color="gray" variant="ghost" icon="i-heroicons-ellipsis-horizontal-20-solid" />
      </UDropdown>
    </template>
    </UTable>

    <!-- Number of rows & Pagination -->
    <template #footer>
      <div class="flex flex-wrap justify-between items-center">
        <div>
          <span class="text-sm leading-5">
            显示从
            <span class="font-medium">{{ pageFrom }}</span>
            到
            <span class="font-medium">{{ pageTo }}</span>
            ，共
            <span class="font-medium">{{ pageTotal }}</span>
            条
          </span>
        </div>

        <UPagination
          v-model="page"
          :page-count="pageCount"
          :total="pageTotal"
          :ui="{
            wrapper: 'flex items-center gap-1',
            rounded: '!rounded-full min-w-[32px] justify-center',
            default: {
              activeButton: {
                variant: 'outline'
              }
            }
          }"
        />
      </div>
    </template>
  </UCard>
</div>

</template>