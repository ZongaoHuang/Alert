<script lang="ts" setup>
import { useRouter } from 'vue-router';
import { invests_data } from '~/models/mock_data_invests';

const router = useRouter();
const slideIsOpen = ref(false)
const modalIsOpen = ref(false)
const selectedInvest = ref([])
const selectedChildren = ref({})
const columns = [{
  key: 'invest_id',
  label: 'ID'
}, {
  key: 'name',
  label: '名称'
}, {
  key: 'sip',
  label: '源IP'
},{
  key: 'dip',
  label: '目的IP'
},{
  key: 'amount',
  label: '告警数量'
}, {
  key: 'date',
  label: '日期'
}, {
  key: 'alert_index',
  label: '来源'
},{
  key: 'conclusion',
  label: '结论'
},{
  key: 'completed',
  label: '状态',
  sortable: true
}, {
  key: 'actions',
  label: '处理',
  sortable: false
}]

const childrenColumns = [{
  key: '_id',
  label: 'ID'
}, {
  key: 'rule_name',
  label: '规则名称'
}, {
  key: 'sip',
  label: '源IP'
},{
  key: 'dip',
  label: '目的IP'
},{
  key:'timestamp',
  label: '时间'
},{
  key: '_index',
  label: '日志来源'
},{
  key: 'score_all',
  label: '威胁分数'
}]

const selectedColumns = ref(columns)
const columnsTable = computed(() => columns.filter((column) => selectedColumns.value.includes(column)))

// Selected Rows
const selectedRows = ref([])

function select (row) {
  const index = selectedRows.value.findIndex((item) => item.id === row.id)
  if (index === -1) {
    selectedRows.value.push(row)
  } else {
    selectedRows.value.splice(index, 1)
  }
}

function gotoInvestigation (id: any) {
  router.push(`/investigations/${id}`)
}

function seekInvestigation (row: any) {
  selectedInvest.value = row.children
  slideIsOpen.value = true
}

function seekChildren (row: any) {
  console.log(row)
  selectedChildren.value = row
  modalIsOpen.value = true
}

// Filters
const todoStatus = [{
  key: 'uncompleted',
  label: '待处理',
  value: false
}, {
  key: 'completed',
  label: '处理完成',
  value: true
}]

const search = ref('')
const selectedStatus = ref([])
// const searchStatus = computed(() => {
//   if (selectedStatus.value?.length === 0) {
//     return ''
//   }

//   if (selectedStatus?.value?.length > 1) {
//     return `?completed=${selectedStatus.value[0].value}&completed=${selectedStatus.value[1].value}`
//   }

//   return `?completed=${selectedStatus.value[0].value}`
// })

const resetFilters = () => {
  search.value = ''
  selectedStatus.value = []
}

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



</script>

<template>
  <div class="flex justify-center mt-8 mb-4">
    <UCard class="w-[90%]" :ui="{
      base: '',
      ring: '',
      divide: 'divide-y divide-gray-200 dark:divide-gray-700',
      header: { padding: 'px-4 py-5' },
      body: { padding: '', base: 'divide-y divide-gray-200 dark:divide-gray-700' },
      footer: { padding: 'p-4' }
    }">
      <template #header>
        <h2 class="font-semibold text-xl text-gray-900 dark:text-white leading-tight">
          攻击行为分析
        </h2>
      </template>

      <!-- Filters -->
      <div class="flex items-center justify-between gap-3 px-4 py-3">
        <UInput v-model="search" icon="i-heroicons-magnifying-glass-20-solid" placeholder="Search..." />

        <USelectMenu v-model="selectedStatus" :options="todoStatus" multiple placeholder="状态" class="w-40" />
      </div>

      <!-- Header and Action buttons -->
      <div class="flex justify-between items-center w-full px-4 py-3">
        <div class="flex items-center gap-1.5">
          <span class="text-sm leading-5">每页:</span>

          <USelect v-model="pageCount" :options="[3, 5, 10, 20, 30, 40]" class="me-2 w-20" size="xs" />
        </div>

        <div class="flex gap-1.5 items-center">

          <USelectMenu v-model="selectedColumns" :options="columns" multiple>
            <UButton icon="i-heroicons-view-columns" color="gray" size="lg">
              列筛选
            </UButton>
          </USelectMenu>
        </div>
      </div>

      <!-- Table -->
      <UTable v-model="selectedRows" v-model:sort="sort" :rows="invests_data" :columns="columnsTable"
        sort-asc-icon="i-heroicons-arrow-up" sort-desc-icon="i-heroicons-arrow-down" sort-mode="manual" class="w-full"
        :ui="{ td: { base: ' truncate' }, default: { checkbox: { color: 'gray' } } }" @select="select">
        <template #invest_id-data="{ row }">
          <span class="text-sm font-semibold hover:text-primary" @click="seekInvestigation(row)">{{ row.invest_id
            }}</span>
        </template>

        <template #name-data="{ row }">
          <span class="text-sm font-semibold hover:text-primary" @click="seekInvestigation(row)">{{ row.name }}</span>
        </template>

        <template #completed-data="{ row }">
          <UBadge size="xs" :label="row.completed ? '处理完成' : '待处理'" :color="row.completed ? 'emerald' : 'orange'"
            variant="subtle" />
        </template>

        <template #actions-data="{ row }">
          <UButton @click="gotoInvestigation(row.invest_id)" label="处理" />

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

          <UPagination v-model="page" :page-count="pageCount" :total="pageTotal" :ui="{
            wrapper: 'flex items-center gap-1',
            rounded: '!rounded-full min-w-[32px] justify-center',
            default: {
              activeButton: {
                variant: 'outline'
              }
            }
          }" />
        </div>
      </template>
    </UCard>

    <!-- 侧边栏 -->
    <USlideover v-model="slideIsOpen" :ui="{strategy: 'override',width: 'w-screen max-w-[60%]'}" prevent-close>
      <UCard class="flex flex-col flex-1"
        :ui="{ body: { base: 'flex-1' }, ring: '', divide: 'divide-y divide-gray-100 dark:divide-gray-800'}">
        <template #header>
          <div class="flex items-center justify-between">
            <h3 class="text-base font-semibold leading-6 text-gray-900 dark:text-white">
              详情
            </h3>
            <UButton color="gray" variant="ghost" icon="i-heroicons-x-mark-20-solid" class="-my-1"
              @click="slideIsOpen = false" />
          </div>
        </template>

        <!-- <Placeholder class="h-full" /> -->
        <UTable :rows="selectedInvest" :columns="childrenColumns"
          :ui="{strategy: 'override',base: 'whitespace-nowrap',td:{padding: 'px-2 py-3',size:'text-xs',base:''},th:{padding: 'px-0 py-1',size:'text-xs'}}">
          <template #_id-data="{ row }">
            <span class="hover:text-primary  cursor-pointer" @click="seekChildren(row)">{{ row._id }}</span>
          </template>
          <template #rule_name-data="{ row }">
            <span class="hover:text-primary  cursor-pointer" @click="seekChildren(row)">{{ row.rule_name }}</span>
          </template>
        </UTable>
        <template #footer>
          <Placeholder class="h-8" />
        </template>
      </UCard>
    </USlideover>
    <!-- 模态框 -->
    <UModal v-model="modalIsOpen" :ui="{strategy: 'override',width: 'w-screen max-w-[80%]'}">
      <UCard class=" z-10" :ui="{ ring: '', divide: 'divide-y divide-gray-100 dark:divide-gray-800' }">
        <template #header>
          <div class="flex items-center justify-between">
            <h3 class="text-base font-semibold leading-6 text-gray-900 dark:text-white">
              告警详情
            </h3>
            <UButton color="gray" variant="ghost" icon="i-heroicons-x-mark-20-solid" class="-my-1"
              @click="modalIsOpen = false" />
          </div>
        </template>
        <div class="p-4 space-y-4 text-lg">
          <div class="grid grid-cols-6 border m-2">
            <!-- Row 1 -->
            <div class="border border-gray-300 bg-blue-50 text-sm font-semibold text-gray-700 p-2">日志种类</div>
            <div class="border text-base text-gray-900 p-2">{{ selectedChildren._index }}</div>
            <div class="border border-gray-300 bg-blue-50 text-sm font-semibold text-gray-700 p-2">日志ID</div>
            <div class="border text-sm text-gray-900 p-2">{{ selectedChildren._id }}</div>
            <div class="border border-gray-300 bg-blue-50 text-sm font-semibold text-gray-700 p-2">时间戳</div>
            <div class="border text-base text-gray-900 p-2">{{ selectedChildren.timestamp }}</div>
            <!-- Row 2 -->
            <div class="border border-gray-300 bg-blue-50 text-sm font-semibold text-gray-700 p-2">SIP</div>
            <div class="border text-base text-gray-900 p-2">{{ selectedChildren.sip }}</div>
            <div class="border border-gray-300 bg-blue-50 text-sm font-semibold text-gray-700 p-2">SPORT</div>
            <div class="border text-base text-gray-900 p-2">{{ selectedChildren.sport }}</div>
            <div class="border border-gray-300 bg-blue-50 text-sm font-semibold text-gray-700 p-2">攻击类型</div>
            <div class="border text-base text-gray-900 p-2">{{ selectedChildren.rule_name }}</div>
            <div class="border border-gray-300 bg-blue-50 text-sm font-semibold text-gray-700 p-2">DIP</div>
            <div class="border text-base text-gray-900 p-2">{{ selectedChildren.dip }}</div>
            <div class="border border-gray-300 bg-blue-50 text-sm font-semibold text-gray-700 p-2">DPORT</div>
            <div class="border text-base text-gray-900 p-2">{{ selectedChildren.dport }}</div>
            <div class="border border-gray-300 bg-blue-50 text-sm font-semibold text-gray-700 p-2">威胁程度评分</div>
            <div class="border text-base text-gray-900 p-2">{{ selectedChildren.score_all }}</div>
            <!-- Large Warning Field -->
            <div class="col-span-6 border border-gray-300 bg-blue-50 text-sm font-semibold text-gray-700 p-2">告警载荷</div>
            <div class="col-span-6 border text-base text-gray-900 p-4 font-sans">{{selectedChildren.payload}}</div>
            <!-- Bottom Rows -->
            <div class="border border-gray-300 bg-blue-50 text-sm font-semibold text-gray-700 p-2">自定义规则评分</div>
            <div class="border text-base text-gray-900 p-2">{{ selectedChildren.score_rule }}</div>
            <div class="border border-gray-300 bg-blue-50 text-sm font-semibold text-gray-700 p-2">信息熵评分</div>
            <div class="border text-base text-gray-900 p-2">{{ selectedChildren.score_entropy }}</div>
            <div class="border border-gray-300 bg-blue-50 text-sm font-semibold text-gray-700 p-2">大模型评分</div>
            <div class="border text-base text-gray-900 p-2">{{ selectedChildren.score_llm }}</div>
          </div>
        </div>

      </UCard>
    </UModal>
  </div>

</template>