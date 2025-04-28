<script setup>
import { ref } from 'vue'
import VChart from 'vue-echarts'
import { use } from 'echarts/core'
import { CanvasRenderer } from 'echarts/renderers'
import { PieChart,BarChart,LineChart,GaugeChart } from 'echarts/charts'
import {
    LegendComponent,
    TitleComponent,
    TooltipComponent,
    ToolboxComponent,
    GridComponent 
} from 'echarts/components'
import {gauge_option, pie_option, stacked_area_option, bar_stack_option } from '~/models/mock_data_chart'


use([
    CanvasRenderer,
    PieChart,
    BarChart,
    LineChart,
    GaugeChart,
    GridComponent,
    ToolboxComponent,
    TitleComponent,
    TooltipComponent,
    LegendComponent,
])


</script>

<template>
    <div>
        <ClientOnly fallback-tag="div" fallback="Loading comments...">
            <div class="m-4 grid grid-cols-3 grid-rows-2 gap-4 w-full">
            <UCard> 
                <template #header>
                    分析数量
                </template>
                <!-- <VChart class=" h-64" :option="gauge_option" /> -->
                <div class="flex flex-col items-center justify-center h-64">
                    <span class="text-3xl text-gray-600 mb-2" style="text-shadow: 2px 2px 4px rgba(0, 0, 0, 0.1);">已过滤 16453 个告警</span>
                    <span class="text-3xl text-gray-600" style="text-shadow: 2px 2px 4px rgba(0, 0, 0, 0.1);">已研判 14453 个告警</span>
                </div>
            </UCard>
            <UCard class="col-span-2">
                <template #header>
                    告警数量
                </template>
                <VChart class=" h-64" :option="stacked_area_option" />
            </UCard>
            <UCard class="col-span-2">
                <template #header>
                    告警时间
                </template>
                <VChart class=" h-64" :option="bar_stack_option" />
            </UCard>
            <UCard>
                <template #header>
                    告警类型
                </template>
                <VChart class=" h-64" :option="pie_option" />
            </UCard>
        </div>
        </ClientOnly>
    </div>
</template>
