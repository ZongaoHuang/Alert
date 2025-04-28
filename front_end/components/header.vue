<script setup lang="ts">
import { render, h, renderSlot } from 'vue';
const route = useRoute()

const links = [
    {
        label: '仪表盘',
        icon: 'i-heroicons-home',
        to: '/dashboard'
    }, {
        label: '调查',
        icon: 'i-heroicons-chart-pie',
        to: `/investigations`
    }, {
        label: '聊天',
        icon: 'i-heroicons-command-line',
        to: '/chat'
    },
    {
        label: '上下文记忆',
        icon: 'i-heroicons-cog',
        to: '/memory'
    }]
</script>

<template>
    <div class="flex flex-col justify-center items-center h-full">
        <span class="text-2xl mt-6 ml-4 mb-4 font-bold text-gray-400">SOCLLM</span>
        <UVerticalNavigation :links="links" class="ml-4">
            <template #default="{ link }">
                <span class="group-hover:text-primary relative">{{ link.label }}</span>
            </template>
        </UVerticalNavigation>
    </div>
</template>
