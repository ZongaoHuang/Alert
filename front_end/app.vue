<template>
  <div>
    <NuxtRouteAnnouncer />
  </div>
  <NuxtLayout>
    <div class="flex overflow-hidden">
      <div class="w-1/10 fixed top-0 left-0">
        <Header />
      </div>
      <div class="flex-grow max-w-[89%]  ml-[9%]">
        <NuxtPage />
      </div>
    </div>
    <Footer />
  </NuxtLayout>
</template>
