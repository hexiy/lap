<template>
  <ModalDialog
    :title="$t('hidden.unlock_title')"
    :width="340"
    position-key="unlock-hidden"
    @cancel="cancel"
  >
    <p class="text-sm whitespace-pre-line">
      {{ pinConfigured ? $t('hidden.enter_pin') : $t('hidden.create_pin') }}
    </p>

    <input
      ref="pinInputRef"
      v-model="pin"
      type="password"
      inputmode="numeric"
      autocomplete="off"
      class="input input-sm w-full mt-3 bg-base-100"
      :placeholder="$t('hidden.pin')"
      :disabled="busy"
      @keydown.enter.prevent="submit"
    />
    <input
      v-if="!pinConfigured"
      v-model="pinConfirm"
      type="password"
      inputmode="numeric"
      autocomplete="off"
      class="input input-sm w-full mt-2 bg-base-100"
      :placeholder="$t('hidden.pin_confirm')"
      :disabled="busy"
      @keydown.enter.prevent="submit"
    />

    <p v-if="error" class="text-error text-xs mt-2">{{ error }}</p>

    <div class="mt-4 flex justify-end gap-2">
      <button
        class="px-3 py-1 rounded-box hover:bg-base-100 cursor-pointer"
        :disabled="busy"
        @click="cancel"
      >
        {{ $t('msgbox.cancel') }}
      </button>
      <button
        class="px-3 py-1 rounded-box bg-primary text-primary-content hover:bg-primary/90 cursor-pointer disabled:opacity-50"
        :disabled="busy || !canSubmit"
        @click="submit"
      >
        {{ pinConfigured ? $t('hidden.unlock') : $t('hidden.create') }}
      </button>
    </div>
  </ModalDialog>
</template>

<script setup lang="ts">
import { computed, onMounted, onUnmounted, ref } from 'vue';
import { useI18n } from 'vue-i18n';
import { useUIStore } from '@/stores/uiStore';
import { getHiddenPinStatus, setHiddenPin, verifyHiddenPin } from '@/common/api';
import ModalDialog from '@/components/ModalDialog.vue';

const emit = defineEmits(['unlock', 'cancel']);
const { t } = useI18n();
const uiStore = useUIStore();

const pinConfigured = ref(true);
const pin = ref('');
const pinConfirm = ref('');
const error = ref('');
const busy = ref(false);
const pinInputRef = ref<HTMLInputElement | null>(null);

const MIN_PIN_LENGTH = 4;

const canSubmit = computed(() =>
  pin.value.length >= MIN_PIN_LENGTH &&
  (pinConfigured.value || pinConfirm.value.length >= MIN_PIN_LENGTH));

onMounted(async () => {
  uiStore.pushInputHandler('UnlockHiddenDialog');
  pinConfigured.value = await getHiddenPinStatus();
  pinInputRef.value?.focus();
});
onUnmounted(() => uiStore.removeInputHandler('UnlockHiddenDialog'));

function cancel() {
  if (!busy.value) emit('cancel');
}

async function submit() {
  if (!canSubmit.value || busy.value) return;
  error.value = '';
  busy.value = true;
  try {
    if (pinConfigured.value) {
      if (await verifyHiddenPin(pin.value)) {
        emit('unlock');
      } else {
        error.value = t('hidden.wrong_pin');
        pin.value = '';
      }
      return;
    }
    if (pin.value !== pinConfirm.value) {
      error.value = t('hidden.pin_mismatch');
      return;
    }
    const result = await setHiddenPin(pin.value);
    if (result === true) {
      emit('unlock');
    } else {
      error.value = String(result);
    }
  } finally {
    busy.value = false;
  }
}
</script>
