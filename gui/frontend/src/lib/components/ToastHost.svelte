<script lang="ts">
  import Icon from "$lib/components/Icon.svelte";
  import { toast } from "$lib/state/toast.svelte";
</script>

<div class="toast" class:show={toast.visible} role="status">
  <Icon name="check" cls="sm" />
  <span>{toast.message}</span>
</div>
