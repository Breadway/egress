<script lang="ts">
  let {
    checked = $bindable(false),
    label = "",
    onchange
  }: { checked?: boolean; label?: string; onchange?: () => void } = $props();

  function flip() {
    checked = !checked;
    onchange?.();
  }
</script>

<button
  class="toggle"
  class:on={checked}
  role="switch"
  aria-checked={checked}
  aria-label={label}
  onclick={flip}
></button>
