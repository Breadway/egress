<script lang="ts">
  let { name, size = 18, cls = "" }: { name: string; size?: number; cls?: string } = $props();
</script>

<svg class="icon {cls}" width={size} height={size} aria-hidden="true">
  <use href={`#i-${name}`} />
</svg>
