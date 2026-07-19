<script lang="ts">
  let { children } = $props();
</script>

{@render children()}

<style>
  :global(*, *::before, *::after) { box-sizing: border-box; }
  :global(html, body) {
    margin: 0; padding: 0; height: 100%;
    background: #0f1115; color: #e6e7e9;
    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", "Hiragino Sans", "Noto Sans JP", sans-serif;
    -webkit-font-smoothing: antialiased;
  }
  :global(button) { cursor: pointer; }
  :global(input, textarea) { font-family: inherit; }
</style>
