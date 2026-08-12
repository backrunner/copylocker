<script lang="ts">
  import { DocsApp } from 'svedocs/theme';
  import components from 'virtual:svedocs/components';
  import layouts from 'virtual:svedocs/layouts';
  import themeComponents from 'virtual:svedocs/theme-components';
  import loadSearch from 'virtual:svedocs/search-loader';
  import Landing from '$lib/landing/Landing.svelte';
  export let data;
</script>

<DocsApp
  page={data.page}
  pages={data.pages}
  tree={data.tree}
  search={data.search}
  config={data.config}
  {components}
  {layouts}
  {themeComponents}
  {loadSearch}
>
  <svelte:fragment slot="landing">
    <Landing />
  </svelte:fragment>
</DocsApp>
