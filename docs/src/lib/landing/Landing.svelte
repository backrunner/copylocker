<script lang="ts">
  import Hero from './Hero.svelte';
  import Features from './Features.svelte';
  import CodeStrip from './CodeStrip.svelte';
  import Levels from './Levels.svelte';
  import HonestNote from './HonestNote.svelte';
</script>

<div class="cl-landing">
  <Hero />
  <Features />
  <CodeStrip />
  <Levels />
  <HonestNote />
</div>

<style>
  .cl-landing {
    --cl-max: 72rem;
    --cl-gutter: clamp(1.25rem, 4vw, 3rem);
    display: flex;
    flex-direction: column;
  }

  .cl-landing :global(.cl-section) {
    max-width: var(--cl-max);
    width: 100%;
    margin: 0 auto;
    padding: clamp(3rem, 7vw, 5.5rem) var(--cl-gutter);
  }

  .cl-landing :global(.cl-kicker) {
    font-family: var(--font-mono);
    font-size: 0.75rem;
    font-weight: 500;
    letter-spacing: 0.14em;
    text-transform: uppercase;
    color: var(--sd-muted);
  }

  .cl-landing :global(.cl-kicker-mark) {
    display: inline-block;
    width: 0.5rem;
    height: 0.5rem;
    margin-right: 0.625rem;
    background: var(--sd-accent);
    vertical-align: baseline;
  }

  .cl-landing :global(:focus-visible) {
    outline: 2px solid var(--sd-accent);
    outline-offset: 2px;
    border-radius: 2px;
  }
</style>
