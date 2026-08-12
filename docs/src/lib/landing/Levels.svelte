<script lang="ts">
  const levels = [
    { id: 'L0', line: 'A single boolean check. Demos only — never ship it.' },
    { id: 'L1', line: 'Multi-point async instrumentation with delayed, randomized failure.' },
    { id: 'L2', line: 'Critical config and data sealed under a feature key. The default.' },
    { id: 'L3', line: 'Critical code chunks and WASM segments sealed. High-value software.' },
    { id: 'L4', line: 'Critical computation stays server-side. Cannot be cracked offline.' }
  ];
</script>

<section class="cl-section" aria-labelledby="cl-levels-title">
  <p class="cl-kicker"><span class="cl-kicker-mark" aria-hidden="true"></span>Protection levels</p>
  <h2 id="cl-levels-title" class="cl-section-title">Pick how much work a cracker must redo</h2>
  <ol class="cl-levels" role="list">
    {#each levels as level}
      <li>
        <a class="cl-level" href="/docs/guide/protection-levels">
          <span class="cl-level-id">{level.id}</span>
          <span class="cl-level-line">{level.line}</span>
        </a>
      </li>
    {/each}
  </ol>
  <p class="cl-levels-more">
    <a href="/docs/guide/protection-levels">The full levels guide, with copyable examples →</a>
  </p>
</section>

<style>
  .cl-section-title {
    margin: 0.75rem 0 2.25rem;
    font-size: clamp(1.5rem, 3.5vw, 2rem);
    font-weight: 650;
    letter-spacing: -0.02em;
    line-height: 1.2;
    color: var(--sd-ink);
  }

  .cl-levels {
    display: grid;
    grid-template-columns: repeat(5, 1fr);
    gap: 1px;
    margin: 0;
    padding: 0;
    list-style: none;
    background: var(--sd-line);
    border: 1px solid var(--sd-line);
    border-radius: var(--sd-radius);
    overflow: hidden;
    counter-reset: level;
  }

  .cl-level {
    display: flex;
    flex-direction: column;
    gap: 0.75rem;
    height: 100%;
    padding: 1.25rem;
    background: var(--sd-bg);
    text-decoration: none;
    transition: background-color 150ms ease;
  }

  .cl-level:hover {
    background: var(--sd-panel);
  }

  .cl-level-id {
    font-family: var(--font-mono);
    font-size: 0.875rem;
    font-weight: 600;
    color: var(--sd-accent);
  }

  .cl-level-line {
    font-size: 0.8125rem;
    line-height: 1.55;
    color: var(--sd-muted);
  }

  .cl-levels-more {
    margin: 1.25rem 0 0;
    font-size: 0.9375rem;
  }

  .cl-levels-more a {
    color: var(--sd-accent);
    text-decoration: none;
    border-bottom: 1px solid color-mix(in srgb, var(--sd-accent) 35%, transparent);
  }

  .cl-levels-more a:hover {
    border-bottom-color: var(--sd-accent);
  }

  @media (max-width: 60rem) {
    .cl-levels {
      grid-template-columns: repeat(2, 1fr);
    }
  }

  @media (max-width: 30rem) {
    .cl-levels {
      grid-template-columns: 1fr;
    }
  }
</style>
