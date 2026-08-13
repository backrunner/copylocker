<script lang="ts">
  const levels = [
    { id: 'L0', line: 'A single boolean check. Demos only — never ship it.' },
    { id: 'L1', line: 'Multi-point async instrumentation with delayed, randomized failure.' },
    { id: 'L2', line: 'Critical config and data sealed under a feature key.', dflt: true },
    { id: 'L3', line: 'Critical code chunks and WASM segments sealed. High-value software.' },
    { id: 'L4', line: 'Critical computation stays server-side. Cannot be cracked offline.' }
  ];
</script>

<section class="cl-section" aria-labelledby="cl-levels-title">
  <p class="cl-kicker"><span class="cl-kicker-mark" aria-hidden="true"></span>Protection levels</p>
  <h2 id="cl-levels-title" class="cl-section-title">Pick how much work a cracker must redo</h2>
  <ol class="cl-levels" role="list">
    {#each levels as level}
      <li class:cl-level-default={level.dflt === true}>
        <a class="cl-level" href="/docs/guide/protection-levels">
          <span class="cl-level-head">
            <span class="cl-level-id">{level.id}</span>
            {#if level.dflt}<span class="cl-level-tag">default</span>{/if}
          </span>
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
    gap: clamp(1rem, 2.5vw, 1.75rem);
    margin: 0;
    padding: 0;
    list-style: none;
  }

  .cl-levels li {
    position: relative;
    padding-top: 1.375rem;
  }

  /* The rail connecting the steps. */
  .cl-levels li::before {
    content: '';
    position: absolute;
    top: 0.4375rem;
    left: 0;
    width: 100%;
    height: 1px;
    background: var(--sd-line);
  }

  /* The stop on the rail. */
  .cl-levels li::after {
    content: '';
    position: absolute;
    top: 0.125rem;
    left: 0;
    width: 0.625rem;
    height: 0.625rem;
    border-radius: 50%;
    background: var(--sd-bg);
    border: 2px solid var(--sd-muted);
    transition:
      border-color 150ms ease,
      background-color 150ms ease;
  }

  .cl-levels li:hover::after,
  .cl-levels li:focus-within::after {
    border-color: var(--sd-accent);
  }

  .cl-levels li.cl-level-default::after {
    border-color: var(--sd-accent);
    background: var(--sd-accent);
  }

  .cl-level {
    display: flex;
    flex-direction: column;
    gap: 0.625rem;
    height: 100%;
    text-decoration: none;
  }

  .cl-level-head {
    display: flex;
    align-items: center;
    gap: 0.5rem;
  }

  .cl-level-id {
    font-family: var(--font-mono);
    font-size: 0.9375rem;
    font-weight: 600;
    color: var(--sd-ink);
    transition: color 150ms ease;
  }

  .cl-level:hover .cl-level-id {
    color: var(--sd-accent);
  }

  .cl-level-tag {
    padding: 0.125rem 0.5rem;
    border-radius: 999px;
    background: color-mix(in srgb, var(--sd-accent) 14%, transparent);
    font-family: var(--font-mono);
    font-size: 0.625rem;
    letter-spacing: 0.08em;
    text-transform: uppercase;
    color: var(--sd-accent);
  }

  .cl-level-line {
    font-size: 0.8125rem;
    line-height: 1.55;
    color: var(--sd-muted);
  }

  .cl-levels-more {
    margin: 2rem 0 0;
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

  @media (max-width: 56rem) {
    .cl-levels {
      grid-template-columns: 1fr;
      gap: 1.25rem;
    }

    /* Vertical rail on small screens. */
    .cl-levels li {
      padding-top: 0;
      padding-left: 1.625rem;
    }

    .cl-levels li::before {
      top: 0;
      left: 0.4375rem;
      width: 1px;
      height: 100%;
    }

    .cl-levels li::after {
      top: 0.25rem;
    }
  }
</style>
