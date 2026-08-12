<section class="cl-hero cl-section" aria-labelledby="cl-hero-title">
  <div class="cl-hero-inner">
    <p class="cl-kicker">
      <span class="cl-kicker-mark" aria-hidden="true"></span>Open-source licensing infrastructure · GPL-3.0-only
    </p>
    <h1 id="cl-hero-title" class="cl-wordmark">CopyLocker</h1>
    <p class="cl-tagline">
      Licensing and anti-tamper toolkit: post-quantum hybrid credentials, sealed assets, and
      honest client-side hardening.
    </p>
    <div class="cl-cta">
      <a class="cl-button cl-button-primary" href="/docs/guide/quickstart">Get started</a>
      <a
        class="cl-button cl-button-secondary"
        href="https://github.com/backrunner/copylocker"
        target="_blank"
        rel="noreferrer"
      >
        GitHub
        <span class="cl-button-arrow" aria-hidden="true">↗</span>
      </a>
    </div>
  </div>
</section>

<style>
  .cl-hero {
    position: relative;
    border-bottom: 1px solid var(--sd-line);
    --cl-grid-line: color-mix(in srgb, var(--sd-line) 42%, transparent);
    background-image:
      linear-gradient(var(--cl-grid-line) 1px, transparent 1px),
      linear-gradient(90deg, var(--cl-grid-line) 1px, transparent 1px);
    background-size: 2.5rem 2.5rem;
    background-position: center top;
  }

  /* Fade the blueprint grid out toward the content column edges. */
  .cl-hero::before {
    content: '';
    position: absolute;
    inset: 0;
    background: linear-gradient(
      to bottom,
      transparent 0%,
      transparent 55%,
      var(--sd-bg) 100%
    );
    pointer-events: none;
  }

  .cl-hero-inner {
    position: relative;
    display: flex;
    flex-direction: column;
    align-items: flex-start;
    gap: 1.5rem;
    padding-top: clamp(2rem, 5vw, 4rem);
    padding-bottom: clamp(1rem, 3vw, 2rem);
  }

  .cl-wordmark {
    margin: 0;
    font-family: var(--sd-font-display);
    font-size: clamp(2.75rem, 8vw, 5rem);
    font-weight: 700;
    letter-spacing: -0.035em;
    line-height: 1.02;
    color: var(--sd-ink);
  }

  .cl-tagline {
    margin: 0;
    max-width: 38rem;
    font-size: clamp(1.0625rem, 2.2vw, 1.25rem);
    line-height: 1.55;
    color: var(--sd-muted);
    text-wrap: pretty;
  }

  .cl-cta {
    display: flex;
    flex-wrap: wrap;
    gap: 0.75rem;
    margin-top: 0.5rem;
  }

  .cl-button {
    display: inline-flex;
    align-items: center;
    gap: 0.5rem;
    padding: 0.6875rem 1.375rem;
    border: 1px solid var(--sd-ink);
    border-radius: var(--sd-radius);
    font-size: 0.9375rem;
    font-weight: 500;
    line-height: 1;
    text-decoration: none;
    transition:
      background-color 150ms ease,
      color 150ms ease,
      border-color 150ms ease;
  }

  .cl-button-primary {
    background: var(--sd-ink);
    color: var(--sd-bg);
  }

  .cl-button-primary:hover {
    background: var(--sd-accent);
    border-color: var(--sd-accent);
    color: oklch(1 0 0);
  }

  :global(:root[data-theme='dark']) .cl-button-primary:hover,
  :global(.sd-root[data-theme='dark']) .cl-button-primary:hover {
    color: oklch(0.145 0 0);
  }

  .cl-button-secondary {
    background: transparent;
    border-color: var(--sd-line);
    color: var(--sd-ink);
  }

  .cl-button-secondary:hover {
    border-color: var(--sd-ink);
  }

  .cl-button-arrow {
    font-size: 0.875em;
  }
</style>
