<section class="cl-hero" aria-labelledby="cl-hero-title">
  <div class="cl-hero-inner cl-section">
    <div class="cl-hero-copy">
      <p class="cl-kicker">
        <span class="cl-kicker-mark" aria-hidden="true"></span>Open-source licensing infrastructure ·
        GPL-3.0-only
      </p>
      <h1 id="cl-hero-title" class="cl-wordmark">
        Ship software that<br />only runs <em>licensed</em>.
      </h1>
      <p class="cl-tagline">
        CopyLocker is a licensing and anti-tamper toolkit: post-quantum hybrid credentials, sealed
        assets, and honest client-side hardening — self-hosted on your own Cloudflare account.
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
      <ul class="cl-chips" aria-label="Key facts">
        <li>CL-STD-1</li>
        <li>ML-DSA + X-Wing</li>
        <li>Offline activation</li>
        <li>L0–L4 protection levels</li>
      </ul>
    </div>

    <div class="cl-hero-visual" aria-hidden="true">
      <div class="cl-seal-card">
        <div class="cl-seal-head">
          <span class="cl-seal-title">license.cl</span>
          <span class="cl-seal-state">
            <span class="cl-seal-dot"></span>verified
          </span>
        </div>
        <div class="cl-seal-body">
          <div class="cl-seal-row"><span class="cl-seal-k">sub</span><span class="cl-seal-v">acme-desktop</span></div>
          <div class="cl-seal-row"><span class="cl-seal-k">features</span><span class="cl-seal-v">pro.export, pro.batch</span></div>
          <div class="cl-seal-row"><span class="cl-seal-k">exp</span><span class="cl-seal-v">2027-08-01</span></div>
          <div class="cl-seal-row"><span class="cl-seal-k">kem</span><span class="cl-seal-v">X-Wing · ML-KEM-768</span></div>
          <div class="cl-seal-row"><span class="cl-seal-k">sig</span><span class="cl-seal-v cl-seal-sig">ML-DSA ▮▮▮▮▮▮▮▮</span></div>
        </div>
        <div class="cl-seal-foot">
          <span class="cl-seal-line"></span>
          <span class="cl-seal-foot-label">hybrid signature · CL-STD-1</span>
        </div>
      </div>
    </div>
  </div>
</section>

<style>
  .cl-hero {
    position: relative;
    overflow: hidden;
    border-bottom: 1px solid var(--sd-line);
  }

  /* Soft accent aurora — replaces the old blueprint grid. */
  .cl-hero::before {
    content: '';
    position: absolute;
    inset: -20% -10% auto -10%;
    height: 130%;
    background:
      radial-gradient(
        42rem 26rem at 78% 18%,
        color-mix(in srgb, var(--sd-accent) 14%, transparent),
        transparent 68%
      ),
      radial-gradient(
        30rem 20rem at 12% 78%,
        color-mix(in srgb, var(--sd-accent-2) 9%, transparent),
        transparent 70%
      );
    pointer-events: none;
  }

  .cl-hero-inner {
    position: relative;
    display: grid;
    grid-template-columns: minmax(0, 1.15fr) minmax(0, 0.85fr);
    align-items: center;
    gap: clamp(2rem, 5vw, 4rem);
    padding-top: clamp(3.5rem, 8vw, 6.5rem);
    padding-bottom: clamp(3rem, 7vw, 5.5rem);
  }

  .cl-hero-copy {
    display: flex;
    flex-direction: column;
    align-items: flex-start;
    gap: 1.5rem;
  }

  .cl-wordmark {
    margin: 0;
    font-family: var(--sd-font-display);
    font-size: clamp(2.25rem, 5.2vw, 3.75rem);
    font-weight: 700;
    letter-spacing: -0.035em;
    line-height: 1.06;
    color: var(--sd-ink);
    text-wrap: balance;
  }

  .cl-wordmark em {
    font-style: normal;
    color: var(--sd-accent);
  }

  .cl-tagline {
    margin: 0;
    max-width: 34rem;
    font-size: clamp(1rem, 1.6vw, 1.125rem);
    line-height: 1.6;
    color: var(--sd-muted);
    text-wrap: pretty;
  }

  .cl-cta {
    display: flex;
    flex-wrap: wrap;
    gap: 0.75rem;
    margin-top: 0.25rem;
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

  .cl-chips {
    display: flex;
    flex-wrap: wrap;
    gap: 0.5rem;
    margin: 0.5rem 0 0;
    padding: 0;
    list-style: none;
  }

  .cl-chips li {
    padding: 0.3125rem 0.625rem;
    border: 1px solid var(--sd-line);
    border-radius: 999px;
    font-family: var(--font-mono);
    font-size: 0.6875rem;
    letter-spacing: 0.04em;
    color: var(--sd-muted);
    background: color-mix(in srgb, var(--sd-bg) 72%, transparent);
  }

  /* Credential card visual */
  .cl-hero-visual {
    display: flex;
    justify-content: center;
  }

  .cl-seal-card {
    width: min(100%, 22rem);
    border: 1px solid var(--sd-line);
    border-radius: calc(var(--sd-radius) + 4px);
    background: var(--sd-panel);
    box-shadow:
      0 1px 2px oklch(0 0 0 / 4%),
      0 16px 48px -16px color-mix(in srgb, var(--sd-accent) 24%, transparent);
    font-family: var(--font-mono);
    transform: rotate(1.2deg);
  }

  .cl-seal-head {
    display: flex;
    align-items: center;
    justify-content: space-between;
    padding: 0.875rem 1.125rem;
    border-bottom: 1px solid var(--sd-line);
  }

  .cl-seal-title {
    font-size: 0.75rem;
    font-weight: 600;
    letter-spacing: 0.06em;
    color: var(--sd-ink);
  }

  .cl-seal-state {
    display: inline-flex;
    align-items: center;
    gap: 0.375rem;
    font-size: 0.6875rem;
    letter-spacing: 0.08em;
    text-transform: uppercase;
    color: var(--sd-accent);
  }

  .cl-seal-dot {
    width: 0.4375rem;
    height: 0.4375rem;
    border-radius: 50%;
    background: var(--sd-accent);
    box-shadow: 0 0 0 3px color-mix(in srgb, var(--sd-accent) 22%, transparent);
  }

  .cl-seal-body {
    display: flex;
    flex-direction: column;
    gap: 0.625rem;
    padding: 1.125rem;
  }

  .cl-seal-row {
    display: flex;
    align-items: baseline;
    gap: 1rem;
    font-size: 0.75rem;
    line-height: 1.4;
  }

  .cl-seal-k {
    flex: 0 0 4.5rem;
    color: var(--sd-muted);
  }

  .cl-seal-v {
    color: var(--sd-ink);
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
  }

  .cl-seal-sig {
    color: var(--sd-accent);
    letter-spacing: 0.12em;
  }

  .cl-seal-foot {
    display: flex;
    align-items: center;
    gap: 0.75rem;
    padding: 0.875rem 1.125rem;
    border-top: 1px solid var(--sd-line);
  }

  .cl-seal-line {
    flex: 1;
    height: 1px;
    background: linear-gradient(to right, var(--sd-accent), transparent);
  }

  .cl-seal-foot-label {
    font-size: 0.625rem;
    letter-spacing: 0.1em;
    text-transform: uppercase;
    color: var(--sd-muted);
    white-space: nowrap;
  }

  @media (max-width: 56rem) {
    .cl-hero-inner {
      grid-template-columns: 1fr;
    }

    .cl-hero-visual {
      justify-content: flex-start;
    }

    .cl-seal-card {
      transform: none;
    }
  }
</style>
