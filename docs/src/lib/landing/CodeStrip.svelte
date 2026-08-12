<section class="cl-section" aria-labelledby="cl-code-title">
  <p class="cl-kicker"><span class="cl-kicker-mark" aria-hidden="true"></span>From zero to first unseal</p>
  <h2 id="cl-code-title" class="cl-section-title">Three commands</h2>
  <div class="cl-terminal">
    <div class="cl-terminal-bar" aria-hidden="true">
      <span class="cl-terminal-dot"></span>
      <span class="cl-terminal-dot"></span>
      <span class="cl-terminal-dot"></span>
      <span class="cl-terminal-title">copylocker — quickstart</span>
    </div>
    <pre><code
        ><span class="cl-line"><span class="cl-prompt">$</span> <span class="cl-cmd">cargo install --locked --path crates/copylocker-cli</span></span
        ><span class="cl-line"><span class="cl-prompt">$</span> <span class="cl-cmd">copylocker init server --product my-app \
    --d1-database-id … --kv-namespace-id … --secret-store-id …</span></span
        ><span class="cl-line"><span class="cl-prompt">$</span> <span class="cl-cmd">copylocker deploy --confirm</span></span></code></pre>
    <p class="cl-terminal-note">
      Server up, license issued, first <code>unseal()</code> — the full loop is in the
      <a href="/docs/guide/quickstart">5-minute quickstart</a>.
    </p>
  </div>
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

  .cl-terminal {
    border: 1px solid var(--sd-line);
    border-radius: var(--sd-radius);
    overflow: hidden;
    background: oklch(0.145 0 0);
    color: oklch(0.92 0 0);
  }

  .cl-terminal-bar {
    display: flex;
    align-items: center;
    gap: 0.5rem;
    padding: 0.75rem 1rem;
    border-bottom: 1px solid oklch(1 0 0 / 8%);
  }

  .cl-terminal-dot {
    width: 0.625rem;
    height: 0.625rem;
    border-radius: 50%;
    background: oklch(1 0 0 / 14%);
  }

  .cl-terminal-title {
    margin-left: 0.5rem;
    font-family: var(--font-mono);
    font-size: 0.75rem;
    color: oklch(0.6 0 0);
  }

  .cl-terminal pre {
    margin: 0;
    padding: 1.25rem 1.5rem;
    overflow-x: auto;
    font-family: var(--font-mono);
    font-size: 0.8125rem;
    line-height: 1.9;
  }

  .cl-line {
    display: block;
    white-space: pre;
  }

  .cl-prompt {
    color: oklch(0.75 0.13 178);
    user-select: none;
  }

  .cl-cmd {
    color: oklch(0.92 0 0);
  }

  .cl-terminal-note {
    margin: 0;
    padding: 0 1.5rem 1.25rem;
    font-size: 0.8125rem;
    line-height: 1.6;
    color: oklch(0.6 0 0);
  }

  .cl-terminal-note a {
    color: oklch(0.75 0.13 178);
    text-decoration: none;
    border-bottom: 1px solid oklch(0.75 0.13 178 / 40%);
  }

  .cl-terminal-note a:hover {
    border-bottom-color: oklch(0.75 0.13 178);
  }
</style>
