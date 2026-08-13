<section class="cl-section" aria-labelledby="cl-honest-title">
  <div class="cl-honest">
    <p class="cl-kicker"><span class="cl-kicker-mark" aria-hidden="true"></span>Honest security</p>
    <h2 id="cl-honest-title" class="cl-honest-title">
      We raise the cost of cracking.<br />We do not claim impossibility.
    </h2>
    <p class="cl-honest-body">
      An attacker with physical control of a machine can eventually extract whatever that machine
      can decrypt. Every client-side scheme only raises the bar — and the web build is inherently
      weaker than the native builds. CopyLocker's residual risks are written down, in public, in
      the threat model: what breaks, for whom, at what cost.
    </p>
    <p class="cl-honest-link">
      <a href="/docs/security/threat-model">Read the threat model before you ship →</a>
    </p>
  </div>
</section>

<style>
  .cl-honest {
    max-width: 46rem;
    padding-top: 2.5rem;
    border-top: 2px solid var(--sd-accent);
  }

  .cl-honest-title {
    margin: 0.875rem 0 1.25rem;
    font-size: clamp(1.625rem, 3.6vw, 2.25rem);
    font-weight: 650;
    letter-spacing: -0.025em;
    line-height: 1.18;
    color: var(--sd-ink);
    text-wrap: balance;
  }

  .cl-honest-body {
    margin: 0;
    font-size: 1rem;
    line-height: 1.65;
    color: var(--sd-muted);
  }

  .cl-honest-link {
    margin: 1.5rem 0 0;
    font-size: 0.9375rem;
  }

  .cl-honest-link a {
    color: var(--sd-accent);
    text-decoration: none;
    border-bottom: 1px solid color-mix(in srgb, var(--sd-accent) 35%, transparent);
  }

  .cl-honest-link a:hover {
    border-bottom-color: var(--sd-accent);
  }
</style>
