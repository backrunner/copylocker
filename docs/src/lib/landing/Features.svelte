<script lang="ts">
  const features = [
    {
      title: 'Post-quantum hybrid credentials',
      line: 'ML-DSA hybrid signatures and X-Wing (ML-KEM-768 + X25519) KEM — CL-STD-1, with public known-answer vectors.',
      href: '/docs/guide/licensing-model'
    },
    {
      title: 'Sealed assets & R-bound builds',
      line: 'Features stay encrypted until a valid credential derives their keys — skipping the check means skipping the content.',
      href: '/docs/guide/protection-levels'
    },
    {
      title: 'Offline activation loop',
      line: 'Grace windows, monotonic clocks, and a public offline portal keep paying users working through outages.',
      href: '/docs/guide/quickstart'
    },
    {
      title: 'Privacy-preserving analytics & DSR',
      line: 'No end-user data leaves your Cloudflare account; the only subprocessor in the data path is Cloudflare.',
      href: '/docs/operations/runbook'
    },
    {
      title: 'Admin console & typed SDK',
      line: 'Operate licenses, epochs, and catalogs through the copylocker CLI and the authenticated Admin API.',
      href: '/docs/guide/deployment'
    },
    {
      title: 'Honest threat model',
      line: 'Residual risks are written down in public. We raise the cost of cracking; we do not claim impossibility.',
      href: '/docs/security/threat-model'
    }
  ];
</script>

<section class="cl-section" aria-labelledby="cl-features-title">
  <p class="cl-kicker"><span class="cl-kicker-mark" aria-hidden="true"></span>What it does</p>
  <h2 id="cl-features-title" class="cl-section-title">Six things, done deliberately</h2>
  <ul class="cl-grid" role="list">
    {#each features as feature, i}
      <li>
        <a class="cl-card" href={feature.href}>
          <span class="cl-card-num" aria-hidden="true">{String(i + 1).padStart(2, '0')}</span>
          <span class="cl-card-title">{feature.title}</span>
          <span class="cl-card-line">{feature.line}</span>
          <span class="cl-card-more" aria-hidden="true">→</span>
        </a>
      </li>
    {/each}
  </ul>
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

  .cl-grid {
    display: grid;
    grid-template-columns: repeat(3, 1fr);
    gap: 1px;
    margin: 0;
    padding: 0;
    list-style: none;
    background: var(--sd-line);
    border: 1px solid var(--sd-line);
    border-radius: var(--sd-radius);
    overflow: hidden;
  }

  .cl-card {
    position: relative;
    display: flex;
    flex-direction: column;
    gap: 0.625rem;
    height: 100%;
    padding: 1.5rem;
    background: var(--sd-bg);
    text-decoration: none;
    transition: background-color 150ms ease;
  }

  /* Accent hairline that draws in from the left on hover. */
  .cl-card::before {
    content: '';
    position: absolute;
    top: 0;
    left: 0;
    width: 100%;
    height: 2px;
    background: var(--sd-accent);
    transform: scaleX(0);
    transform-origin: left;
    transition: transform 200ms ease;
  }

  .cl-card:hover {
    background: var(--sd-panel);
  }

  .cl-card:hover::before,
  .cl-card:focus-visible::before {
    transform: scaleX(1);
  }

  .cl-card-num {
    font-family: var(--font-mono);
    font-size: 0.6875rem;
    letter-spacing: 0.1em;
    color: var(--sd-muted);
  }

  .cl-card-title {
    font-size: 1rem;
    font-weight: 600;
    letter-spacing: -0.01em;
    color: var(--sd-ink);
  }

  .cl-card-line {
    font-size: 0.875rem;
    line-height: 1.6;
    color: var(--sd-muted);
  }

  .cl-card-more {
    margin-top: auto;
    padding-top: 0.75rem;
    font-size: 0.875rem;
    color: var(--sd-accent);
    opacity: 0;
    transform: translateX(-4px);
    transition:
      opacity 150ms ease,
      transform 150ms ease;
  }

  .cl-card:hover .cl-card-more,
  .cl-card:focus-visible .cl-card-more {
    opacity: 1;
    transform: translateX(0);
  }

  @media (max-width: 60rem) {
    .cl-grid {
      grid-template-columns: repeat(2, 1fr);
    }
  }

  @media (max-width: 38rem) {
    .cl-grid {
      grid-template-columns: 1fr;
    }

    .cl-card-more {
      opacity: 1;
      transform: none;
    }
  }
</style>
