import { defineConfig } from 'svedocs/config';

export default defineConfig({
  site: {
    name: 'CopyLocker',
    title: 'CopyLocker Docs',
    description:
      'Licensing and anti-tamper toolkit: post-quantum hybrid credentials, sealed assets, and honest client-side hardening.',
    url: 'https://copylocker.pwp.sh'
  },
  theme: {
    defaultMode: 'system',
    palette: {
      accent: 'oklch(0.55 0.12 190)'
    },
    fonts: {
      sans: '"IBM Plex Sans", "Avenir Next", "Segoe UI", system-ui, sans-serif',
      mono: '"JetBrains Mono", "SFMono-Regular", ui-monospace, monospace',
      display: '"IBM Plex Sans", "Avenir Next", "Segoe UI", system-ui, sans-serif'
    },
    radius: '0.625rem',
    brand: {
      label: 'CopyLocker',
      href: '/',
      logo: '/mark.svg'
    },
    nav: [
      { label: 'Guide', href: '/docs/guide/quickstart' },
      { label: 'Security', href: '/docs/security/threat-model' },
      { label: 'Operations', href: '/docs/operations/runbook' }
    ],
    social: [
      {
        label: 'GitHub',
        href: 'https://github.com/backrunner/copylocker',
        external: true
      }
    ],
    footer: {
      text: 'CopyLocker is licensed GPL-3.0-only.',
      links: [
        {
          label: 'GitHub',
          href: 'https://github.com/backrunner/copylocker',
          external: true
        },
        {
          label: 'Licensing',
          href: 'https://github.com/backrunner/copylocker/blob/main/LICENSING.md',
          external: true
        },
        {
          label: 'Security',
          href: 'https://github.com/backrunner/copylocker/blob/main/SECURITY.md',
          external: true
        }
      ]
    }
  },
  search: {
    enabled: true,
    provider: 'local'
  },
  ai: false,
  seo: {
    sitemap: true,
    robots: true,
    rss: false
  },
  source: {
    editBaseUrl: 'https://github.com/backrunner/copylocker/edit/main/docs/'
  }
});
