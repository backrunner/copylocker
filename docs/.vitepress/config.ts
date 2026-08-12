import { defineConfig } from 'vitepress'

export default defineConfig({
  title: 'CopyLocker',
  description:
    'Licensing and anti-tamper toolkit: post-quantum hybrid credentials, sealed assets, and honest client-side hardening.',
  lang: 'en-US',
  cleanUrls: true,
  lastUpdated: true,
  themeConfig: {
    nav: [
      { text: 'Guide', link: '/guide/quickstart' },
      { text: 'Security', link: '/security/threat-model' },
      { text: 'Operations', link: '/operations/runbook' },
    ],
    sidebar: {
      '/guide/': [
        {
          text: 'Guide',
          items: [
            { text: 'What is CopyLocker', link: '/guide/' },
            { text: '5-Minute Quickstart', link: '/guide/quickstart' },
            { text: 'Protection Levels (L0–L4)', link: '/guide/protection-levels' },
            { text: 'The Licensing Model', link: '/guide/licensing-model' },
            { text: 'Web SDK', link: '/guide/web-sdk' },
            { text: 'Deployment', link: '/guide/deployment' },
            { text: 'Migration', link: '/guide/migration' },
            { text: 'FAQ', link: '/guide/faq' },
          ],
        },
      ],
      '/security/': [
        {
          text: 'Security',
          items: [{ text: 'Security & Threat Model', link: '/security/threat-model' }],
        },
      ],
      '/operations/': [
        {
          text: 'Operations',
          items: [
            { text: 'Runbook', link: '/operations/runbook' },
            { text: 'SLOs & Alerting', link: '/operations/slo' },
            { text: 'Cost Estimation', link: '/operations/cost-estimation' },
          ],
        },
      ],
    },
    outline: { level: [2, 3] },
    search: { provider: 'local' },
    socialLinks: [{ icon: 'github', link: 'https://github.com/backrunner/copylocker' }],
    footer: {
      message: 'CopyLocker is licensed GPL-3.0-only.',
    },
  },
})
