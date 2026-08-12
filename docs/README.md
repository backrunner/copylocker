# CopyLocker documentation site

The CopyLocker documentation site, built with [svedocs](https://github.com/backrunner/svedocs)
(SvelteKit + Cloudflare Pages) with a custom CopyLocker theme and landing page.

## Develop

```bash
npm install
npm run dev
```

Content lives in `content/`:

- `content/docs/**` renders under `/docs/**` (guide, security, operations) — frontmatter
  `title` / `navTitle` / `order` drive the sidebar.
- `content/pages/index.md` is the landing driver (`layout: home`); the landing itself is
  implemented in `src/lib/landing/` through the svedocs `landing` slot.

Theme configuration is in `svedocs.config.ts`; precise token overrides for light/dark are in
`src/lib/styles/copylocker.css`. The `Callout` MDX component (`src/lib/Callout.svelte`,
info/warning/danger) is registered in `vite.config.ts`.

## Check and build

```bash
npm run check    # svelte-kit sync + tsc --noEmit
npm run build    # edge build → .svelte-kit/cloudflare
npm run preview  # wrangler pages dev .svelte-kit/cloudflare
```

## Deploy

```bash
npm run deploy   # svedocs deploy cloudflare -- --project-name copylocker-docs
```

The deploy targets the Cloudflare Pages project `copylocker-docs`. Attaching the custom domain
`copylocker.pwp.sh` is a Cloudflare dashboard action: Pages project → **Custom domains** →
**Set up a custom domain**. CI (`.github/workflows/docs.yml`) build-checks the site on every
docs change and deploys when the `CL_DOCS_DEPLOY` repository variable is `'true'` and the
`CLOUDFLARE_API_TOKEN` / `CLOUDFLARE_ACCOUNT_ID` secrets are configured.
