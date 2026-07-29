import { build } from 'esbuild'

const common = {
  bundle: true,
  logLevel: 'info',
  minify: false,
  platform: 'node',
  sourcemap: false,
  target: 'node22',
}

await Promise.all([
  build({
    ...common,
    entryPoints: ['src/main/index.ts'],
    external: ['@copylocker/node', 'electron'],
    outfile: 'dist/electron/main.cjs',
    format: 'cjs',
  }),
  build({
    ...common,
    entryPoints: ['src/preload/index.ts'],
    external: ['electron'],
    outfile: 'dist/electron/preload.cjs',
    format: 'cjs',
  }),
])
