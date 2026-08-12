import { defineConfig } from 'tsup'

export default defineConfig({
  entry: ['src/index.ts'],
  format: ['esm'],
  // dts via `tsc --emitDeclarationOnly`: rollup-plugin-dts is incompatible
  // with the repo-pinned TypeScript 7.
  dts: false,
  sourcemap: true,
  clean: true,
  outDir: 'dist',
})
