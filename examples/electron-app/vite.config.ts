import { resolve } from 'node:path'

import { defineConfig } from 'vite'

export default defineConfig({
  base: './',
  publicDir: resolve(import.meta.dirname, '../assets'),
  resolve: {
    preserveSymlinks: true,
  },
  build: {
    commonjsOptions: {
      include: [/node_modules/, /packages\/electron\/dist/],
    },
    outDir: 'dist/renderer',
    emptyOutDir: true,
  },
  clearScreen: false,
  server: {
    host: '127.0.0.1',
    port: 1421,
    strictPort: true,
  },
})
