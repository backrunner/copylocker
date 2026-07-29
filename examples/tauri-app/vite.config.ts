import { resolve } from 'node:path'
import { defineConfig } from 'vite'

export default defineConfig({
  publicDir: resolve(import.meta.dirname, '../assets'),
  clearScreen: false,
  server: {
    strictPort: true,
  },
})
