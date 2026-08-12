import { defineConfig } from 'vitest/config'

// The container cross-tests import the `@copylocker/web` sources directly
// (`../web/src/unseal.ts`) so the byte-compatibility checks always run against
// the web package's current implementation, not a stale published artifact.
export default defineConfig({
  server: {
    fs: {
      allow: ['..'],
    },
  },
})
