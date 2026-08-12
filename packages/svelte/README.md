# @copylocker/svelte

Svelte bindings for [`@copylocker/web`](../web) (FR-WEB-010). A thin wrapper:
`createCopyLockerStore()` wraps a `CopyLocker` instance in a Svelte store and
forwards every call to it. No caching of unseal results, no derived
entitlement booleans.

> The `state` store is **advisory, for UI display only** (ADR-0004). It can
> be stale, spoofed, or bypassed — never gate features on it. The only
> "use the license" entry point is `unseal` / `loadSealed`.

## Usage

```ts
// copylocker.ts — create once, on the client
import { createCopyLockerStore } from '@copylocker/svelte'

export const copylocker = createCopyLockerStore({
  serverUrl: 'https://license.example.com',
  productId: 'my-product',
  rootPins: ['…hex…'],
})
```

```svelte
<script lang="ts">
  import { copylocker } from './copylocker'
  const { state } = copylocker
</script>

<!-- $state: advisory display only -->
<p>License: {$state}</p>
```

The store follows the Svelte store contract (`state.subscribe`), so it works
with `$state` auto-subscription and `get()` from `svelte/store`.

## Notes

- **SSR safe**: the instance is only created when `window` exists. During
  SSR the store stays at `'unlicensed'` and the methods throw
  `CopyLocker: client is not ready yet`; if creation itself fails, the
  methods rethrow that failure.
- Call `copylocker.dispose()` when tearing down the app to stop the
  scheduler and release the state subscription.

## Compatibility

- `svelte >= 4 || >= 5` (only `svelte/store` is used)
- `@copylocker/web 0.1.0`

## License

GPL-3.0-only
