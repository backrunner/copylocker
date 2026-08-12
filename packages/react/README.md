# @copylocker/react

React bindings for [`@copylocker/web`](../web) (FR-WEB-010). A thin wrapper:
`CopyLockerProvider` holds a `CopyLocker` instance in context and
`useCopyLocker()` forwards to it. No caching of unseal results, no derived
entitlement booleans.

> The `state` returned by the hook is **advisory, for UI display only**
> (ADR-0004). It can be stale, spoofed, or bypassed — never gate features on
> it. The only "use the license" entry point is `unseal` / `loadSealed`.

## Usage

```tsx
import { CopyLockerProvider, useCopyLocker } from '@copylocker/react'

function App() {
  return (
    <CopyLockerProvider
      options={{
        serverUrl: 'https://license.example.com',
        productId: 'my-product',
        rootPins: ['…hex…'],
      }}
    >
      <Feature />
    </CopyLockerProvider>
  )
}

function Feature() {
  const { state, unseal, activate } = useCopyLocker()
  // state: advisory display string; unseal(featureId, sealed) → Uint8Array
  ...
}
```

Pass `instance` instead of `options` to supply an already-created
`CopyLocker` (takes precedence):

```tsx
<CopyLockerProvider instance={client}>…</CopyLockerProvider>
```

## Notes

- **SSR safe**: the instance is created in an effect; nothing touches the
  browser at module scope or during server render. The server snapshot of
  `state` is `'unlicensed'`.
- An instance created from `options` is `dispose()`d when the provider
  unmounts; a caller-provided `instance` is left to its owner.
- Before creation resolves, `state` is `'unlicensed'` and the methods throw
  `CopyLocker: client is not ready yet`; if creation itself fails, the
  methods rethrow that failure.

## Compatibility

- `react >= 18` (uses `useSyncExternalStore`)
- `@copylocker/web 0.1.0`

## License

GPL-3.0-only
