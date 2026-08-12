# @copylocker/vue

Vue 3 bindings for [`@copylocker/web`](../web) (FR-WEB-010). A thin wrapper:
`createCopyLocker()` installs a plugin that provides a `CopyLocker` instance,
and `useCopyLocker()` forwards to it. No caching of unseal results, no derived
entitlement booleans.

> The `state` ref returned by the composable is **advisory, for UI display
> only** (ADR-0004). It can be stale, spoofed, or bypassed — never gate
> features on it. The only "use the license" entry point is `unseal` /
> `loadSealed`.

## Usage

```ts
import { createApp } from 'vue'
import { createCopyLocker } from '@copylocker/vue'
import App from './App.vue'

createApp(App)
  .use(
    createCopyLocker({
      options: {
        serverUrl: 'https://license.example.com',
        productId: 'my-product',
        rootPins: ['…hex…'],
      },
    }),
  )
  .mount('#app')
```

```vue
<script setup lang="ts">
import { useCopyLocker } from '@copylocker/vue'

const { state, unseal, activate } = useCopyLocker()
// state: Readonly<Ref<LicenseState>> — advisory display only
</script>
```

Pass `instance` instead of `options` to supply an already-created
`CopyLocker` (takes precedence):

```ts
app.use(createCopyLocker({ instance: client }))
```

## Notes

- **SSR safe**: nothing touches the browser at module scope, and the
  instance is only created when `window` exists. During SSR `state.value`
  stays `'unlicensed'` and the methods throw
  `CopyLocker: client is not ready yet` (see the `@copylocker/web` README
  "SSR" section).
- On `app.unmount()` (Vue 3.5+) the state subscription is released; an
  instance created from `options` is `dispose()`d, while a caller-provided
  `instance` is left to its owner.
- Before creation resolves, `state.value` is `'unlicensed'` and the methods
  throw `CopyLocker: client is not ready yet`; if creation itself fails, the
  methods rethrow that failure.

## Compatibility

- `vue >= 3` (auto-dispose on unmount needs Vue >= 3.5; earlier versions keep
  the instance alive)
- `@copylocker/web 0.1.0`

## License

GPL-3.0-only
