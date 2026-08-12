# @copylocker/guard

Runtime integrity verification for CopyLocker-built web bundles (M4). The
build-time half lives in `@copylocker/unplugin`, which injects this package
into the bundle entry.

**The one-sentence contract:** `bootGuard()` returns `R` — the
**actually-computed** Merkle root over the bundle's chunks — and `R`
participates in `FinalKey` derivation in `@copylocker/web`. Integrity
failure never throws; it changes `R`, which changes the derived key, which
makes sealed assets fail to open. Deleting the guard means never computing
`R`, which is why the check cannot be removed or stubbed out.

```ts
import { bootGuard } from '@copylocker/guard'

const { R, report } = await bootGuard({
  manifest: __CL_MANIFEST__, // inlined signed manifest (CBOR bytes)
  rootPins: __CL_ROOT_PINS__, // pinned Ed25519 public keys (hex or raw)
  chunks: __CL_CHUNKS__, // injected [{ url, pattern }] mapping (entry first)
  strategy: 'idle', // default; see below
})
// hand R to @copylocker/web:
//   CopyLocker.create({ ..., integrity: { manifestRoot: () => R } })
```

## Strategies

| strategy | `R` computed over | notes |
|---|---|---|
| `'sync'` | actual digests | verify everything before returning |
| `'idle'` (default) | actual digests | first listed chunk (the entry chunk, by injection convention) inline; the rest one per `requestIdleCallback` slice (`setTimeout` fallback). NFR-PERF-006: keeps LCP impact under 20ms |
| `'lazy'` | **expected** digests | returns immediately; verification continues in the background and lands in `report` (await `result.settled`). Weakest binding — use only where boot latency dominates |
| `'report-only'` | actual digests | **same R semantics as `'sync'`** — it only adds per-entry diagnostics via `log`. Development/diagnosis mode |

Missing, unfetchable, or unmatched chunks contribute a 32-zero-byte digest,
which differs from any real expected digest — tampering by deletion still
changes `R`. Under `'lazy'` (where `R` is computed over expected digests)
any non-`ok` background result is additionally mixed into `GuardState`, so
it still perturbs derived keys once observed.

Digests use `crypto.subtle.digest('SHA-256', …)` (WebCrypto: no CSP
relaxation needed, worker-friendly). BLAKE3 is reserved for a later WASM
variant (`hash_alg` other than `'sha256'` is logged and computed as
SHA-256 by this runtime).

## Manifest wire format (v1 decisions)

Canonical CBOR throughout (RFC 7049 §3.9; the strict decoder rejects
non-canonical input). Container and payload:

```cddl
signed_integrity_manifest = {
  0: bytes,   ; canonical CBOR of integrity_manifest_tbs
  1: bytes,   ; Ed25519 signature (empty = unsigned development build)
}

integrity_manifest_tbs = {
  0: uint,              ; proto_ver (= 1)
  1: bytes .size 4,     ; suite_id
  2: tstr,              ; product_id
  3: tstr,              ; build_fingerprint
  4: int,               ; built_at (unix seconds)
  5: tstr,              ; hash_alg ("sha256" for this runtime)
  6: { * tstr => {      ; pattern => entry — v1 extension of protocol-spec §9's
         1: bytes,      ;   bare `{* tstr => bytes}`: a map carrying the digest
         2: ? [* [uint, uint]], ; excludedRanges [start, end) pairs
       } },
  7: ? { * tstr => bytes }, ; guarded function id => normalized body digest
  8: ? [* tstr],        ; sealed asset ids
  9: bytes,             ; root — Merkle root over the entries
}
```

Decisions recorded here (the unplugin MUST match them exactly):

- **Signature payload**: `Ed25519.sign("copylocker/im-sig/v1" ‖ tbs-bytes)`
  where `tbs-bytes` is the exact canonical-CBOR bstr of field 0 (the tbs is
  embedded as a bstr, not re-encoded, so verification does not depend on
  re-encoding correctness).
- **Entries extension**: protocol-spec §9 defines `6: {* tstr => bytes}`;
  the v1 web extension makes each value a map `{1: digest, 2: ?
  excludedRanges}`. The decoder still tolerates a bare `bytes` value (no
  excludedRanges possible) for forward compatibility.
- **Merkle leaf order**: the entries map order, which — because the CBOR is
  canonical and the decoder enforces key order — is canonical CBOR key
  order (encoded keys: shorter first, then bytewise). No re-sorting at
  runtime.
- **Merkle rules**: leaf `= SHA-256(utf8(pattern) ‖ digest)`; internal node
  `= SHA-256(left ‖ right)`; an odd node at a level is duplicated
  (`H(last ‖ last)`); a single leaf IS the root; the empty tree's root is
  `SHA-256("")`.

### Signature verification is provenance, not enforcement

The Ed25519 check proves the manifest came from the vendor's build key. The
integrity **enforcement** comes from `R` feeding key derivation — a validly
signed manifest over tampered chunks still derives the wrong key. When
WebCrypto Ed25519 is unavailable (e.g. older Firefox), verification degrades
to `'unsupported'`: a warning is logged and boot continues. Statuses:
`'verified' | 'failed' | 'unsigned' | 'no-pins' | 'unsupported'`.

## Placeholder zeroing (two-round self-reference)

The manifest contains chunk digests, but chunks embed the manifest root —
a cycle. The build breaks it with fixed-length placeholders:

1. Build digests every chunk with the placeholder span **zeroed**, and
   records the span in the entry's `excludedRanges`.
2. Build writes the real root into the placeholder (same length — offsets
   unchanged) and ships.
3. Runtime zeroes `excludedRanges` before digesting → digests match.

`zeroExcludedRanges(bytes, ranges)` is exported for parity testing; ranges
are `[start, end)`, clamped to bounds, inverted ranges ignored.

## `@guarded` and `GuardState`

```ts
import { guarded, guardedFn, GuardState } from '@copylocker/guard'

class Engine {
  @guarded('engine.render')           // TS 5 standard AND legacy signatures
  render(scene: Scene) { /* … */ }
}

export const compute = guardedFn('compute', (x: number) => /* … */)
```

On each sampled call (default rate 0.15, `shouldSample`), the wrapper reads
the function body through a module-load-captured native
`Function.prototype.toString`, normalizes it (`normalizeSource`: comments
and whitespace removed, strings/templates verbatim), digests it, and
**mixes** it into the global state:

```
state₀ = 0×32 bytes
stateₙ₊₁ = SHA-256(stateₙ ‖ utf8(id) ‖ digest)
```

`GuardState.getR()` returns the current snapshot; `GuardState.settled()`
awaits all queued mixes (mixes are queued through a promise chain, so their
ORDER is deterministic regardless of async completion). Never throws — a
replaced body just moves the state. `bootGuard` also mixes boot-time
`mismatch`/`missing` discrepancies under ids `boot:<pattern>`, so consumers
that combine `GuardState.getR()` into derivation pick up late (idle/lazy)
failures too.

A `Function.prototype.toString` override is detected by `===` against the
captured native reference — on every sampled call and via the optional
`startToStringWatch(intervalMs)` interval — and mixed in (id
`copylocker/guard:tostring-override`), never thrown. Honest limitation: an
attacker executing BEFORE the guard chunk (browser extension, patched
`index.html`) can still win; this raises the cost of automated tooling.

`normalizeSource` uses a heuristic to tell regex literals from division
(after an identifier/`)`/`]` → division; after punctuation or a keyword →
regex). Known limitation: `if (x) /re/.test(y)` misclassifies; guarded
functions should avoid regex literals there. The same normalizer must run
at build time and runtime — it is exported for the unplugin transformer.

## Diagnostics

`@copylocker/guard/diagnose` (a separate subpath export, kept off the boot
path) runs a full synchronous verification and returns per-entry
expected/actual digests — for consoles and support tooling only:

```ts
import { diagnose, formatDiagnosis } from '@copylocker/guard/diagnose'
console.log(formatDiagnosis(await diagnose({ manifest, rootPins, chunks })))
```

## Deployment notes

- **CORS**: the guard fetches its own chunks with `cache: 'force-cache'`.
  Cross-origin CDN chunks must send `Access-Control-Allow-Origin` (and be
  served with CORS-enabled `<script crossorigin>` tags) or the bytes are
  unreadable — entries degrade to `fetch-error` and `R` changes. Same-origin
  needs nothing.
- **HTTP cache**: `force-cache` serves the already-downloaded copy instead
  of re-fetching. A Service Worker can still serve tampered bytes — the
  known bypass; mitigate by including the SW script in the manifest and
  watching `navigator.serviceWorker.controller`.
- **Inline scripts** cannot be fetched by URL; keep guarded chunks external.
- **CSP**: no `unsafe-eval`, no extra directives needed (WebCrypto + fetch
  only).

## Interface for `@copylocker/unplugin` (build-time half)

The next task implements the plugin against these exact injection points:

- `__CL_MANIFEST__` — `Uint8Array`, CBOR `signed_integrity_manifest` (above).
- `__CL_ROOT_PINS__` — `string[]`, hex Ed25519 public keys.
- `__CL_CHUNKS__` — `{ url: string; pattern: string }[]`, **entry chunk
  first**; patterns must be the manifest's key-6 keys. URL resolution falls
  back to `performance.getEntriesByType('resource')` suffix matching when a
  pattern is unmapped.
- Placeholder spans: fixed-length regions recorded as `excludedRanges`
  `[start, end)` per entry; the plugin digests with them zeroed, then writes
  the root (and K_BUILD shards) into them without changing lengths.
- Entry-point injection (pseudocode, emitted by the plugin):

  ```ts
  import { bootGuard } from '@copylocker/guard'
  const { R } = await bootGuard({
    manifest: __CL_MANIFEST__,
    rootPins: __CL_ROOT_PINS__,
    chunks: __CL_CHUNKS__,
    strategy: 'idle',
  })
  // then: CopyLocker.create({ …, integrity: { manifestRoot: () => R } })
  ```

- Guarded functions: the transformer digests
  `SHA-256(utf8(normalizeSource(fnSource)))` per function id into manifest
  key 7, using the exported `normalizeSource` from this package — digests
  MUST be collected from the final (minified) output, so the plugin must run
  after minification (`enforce: 'post'`).

## License

GPL-3.0-only.
