/// <reference types="vite/client" />

interface ImportMetaEnv {
  /** Base URL of the CopyLocker Worker (default http://localhost:8787). */
  readonly VITE_CL_SERVER_URL?: string
  /** Product id (default `kat-product`, matching the CL-STD-1 KAT). */
  readonly VITE_CL_PRODUCT_ID?: string
  /** Hex-encoded pinned Root verifying key (default: the CL-STD-1 KAT key). */
  readonly VITE_CL_ROOT_PIN?: string
  /** Release id the client reports (default `dev`). */
  readonly VITE_CL_RELEASE_ID?: string
  /** Build fingerprint evidence string (default `dev`). */
  readonly VITE_CL_BUILD_FINGERPRINT?: string
  /** Numeric variant id the client reports (default `0`). */
  readonly VITE_CL_VARIANT_ID?: string
  /** Scheduler tick interval in milliseconds (SDK default 60000). */
  readonly VITE_CL_SCHEDULER_INTERVAL_MS?: string
  /** Minimum validation interval in seconds (core default 60). */
  readonly VITE_CL_MIN_VALIDATION_INTERVAL_SECS?: string
}

interface ImportMeta {
  readonly env: ImportMetaEnv
}

/**
 * Published by the `@copylocker/unplugin` guard bootstrap (build-only): the
 * actually-computed integrity-manifest root. `undefined` in `vite dev` and in
 * builds without the plugin.
 */
// eslint-disable-next-line no-var
declare var __CL_GUARD_R__: Promise<Uint8Array> | undefined
