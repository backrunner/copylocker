# CopyLocker Electron example

Build `crates/copylocker-node` and `packages/electron`, then install this example and run
`npm start`. The development configuration uses the public Root verifying key from the committed
CL-STD-1 KAT and the loopback Worker URL `http://127.0.0.1:8787/`.

The build script embeds configuration before bundling the main process. Set
`CL_EXAMPLE_SERVER_URL`, `CL_EXAMPLE_PRODUCT_ID`, `CL_EXAMPLE_RELEASE_ID`,
`CL_EXAMPLE_BUILD_FINGERPRINT`, and `CL_EXAMPLE_MODULE_DIGEST` in the release build environment.
`CL_EXAMPLE_MODULE_DIGEST` is the 32-byte evidence fallback registered for that release; the
development default is not suitable for production registration.

The sandboxed preload is bundled into one file because Electron's sandboxed preload loader cannot
resolve arbitrary npm modules. The renderer receives only the fixed `window.__cl` bridge. The main
process allowlists `pro-config`, keeps opaque challenge handling disabled, rejects child-frame IPC,
and rate-limits both requests and bytes.
Renderer assets are served from the standard, secure `copylocker://bundle` protocol with normalized
paths constrained to the packaged renderer directory, so the file-protocol privilege fuse stays off.

`npm run package` creates an unpacked application under `release/`. Electron Packager keeps
`app.asar` enabled and unpacks native `.node` files; the fuse step then enables embedded ASAR
integrity validation and ASAR-only loading, and disables RunAsNode, Node options, and CLI inspection fuses. Production
artifacts still require platform code signing and macOS notarization or Windows Authenticode.
The packaging command reads the resulting fuse wire and verifies both `app.asar` and the unpacked
native binding before it succeeds.
