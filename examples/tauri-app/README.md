# CopyLocker Tauri example

Build `packages/tauri` first, then install this example and run `npm run tauri dev`.
The development fallback uses the public Root verifying key from the committed CL-STD-1 KAT and
loopback Worker URL `http://127.0.0.1:8787/`. Override the compile-time values with
`CL_EXAMPLE_SERVER_URL`, `CL_EXAMPLE_PRODUCT_ID`, `CL_EXAMPLE_RELEASE_ID`, and
`CL_EXAMPLE_BUILD_FINGERPRINT` for a registered release.

The capability grants `copylocker:allow-unseal` explicitly. Release builds keep devtools disabled
and use a restrictive CSP.
