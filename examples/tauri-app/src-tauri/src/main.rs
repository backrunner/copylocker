#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use copylocker_suite_std::ClStd1;
use tauri_plugin_copylocker::CopyLockerConfig;

fn main() {
    let root_key = include_bytes!(concat!(env!("OUT_DIR"), "/development-root-key.bin"));
    let config = CopyLockerConfig::<ClStd1>::new(
        option_env!("CL_EXAMPLE_SERVER_URL").unwrap_or("http://127.0.0.1:8787/"),
        "dev.copylocker.example.tauri",
        option_env!("CL_EXAMPLE_PRODUCT_ID").unwrap_or("kat-product"),
        env!("CARGO_PKG_VERSION"),
        option_env!("CL_EXAMPLE_RELEASE_ID").unwrap_or("desktop-example"),
        option_env!("CL_EXAMPLE_BUILD_FINGERPRINT").unwrap_or("desktop-example-dev"),
        root_key.to_vec(),
        b"copylocker-desktop-example-fingerprint-salt".to_vec(),
        1,
        [0x43; 32],
        [0; 32],
    )
    .with_insecure_localhost(true);

    let result = tauri::Builder::default()
        .plugin(tauri_plugin_copylocker::init::<_, ClStd1>(config))
        .run(tauri::generate_context!());
    if let Err(error) = result {
        eprintln!("CopyLocker Tauri example failed: {error}");
    }
}
