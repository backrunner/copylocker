//! Tauri v2 host integration for CopyLocker.
//!
//! Commands expose productive byte transformations and an advisory UI state. There is
//! intentionally no boolean licence predicate.

#![forbid(unsafe_code)]
#![cfg_attr(
    test,
    allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)
)]

mod commands;
mod config;
pub mod evidence;
mod state;

use std::io;
use std::sync::Arc;

use copylocker_suite::{CryptoSuite, SignatureScheme};
use futures_util::StreamExt;
use tauri::plugin::{Builder as PluginBuilder, TauriPlugin};
use tauri::{Emitter, Manager, Runtime};

pub use config::CopyLockerConfig;
pub use state::{CommandError, StateDto, StateName, StateReasonName};

use state::{ClientApi, ManagedClient};

/// Event emitted whenever the advisory UI state changes.
pub const STATE_CHANGED_EVENT: &str = "copylocker://state-changed";

/// Build the CopyLocker plugin with a compile-time selected crypto suite.
pub fn init<R, S>(config: CopyLockerConfig<S>) -> TauriPlugin<R>
where
    R: Runtime,
    S: CryptoSuite,
    <S::Sig as SignatureScheme>::VerifyingKey: Send + Sync,
{
    PluginBuilder::new("copylocker")
        .invoke_handler(tauri::generate_handler![
            commands::cl_activate,
            commands::cl_deactivate,
            commands::cl_state,
            commands::cl_unseal,
            commands::cl_challenge,
            commands::cl_offline_request,
            commands::cl_offline_import,
            commands::cl_import_olk,
        ])
        .setup(move |app, _api| {
            let report = evidence::collect(
                config.expected_module_digest,
                &config.build_fingerprint,
                config.evidence_extra.clone(),
            );
            if report.degraded() {
                log::warn!(
                    "CopyLocker executable evidence collection degraded to the embedded digest"
                );
            }
            let client_config = config.into_client_config(report.into_evidence())?;
            let client = tauri::async_runtime::block_on(
                copylocker_client::CopyLockerClient::<S>::new(client_config),
            )?;
            let client: Arc<dyn ClientApi> = Arc::new(client);
            let mut changes = client.subscribe();
            if !app.manage(ManagedClient::new(Arc::clone(&client))) {
                return Err(io::Error::new(
                    io::ErrorKind::AlreadyExists,
                    "CopyLocker state is already managed",
                )
                .into());
            }

            let handle = app.clone();
            tauri::async_runtime::spawn(async move {
                while let Some(change) = changes.next().await {
                    let _ = handle.emit(STATE_CHANGED_EVENT, StateDto::from(change));
                }
            });
            Ok(())
        })
        .build()
}
