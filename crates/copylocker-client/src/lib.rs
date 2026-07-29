//! Async desktop facade for CopyLocker (`20-client-core.md §4`).
//!
//! The crate joins the deterministic domain core to bounded HTTP transport, device-bound secure
//! storage, fingerprint collection, and opportunistic validation scheduling. Productive access
//! remains key-based: there is intentionally no `is_valid()` or `is_licensed()` API.

#![forbid(unsafe_code)]
#![cfg_attr(
    test,
    allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)
)]

mod client;
mod config;
mod error;
mod host;
mod platform;
mod scheduler;
mod snapshot;
mod transport;
mod trust;

pub use client::{CopyLockerClient, StateChange, StateSubscription};
pub use config::{Config, ConfigError, SchedulerConfig};
pub use error::{
    ActivateError, ActivationRejection, ClientInitError, DeactivateError, LocalError, OfflineError,
    ValidationError,
};
pub use host::HostErrorCode;
pub use transport::{
    HttpMethod, Transport, TransportError, TransportFuture, TransportRequest, TransportResponse,
};

#[cfg(feature = "transport-reqwest")]
pub use transport::ReqwestTransport;
