//! Stable C ABI for native CopyLocker hosts.
//!
//! Handles are opaque process-local tokens. Productive access is exposed only as byte
//! transformations; the numeric state is advisory UI information.

#![deny(unsafe_op_in_unsafe_fn)]
#![cfg_attr(
    test,
    allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)
)]

use core::ffi::c_char;
use core::ptr;
use std::collections::HashMap;
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, OnceLock};

use copylocker_client::{Config, CopyLockerClient, HostErrorCode};
use copylocker_proto::{ClientInfo, MAX_FEATURE_CHALLENGE_BYTES, MAX_SEALED_ASSET_BYTES};
use copylocker_suite::EnvEvidence;
use copylocker_suite_std::ClStd1;
use copylocker_types::{Digest, LicenseState};
use tokio::runtime::{Builder as RuntimeBuilder, Runtime};

const MAX_SERVER_URL_BYTES: usize = 4 * 1024;
const MAX_IDENTIFIER_BYTES: usize = 128;
const MAX_BUILD_METADATA_BYTES: usize = 1024;
const MAX_KEY_BYTES: usize = 4 * 1024;
const MAX_ROOT_KEY_BYTES: usize = 64 * 1024;
const MAX_FINGERPRINT_SALT_BYTES: usize = 64 * 1024;
const MAX_FEATURE_BYTES: usize = 1024;
const MAX_OFFLINE_RESPONSE_BYTES: usize = 1024 * 1024;
const MAX_ARMORED_OLK_BYTES: usize = 2 * 1024 * 1024;

/// Operation completed successfully.
pub const CL_SUCCESS: i32 = 0;
/// Operation failed; inspect `cl_error.code` for the stable numeric category.
pub const CL_FAILURE: i32 = -1;

/// Invalid or destroyed client handle.
pub const CL_STATE_ERROR: i32 = -1;
/// No credential is installed.
pub const CL_STATE_UNLICENSED: i32 = 0;
/// Activation is in progress.
pub const CL_STATE_ACTIVATING: i32 = 1;
/// The credential is current.
pub const CL_STATE_ACTIVE: i32 = 2;
/// An online refresh is due.
pub const CL_STATE_NEEDS_REVALIDATION: i32 = 3;
/// A transient outage is inside grace.
pub const CL_STATE_GRACE: i32 = 4;
/// Productive key derivation is unavailable pending recovery.
pub const CL_STATE_LOCKED: i32 = 5;
/// The credential was revoked and wiped.
pub const CL_STATE_REVOKED: i32 = 6;
/// Integrity verification failed closed.
pub const CL_STATE_TAMPERED: i32 = 7;

/// Borrowed byte slice. The caller retains ownership for the duration of the call.
#[allow(non_camel_case_types)]
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct cl_bytes {
    pub data: *const u8,
    pub len: usize,
}

impl Default for cl_bytes {
    fn default() -> Self {
        Self {
            data: ptr::null(),
            len: 0,
        }
    }
}

/// Borrowed length-delimited UTF-8 string. A trailing NUL is neither required nor included.
#[allow(non_camel_case_types)]
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct cl_str {
    pub data: *const c_char,
    pub len: usize,
}

impl Default for cl_str {
    fn default() -> Self {
        Self {
            data: ptr::null(),
            len: 0,
        }
    }
}

/// Owned output buffer. Release it with `cl_free_buf` exactly once when practical.
/// Repeated releases of the same unchanged value are tolerated.
#[allow(non_camel_case_types)]
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct cl_buf {
    pub data: *mut u8,
    pub len: usize,
    /// Opaque allocation token; callers must not modify it.
    pub handle: usize,
}

impl Default for cl_buf {
    fn default() -> Self {
        Self {
            data: ptr::null_mut(),
            len: 0,
            handle: 0,
        }
    }
}

/// Stable detail-free error returned across the host boundary.
#[allow(non_camel_case_types)]
#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct cl_error {
    pub code: u32,
}

/// Build-time client configuration. All borrowed fields are copied by `cl_create`.
#[allow(non_camel_case_types)]
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct cl_config {
    pub server_url: cl_str,
    pub app_id: cl_str,
    pub product_id: cl_str,
    pub app_version: cl_str,
    pub release_id: cl_str,
    pub build_fingerprint: cl_str,
    pub current_root_key: cl_bytes,
    /// Empty when no successor Root key is pre-positioned.
    pub next_root_key: cl_bytes,
    pub fingerprint_salt: cl_bytes,
    pub variant_id: u64,
    /// Exactly 32 bytes.
    pub variant_const: cl_bytes,
    /// Exactly 32 bytes and registered with the release evidence.
    pub module_digest: cl_bytes,
    /// Must be 0 or 1.
    pub allow_unbound_olk: u8,
    /// Must be 0 or 1; permits HTTP only for loopback development origins.
    pub allow_insecure_localhost: u8,
}

/// Opaque process-local client handle. Never dereference this pointer.
#[allow(non_camel_case_types, dead_code)]
#[derive(Debug)]
pub struct cl_client {
    private: [u8; 0],
}

type BoundaryResult<T> = Result<T, HostErrorCode>;
type SharedClient = Arc<Mutex<Box<dyn ClientApi>>>;

static CLIENTS: OnceLock<Mutex<HashMap<usize, SharedClient>>> = OnceLock::new();
static NEXT_CLIENT_HANDLE: AtomicUsize = AtomicUsize::new(1);
static BUFFERS: OnceLock<Mutex<HashMap<usize, Box<[u8]>>>> = OnceLock::new();
static NEXT_BUFFER_HANDLE: AtomicUsize = AtomicUsize::new(1);

trait ClientApi: Send {
    fn activate(&mut self, key: &str) -> BoundaryResult<()>;
    fn deactivate(&mut self) -> BoundaryResult<()>;
    fn state(&self) -> LicenseState;
    fn unseal(&mut self, feature: &str, data: &[u8]) -> BoundaryResult<Vec<u8>>;
    fn challenge(&mut self, input: &[u8]) -> BoundaryResult<Vec<u8>>;
    fn offline_request(&mut self, key: &str) -> BoundaryResult<Vec<u8>>;
    fn offline_import(&mut self, data: &[u8]) -> BoundaryResult<()>;
    fn import_olk(&mut self, data: &str) -> BoundaryResult<()>;
}

struct NativeClient {
    runtime: Runtime,
    client: CopyLockerClient<ClStd1>,
}

impl NativeClient {
    fn new(config: Config) -> BoundaryResult<Self> {
        let runtime = RuntimeBuilder::new_multi_thread()
            .worker_threads(1)
            .thread_name("copylocker-ffi")
            .enable_all()
            .build()
            .map_err(|_| HostErrorCode::UNKNOWN_FATAL)?;
        let client = runtime
            .block_on(CopyLockerClient::<ClStd1>::new(config))
            .map_err(HostErrorCode::from)?;
        Ok(Self { runtime, client })
    }
}

impl ClientApi for NativeClient {
    fn activate(&mut self, key: &str) -> BoundaryResult<()> {
        self.runtime
            .block_on(self.client.activate(key))
            .map_err(HostErrorCode::from)
    }

    fn deactivate(&mut self) -> BoundaryResult<()> {
        self.runtime
            .block_on(self.client.deactivate())
            .map_err(HostErrorCode::from)
    }

    fn state(&self) -> LicenseState {
        self.client.state()
    }

    fn unseal(&mut self, feature: &str, data: &[u8]) -> BoundaryResult<Vec<u8>> {
        self.client
            .unseal(feature, data)
            .map_err(HostErrorCode::from)
    }

    fn challenge(&mut self, input: &[u8]) -> BoundaryResult<Vec<u8>> {
        self.client.challenge(input).map_err(HostErrorCode::from)
    }

    fn offline_request(&mut self, key: &str) -> BoundaryResult<Vec<u8>> {
        self.client
            .build_offline_request(key)
            .map_err(HostErrorCode::from)
    }

    fn offline_import(&mut self, data: &[u8]) -> BoundaryResult<()> {
        self.client
            .import_offline_response(data)
            .map_err(HostErrorCode::from)
    }

    fn import_olk(&mut self, data: &str) -> BoundaryResult<()> {
        self.client.import_olk(data).map_err(HostErrorCode::from)
    }
}

/// Create and restore a client. Returns NULL on failure.
///
/// # Safety
/// `config` and every non-empty borrowed field must point to readable memory for the duration of
/// this call. `error`, when non-NULL, must point to writable `cl_error` storage.
#[no_mangle]
pub unsafe extern "C" fn cl_create(
    config: *const cl_config,
    error: *mut cl_error,
) -> *mut cl_client {
    // SAFETY: The caller obligations are documented above; all borrowed fields are copied here.
    unsafe {
        ffi_call(error, ptr::null_mut(), || {
            let config = parse_config(config)?;
            register_client(Box::new(NativeClient::new(config)?))
        })
    }
}

/// Destroy a client handle. NULL, invalid, and repeated destroys are no-ops.
#[no_mangle]
pub extern "C" fn cl_destroy(client: *mut cl_client) {
    let _ = catch_unwind(AssertUnwindSafe(|| {
        if client.is_null() {
            return;
        }
        if let Ok(mut clients) = clients().lock() {
            clients.remove(&(client as usize));
        }
    }));
}

/// Activate with a license key.
///
/// # Safety
/// Non-empty input fields must point to readable memory. `error`, when non-NULL, must be writable.
#[no_mangle]
pub unsafe extern "C" fn cl_activate(
    client: *mut cl_client,
    key: cl_str,
    error: *mut cl_error,
) -> i32 {
    // SAFETY: The caller obligations are documented above and the key is copied before use.
    unsafe {
        ffi_call(error, CL_FAILURE, || {
            let key = copy_text(key, MAX_KEY_BYTES)?;
            with_client(client, |client| client.activate(&key))?;
            Ok(CL_SUCCESS)
        })
    }
}

/// Release an online seat or erase a local OLK.
///
/// # Safety
/// `error`, when non-NULL, must point to writable `cl_error` storage.
#[no_mangle]
pub unsafe extern "C" fn cl_deactivate(client: *mut cl_client, error: *mut cl_error) -> i32 {
    // SAFETY: The only raw write is to the caller-provided optional error slot.
    unsafe {
        ffi_call(error, CL_FAILURE, || {
            with_client(client, |client| client.deactivate())?;
            Ok(CL_SUCCESS)
        })
    }
}

/// Return the advisory UI state, or `CL_STATE_ERROR` for an invalid handle or panic.
#[no_mangle]
pub extern "C" fn cl_state(client: *mut cl_client) -> i32 {
    catch_unwind(AssertUnwindSafe(|| {
        with_client(client, |client| Ok(state_code(client.state()))).unwrap_or(CL_STATE_ERROR)
    }))
    .unwrap_or(CL_STATE_ERROR)
}

/// Authenticate and decrypt a sealed asset.
///
/// # Safety
/// Non-empty input fields must point to readable memory. `error`, when non-NULL, must be writable.
#[no_mangle]
pub unsafe extern "C" fn cl_unseal(
    client: *mut cl_client,
    feature: cl_str,
    data: cl_bytes,
    error: *mut cl_error,
) -> cl_buf {
    // SAFETY: The caller obligations are documented above and all input is copied before use.
    unsafe {
        ffi_call(error, cl_buf::default(), || {
            let feature = copy_text(feature, MAX_FEATURE_BYTES)?;
            let data = copy_bytes(data, MAX_SEALED_ASSET_BYTES, false)?;
            let output = with_client(client, |client| client.unseal(&feature, &data))?;
            register_buffer(output)
        })
    }
}

/// Answer an opaque canonical-CBOR feature challenge.
///
/// # Safety
/// Non-empty input fields must point to readable memory. `error`, when non-NULL, must be writable.
#[no_mangle]
pub unsafe extern "C" fn cl_challenge(
    client: *mut cl_client,
    input: cl_bytes,
    error: *mut cl_error,
) -> cl_buf {
    // SAFETY: The caller obligations are documented above and all input is copied before use.
    unsafe {
        ffi_call(error, cl_buf::default(), || {
            let input = copy_bytes(input, MAX_FEATURE_CHALLENGE_BYTES, false)?;
            let output = with_client(client, |client| client.challenge(&input))?;
            register_buffer(output)
        })
    }
}

/// Create and persist a device-bound offline activation request.
///
/// # Safety
/// Non-empty input fields must point to readable memory. `error`, when non-NULL, must be writable.
#[no_mangle]
pub unsafe extern "C" fn cl_offline_request(
    client: *mut cl_client,
    key: cl_str,
    error: *mut cl_error,
) -> cl_buf {
    // SAFETY: The caller obligations are documented above and the key is copied before use.
    unsafe {
        ffi_call(error, cl_buf::default(), || {
            let key = copy_text(key, MAX_KEY_BYTES)?;
            let output = with_client(client, |client| client.offline_request(&key))?;
            register_buffer(output)
        })
    }
}

/// Verify and install an offline activation response.
///
/// # Safety
/// Non-empty input fields must point to readable memory. `error`, when non-NULL, must be writable.
#[no_mangle]
pub unsafe extern "C" fn cl_offline_import(
    client: *mut cl_client,
    data: cl_bytes,
    error: *mut cl_error,
) -> i32 {
    // SAFETY: The caller obligations are documented above and all input is copied before use.
    unsafe {
        ffi_call(error, CL_FAILURE, || {
            let data = copy_bytes(data, MAX_OFFLINE_RESPONSE_BYTES, false)?;
            with_client(client, |client| client.offline_import(&data))?;
            Ok(CL_SUCCESS)
        })
    }
}

/// Verify and install an armored Offline License Key bundle.
///
/// # Safety
/// Non-empty input fields must point to readable memory. `error`, when non-NULL, must be writable.
#[no_mangle]
pub unsafe extern "C" fn cl_import_olk(
    client: *mut cl_client,
    data: cl_str,
    error: *mut cl_error,
) -> i32 {
    // SAFETY: The caller obligations are documented above and all input is copied before use.
    unsafe {
        ffi_call(error, CL_FAILURE, || {
            let data = copy_text(data, MAX_ARMORED_OLK_BYTES)?;
            with_client(client, |client| client.import_olk(&data))?;
            Ok(CL_SUCCESS)
        })
    }
}

/// Release a buffer returned by this library. Repeated releases are no-ops.
#[no_mangle]
pub extern "C" fn cl_free_buf(buffer: cl_buf) {
    let _ = catch_unwind(AssertUnwindSafe(|| {
        if buffer.handle == 0 || buffer.data.is_null() {
            return;
        }
        if let Ok(mut buffers) = buffers().lock() {
            let matches = buffers
                .get(&buffer.handle)
                .is_some_and(|stored| core::ptr::eq(stored.as_ptr(), buffer.data.cast_const()));
            if matches {
                buffers.remove(&buffer.handle);
            }
        }
    }));
}

fn clients() -> &'static Mutex<HashMap<usize, SharedClient>> {
    CLIENTS.get_or_init(|| Mutex::new(HashMap::new()))
}

fn buffers() -> &'static Mutex<HashMap<usize, Box<[u8]>>> {
    BUFFERS.get_or_init(|| Mutex::new(HashMap::new()))
}

fn next_handle(counter: &AtomicUsize) -> BoundaryResult<usize> {
    counter
        .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |current| {
            current.checked_add(1).filter(|next| *next != 0)
        })
        .map_err(|_| HostErrorCode::UNKNOWN_FATAL)
}

fn register_client(client: Box<dyn ClientApi>) -> BoundaryResult<*mut cl_client> {
    let handle = next_handle(&NEXT_CLIENT_HANDLE)?;
    clients()
        .lock()
        .map_err(|_| HostErrorCode::UNKNOWN_FATAL)?
        .insert(handle, Arc::new(Mutex::new(client)));
    Ok(handle as *mut cl_client)
}

fn with_client<T>(
    handle: *mut cl_client,
    operation: impl FnOnce(&mut dyn ClientApi) -> BoundaryResult<T>,
) -> BoundaryResult<T> {
    if handle.is_null() {
        return Err(HostErrorCode::INVALID_ARGUMENT);
    }
    let client = clients()
        .lock()
        .map_err(|_| HostErrorCode::UNKNOWN_FATAL)?
        .get(&(handle as usize))
        .cloned()
        .ok_or(HostErrorCode::INVALID_ARGUMENT)?;
    let mut client = client.lock().map_err(|_| HostErrorCode::UNKNOWN_FATAL)?;
    operation(client.as_mut())
}

fn register_buffer(bytes: Vec<u8>) -> BoundaryResult<cl_buf> {
    if bytes.is_empty() {
        return Ok(cl_buf::default());
    }
    let handle = next_handle(&NEXT_BUFFER_HANDLE)?;
    let mut bytes = bytes.into_boxed_slice();
    let output = cl_buf {
        data: bytes.as_mut_ptr(),
        len: bytes.len(),
        handle,
    };
    buffers()
        .lock()
        .map_err(|_| HostErrorCode::UNKNOWN_FATAL)?
        .insert(handle, bytes);
    Ok(output)
}

fn state_code(state: LicenseState) -> i32 {
    match state {
        LicenseState::Unlicensed => CL_STATE_UNLICENSED,
        LicenseState::Activating => CL_STATE_ACTIVATING,
        LicenseState::Active => CL_STATE_ACTIVE,
        LicenseState::NeedsRevalidation => CL_STATE_NEEDS_REVALIDATION,
        LicenseState::Grace => CL_STATE_GRACE,
        LicenseState::Locked => CL_STATE_LOCKED,
        LicenseState::Revoked => CL_STATE_REVOKED,
        LicenseState::Tampered => CL_STATE_TAMPERED,
    }
}

unsafe fn ffi_call<T: Copy>(
    error: *mut cl_error,
    fallback: T,
    operation: impl FnOnce() -> BoundaryResult<T>,
) -> T {
    // SAFETY: The caller of each exported function guarantees a writable optional error pointer.
    unsafe { write_error(error, 0) };
    match catch_unwind(AssertUnwindSafe(operation)) {
        Ok(Ok(value)) => value,
        Ok(Err(code)) => {
            // SAFETY: Same error-pointer obligation as above.
            unsafe { write_error(error, code.get()) };
            fallback
        }
        Err(_) => {
            // SAFETY: Same error-pointer obligation as above.
            unsafe { write_error(error, HostErrorCode::UNKNOWN_FATAL.get()) };
            fallback
        }
    }
}

unsafe fn write_error(error: *mut cl_error, code: u32) {
    // SAFETY: Exported functions document that a non-NULL error pointer is writable.
    if let Some(error) = unsafe { error.as_mut() } {
        error.code = code;
    }
}

unsafe fn parse_config(config: *const cl_config) -> BoundaryResult<Config> {
    // SAFETY: cl_create requires config to point to readable cl_config storage.
    let raw = unsafe { config.as_ref() }
        .copied()
        .ok_or(HostErrorCode::INVALID_ARGUMENT)?;
    // SAFETY: cl_create requires every non-empty field to be readable for this call.
    let server_url = unsafe { copy_text(raw.server_url, MAX_SERVER_URL_BYTES) }?;
    // SAFETY: Same field-level caller obligation as above.
    let app_id = unsafe { copy_text(raw.app_id, MAX_IDENTIFIER_BYTES) }?;
    // SAFETY: Same field-level caller obligation as above.
    let product_id = unsafe { copy_text(raw.product_id, MAX_IDENTIFIER_BYTES) }?;
    // SAFETY: Same field-level caller obligation as above.
    let app_version = unsafe { copy_text(raw.app_version, MAX_BUILD_METADATA_BYTES) }?;
    // SAFETY: Same field-level caller obligation as above.
    let release_id = unsafe { copy_text(raw.release_id, MAX_BUILD_METADATA_BYTES) }?;
    // SAFETY: Same field-level caller obligation as above.
    let build_fingerprint = unsafe { copy_text(raw.build_fingerprint, MAX_BUILD_METADATA_BYTES) }?;
    // SAFETY: Same field-level caller obligation as above.
    let current_root_key = unsafe { copy_bytes(raw.current_root_key, MAX_ROOT_KEY_BYTES, false) }?;
    // SAFETY: Same field-level caller obligation as above; this field may be empty.
    let next_root_key = unsafe { copy_bytes(raw.next_root_key, MAX_ROOT_KEY_BYTES, true) }?;
    // SAFETY: Same field-level caller obligation as above.
    let fingerprint_salt =
        unsafe { copy_bytes(raw.fingerprint_salt, MAX_FINGERPRINT_SALT_BYTES, false) }?;
    // SAFETY: Same field-level caller obligation as above.
    let variant_const = fixed_32(unsafe { copy_bytes(raw.variant_const, 32, false) }?)?;
    // SAFETY: Same field-level caller obligation as above.
    let module_digest = fixed_32(unsafe { copy_bytes(raw.module_digest, 32, false) }?)?;
    let allow_unbound_olk = bool_flag(raw.allow_unbound_olk)?;
    let allow_insecure_localhost = bool_flag(raw.allow_insecure_localhost)?;

    let info = ClientInfo {
        app_version,
        sdk_version: env!("CARGO_PKG_VERSION").to_owned(),
        os: std::env::consts::OS.to_owned(),
        arch: std::env::consts::ARCH.to_owned(),
        build_fingerprint: build_fingerprint.clone(),
        release_id,
        variant_id: raw.variant_id,
        supported_suites: vec![copylocker_suite_std::CL_STD_1_SUITE_ID],
        supported_variants: vec![raw.variant_id],
    };
    let evidence = EnvEvidence {
        module_digest: Digest(module_digest),
        build_fingerprint: build_fingerprint.into_bytes(),
        extra: Vec::new(),
    };
    let mut config = Config::new_with_localhost_http(
        &server_url,
        app_id,
        product_id,
        info,
        current_root_key,
        fingerprint_salt,
        variant_const,
        evidence,
        allow_insecure_localhost,
    )
    .map_err(|_| HostErrorCode::INVALID_ARGUMENT)?;
    if !next_root_key.is_empty() {
        config = config
            .with_next_root_key(next_root_key)
            .map_err(|_| HostErrorCode::INVALID_ARGUMENT)?;
    }
    config
        .with_unbound_olk(allow_unbound_olk)
        .map_err(|_| HostErrorCode::INVALID_ARGUMENT)
}

unsafe fn copy_text(value: cl_str, max_len: usize) -> BoundaryResult<String> {
    // SAFETY: This helper applies the same bounds and pointer rules as copy_bytes.
    let bytes = unsafe {
        copy_bytes(
            cl_bytes {
                data: value.data.cast(),
                len: value.len,
            },
            max_len,
            false,
        )
    }?;
    if bytes.contains(&0) {
        return Err(HostErrorCode::INVALID_ARGUMENT);
    }
    String::from_utf8(bytes).map_err(|_| HostErrorCode::INVALID_ARGUMENT)
}

unsafe fn copy_bytes(
    value: cl_bytes,
    max_len: usize,
    allow_empty: bool,
) -> BoundaryResult<Vec<u8>> {
    if value.len == 0 {
        return if allow_empty {
            Ok(Vec::new())
        } else {
            Err(HostErrorCode::INVALID_ARGUMENT)
        };
    }
    if value.len > max_len || value.data.is_null() {
        return Err(HostErrorCode::INVALID_ARGUMENT);
    }
    // SAFETY: The caller guarantees `data` is readable for `len` bytes. The checked maximum also
    // ensures the length is representable for a Rust slice on supported targets.
    Ok(unsafe { core::slice::from_raw_parts(value.data, value.len) }.to_vec())
}

fn fixed_32(bytes: Vec<u8>) -> BoundaryResult<[u8; 32]> {
    bytes
        .try_into()
        .map_err(|_| HostErrorCode::INVALID_ARGUMENT)
}

fn bool_flag(value: u8) -> BoundaryResult<bool> {
    match value {
        0 => Ok(false),
        1 => Ok(true),
        _ => Err(HostErrorCode::INVALID_ARGUMENT),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::AtomicUsize;
    use std::thread;

    struct FakeClient {
        calls: Arc<AtomicUsize>,
    }

    impl ClientApi for FakeClient {
        fn activate(&mut self, _key: &str) -> BoundaryResult<()> {
            self.calls.fetch_add(1, Ordering::Relaxed);
            Ok(())
        }

        fn deactivate(&mut self) -> BoundaryResult<()> {
            self.calls.fetch_add(1, Ordering::Relaxed);
            Ok(())
        }

        fn state(&self) -> LicenseState {
            self.calls.fetch_add(1, Ordering::Relaxed);
            LicenseState::Unlicensed
        }

        fn unseal(&mut self, _feature: &str, data: &[u8]) -> BoundaryResult<Vec<u8>> {
            Ok(data.to_vec())
        }

        fn challenge(&mut self, input: &[u8]) -> BoundaryResult<Vec<u8>> {
            Ok(input.iter().rev().copied().collect())
        }

        fn offline_request(&mut self, key: &str) -> BoundaryResult<Vec<u8>> {
            Ok(key.as_bytes().to_vec())
        }

        fn offline_import(&mut self, _data: &[u8]) -> BoundaryResult<()> {
            Ok(())
        }

        fn import_olk(&mut self, _data: &str) -> BoundaryResult<()> {
            Ok(())
        }
    }

    struct PanicClient;

    impl ClientApi for PanicClient {
        fn activate(&mut self, _key: &str) -> BoundaryResult<()> {
            unreachable!()
        }

        fn deactivate(&mut self) -> BoundaryResult<()> {
            unreachable!()
        }

        fn state(&self) -> LicenseState {
            unreachable!()
        }

        fn unseal(&mut self, _feature: &str, _data: &[u8]) -> BoundaryResult<Vec<u8>> {
            unreachable!()
        }

        #[allow(clippy::panic)] // The test verifies that an implementation panic is contained.
        fn challenge(&mut self, _input: &[u8]) -> BoundaryResult<Vec<u8>> {
            std::panic::panic_any("contained")
        }

        fn offline_request(&mut self, _key: &str) -> BoundaryResult<Vec<u8>> {
            unreachable!()
        }

        fn offline_import(&mut self, _data: &[u8]) -> BoundaryResult<()> {
            unreachable!()
        }

        fn import_olk(&mut self, _data: &str) -> BoundaryResult<()> {
            unreachable!()
        }
    }

    fn borrowed_bytes(value: &[u8]) -> cl_bytes {
        cl_bytes {
            data: value.as_ptr(),
            len: value.len(),
        }
    }

    fn borrowed_text(value: &str) -> cl_str {
        cl_str {
            data: value.as_ptr().cast(),
            len: value.len(),
        }
    }

    fn fake_client() -> (*mut cl_client, Arc<AtomicUsize>) {
        let calls = Arc::new(AtomicUsize::new(0));
        let handle = register_client(Box::new(FakeClient {
            calls: Arc::clone(&calls),
        }))
        .unwrap();
        (handle, calls)
    }

    #[test]
    fn null_and_oversized_inputs_fail_locally() {
        let mut error = cl_error::default();
        // SAFETY: The config is intentionally NULL and the error slot is writable.
        let created = unsafe { cl_create(ptr::null(), &mut error) };
        assert!(created.is_null());
        assert_eq!(error.code, HostErrorCode::INVALID_ARGUMENT.get());

        let (client, _) = fake_client();
        let oversized = cl_bytes {
            data: core::ptr::NonNull::<u8>::dangling().as_ptr(),
            len: MAX_FEATURE_CHALLENGE_BYTES + 1,
        };
        // SAFETY: Oversized input is rejected before the deliberately dangling pointer is read.
        let output = unsafe { cl_challenge(client, oversized, &mut error) };
        assert!(output.data.is_null());
        assert_eq!(error.code, HostErrorCode::INVALID_ARGUMENT.get());

        // SAFETY: Empty feature and data are represented by NULL/zero borrowed fields.
        let output =
            unsafe { cl_unseal(client, cl_str::default(), cl_bytes::default(), &mut error) };
        assert!(output.data.is_null());
        assert_eq!(error.code, HostErrorCode::INVALID_ARGUMENT.get());
        cl_destroy(client);
    }

    #[test]
    fn buffers_and_clients_tolerate_repeated_release() {
        let (client, _) = fake_client();
        let input = [1, 2, 3, 4];
        let mut error = cl_error::default();
        // SAFETY: Input and error storage remain valid for the duration of the call.
        let output = unsafe { cl_challenge(client, borrowed_bytes(&input), &mut error) };
        assert_eq!(error.code, 0);
        assert_eq!(output.len, input.len());
        // SAFETY: The returned buffer remains owned by the registry until cl_free_buf below.
        assert_eq!(
            unsafe { core::slice::from_raw_parts(output.data, output.len) },
            [4, 3, 2, 1]
        );
        cl_free_buf(output);
        cl_free_buf(output);

        cl_destroy(client);
        cl_destroy(client);
        assert_eq!(cl_state(client), CL_STATE_ERROR);
    }

    #[test]
    fn one_handle_is_serialized_across_threads() {
        let (client, calls) = fake_client();
        let token = client as usize;
        let threads: Vec<_> = (0..8)
            .map(|_| {
                thread::spawn(move || {
                    for _ in 0..64 {
                        assert_eq!(cl_state(token as *mut cl_client), CL_STATE_UNLICENSED);
                    }
                })
            })
            .collect();
        for thread in threads {
            thread.join().unwrap();
        }
        assert_eq!(calls.load(Ordering::Relaxed), 8 * 64);
        cl_destroy(client);
    }

    #[test]
    fn panic_is_contained_and_reduced_to_a_stable_code() {
        let client = register_client(Box::new(PanicClient)).unwrap();
        let input = [1];
        let mut error = cl_error::default();
        // SAFETY: Input and error storage remain valid for the duration of the call.
        let output = unsafe { cl_challenge(client, borrowed_bytes(&input), &mut error) };
        assert!(output.data.is_null());
        assert_eq!(error.code, HostErrorCode::UNKNOWN_FATAL.get());
        cl_destroy(client);
    }

    #[test]
    fn all_operations_clear_or_set_the_error_slot() {
        let (client, calls) = fake_client();
        let mut error = cl_error { code: u32::MAX };
        // SAFETY: Borrowed key and writable error storage remain valid for the call.
        assert_eq!(
            unsafe { cl_activate(client, borrowed_text("CL1-TEST"), &mut error) },
            CL_SUCCESS
        );
        assert_eq!(error.code, 0);
        // SAFETY: The error slot remains writable.
        assert_eq!(unsafe { cl_deactivate(client, &mut error) }, CL_SUCCESS);
        assert_eq!(error.code, 0);
        assert_eq!(calls.load(Ordering::Relaxed), 2);
        cl_destroy(client);
    }
}
