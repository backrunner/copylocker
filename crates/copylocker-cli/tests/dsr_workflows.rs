#![allow(clippy::expect_used, clippy::indexing_slicing, clippy::panic)]

//! Mock-server coverage for the DSR and telemetry Admin commands, following the
//! `cli_workflows.rs` conventions.

use std::collections::BTreeMap;
use std::ffi::OsString;
use std::fs;
use std::io::{Read as _, Write as _};
use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::atomic::{AtomicU64, Ordering};
use std::thread;
use std::time::{Duration, Instant};

use serde_json::Value;

const TEST_ADMIN_TOKEN: &str = "clat_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
const MACHINE_ID: &str = "abababababababababababababababab";
const LICENSE_ID: &str = "cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd";

#[test]
fn dsr_export_posts_the_selector_and_writes_the_bundle() {
    let root = temporary_dir("dsr-export");
    fs::create_dir_all(&root).expect("create test directory");
    let bundle_path = root.join("dsr-bundle.json");
    let (url, server) = spawn_mock(vec![json_response(
        "200 OK",
        serde_json::json!({
            "ok": true,
            "product_id": "acme",
            "subject": {"machine_id": MACHINE_ID},
            "machines": [{"id": MACHINE_ID, "status": "active"}],
            "licenses": [{"id": LICENSE_ID}],
            "audit_references": [],
            "audit_truncated": false
        }),
    )]);

    let output = run_remote_str(
        &root,
        &[
            "--json",
            "dsr",
            "export",
            "--api-url",
            &url,
            "--product",
            "acme",
            "--machine",
            MACHINE_ID,
            "--out",
            bundle_path.to_str().expect("bundle path is UTF-8"),
        ],
    );
    assert_success(&output);
    assert_eq!(json_stdout(&output)["command"], "dsr.export");

    let bundle: Value =
        serde_json::from_slice(&fs::read(&bundle_path).expect("read written bundle"))
            .expect("parse written bundle");
    assert_eq!(bundle["subject"]["machine_id"], MACHINE_ID);
    assert_eq!(bundle["machines"][0]["status"], "active");

    let requests = server.join().expect("join mock server");
    assert_eq!(requests.len(), 1);
    let request = &requests[0];
    assert_eq!(request.method, "POST");
    assert_eq!(request.target, "/v1/admin/dsr/export");
    assert_eq!(
        request.headers.get("authorization").map(String::as_str),
        Some(format!("Bearer {TEST_ADMIN_TOKEN}").as_str())
    );
    // Reads need no Idempotency-Key.
    assert!(!request.headers.contains_key("idempotency-key"));
    let body = request_json(request);
    assert_eq!(body["product_id"], "acme");
    assert_eq!(body["machine_id"], MACHINE_ID);
    assert!(body.get("license_id").is_none());

    fs::remove_dir_all(root).expect("remove test directory");
}

#[test]
fn dsr_delete_is_a_dry_run_until_confirmed_with_an_idempotency_key() {
    let root = temporary_dir("dsr-delete");
    fs::create_dir_all(&root).expect("create test directory");
    let (url, server) = spawn_mock(vec![
        json_response(
            "200 OK",
            serde_json::json!({
                "ok": true,
                "dry_run": true,
                "machines": [{"id": MACHINE_ID}],
                "raw_records": 1,
                "audit_tombstone": false
            }),
        ),
        json_response(
            "200 OK",
            serde_json::json!({
                "ok": true,
                "dry_run": false,
                "deleted_machines": 1,
                "deleted_raw_records": 1,
                "audit_tombstone": false
            }),
        ),
    ]);

    let dry_run = run_remote_str(
        &root,
        &[
            "--json",
            "dsr",
            "delete",
            "--api-url",
            &url,
            "--product",
            "acme",
            "--machine",
            MACHINE_ID,
        ],
    );
    assert_success(&dry_run);
    assert_eq!(json_stdout(&dry_run)["dry_run"], true);

    let confirmed = run_remote_str(
        &root,
        &[
            "--json",
            "dsr",
            "delete",
            "--api-url",
            &url,
            "--product",
            "acme",
            "--machine",
            MACHINE_ID,
            "--confirm",
            "--idempotency-key",
            "dsr-delete-001",
        ],
    );
    assert_success(&confirmed);
    assert_eq!(json_stdout(&confirmed)["dry_run"], false);

    let requests = server.join().expect("join mock server");
    assert_eq!(requests.len(), 2);
    assert_eq!(requests[0].target, "/v1/admin/dsr/delete?dry_run=true");
    assert!(!requests[0].headers.contains_key("idempotency-key"));
    assert_eq!(requests[1].target, "/v1/admin/dsr/delete?dry_run=false");
    assert_eq!(
        requests[1]
            .headers
            .get("idempotency-key")
            .map(String::as_str),
        Some("dsr-delete-001")
    );
    assert_eq!(request_json(&requests[1])["machine_id"], MACHINE_ID);

    fs::remove_dir_all(root).expect("remove test directory");
}

#[test]
fn telemetry_purge_requires_confirmation_and_sends_the_cutoff() {
    let root = temporary_dir("telemetry-purge");
    fs::create_dir_all(&root).expect("create test directory");
    let (url, server) = spawn_mock(vec![
        json_response(
            "200 OK",
            serde_json::json!({
                "ok": true,
                "dry_run": true,
                "cutoff": "2026-07-15",
                "raw_records": 2,
                "rollup_rows": 1
            }),
        ),
        json_response(
            "200 OK",
            serde_json::json!({
                "ok": true,
                "dry_run": false,
                "deleted_raw_records": 2,
                "deleted_rollup_rows": 1,
                "journaled": true
            }),
        ),
    ]);

    let dry_run = run_remote_str(
        &root,
        &[
            "--json",
            "telemetry",
            "purge",
            "--api-url",
            &url,
            "--product",
            "acme",
            "--before",
            "2026-07-15",
        ],
    );
    assert_success(&dry_run);
    assert_eq!(json_stdout(&dry_run)["dry_run"], true);

    let confirmed = run_remote_str(
        &root,
        &[
            "--json",
            "telemetry",
            "purge",
            "--api-url",
            &url,
            "--product",
            "acme",
            "--before",
            "2026-07-15",
            "--confirm",
            "--idempotency-key",
            "telemetry-purge-001",
        ],
    );
    assert_success(&confirmed);
    assert_eq!(json_stdout(&confirmed)["deleted_raw_records"], 2);

    let requests = server.join().expect("join mock server");
    assert_eq!(requests.len(), 2);
    assert_eq!(requests[0].target, "/v1/admin/telemetry/purge?dry_run=true");
    assert_eq!(
        requests[1].target,
        "/v1/admin/telemetry/purge?dry_run=false"
    );
    assert_eq!(
        requests[1]
            .headers
            .get("idempotency-key")
            .map(String::as_str),
        Some("telemetry-purge-001")
    );
    let body = request_json(&requests[1]);
    assert_eq!(body["product_id"], "acme");
    assert_eq!(body["before"], "2026-07-15");

    fs::remove_dir_all(root).expect("remove test directory");
}

#[test]
fn telemetry_purge_rejects_a_malformed_before_date_without_calling_the_api() {
    let root = temporary_dir("telemetry-purge-date");
    fs::create_dir_all(&root).expect("create test directory");
    let (url, watcher) = no_request_listener();
    let output = run_remote_str(
        &root,
        &[
            "--json",
            "telemetry",
            "purge",
            "--api-url",
            &url,
            "--product",
            "acme",
            "--before",
            "15.07.2026",
        ],
    );
    assert!(!output.status.success());
    assert_eq!(json_stdout(&output)["error"]["code"], "invalid_date");
    assert!(!watch_for_request(watcher, Duration::from_millis(300))
        .join()
        .expect("join request watcher"));

    fs::remove_dir_all(root).expect("remove test directory");
}

#[test]
fn dsr_delete_surfaces_server_errors() {
    let root = temporary_dir("dsr-delete-error");
    fs::create_dir_all(&root).expect("create test directory");
    let (url, server) = spawn_mock(vec![json_response(
        "404 Not Found",
        serde_json::json!({
            "ok": false,
            "error": {"code": "not_found", "message": "machine not found"}
        }),
    )]);

    let output = run_remote_str(
        &root,
        &[
            "--json",
            "dsr",
            "delete",
            "--api-url",
            &url,
            "--product",
            "acme",
            "--machine",
            MACHINE_ID,
        ],
    );
    assert!(!output.status.success());
    assert_eq!(json_stdout(&output)["error"]["code"], "not_found");

    let requests = server.join().expect("join mock server");
    assert_eq!(requests.len(), 1);

    fs::remove_dir_all(root).expect("remove test directory");
}

// --- minimal mock-server helpers, mirroring cli_workflows.rs ----------------

fn temporary_dir(label: &str) -> PathBuf {
    static NEXT_ID: AtomicU64 = AtomicU64::new(0);
    std::env::temp_dir().join(format!(
        "copylocker-cli-dsr-{}-{}-{label}",
        std::process::id(),
        NEXT_ID.fetch_add(1, Ordering::Relaxed)
    ))
}

#[derive(Debug)]
struct RecordedRequest {
    method: String,
    target: String,
    headers: BTreeMap<String, String>,
    body: Vec<u8>,
}

#[derive(Debug)]
struct MockResponse {
    status: String,
    body: Vec<u8>,
}

fn json_response(status: &str, body: Value) -> MockResponse {
    MockResponse {
        status: status.to_owned(),
        body: body.to_string().into_bytes(),
    }
}

fn spawn_mock(responses: Vec<MockResponse>) -> (String, thread::JoinHandle<Vec<RecordedRequest>>) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind mock server");
    let url = format!("http://{}", listener.local_addr().expect("mock address"));
    let handle = thread::spawn(move || {
        listener
            .set_nonblocking(true)
            .expect("make mock listener nonblocking");
        let mut requests = Vec::with_capacity(responses.len());
        for response in responses {
            let mut stream = accept_with_timeout(&listener, Duration::from_secs(5));
            requests.push(read_request(&mut stream));
            write_response(&mut stream, &response);
        }
        requests
    });
    (url, handle)
}

fn accept_with_timeout(listener: &TcpListener, duration: Duration) -> TcpStream {
    let deadline = Instant::now() + duration;
    loop {
        match listener.accept() {
            Ok((stream, _)) => {
                stream
                    .set_nonblocking(false)
                    .expect("make mock stream blocking");
                return stream;
            }
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                assert!(
                    Instant::now() < deadline,
                    "mock server timed out waiting for request"
                );
                thread::sleep(Duration::from_millis(10));
            }
            Err(error) => panic!("mock accept failed: {error}"),
        }
    }
}

fn read_request(stream: &mut TcpStream) -> RecordedRequest {
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .expect("set mock read timeout");
    let mut bytes = Vec::new();
    let mut chunk = [0_u8; 4096];
    let (header_end, body_length) = loop {
        let count = stream.read(&mut chunk).expect("read mock request");
        assert_ne!(count, 0, "client closed before completing headers");
        bytes.extend_from_slice(&chunk[..count]);
        if let Some(header_end) = find_bytes(&bytes, b"\r\n\r\n") {
            let headers = String::from_utf8_lossy(&bytes[..header_end]);
            let body_length = headers
                .lines()
                .filter_map(|line| line.split_once(':'))
                .find(|(name, _)| name.eq_ignore_ascii_case("content-length"))
                .and_then(|(_, value)| value.trim().parse::<usize>().ok())
                .unwrap_or(0);
            break (header_end + 4, body_length);
        }
    };
    while bytes.len() < header_end + body_length {
        let count = stream.read(&mut chunk).expect("read mock request body");
        assert_ne!(count, 0, "client closed before completing body");
        bytes.extend_from_slice(&chunk[..count]);
    }

    let head = String::from_utf8_lossy(&bytes[..header_end - 4]);
    let mut lines = head.lines();
    let request_line = lines.next().expect("request line");
    let mut request_parts = request_line.split_ascii_whitespace();
    let method = request_parts.next().expect("request method").to_owned();
    let target = request_parts.next().expect("request target").to_owned();
    let headers = lines
        .filter_map(|line| line.split_once(':'))
        .map(|(name, value)| (name.to_ascii_lowercase(), value.trim().to_owned()))
        .collect();
    RecordedRequest {
        method,
        target,
        headers,
        body: bytes[header_end..header_end + body_length].to_vec(),
    }
}

fn write_response(stream: &mut TcpStream, response: &MockResponse) {
    let head = format!(
        "HTTP/1.1 {}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        response.status,
        response.body.len()
    );
    stream
        .write_all(head.as_bytes())
        .expect("write response head");
    stream
        .write_all(&response.body)
        .expect("write response body");
    stream.flush().expect("flush mock response");
}

fn find_bytes(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

fn request_json(request: &RecordedRequest) -> Value {
    serde_json::from_slice(&request.body).expect("parse recorded JSON body")
}

fn no_request_listener() -> (String, TcpListener) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind request watcher");
    let url = format!("http://{}", listener.local_addr().expect("watcher address"));
    (url, listener)
}

fn watch_for_request(listener: TcpListener, duration: Duration) -> thread::JoinHandle<bool> {
    thread::spawn(move || {
        listener
            .set_nonblocking(true)
            .expect("make watcher nonblocking");
        let deadline = Instant::now() + duration;
        loop {
            match listener.accept() {
                Ok(_) => return true,
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    if Instant::now() >= deadline {
                        return false;
                    }
                    thread::sleep(Duration::from_millis(10));
                }
                Err(_) => return false,
            }
        }
    })
}

fn run_remote_str(current_dir: &Path, args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_copylocker"))
        .args(args.iter().map(OsString::from))
        .current_dir(current_dir)
        .env("COPYLOCKER_ADMIN_TOKEN", TEST_ADMIN_TOKEN)
        .output()
        .expect("run remote copylocker CLI")
}

fn assert_success(output: &Output) {
    assert!(
        output.status.success(),
        "CLI failed: stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

fn json_stdout(output: &Output) -> Value {
    serde_json::from_slice(&output.stdout).expect("CLI stdout is JSON")
}
