#![allow(clippy::expect_used, clippy::indexing_slicing, clippy::panic)]

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

#[test]
fn init_and_catalog_commands_work_outside_the_source_tree() {
    let root = temporary_dir("init-catalog");
    fs::create_dir_all(&root).expect("create test directory");
    let server = root.join("server");
    let init = run(
        &root,
        [
            "--json".into(),
            "init".into(),
            server.as_os_str().into(),
            "--product".into(),
            "acme.desktop".into(),
            "--d1-database-id".into(),
            "00000000-0000-0000-0000-000000000001".into(),
            "--kv-namespace-id".into(),
            "00000000000000000000000000000002".into(),
            "--secret-store-id".into(),
            "00000000000000000000000000000003".into(),
            "--api-url".into(),
            "https://licenses.example.test".into(),
        ],
    );
    assert_success(&init);
    assert_eq!(json_stdout(&init)["project_name"], "server");

    for file in ["wrangler.jsonc", "package.json", "copylocker.json"] {
        let contents = fs::read_to_string(server.join(file)).expect("read rendered template");
        assert!(
            !contents.contains("__COPYLOCKER_"),
            "{file} was not rendered"
        );
    }
    for migration in [
        "0001_initial.sql",
        "0002_release_feature_keks.sql",
        "0003_admin_revocations.sql",
        "0004_admin_audit.sql",
        "0005_billing_webhooks.sql",
        "0006_unified_admin_audit.sql",
        "0007_admin_operations.sql",
        "0008_epoch_approvals.sql",
        "0009_integrity_signer_keys.sql",
        "0010_release_admin.sql",
    ] {
        assert_eq_migration(&server, migration);
    }

    let bootstrap_bundle = root.join("bootstrap.secret.json");
    let prepare = run(
        &root,
        [
            "--json".into(),
            "bootstrap".into(),
            "prepare".into(),
            "--project".into(),
            server.as_os_str().into(),
            "--vendor".into(),
            "vendor-acme".into(),
            "--actor".into(),
            "owner".into(),
            "--out".into(),
            bootstrap_bundle.as_os_str().into(),
        ],
    );
    assert_success(&prepare);
    assert_secret_permissions(&bootstrap_bundle);
    let bundle: Value =
        serde_json::from_slice(&fs::read(&bootstrap_bundle).expect("read bootstrap bundle"))
            .expect("parse bootstrap bundle");
    let bootstrap_token = bundle["admin_token"].as_str().expect("bootstrap token");
    assert!(bootstrap_token.starts_with("clat_"));
    assert_eq!(bootstrap_token.len(), 48);
    assert!(!String::from_utf8_lossy(&prepare.stdout).contains(bootstrap_token));
    let apply_plan = run(
        &root,
        [
            "--json".into(),
            "bootstrap".into(),
            "apply".into(),
            "--project".into(),
            server.as_os_str().into(),
            "--bundle".into(),
            bootstrap_bundle.as_os_str().into(),
        ],
    );
    assert_success(&apply_plan);
    assert_eq!(json_stdout(&apply_plan)["dry_run"], true);

    assert_success(&run_str(
        &server,
        &[
            "--json",
            "catalog",
            "feature",
            "add",
            "--id",
            "export.pdf",
            "--label",
            "PDF",
        ],
    ));
    assert_success(&run_str(
        &server,
        &[
            "--json",
            "catalog",
            "group",
            "add",
            "--id",
            "exports",
            "--label",
            "Exports",
            "--feature",
            "export.pdf",
        ],
    ));
    assert_success(&run_str(
        &server,
        &[
            "--json",
            "catalog",
            "tier",
            "add",
            "--id",
            "pro",
            "--label",
            "Pro",
            "--rank",
            "1",
            "--group",
            "exports",
            "--limit",
            "projects=10",
        ],
    ));
    let resolved = run_str(
        &server,
        &[
            "--json",
            "catalog",
            "resolve",
            "--tier",
            "pro",
            "--at",
            "1785185000",
        ],
    );
    assert_success(&resolved);
    let resolved = json_stdout(&resolved);
    assert_eq!(resolved["catalog_version"], 4);
    assert_eq!(resolved["features"], serde_json::json!(["export.pdf"]));
    assert_eq!(resolved["limits"]["projects"], 10);

    let duplicate = run_str(
        &server,
        &[
            "--json",
            "catalog",
            "feature",
            "add",
            "--id",
            "export.pdf",
            "--label",
            "Renamed",
        ],
    );
    assert!(!duplicate.status.success());
    assert_eq!(json_stdout(&duplicate)["error"]["code"], "feature_exists");

    let deploy_without_install = run_str(&server, &["--json", "deploy"]);
    assert!(!deploy_without_install.status.success());
    assert_eq!(
        json_stdout(&deploy_without_install)["error"]["code"],
        "wrangler_missing"
    );

    fs::remove_dir_all(root).expect("remove test directory");
}

#[test]
fn keygen_outputs_worker_compatible_secrets_and_inspectable_certificate() {
    let root = temporary_dir("keygen");
    fs::create_dir_all(&root).expect("create test directory");
    let keys = root.join("keys");

    let missing_confirmation = run(
        &root,
        [
            "--json".into(),
            "keygen".into(),
            "root".into(),
            "--out-dir".into(),
            keys.as_os_str().into(),
        ],
    );
    assert!(!missing_confirmation.status.success());
    assert_eq!(
        json_stdout(&missing_confirmation)["error"]["code"],
        "offline_confirmation_required"
    );

    let roots = run(
        &root,
        [
            "--json".into(),
            "keygen".into(),
            "root".into(),
            "--out-dir".into(),
            keys.as_os_str().into(),
            "--offline-confirm".into(),
        ],
    );
    assert_success(&roots);
    let root_secret = keys.join("cl-root.secret.json");
    assert_secret_permissions(&root_secret);

    let epoch_dir = keys.join("epoch");
    let epoch = run(
        &root,
        [
            "--json".into(),
            "keygen".into(),
            "epoch".into(),
            "--root-key".into(),
            root_secret.as_os_str().into(),
            "--product".into(),
            "acme.desktop".into(),
            "--not-before".into(),
            "1785185300".into(),
            "--not-after".into(),
            "1792961300".into(),
            "--epoch-id".into(),
            "0011223344556677".into(),
            "--out-dir".into(),
            epoch_dir.as_os_str().into(),
        ],
    );
    assert_success(&epoch);
    let signing_secret = epoch_dir.join("epoch-0011223344556677.signing.secret.json");
    let fast_secret = epoch_dir.join("epoch-0011223344556677.fast-signing.secret.json");
    assert_secret_permissions(&signing_secret);
    assert_secret_permissions(&fast_secret);
    let signing: Value =
        serde_json::from_slice(&fs::read(&signing_secret).expect("read epoch secret"))
            .expect("parse epoch secret");
    let fast: Value = serde_json::from_slice(&fs::read(&fast_secret).expect("read fast secret"))
        .expect("parse fast secret");
    assert_eq!(signing["schema_version"], 1);
    assert_eq!(
        signing["epoch_id"],
        serde_json::json!([0, 17, 34, 51, 68, 85, 102, 119])
    );
    assert_eq!(signing["signing_key"].as_array().map(Vec::len), Some(64));
    assert_eq!(fast["signing_key"].as_array().map(Vec::len), Some(32));

    let certificate = epoch_dir.join("epoch-0011223344556677.cert.cbor");
    let inspected = run(
        &root,
        [
            "--json".into(),
            "inspect".into(),
            certificate.as_os_str().into(),
        ],
    );
    assert_success(&inspected);
    let inspected = json_stdout(&inspected);
    assert_eq!(inspected["trusted"], false);
    assert_eq!(inspected["artifact"]["container"], "envelope");
    assert_eq!(inspected["artifact"]["artifact_kind"], "epoch-cert");
    assert_eq!(inspected["artifact"]["decoded"]["7"], "acme.desktop");

    let root_public = keys.join("cl-root.public.json");
    let (url, server) = spawn_mock(vec![json_response(
        "201 Created",
        serde_json::json!({
            "ok": true,
            "epoch": {"epoch_id": "0011223344556677", "product_id": "acme.desktop"},
            "version": 1
        }),
    )]);
    let upload = run_remote(
        &root,
        [
            "--json".into(),
            "epoch".into(),
            "upload".into(),
            "--api-url".into(),
            url.into(),
            certificate.as_os_str().into(),
            "--root-public".into(),
            root_public.as_os_str().into(),
            "--idempotency-key".into(),
            "epoch-upload-001".into(),
        ],
    );
    assert_success(&upload);
    let requests = server.join().expect("join epoch upload server");
    assert_eq!(requests[0].target, "/v1/admin/epochs");
    assert_eq!(requests[0].method, "POST");
    assert_eq!(
        requests[0]
            .headers
            .get("idempotency-key")
            .map(String::as_str),
        Some("epoch-upload-001")
    );
    let upload_body = request_json(&requests[0]);
    assert_eq!(
        upload_body["certificate_hex"],
        hex::encode(fs::read(&certificate).expect("read uploaded certificate"))
    );
    let public: Value =
        serde_json::from_slice(&fs::read(&root_public).expect("read uploaded Root public key"))
            .expect("parse uploaded Root public key");
    assert_eq!(
        upload_body["root_verifying_key_hex"],
        public["verifying_key_hex"]
    );

    let overwrite = run(
        &root,
        [
            "--json".into(),
            "keygen".into(),
            "root".into(),
            "--out-dir".into(),
            keys.as_os_str().into(),
            "--offline-confirm".into(),
        ],
    );
    assert!(!overwrite.status.success());
    assert_eq!(json_stdout(&overwrite)["error"]["code"], "file_exists");

    fs::remove_dir_all(root).expect("remove test directory");
}

#[test]
fn remote_license_issue_sends_bearer_idempotency_and_json_body() {
    let root = temporary_dir("remote-issue");
    fs::create_dir_all(&root).expect("create test directory");
    let (url, server) = spawn_mock(vec![json_response(
        "201 Created",
        serde_json::json!({
            "ok": true,
            "product_id": "acme",
            "policy_id": "pro",
            "count": 2,
            "licenses": []
        }),
    )]);

    let output = run_remote_str(
        &root,
        &[
            "--json",
            "license",
            "issue",
            "--api-url",
            &url,
            "--product",
            "acme",
            "--policy",
            "pro",
            "--count",
            "2",
            "--idempotency-key",
            "issue-001",
        ],
    );
    assert_success(&output);
    assert_eq!(json_stdout(&output)["http_status"], 201);

    let requests = server.join().expect("join mock server");
    assert_eq!(requests.len(), 1);
    let request = &requests[0];
    assert_eq!(request.method, "POST");
    assert_eq!(request.target, "/v1/admin/licenses");
    let expected_authorization = format!("Bearer {TEST_ADMIN_TOKEN}");
    assert_eq!(
        request.headers.get("authorization").map(String::as_str),
        Some(expected_authorization.as_str())
    );
    assert_eq!(
        request.headers.get("idempotency-key").map(String::as_str),
        Some("issue-001")
    );
    let body: Value = serde_json::from_slice(&request.body).expect("parse request JSON");
    assert_eq!(body["product_id"], "acme");
    assert_eq!(body["policy_id"], "pro");
    assert_eq!(body["count"], 2);

    fs::remove_dir_all(root).expect("remove test directory");
}

#[test]
fn asset_kek_register_posts_hex_and_validates_input() {
    let root = temporary_dir("asset-kek");
    fs::create_dir_all(&root).expect("create test directory");
    let kek_hex = "ab".repeat(32);
    let (url, server) = spawn_mock(vec![json_response(
        "201 Created",
        serde_json::json!({
            "ok": true,
            "product_id": "acme",
            "release_id": "rel-1",
            "feature_id": "export.pdf",
            "key_version": 1,
            "kek_fingerprint": "f".repeat(64)
        }),
    )]);

    let output = run_remote_str(
        &root,
        &[
            "--json",
            "asset-kek",
            "register",
            "--api-url",
            &url,
            "--product",
            "acme",
            "--release",
            "rel-1",
            "--feature",
            "export.pdf",
            "--kek-hex",
            &kek_hex,
            "--idempotency-key",
            "kek-register-001",
        ],
    );
    assert_success(&output);
    assert_eq!(json_stdout(&output)["http_status"], 201);
    assert_eq!(json_stdout(&output)["kek_hex"], kek_hex);

    let requests = server.join().expect("join mock server");
    assert_eq!(requests.len(), 1);
    let request = &requests[0];
    assert_eq!(request.method, "POST");
    assert_eq!(request.target, "/v1/admin/asset-keks");
    assert_eq!(
        request.headers.get("idempotency-key").map(String::as_str),
        Some("kek-register-001")
    );
    let body: Value = serde_json::from_slice(&request.body).expect("parse request JSON");
    assert_eq!(body["kek_hex"], kek_hex);
    assert_eq!(body["release_id"], "rel-1");
    assert_eq!(body["feature_id"], "export.pdf");

    let invalid = run_remote_str(
        &root,
        &[
            "--json",
            "asset-kek",
            "register",
            "--api-url",
            "http://127.0.0.1:1",
            "--product",
            "acme",
            "--release",
            "rel-1",
            "--feature",
            "export.pdf",
            "--kek-hex",
            "not-hex",
            "--idempotency-key",
            "kek-register-002",
        ],
    );
    assert!(!invalid.status.success());
    assert_eq!(json_stdout(&invalid)["error"]["code"], "invalid_kek");

    fs::remove_dir_all(root).expect("remove test directory");
}

#[test]
fn release_register_posts_seed_and_validates_input() {
    let root = temporary_dir("release-register");
    fs::create_dir_all(&root).expect("create test directory");
    let seed_hex = "cd".repeat(32);
    let (url, server) = spawn_mock(vec![json_response(
        "201 Created",
        serde_json::json!({
            "ok": true,
            "already_registered": false,
            "variant_reused": false,
            "release": {
                "id": "rel_0123456789abcdef01234567",
                "product_id": "acme",
                "app_version": "1.4.2",
                "variant_id": 7,
                "build_fingerprint": "build-2026-08",
                "channel": "stable",
                "status": "active",
                "published_at": 1_800_000_000
            },
            "warnings": []
        }),
    )]);

    let output = run_remote_str(
        &root,
        &[
            "--json",
            "release",
            "register",
            "--api-url",
            &url,
            "--product",
            "acme",
            "--app-version",
            "1.4.2",
            "--build-fingerprint",
            "build-2026-08",
            "--channel",
            "stable",
            "--variant-seed-hex",
            &seed_hex,
            "--idempotency-key",
            "release-register-001",
        ],
    );
    assert_success(&output);
    assert_eq!(json_stdout(&output)["http_status"], 201);
    assert_eq!(json_stdout(&output)["variant_seed_hex"], seed_hex);
    assert_eq!(json_stdout(&output)["variant_seed_generated"], false);

    let requests = server.join().expect("join mock server");
    assert_eq!(requests.len(), 1);
    let request = &requests[0];
    assert_eq!(request.method, "POST");
    assert_eq!(request.target, "/v1/admin/releases");
    assert_eq!(
        request.headers.get("idempotency-key").map(String::as_str),
        Some("release-register-001")
    );
    let body: Value = serde_json::from_slice(&request.body).expect("parse request JSON");
    assert_eq!(body["product_id"], "acme");
    assert_eq!(body["app_version"], "1.4.2");
    assert_eq!(body["build_fingerprint"], "build-2026-08");
    assert_eq!(body["channel"], "stable");
    assert_eq!(body["variant_seed_hex"], seed_hex);

    let invalid = run_remote_str(
        &root,
        &[
            "--json",
            "release",
            "register",
            "--api-url",
            "http://127.0.0.1:1",
            "--product",
            "acme",
            "--app-version",
            "1.4.2",
            "--build-fingerprint",
            "build-2026-08",
            "--variant-seed-hex",
            "not-hex",
            "--idempotency-key",
            "release-register-002",
        ],
    );
    assert!(!invalid.status.success());
    assert_eq!(json_stdout(&invalid)["error"]["code"], "invalid_identifier");

    fs::remove_dir_all(root).expect("remove test directory");
}

#[test]
fn release_register_generates_a_seed_when_omitted() {
    let root = temporary_dir("release-generate");
    fs::create_dir_all(&root).expect("create test directory");
    let (url, server) = spawn_mock(vec![json_response(
        "201 Created",
        serde_json::json!({
            "ok": true,
            "already_registered": false,
            "variant_reused": false,
            "release": {"id": "rel_1", "variant_id": 1},
            "warnings": [
                {"id": "variant_stable", "message": "variant isolation is disabled"}
            ]
        }),
    )]);

    let output = run_remote_str(
        &root,
        &[
            "--json",
            "release",
            "register",
            "--api-url",
            &url,
            "--product",
            "acme",
            "--app-version",
            "2.0.0",
            "--build-fingerprint",
            "build-2026-09",
            "--idempotency-key",
            "release-register-003",
        ],
    );
    assert_success(&output);
    let json = json_stdout(&output);
    let seed = json["variant_seed_hex"].as_str().expect("generated seed");
    assert_eq!(seed.len(), 64);
    assert!(seed.bytes().all(|byte| byte.is_ascii_hexdigit()));
    assert_eq!(json["variant_seed_generated"], true);

    let requests = server.join().expect("join mock server");
    let body: Value = serde_json::from_slice(&requests[0].body).expect("parse request JSON");
    assert_eq!(body["variant_seed_hex"], seed);
    // The default channel is stable.
    assert_eq!(body["channel"], "stable");

    fs::remove_dir_all(root).expect("remove test directory");
}

#[test]
fn release_lifecycle_dry_run_then_confirm_and_revoke_acknowledgement() {
    let root = temporary_dir("release-lifecycle");
    fs::create_dir_all(&root).expect("create test directory");
    let dry_run_body = serde_json::json!({
        "ok": true,
        "dry_run": true,
        "action": "revoke",
        "release": {
            "id": "rel_1",
            "product_id": "acme",
            "app_version": "1.4.2",
            "variant_id": 42,
            "published_at": 1_800_000_000
        },
        "impact": {"devices": 8432, "checkins_last_7d": 6109},
        "effects": ["every device on this release receives a KillOrder at its next validation"],
        "requires_acknowledgement": true,
        "security_floor": {"current": 3, "next": 4}
    });
    let (url, server) = spawn_mock(vec![
        json_response("200 OK", dry_run_body.clone()),
        json_response(
            "200 OK",
            serde_json::json!({
                "ok": true,
                "dry_run": false,
                "action": "revoke",
                "release": {"id": "rel_1", "status": "compromised"},
                "impact": {"devices": 8432, "checkins_last_7d": 6109},
                "security_floor": 4
            }),
        ),
    ]);

    // A confirmed revoke without --ack-revoke fails locally before any request.
    let unacknowledged = run_remote_str(
        &root,
        &[
            "--json",
            "release",
            "mark-compromised",
            "rel_1",
            "--api-url",
            &url,
            "--product",
            "acme",
            "--action",
            "revoke",
            "--confirm",
            "--idempotency-key",
            "release-revoke-001",
        ],
    );
    assert!(!unacknowledged.status.success());
    assert_eq!(
        json_stdout(&unacknowledged)["error"]["code"],
        "acknowledgement_required"
    );

    let dry_run = run_remote_str(
        &root,
        &[
            "--json",
            "release",
            "mark-compromised",
            "rel_1",
            "--api-url",
            &url,
            "--product",
            "acme",
            "--action",
            "revoke",
            "--bump-security-floor",
        ],
    );
    assert_success(&dry_run);
    assert_eq!(json_stdout(&dry_run)["dry_run"], true);
    assert_eq!(json_stdout(&dry_run)["impact"]["devices"], 8432);

    let confirm = run_remote_str(
        &root,
        &[
            "--json",
            "release",
            "mark-compromised",
            "rel_1",
            "--api-url",
            &url,
            "--product",
            "acme",
            "--action",
            "revoke",
            "--bump-security-floor",
            "--confirm",
            "--ack-revoke",
            "--idempotency-key",
            "release-revoke-002",
        ],
    );
    assert_success(&confirm);
    assert_eq!(json_stdout(&confirm)["dry_run"], false);

    let requests = server.join().expect("join mock server");
    assert_eq!(requests.len(), 2);
    assert_eq!(
        requests[0].target,
        "/v1/admin/releases/rel_1/mark-compromised?product_id=acme&dry_run=true"
    );
    assert!(!requests[0].headers.contains_key("idempotency-key"));
    assert_eq!(
        requests[1].target,
        "/v1/admin/releases/rel_1/mark-compromised?product_id=acme&dry_run=false"
    );
    assert_eq!(
        requests[1]
            .headers
            .get("idempotency-key")
            .map(String::as_str),
        Some("release-revoke-002")
    );
    let body: Value = serde_json::from_slice(&requests[1].body).expect("parse request JSON");
    assert_eq!(body["action"], "revoke");
    assert_eq!(body["acknowledge_revoke"], true);
    assert_eq!(body["bump_security_floor"], true);

    fs::remove_dir_all(root).expect("remove test directory");
}

#[test]
fn release_list_show_and_deprecate_use_the_admin_contract() {
    let root = temporary_dir("release-read");
    fs::create_dir_all(&root).expect("create test directory");
    let (url, server) = spawn_mock(vec![
        json_response(
            "200 OK",
            serde_json::json!({"ok": true, "product_id": "acme", "items": []}),
        ),
        json_response(
            "200 OK",
            serde_json::json!({"ok": true, "release": {"id": "rel_1", "status": "active"}}),
        ),
        json_response(
            "200 OK",
            serde_json::json!({
                "ok": true,
                "dry_run": true,
                "action": "deprecate",
                "release": {"id": "rel_1", "product_id": "acme", "app_version": "1.4.2",
                            "variant_id": 7, "published_at": 1_800_000_000},
                "impact": {"devices": 0, "checkins_last_7d": 0},
                "effects": []
            }),
        ),
    ]);

    for args in [
        vec!["release", "list"],
        vec!["release", "show", "rel_1"],
        vec!["release", "deprecate", "rel_1"],
    ] {
        let mut full = vec!["--json"];
        full.extend(args);
        full.extend(["--api-url", &url, "--product", "acme"]);
        let output = run_remote_str(&root, &full);
        assert_success(&output);
    }

    let requests = server.join().expect("join mock server");
    assert_eq!(requests.len(), 3);
    assert_eq!(requests[0].method, "GET");
    assert_eq!(requests[0].target, "/v1/admin/releases?product_id=acme");
    assert_eq!(
        requests[1].target,
        "/v1/admin/releases/rel_1?product_id=acme"
    );
    assert_eq!(requests[2].method, "POST");
    assert_eq!(
        requests[2].target,
        "/v1/admin/releases/rel_1/deprecate?product_id=acme&dry_run=true"
    );

    fs::remove_dir_all(root).expect("remove test directory");
}

#[test]
fn remote_errors_redirects_and_raw_path_boundaries_are_preserved() {
    let root = temporary_dir("remote-errors");
    fs::create_dir_all(&root).expect("create test directory");

    let (url, server) = spawn_mock(vec![json_response(
        "422 Unprocessable Entity",
        serde_json::json!({
            "ok": false,
            "error": {"code": "catalog_conflict", "message": "catalog changed"}
        }),
    )]);
    let failure = run_remote_str(
        &root,
        &[
            "--json",
            "request",
            "--api-url",
            &url,
            "get",
            "/v1/admin/catalog/features?product_id=acme",
        ],
    );
    assert!(!failure.status.success());
    assert_eq!(json_stdout(&failure)["error"]["code"], "catalog_conflict");
    assert_eq!(server.join().expect("join error server").len(), 1);

    let (redirect_url, redirect_listener) = no_request_listener();
    let redirect_watch = watch_for_request(redirect_listener, Duration::from_millis(750));
    let (url, server) = spawn_mock(vec![MockResponse {
        status: "302 Found".to_owned(),
        headers: vec![("Location".to_owned(), format!("{redirect_url}/stolen"))],
        body: serde_json::json!({
            "error": {"code": "redirect_rejected", "message": "do not follow"}
        })
        .to_string()
        .into_bytes(),
    }]);
    let redirected = run_remote_str(
        &root,
        &[
            "--json",
            "request",
            "--api-url",
            &url,
            "get",
            "/v1/admin/policies/policy-1",
        ],
    );
    assert!(!redirected.status.success());
    assert_eq!(
        json_stdout(&redirected)["error"]["code"],
        "redirect_rejected"
    );
    assert_eq!(server.join().expect("join redirect server").len(), 1);
    assert!(!redirect_watch.join().expect("join redirect watcher"));

    let (unused_url, listener) = no_request_listener();
    let no_request = watch_for_request(listener, Duration::from_millis(500));
    let invalid = run_remote_str(
        &root,
        &[
            "--json",
            "request",
            "--api-url",
            &unused_url,
            "get",
            "/v1/activate",
        ],
    );
    assert!(!invalid.status.success());
    assert_eq!(json_stdout(&invalid)["error"]["code"], "invalid_admin_path");
    assert!(!no_request.join().expect("join raw-path watcher"));

    fs::remove_dir_all(root).expect("remove test directory");
}

#[test]
fn dangerous_remote_commands_are_dry_run_and_typed_confirmation_is_local() {
    let root = temporary_dir("remote-confirmation");
    fs::create_dir_all(&root).expect("create test directory");
    let license_id = "00112233445566778899aabbccddeeff";

    let (url, server) = spawn_mock(vec![json_response(
        "200 OK",
        serde_json::json!({
            "ok": true,
            "dry_run": true,
            "kind": "license",
            "target": license_id,
            "affected_machines": 3,
            "already_revoked": false
        }),
    )]);
    let preview = run_remote_str(
        &root,
        &["--json", "license", "revoke", "--api-url", &url, license_id],
    );
    assert_success(&preview);
    let requests = server.join().expect("join dry-run server");
    assert_eq!(requests[0].method, "POST");
    assert_eq!(
        requests[0].target,
        format!("/v1/admin/licenses/{license_id}/revoke?dry_run=true")
    );
    assert!(!requests[0].headers.contains_key("idempotency-key"));

    let (url, server) = spawn_mock(vec![json_response(
        "200 OK",
        serde_json::json!({
            "ok": true,
            "dry_run": false,
            "kind": "license",
            "target": license_id,
            "revocation_epoch": 1
        }),
    )]);
    let confirmed = run_remote_str(
        &root,
        &[
            "--json",
            "license",
            "revoke",
            "--api-url",
            &url,
            license_id,
            "--confirm",
            "--idempotency-key",
            "revoke-001",
        ],
    );
    assert_success(&confirmed);
    let requests = server.join().expect("join confirmed server");
    assert_eq!(
        requests[0].target,
        format!("/v1/admin/licenses/{license_id}/revoke?dry_run=false")
    );
    assert_eq!(
        requests[0]
            .headers
            .get("idempotency-key")
            .map(String::as_str),
        Some("revoke-001")
    );

    let (unused_url, listener) = no_request_listener();
    let no_request = watch_for_request(listener, Duration::from_millis(500));
    let mismatch = run_remote_str(
        &root,
        &[
            "--json",
            "epoch",
            "revoke",
            "--api-url",
            &unused_url,
            "0011223344556677",
            "--confirm",
            "--confirm-epoch-id",
            "8899aabbccddeeff",
            "--idempotency-key",
            "epoch-revoke-001",
        ],
    );
    assert!(!mismatch.status.success());
    assert_eq!(
        json_stdout(&mismatch)["error"]["code"],
        "confirmation_mismatch"
    );
    assert!(!no_request.join().expect("join epoch watcher"));

    fs::remove_dir_all(root).expect("remove test directory");
}

#[test]
fn catalog_push_uses_patch_create_and_group_dependency_order() {
    let root = temporary_dir("catalog-push");
    fs::create_dir_all(&root).expect("create test directory");
    let catalog_path = root.join("catalog.json");
    fs::write(
        &catalog_path,
        serde_json::to_vec_pretty(&serde_json::json!({
            "product_id": "acme",
            "version": 99,
            "features": [{"id": "export.pdf", "label": "PDF export"}],
            "groups": [
                {
                    "id": "all-exports",
                    "label": "All exports",
                    "members": {"includes": ["base-exports"], "features": []}
                },
                {
                    "id": "base-exports",
                    "label": "Base exports",
                    "members": {"includes": [], "features": ["export.pdf"]}
                }
            ],
            "tiers": [{
                "id": "pro",
                "label": "Pro",
                "rank": 1,
                "groups": ["all-exports"],
                "features": [],
                "limits": {}
            }]
        }))
        .expect("serialize catalog"),
    )
    .expect("write catalog");

    let responses = vec![
        json_response(
            "200 OK",
            serde_json::json!({
                "ok": true,
                "product_id": "acme",
                "catalog_version": 1,
                "items": [{"id": "export.pdf", "label": "Old label"}]
            }),
        ),
        json_response(
            "200 OK",
            serde_json::json!({
                "ok": true, "product_id": "acme", "catalog_version": 1, "items": []
            }),
        ),
        json_response(
            "200 OK",
            serde_json::json!({
                "ok": true, "product_id": "acme", "catalog_version": 1, "items": []
            }),
        ),
        catalog_mutation_response(2),
        catalog_mutation_response(3),
        catalog_mutation_response(4),
        catalog_mutation_response(5),
    ];
    let (url, server) = spawn_mock(responses);
    let output = run_remote(
        &root,
        [
            "--json".into(),
            "catalog".into(),
            "--file".into(),
            catalog_path.as_os_str().into(),
            "push".into(),
            "--api-url".into(),
            url.into(),
            "--product".into(),
            "acme".into(),
            "--idempotency-key".into(),
            "sync-2026-07".into(),
        ],
    );
    assert_success(&output);
    let result = json_stdout(&output);
    assert_eq!(result["catalog_version_before"], 1);
    assert_eq!(result["catalog_version_after"], 5);
    assert_eq!(result["created"], 3);
    assert_eq!(result["updated"], 1);

    let requests = server.join().expect("join catalog server");
    assert_eq!(requests.len(), 7);
    assert_eq!(
        requests[0].target,
        "/v1/admin/catalog/features?product_id=acme"
    );
    assert_eq!(
        requests[1].target,
        "/v1/admin/catalog/groups?product_id=acme"
    );
    assert_eq!(
        requests[2].target,
        "/v1/admin/catalog/tiers?product_id=acme"
    );
    assert_eq!(requests[3].method, "PATCH");
    assert_eq!(requests[3].target, "/v1/admin/catalog/features");
    assert_eq!(request_json(&requests[3])["id"], "export.pdf");
    assert_eq!(requests[4].method, "POST");
    assert_eq!(request_json(&requests[4])["id"], "base-exports");
    assert_eq!(request_json(&requests[5])["id"], "all-exports");
    assert_eq!(request_json(&requests[6])["id"], "pro");
    assert_eq!(
        requests[4]
            .headers
            .get("idempotency-key")
            .map(String::as_str),
        Some("sync-2026-07:groups:base-exports")
    );

    fs::remove_dir_all(root).expect("remove test directory");
}

#[test]
fn doctor_optionally_checks_api_without_disclosing_the_token() {
    let root = temporary_dir("doctor-api");
    fs::create_dir_all(&root).expect("create test directory");
    fs::write(
        root.join("copylocker.json"),
        serde_json::to_vec_pretty(&serde_json::json!({
            "schema_version": 1,
            "project_name": "doctor-test",
            "product_id": "acme",
            "api_url": null,
            "admin_token_env": "COPYLOCKER_ADMIN_TOKEN"
        }))
        .expect("serialize project config"),
    )
    .expect("write project config");
    let (url, server) = spawn_mock(vec![json_response(
        "200 OK",
        serde_json::json!({
            "ok": true,
            "product_id": "acme",
            "catalog_version": 1,
            "items": []
        }),
    )]);
    let missing_vectors = root.join("missing-kat.json");
    let output = run_remote(
        &root,
        [
            "--json".into(),
            "doctor".into(),
            "--project".into(),
            root.as_os_str().into(),
            "--api-url".into(),
            url.into(),
            "--vectors".into(),
            missing_vectors.as_os_str().into(),
            "--check-api".into(),
        ],
    );
    assert_success(&output);
    let result = json_stdout(&output);
    assert_eq!(result["api"]["source"], "argument");
    assert_eq!(result["api"]["reachability"]["status"], "ok");
    assert_eq!(result["api"]["reachability"]["product_id"], "acme");
    assert_eq!(result["auth"]["env"], "COPYLOCKER_ADMIN_TOKEN");
    assert!(!String::from_utf8_lossy(&output.stdout).contains(TEST_ADMIN_TOKEN));
    assert!(!String::from_utf8_lossy(&output.stderr).contains(TEST_ADMIN_TOKEN));
    let requests = server.join().expect("join doctor server");
    assert_eq!(
        requests[0].target,
        "/v1/admin/catalog/features?product_id=acme"
    );

    fs::remove_dir_all(root).expect("remove test directory");
}

#[cfg(unix)]
#[test]
fn bootstrap_apply_keeps_plaintext_credentials_off_the_command_line() {
    use std::os::unix::fs::PermissionsExt as _;

    let root = temporary_dir("bootstrap-apply");
    fs::create_dir_all(&root).expect("create test directory");
    let server = root.join("server");
    let init = run(
        &root,
        [
            "--json".into(),
            "init".into(),
            server.as_os_str().into(),
            "--product".into(),
            "acme.desktop".into(),
            "--d1-database-id".into(),
            "00000000-0000-0000-0000-000000000001".into(),
            "--kv-namespace-id".into(),
            "00000000000000000000000000000002".into(),
            "--secret-store-id".into(),
            "00000000000000000000000000000003".into(),
        ],
    );
    assert_success(&init);
    let bundle_path = root.join("bootstrap.secret.json");
    let prepare = run(
        &root,
        [
            "--json".into(),
            "bootstrap".into(),
            "prepare".into(),
            "--project".into(),
            server.as_os_str().into(),
            "--vendor".into(),
            "vendor-acme".into(),
            "--actor".into(),
            "owner".into(),
            "--out".into(),
            bundle_path.as_os_str().into(),
        ],
    );
    assert_success(&prepare);
    let bundle: Value =
        serde_json::from_slice(&fs::read(&bundle_path).expect("read bootstrap bundle"))
            .expect("parse bootstrap bundle");
    let token = bundle["admin_token"]
        .as_str()
        .expect("bootstrap token")
        .to_owned();

    let wrapper = server.join("node_modules/.bin/wrangler");
    fs::create_dir_all(wrapper.parent().expect("wrapper parent"))
        .expect("create fake Wrangler directory");
    fs::write(
        &wrapper,
        "#!/bin/sh\nmkdir -p .copylocker\nprintf '%s\\n' \"$*\" >> .copylocker/bootstrap-calls\nif [ \"$1\" = \"secrets-store\" ]; then\n  IFS= read -r secret\n  printf '%s' \"$secret\" > .copylocker/bootstrap-secret-stdin\nfi\n",
    )
    .expect("write fake Wrangler");
    let mut permissions = fs::metadata(&wrapper)
        .expect("fake Wrangler metadata")
        .permissions();
    permissions.set_mode(0o700);
    fs::set_permissions(&wrapper, permissions).expect("make fake Wrangler executable");

    let apply = run(
        &root,
        [
            "--json".into(),
            "bootstrap".into(),
            "apply".into(),
            "--project".into(),
            server.as_os_str().into(),
            "--bundle".into(),
            bundle_path.as_os_str().into(),
            "--confirm".into(),
        ],
    );
    assert_success(&apply);
    assert!(!String::from_utf8_lossy(&apply.stdout).contains(&token));
    assert!(!String::from_utf8_lossy(&apply.stderr).contains(&token));
    let calls = fs::read_to_string(server.join(".copylocker/bootstrap-calls"))
        .expect("read fake Wrangler calls");
    assert!(calls.contains(
        "secrets-store secret create 00000000000000000000000000000003 --name ADMIN_TOKEN_PEPPER"
    ));
    assert!(calls.contains("d1 migrations apply server --remote"));
    assert!(calls.contains("d1 execute server --remote --yes --command"));
    assert!(calls.contains("INSERT INTO admin_tokens"));
    assert!(!calls.contains(&token));
    let secret_stdin = fs::read_to_string(server.join(".copylocker/bootstrap-secret-stdin"))
        .expect("read secret stdin");
    let secret: Value = serde_json::from_str(&secret_stdin).expect("parse secret stdin");
    assert_eq!(secret["schema_version"], 1);
    assert_eq!(secret["key"], bundle["admin_token_pepper"]);
    assert!(!secret_stdin.contains(&token));

    fs::remove_dir_all(root).expect("remove test directory");
}

#[test]
fn catalog_push_bridges_limit_keys_before_moving_them_between_tiers() {
    let root = temporary_dir("catalog-limit-bridge");
    fs::create_dir_all(&root).expect("create test directory");
    let catalog_path = root.join("catalog.json");
    fs::write(
        &catalog_path,
        serde_json::to_vec_pretty(&serde_json::json!({
            "product_id": "acme",
            "version": 10,
            "features": [],
            "groups": [],
            "tiers": [
                {
                    "id": "tier-a", "label": "A", "rank": 1,
                    "groups": [], "features": [], "limits": {"limit-y": 1}
                },
                {
                    "id": "tier-b", "label": "B", "rank": 2,
                    "groups": [], "features": [], "limits": {"limit-x": 1}
                }
            ]
        }))
        .expect("serialize catalog"),
    )
    .expect("write catalog");
    let remote_tiers = serde_json::json!([
        {
            "id": "tier-a", "label": "A", "rank": 1,
            "groups": [], "features": [], "limits": {"limit-x": 1}
        },
        {
            "id": "tier-b", "label": "B", "rank": 2,
            "groups": [], "features": [], "limits": {"limit-y": 1}
        }
    ]);
    let responses = vec![
        json_response(
            "200 OK",
            serde_json::json!({
                "ok": true, "product_id": "acme", "catalog_version": 1, "items": []
            }),
        ),
        json_response(
            "200 OK",
            serde_json::json!({
                "ok": true, "product_id": "acme", "catalog_version": 1, "items": []
            }),
        ),
        json_response(
            "200 OK",
            serde_json::json!({
                "ok": true, "product_id": "acme", "catalog_version": 1,
                "items": remote_tiers
            }),
        ),
        catalog_mutation_response(2),
        catalog_mutation_response(3),
        catalog_mutation_response(4),
        catalog_mutation_response(5),
    ];
    let (url, server) = spawn_mock(responses);
    let output = run_remote(
        &root,
        [
            "--json".into(),
            "catalog".into(),
            "--file".into(),
            catalog_path.as_os_str().into(),
            "push".into(),
            "--api-url".into(),
            url.into(),
            "--product".into(),
            "acme".into(),
            "--idempotency-key".into(),
            "move-limits".into(),
        ],
    );
    assert_success(&output);
    let result = json_stdout(&output);
    assert_eq!(result["updated"], 4);
    assert_eq!(result["bridge_updates"], 2);

    let requests = server.join().expect("join limit bridge server");
    assert_eq!(requests.len(), 7);
    assert_eq!(
        request_json(&requests[3])["limits"],
        serde_json::json!({"limit-x": 1, "limit-y": 1})
    );
    assert_eq!(
        request_json(&requests[4])["limits"],
        serde_json::json!({"limit-x": 1, "limit-y": 1})
    );
    assert_eq!(
        request_json(&requests[5])["limits"],
        serde_json::json!({"limit-y": 1})
    );
    assert_eq!(
        request_json(&requests[6])["limits"],
        serde_json::json!({"limit-x": 1})
    );
    assert_eq!(
        requests[3]
            .headers
            .get("idempotency-key")
            .map(String::as_str),
        Some("move-limits:tiers:tier-a:bridge")
    );
    assert_eq!(
        requests[5]
            .headers
            .get("idempotency-key")
            .map(String::as_str),
        Some("move-limits:tiers:tier-a:final")
    );

    fs::remove_dir_all(root).expect("remove test directory");
}

#[test]
fn offline_commands_cover_the_air_gapped_loop() {
    use copylocker_proto::{
        ActivationRequest, ActivationResponse, Envelope, MachineCredential, OfflineLicenseBundle,
    };
    use copylocker_suite::SignatureScheme as _;
    use copylocker_suite_std::{HybridSig, CL_STD_1_SUITE_ID};
    use copylocker_types::{Entitlements, EpochId, LicenseId, MachineId, Mode, PROTO_VER};
    use std::collections::{BTreeMap, BTreeSet};

    let root = temporary_dir("offline-loop");
    fs::create_dir_all(&root).expect("create test directory");
    let keys_dir = root.join("keys");
    let product = "acme.desktop";

    let roots = run(
        &root,
        [
            "--json".into(),
            "keygen".into(),
            "root".into(),
            "--out-dir".into(),
            keys_dir.as_os_str().into(),
            "--offline-confirm".into(),
        ],
    );
    assert_success(&roots);
    let epoch_dir = keys_dir.join("epoch");
    let epoch = run(
        &root,
        [
            "--json".into(),
            "keygen".into(),
            "epoch".into(),
            "--root-key".into(),
            keys_dir.join("cl-root.secret.json").as_os_str().into(),
            "--product".into(),
            product.into(),
            "--not-before".into(),
            "0".into(),
            "--not-after".into(),
            "4000000000".into(),
            "--epoch-id".into(),
            "0011223344556677".into(),
            "--out-dir".into(),
            epoch_dir.as_os_str().into(),
        ],
    );
    assert_success(&epoch);
    let certificate = fs::read(epoch_dir.join("epoch-0011223344556677.cert.cbor"))
        .expect("read epoch certificate");
    let signing_secret: Value = serde_json::from_slice(
        &fs::read(epoch_dir.join("epoch-0011223344556677.signing.secret.json"))
            .expect("read epoch secret"),
    )
    .expect("parse epoch secret");
    let signing_key_bytes: Vec<u8> = signing_secret["signing_key"]
        .as_array()
        .expect("signing key array")
        .iter()
        .map(|value| u8::try_from(value.as_u64().expect("key byte")).expect("key byte"))
        .collect();
    let epoch_signing_key =
        HybridSig::decode_sk(&signing_key_bytes).expect("decode epoch signing key");
    let epoch_id = EpochId([0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77]);
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("system clock")
        .as_secs();
    let now = i64::try_from(now).expect("now fits in i64");

    // 1. The offline device generates its request and device key file.
    let license_key = copylocker_proto::LicenseKey::new(0xab, [7u8; 10]).to_string_grouped();
    let request_path = root.join("request.cbor");
    let device_keys_path = root.join("device.secret.json");
    let request = run(
        &root,
        [
            "--json".into(),
            "offline".into(),
            "request".into(),
            "--product".into(),
            product.into(),
            "--license-key".into(),
            license_key.clone().into(),
            "--release-id".into(),
            "rel_1".into(),
            "--build-fingerprint".into(),
            "build-x".into(),
            "--app-version".into(),
            "1.0.0".into(),
            "--variant-id".into(),
            "1".into(),
            "--fingerprint-hex".into(),
            "0a".repeat(32).into(),
            "--out".into(),
            request_path.as_os_str().into(),
            "--keys-out".into(),
            device_keys_path.as_os_str().into(),
        ],
    );
    assert_success(&request);
    assert_secret_permissions(&device_keys_path);
    let request_bytes = fs::read(&request_path).expect("read activation request");
    let parsed_request = ActivationRequest::decode(&request_bytes).expect("request decodes");
    assert_eq!(parsed_request.product_id, product);
    assert_eq!(parsed_request.client_info.release_id, "rel_1");

    // 1b. The `.clar` armor of the same request decodes back to identical bytes.
    let armor_path = root.join("request.clar");
    let armored = run(
        &root,
        [
            "--json".into(),
            "offline".into(),
            "request".into(),
            "--product".into(),
            product.into(),
            "--license-key".into(),
            license_key.clone().into(),
            "--release-id".into(),
            "rel_1".into(),
            "--build-fingerprint".into(),
            "build-x".into(),
            "--app-version".into(),
            "1.0.0".into(),
            "--variant-id".into(),
            "1".into(),
            "--fingerprint-hex".into(),
            "0a".repeat(32).into(),
            "--out".into(),
            root.join("request-2.cbor").as_os_str().into(),
            "--armor-out".into(),
            armor_path.as_os_str().into(),
            "--keys-out".into(),
            root.join("device-2.secret.json").as_os_str().into(),
        ],
    );
    assert_success(&armored);
    assert!(
        json_stdout(&armored)["armor_chars"]
            .as_u64()
            .expect("armor_chars")
            > 0
    );
    let armor_text = fs::read_to_string(&armor_path).expect("read CLR1 armor");
    assert!(armor_text.starts_with(copylocker_proto::AR_ARMOR_PREFIX));
    let armored_request = fs::read(root.join("request-2.cbor")).expect("read second request");
    assert_eq!(
        copylocker_proto::unarmor_activation_request(&armor_text).expect("CLR1 armor decodes"),
        armored_request,
        "the armor is a lossless carrier of the canonical request"
    );
    let device_keys: Value =
        serde_json::from_slice(&fs::read(&device_keys_path).expect("read device keys"))
            .expect("parse device keys");
    let nonce: [u8; 32] = hex::decode(device_keys["nonce_hex"].as_str().expect("nonce"))
        .expect("nonce hex")
        .try_into()
        .expect("nonce length");

    // 2. The relay uploads the request; the mock server answers with a signed response.
    let mut features = BTreeSet::new();
    features.insert("export.pdf".to_owned());
    let credential = MachineCredential {
        proto_ver: PROTO_VER,
        suite_id: CL_STD_1_SUITE_ID,
        product_id: product.to_owned(),
        license_id: LicenseId([2; 16]),
        machine_id: MachineId([3; 16]),
        fingerprint: copylocker_types::Fingerprint::from_vec(vec![0x0a; 32]),
        kem_ct: vec![6; 1120],
        sealed_cs: vec![7; 72],
        offline_nonce: [8; 32],
        entitlements: Entitlements {
            features,
            limits: BTreeMap::new(),
            tier_id: "pro".to_owned(),
            tier_label: "Pro".to_owned(),
            catalog_version: 1,
            version_scope: None,
            subscription_hint: None,
        },
        issued_at: now - 10,
        not_after: now + 100_000,
        refresh_after: now + 3_600,
        grace_seconds: 3_600,
        mode: Mode::OfflineHybrid,
        revocation_epoch: 0,
        epoch_id,
        build_fingerprint: Some("build-x".to_owned()),
        policy_flags: None,
        security_floor: 0,
        variant_id: 1,
        wrapped_keks: BTreeMap::new(),
        preloaded_keks: None,
    };
    let credential_envelope = Envelope::seal::<HybridSig, _>(
        &credential,
        CL_STD_1_SUITE_ID,
        product,
        Some(epoch_id),
        &epoch_signing_key,
    )
    .expect("seal credential")
    .encode();
    let make_response = |valid_until: i64| -> Vec<u8> {
        Envelope::seal::<HybridSig, _>(
            &ActivationResponse {
                proto_ver: PROTO_VER,
                suite_id: CL_STD_1_SUITE_ID,
                nonce_c_echo: nonce,
                credential: credential_envelope.clone(),
                chain: vec![certificate.clone()],
                server_time: now,
                valid_until,
            },
            CL_STD_1_SUITE_ID,
            product,
            Some(epoch_id),
            &epoch_signing_key,
        )
        .expect("seal response")
        .encode()
    };
    let response_envelope = make_response(now + 86_400);

    let (url, server) = spawn_mock(vec![cbor_response("200 OK", response_envelope)]);
    let response_path = root.join("response.cbor");
    let redeem = run(
        &root,
        [
            "--json".into(),
            "offline".into(),
            "redeem".into(),
            "--api-url".into(),
            url.clone().into(),
            "--request".into(),
            request_path.as_os_str().into(),
            "--out".into(),
            response_path.as_os_str().into(),
            "--idempotency-key".into(),
            "offline-redeem-1".into(),
        ],
    );
    assert_success(&redeem);
    let recorded = server.join().expect("join mock server");
    assert_eq!(recorded.len(), 1);
    assert_eq!(recorded[0].method, "POST");
    assert_eq!(recorded[0].target, "/v1/offline/request");
    assert_eq!(
        recorded[0].headers.get("x-cl-proto").map(String::as_str),
        Some("1")
    );
    assert_eq!(
        recorded[0]
            .headers
            .get("idempotency-key")
            .map(String::as_str),
        Some("offline-redeem-1")
    );
    assert_eq!(recorded[0].body, request_bytes);
    assert!(!recorded[0].headers.contains_key("authorization"));

    // 2b. The relay also accepts the `.clar` armor: the posted bytes are the identical CBOR.
    let (armor_url, armor_server) =
        spawn_mock(vec![cbor_response("200 OK", make_response(now + 86_400))]);
    let armor_redeem = run(
        &root,
        [
            "--json".into(),
            "offline".into(),
            "redeem".into(),
            "--api-url".into(),
            armor_url.into(),
            "--request".into(),
            armor_path.as_os_str().into(),
            "--out".into(),
            root.join("response-2.cbor").as_os_str().into(),
            "--idempotency-key".into(),
            "offline-redeem-armor".into(),
        ],
    );
    assert_success(&armor_redeem);
    let armor_recorded = armor_server.join().expect("join armor mock server");
    assert_eq!(armor_recorded.len(), 1);
    assert_eq!(
        armor_recorded[0].body, armored_request,
        "the armored carrier posts the identical request bytes"
    );

    // 2c. QR-for-AR: a realistic armored request fits a single QR code.
    let qr = run(
        &root,
        [
            "--json".into(),
            "offline".into(),
            "qr".into(),
            "--input".into(),
            armor_path.as_os_str().into(),
        ],
    );
    assert_success(&qr);
    let qr_json = json_stdout(&qr);
    assert_eq!(qr_json["format"], "ascii");
    assert!(qr_json["modules"].as_u64().expect("modules") > 0);
    // The raw CBOR request armors for QR identically.
    let qr_cbor = run(
        &root,
        [
            "--json".into(),
            "offline".into(),
            "qr".into(),
            "--input".into(),
            root.join("request-2.cbor").as_os_str().into(),
        ],
    );
    assert_success(&qr_cbor);
    assert_eq!(
        json_stdout(&qr_cbor)["armor_chars"]
            .as_u64()
            .expect("armor_chars"),
        qr_json["armor_chars"].as_u64().expect("armor_chars"),
        "raw CBOR and CLR1 armor render the same QR payload"
    );

    // 3. The offline device verifies the response and exports the credential.
    let credential_path = root.join("credential.cbor");
    let import = run(
        &root,
        [
            "--json".into(),
            "offline".into(),
            "import".into(),
            "--response".into(),
            response_path.as_os_str().into(),
            "--keys".into(),
            device_keys_path.as_os_str().into(),
            "--root-public".into(),
            keys_dir.join("cl-root.public.json").as_os_str().into(),
            "--out".into(),
            credential_path.as_os_str().into(),
        ],
    );
    assert_success(&import);
    assert_eq!(json_stdout(&import)["verified"], true);
    assert_eq!(
        fs::read(&credential_path).expect("read credential"),
        credential_envelope
    );

    // A tampered response must not import.
    let mut tampered = fs::read(&response_path).expect("read response");
    let last = tampered.len() - 4;
    tampered[last] ^= 0xff;
    let tampered_path = root.join("tampered.cbor");
    fs::write(&tampered_path, tampered).expect("write tampered response");
    let tampered_import = run(
        &root,
        [
            "--json".into(),
            "offline".into(),
            "import".into(),
            "--response".into(),
            tampered_path.as_os_str().into(),
            "--keys".into(),
            device_keys_path.as_os_str().into(),
            "--root-public".into(),
            keys_dir.join("cl-root.public.json").as_os_str().into(),
            "--out".into(),
            root.join("tampered-cred.cbor").as_os_str().into(),
        ],
    );
    assert!(!tampered_import.status.success());

    // An expired response must not import either.
    let expired_path = root.join("expired.cbor");
    fs::write(&expired_path, make_response(now - 10)).expect("write expired response");
    let expired_import = run(
        &root,
        [
            "--json".into(),
            "offline".into(),
            "import".into(),
            "--response".into(),
            expired_path.as_os_str().into(),
            "--keys".into(),
            device_keys_path.as_os_str().into(),
            "--root-public".into(),
            keys_dir.join("cl-root.public.json").as_os_str().into(),
            "--out".into(),
            root.join("expired-cred.cbor").as_os_str().into(),
        ],
    );
    assert!(!expired_import.status.success());
    assert_eq!(
        json_stdout(&expired_import)["error"]["code"],
        "response_expired"
    );

    // A response chained to a different root must not import.
    let wrong_root_import = run(
        &root,
        [
            "--json".into(),
            "offline".into(),
            "import".into(),
            "--response".into(),
            response_path.as_os_str().into(),
            "--keys".into(),
            device_keys_path.as_os_str().into(),
            "--root-public".into(),
            keys_dir.join("cl-root-next.public.json").as_os_str().into(),
            "--out".into(),
            root.join("wrong-root-cred.cbor").as_os_str().into(),
        ],
    );
    assert!(!wrong_root_import.status.success());
    assert_eq!(
        json_stdout(&wrong_root_import)["error"]["code"],
        "chain_verification_failed"
    );

    // 4. QR rendering accepts both the binary bundle and its armor. A CL-STD-1 PQ-signed
    // bundle is kilobytes of armor and intentionally exceeds one QR code
    // (`protocol-spec.md` §8), so the render path is exercised with a small bundle.
    let bundle = OfflineLicenseBundle::new(vec![1, 2, 3, 4, 5], vec![vec![6, 7, 8]]);
    let binary_path = root.join("bundle.clk");
    fs::write(&binary_path, bundle.encode()).expect("write binary bundle");
    let armor_path = root.join("bundle.clk.txt");
    fs::write(&armor_path, bundle.to_armored()).expect("write armor");

    let qr_ascii = run(
        &root,
        [
            "--json".into(),
            "offline".into(),
            "qr".into(),
            "--input".into(),
            armor_path.as_os_str().into(),
        ],
    );
    assert_success(&qr_ascii);
    let qr_svg_path = root.join("bundle.svg");
    let qr_svg = run(
        &root,
        [
            "--json".into(),
            "offline".into(),
            "qr".into(),
            "--input".into(),
            binary_path.as_os_str().into(),
            "--format".into(),
            "svg".into(),
            "--out".into(),
            qr_svg_path.as_os_str().into(),
        ],
    );
    assert_success(&qr_svg);
    let svg = fs::read_to_string(&qr_svg_path).expect("read svg");
    assert!(svg.starts_with("<svg"));
    assert!(svg.contains("<path"));

    // A full PQ-signed CL-STD-1 bundle exceeds one QR code and must say so plainly.
    let big_bundle =
        OfflineLicenseBundle::new(credential_envelope.clone(), vec![certificate.clone()]);
    let big_armor_path = root.join("big.clk.txt");
    fs::write(&big_armor_path, big_bundle.to_armored()).expect("write big armor");
    let qr_too_large = run(
        &root,
        [
            "--json".into(),
            "offline".into(),
            "qr".into(),
            "--input".into(),
            big_armor_path.as_os_str().into(),
        ],
    );
    assert!(!qr_too_large.status.success());
    assert_eq!(
        json_stdout(&qr_too_large)["error"]["code"],
        "offline_bundle_too_large_for_qr"
    );

    // 5. OLK issuance writes the bundle returned by the Admin API.
    let olk_armor = bundle.to_armored();
    let (issue_url, issue_server) = spawn_mock(vec![json_response(
        "201 Created",
        serde_json::json!({
            "ok": true,
            "license_id": "02020202020202020202020202020202",
            "product_id": product,
            "release_id": "rel_1",
            "variant_id": 1,
            "bound": true,
            "armor": olk_armor,
        }),
    )]);
    let issued_bundle_path = root.join("issued.clk");
    let issued_armor_path = root.join("issued.clk.txt");
    let issue = run_remote(
        &root,
        [
            "--json".into(),
            "offline".into(),
            "issue".into(),
            "--api-url".into(),
            issue_url.into(),
            "--license".into(),
            "02".repeat(16).into(),
            "--release-id".into(),
            "rel_1".into(),
            "--bound-fingerprint-hex".into(),
            "07".repeat(32).into(),
            "--idempotency-key".into(),
            "olk-issue-1".into(),
            "--out".into(),
            issued_bundle_path.as_os_str().into(),
            "--armor-out".into(),
            issued_armor_path.as_os_str().into(),
        ],
    );
    assert_success(&issue);
    let recorded = issue_server.join().expect("join issue mock server");
    assert_eq!(recorded.len(), 1);
    assert_eq!(
        recorded[0].target,
        "/v1/admin/licenses/02020202020202020202020202020202/offline-key"
    );
    assert_eq!(
        recorded[0]
            .headers
            .get("idempotency-key")
            .map(String::as_str),
        Some("olk-issue-1")
    );
    assert_eq!(request_json(&recorded[0])["release_id"], "rel_1");
    let issued_bundle =
        OfflineLicenseBundle::decode(&fs::read(&issued_bundle_path).expect("read issued bundle"))
            .expect("issued bundle decodes");
    assert_eq!(issued_bundle, bundle);
    assert_eq!(
        fs::read_to_string(&issued_armor_path).expect("read issued armor"),
        format!("{}\n", bundle.to_armored())
    );

    fs::remove_dir_all(root).expect("remove test directory");
}

fn run_str(current_dir: &Path, args: &[&str]) -> Output {
    run(current_dir, args.iter().map(OsString::from))
}

fn run<I>(current_dir: &Path, args: I) -> Output
where
    I: IntoIterator<Item = OsString>,
{
    Command::new(env!("CARGO_BIN_EXE_copylocker"))
        .args(args)
        .current_dir(current_dir)
        .output()
        .expect("run copylocker CLI")
}

fn run_remote_str(current_dir: &Path, args: &[&str]) -> Output {
    run_remote(current_dir, args.iter().map(OsString::from))
}

fn run_remote<I>(current_dir: &Path, args: I) -> Output
where
    I: IntoIterator<Item = OsString>,
{
    Command::new(env!("CARGO_BIN_EXE_copylocker"))
        .args(args)
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

fn assert_eq_migration(server: &Path, name: &str) {
    let generated =
        fs::read(server.join("migrations").join(name)).expect("read generated migration");
    let canonical = fs::read(
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../copylocker-worker/migrations")
            .join(name),
    )
    .expect("read canonical migration");
    assert_eq!(generated, canonical);
}

#[cfg(unix)]
fn assert_secret_permissions(path: &Path) {
    use std::os::unix::fs::PermissionsExt as _;
    let mode = fs::metadata(path)
        .expect("read secret metadata")
        .permissions()
        .mode()
        & 0o777;
    assert_eq!(mode, 0o600, "{} is not private", path.display());
}

#[cfg(not(unix))]
fn assert_secret_permissions(path: &Path) {
    assert!(path.is_file());
}

fn temporary_dir(label: &str) -> PathBuf {
    static NEXT_ID: AtomicU64 = AtomicU64::new(0);
    std::env::temp_dir().join(format!(
        "copylocker-cli-{}-{}-{label}",
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
    headers: Vec<(String, String)>,
    body: Vec<u8>,
}

fn json_response(status: &str, body: Value) -> MockResponse {
    MockResponse {
        status: status.to_owned(),
        headers: Vec::new(),
        body: body.to_string().into_bytes(),
    }
}

fn cbor_response(status: &str, body: Vec<u8>) -> MockResponse {
    MockResponse {
        status: status.to_owned(),
        headers: vec![("content-type".to_owned(), "application/cbor".to_owned())],
        body,
    }
}

fn catalog_mutation_response(version: u32) -> MockResponse {
    json_response(
        "200 OK",
        serde_json::json!({"ok": true, "catalog_version": version, "item": {}}),
    )
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
    let has_content_type = response
        .headers
        .iter()
        .any(|(name, _)| name.eq_ignore_ascii_case("content-type"));
    let mut head = format!(
        "HTTP/1.1 {}\r\n{}Content-Length: {}\r\nConnection: close\r\n",
        response.status,
        if has_content_type {
            ""
        } else {
            "Content-Type: application/json\r\n"
        },
        response.body.len()
    );
    for (name, value) in &response.headers {
        head.push_str(name);
        head.push_str(": ");
        head.push_str(value);
        head.push_str("\r\n");
    }
    head.push_str("\r\n");
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
        while Instant::now() < deadline {
            match listener.accept() {
                Ok((mut stream, _)) => {
                    let _ = read_request(&mut stream);
                    write_response(
                        &mut stream,
                        &json_response("200 OK", serde_json::json!({"ok": true})),
                    );
                    return true;
                }
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    thread::sleep(Duration::from_millis(10));
                }
                Err(error) => panic!("request watcher failed: {error}"),
            }
        }
        false
    })
}
