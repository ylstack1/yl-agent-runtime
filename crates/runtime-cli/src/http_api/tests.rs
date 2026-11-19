//! Tests for the `/api/v1` auth gate, the device facts endpoint and the console
//! assets. `runtime-cli` is a binary crate without a library target, so these
//! live inline and run with `cargo test -p runtime-cli --bin yl`.

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;

use axum::body::Body;
use axum::extract::ConnectInfo;
use axum::http::{header, Request, StatusCode};
use axum::Router;
use ed25519_dalek::{Signer, SigningKey};
use serde_json::{json, Value};
use tempfile::TempDir;
use tower::ServiceExt;

use runtime_approval::ApprovalBrokerImpl;
use runtime_audit::{AuditService, AuditServiceImpl};
use runtime_config::config::{DiscoveryConfig, DiscoveryRoot};
use runtime_core::types::ExecutionProfile;
use runtime_identity::{IdentityService, IdentityServiceImpl};
use runtime_workspace::discovery::DiscoveryService;
use runtime_workspace::{WorkspaceService, WorkspaceServiceImpl};

use crate::commands::{base_routes, build_router, AppState, RateLimiter};
use crate::http_api::{ApiState, DeviceFacts};

const LOOPBACK: &str = "127.0.0.1:50000";
const REMOTE: &str = "192.168.1.50:50000";

struct TestApp {
    router: Router,
    identity: Arc<IdentityServiceImpl>,
    signing: SigningKey,
    root: PathBuf,
    _dir: TempDir,
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

async fn build(pairing_required: bool, rate_limit: u32) -> TestApp {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().join("root");
    std::fs::create_dir_all(root.join("src")).unwrap();
    std::fs::write(root.join("Cargo.toml"), "[package]").unwrap();

    let discovery_config = DiscoveryConfig {
        roots: vec![DiscoveryRoot {
            id: "test-root".to_string(),
            label: "Test Root".to_string(),
            path: root.clone(),
            enabled: true,
            browse: true,
            create: true,
            register: true,
            import: false,
            clone: false,
            synthetic: false,
        }],
        ..Default::default()
    };

    let data_dir = dir.path().join("data");
    std::fs::create_dir_all(&data_dir).unwrap();
    let fs = Arc::new(
        WorkspaceServiceImpl::with_data_dir(data_dir.clone(), discovery_config).unwrap(),
    );
    fs.register(root.clone(), ExecutionProfile::Development)
        .await
        .unwrap();

    let discovery = Arc::new(DiscoveryService::from_config(fs.discovery_config()).unwrap());
    let audit: Arc<dyn AuditService> =
        Arc::new(AuditServiceImpl::new().with_log_path(data_dir.join("audit.jsonl")));
    let approvals: Arc<dyn runtime_approval::ApprovalBroker> =
        Arc::new(ApprovalBrokerImpl::new().with_log_path(data_dir.join("approvals.jsonl")));
    let identity: Arc<IdentityServiceImpl> = Arc::new(IdentityServiceImpl::new());
    let signing = SigningKey::from_bytes(&[7u8; 32]);

    let api_state = ApiState {
        fs,
        discovery,
        approvals,
        identity: identity.clone(),
        audit,
        facts: DeviceFacts {
            version: env!("CARGO_PKG_VERSION"),
            os: std::env::consts::OS,
            arch: std::env::consts::ARCH,
            yolo: false,
            pairing_required,
            tls_enabled: false,
            cert_fingerprint: Some("AA:BB".to_string()),
            lan_urls: vec![],
        },
    };
    let state = AppState {
        identity: identity.clone(),
        pairing_required,
        limiter: Arc::new(RateLimiter::new(rate_limit)),
        api: api_state,
    };

    TestApp {
        router: build_router(base_routes(), state),
        identity,
        signing,
        root,
        _dir: dir,
    }
}

impl TestApp {
    /// Pair a device through the real identity service and return its bearer
    /// token. This is the same path the console takes, minus the browser.
    async fn token(&self) -> String {
        let public_key = self.signing.verifying_key().to_bytes().to_vec();
        let pairing = self
            .identity
            .request_pairing("test-device".to_string(), public_key)
            .await
            .unwrap();
        let device_id = self
            .identity
            .approve_pairing(pairing.pairing_code)
            .await
            .unwrap();
        let signature = self.signing.sign(device_id.to_string().as_bytes());
        self.identity
            .authenticate_device(device_id, hex(&signature.to_bytes()))
            .await
            .unwrap()
    }
}

fn request(
    method: &str,
    path: &str,
    peer: &str,
    token: Option<&str>,
    body: Option<Value>,
) -> Request<Body> {
    let mut builder = Request::builder().method(method).uri(path);
    if let Some(token) = token {
        builder = builder.header(header::AUTHORIZATION, format!("Bearer {token}"));
    }
    let body = match body {
        Some(value) => {
            builder = builder.header(header::CONTENT_TYPE, "application/json");
            Body::from(serde_json::to_vec(&value).unwrap())
        }
        None => Body::empty(),
    };
    let mut request = builder.body(body).unwrap();
    request
        .extensions_mut()
        .insert(ConnectInfo(peer.parse::<SocketAddr>().unwrap()));
    request
}

async fn send(
    app: &Router,
    method: &str,
    path: &str,
    peer: &str,
    token: Option<&str>,
    body: Option<Value>,
) -> (StatusCode, Value, Option<String>) {
    let response = app
        .clone()
        .oneshot(request(method, path, peer, token, body))
        .await
        .unwrap();
    let status = response.status();
    let content_type = response
        .headers()
        .get(header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .map(str::to_owned);
    let bytes = axum::body::to_bytes(response.into_body(), 1024 * 1024)
        .await
        .unwrap();
    let text = String::from_utf8_lossy(&bytes).to_string();
    let value = serde_json::from_str(&text).unwrap_or(Value::Null);
    (status, value, content_type)
}

#[tokio::test]
async fn loopback_gets_device_facts() {
    let app = build(true, 100).await;
    let (status, body, _) = send(&app.router, "GET", "/api/v1/device", LOOPBACK, None, None).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert!(body.get("version").is_some(), "{body}");
    assert!(
        body["workspace_count"].as_u64().unwrap_or(0) >= 1,
        "{body}"
    );
    let text = body.to_string();
    let root = app.root.to_string_lossy().to_string();
    assert!(!text.contains(&root), "absolute path leaked: {text}");
}

#[tokio::test]
async fn remote_without_token_is_401() {
    let app = build(true, 1000).await;
    let (status, body, _) = send(&app.router, "GET", "/api/v1/device", REMOTE, None, None).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "{body}");
    assert!(body.get("error").is_some(), "{body}");
}

#[tokio::test]
async fn remote_with_valid_token_is_200() {
    let app = build(true, 1000).await;
    let token = app.token().await;
    let (status, body, _) = send(
        &app.router,
        "GET",
        "/api/v1/device",
        REMOTE,
        Some(&token),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
}

#[tokio::test]
async fn pairing_required_false_still_gates_the_api() {
    let app = build(false, 1000).await;
    let (status, body, _) = send(&app.router, "GET", "/api/v1/device", REMOTE, None, None).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "{body}");

    // Public bootstrap paths still pass, which is what makes pairing possible.
    let (health, _, _) = send(&app.router, "GET", "/health", REMOTE, None, None).await;
    assert_eq!(health, StatusCode::OK);
}

#[tokio::test]
async fn remote_can_start_pairing() {
    let app = build(true, 1000).await;
    let key = hex(&SigningKey::from_bytes(&[9u8; 32]).verifying_key().to_bytes());
    let (status, body, _) = send(
        &app.router,
        "POST",
        "/pair/request",
        REMOTE,
        None,
        Some(json!({ "device_name": "phone", "public_key_hex": key })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert!(body["pairing_code"].as_str().unwrap_or("").len() == 6, "{body}");
}

#[tokio::test]
async fn host_only_endpoint_refuses_a_remote_peer() {
    let app = build(true, 1000).await;
    let token = app.token().await;
    let (status, body, _) = send(
        &app.router,
        "POST",
        "/device/revoke",
        REMOTE,
        Some(&token),
        Some(json!({ "device_id": "00000000-0000-0000-0000-000000000000" })),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");

    // The same call from the host is allowed (and just fails on the empty id).
    let (host_status, _, _) = send(
        &app.router,
        "POST",
        "/device/revoke",
        LOOPBACK,
        None,
        Some(json!({ "device_id": "00000000-0000-0000-0000-000000000000" })),
    )
    .await;
    assert_ne!(host_status, StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn limiter_counts_only_unauthenticated_traffic() {
    let app = build(true, 3).await;
    let mut statuses = Vec::new();
    for _ in 0..5 {
        let (status, _, _) =
            send(&app.router, "GET", "/api/v1/device", REMOTE, None, None).await;
        statuses.push(status);
    }
    assert_eq!(
        statuses.last().copied(),
        Some(StatusCode::TOO_MANY_REQUESTS),
        "{statuses:?}"
    );
    assert_eq!(statuses[0], StatusCode::UNAUTHORIZED, "{statuses:?}");

    let token = app.token().await;
    for _ in 0..5 {
        let (status, body, _) = send(
            &app.router,
            "GET",
            "/api/v1/device",
            REMOTE,
            Some(&token),
            None,
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{body}");
    }
}

#[tokio::test]
async fn ui_assets_are_public() {
    let app = build(true, 1000).await;
    for (path, expected) in [
        ("/ui", "text/html"),
        ("/ui/app.js", "text/javascript"),
        ("/ui/app.css", "text/css"),
    ] {
        let (status, _, content_type) =
            send(&app.router, "GET", path, REMOTE, None, None).await;
        assert_eq!(status, StatusCode::OK, "{path}");
        let content_type = content_type.unwrap_or_default();
        assert!(
            content_type.starts_with(expected),
            "{path} had {content_type}"
        );
    }
}

#[tokio::test]
async fn ui_path_traversal_is_404() {
    let app = build(true, 1000).await;
    let (status, _, _) = send(
        &app.router,
        "GET",
        "/ui/../Cargo.toml",
        LOOPBACK,
        None,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn malformed_json_is_400_with_a_json_error() {
    let app = build(true, 1000).await;
    let response = app
        .router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/pair/request")
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from("{"))
                .map(|mut request| {
                    request
                        .extensions_mut()
                        .insert(ConnectInfo(LOOPBACK.parse::<SocketAddr>().unwrap()));
                    request
                })
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let bytes = axum::body::to_bytes(response.into_body(), 1024).await.unwrap();
    let body: Value = serde_json::from_slice(&bytes).unwrap();
    assert!(body.get("error").is_some(), "{body}");
}

// ---- Task 5: discovery ---------------------------------------------------

#[tokio::test]
async fn roots_list_exposes_flags_but_no_absolute_paths() {
    let app = build(true, 1000).await;
    let (status, body, _) = send(
        &app.router,
        "GET",
        "/api/v1/discovery/roots",
        LOOPBACK,
        None,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let roots = body["roots"].as_array().unwrap();
    assert_eq!(roots.len(), 1, "{body}");
    let root = &roots[0];
    assert_eq!(root["id"], "test-root");
    for flag in ["enabled", "browse", "create", "register", "import", "clone", "synthetic"] {
        assert!(root.get(flag).is_some(), "missing {flag}: {body}");
    }
    let text = body.to_string();
    assert!(!text.contains(&app.root.to_string_lossy().to_string()), "{text}");
}

#[tokio::test]
async fn browse_lists_root_relative_entries() {
    let app = build(true, 1000).await;
    let (status, body, _) = send(
        &app.router,
        "GET",
        "/api/v1/discovery/roots/test-root/entries?path=",
        LOOPBACK,
        None,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["root_id"], "test-root");
    let names: Vec<&str> = body["entries"]
        .as_array()
        .unwrap()
        .iter()
        .map(|e| e["name"].as_str().unwrap_or(""))
        .collect();
    assert!(names.contains(&"Cargo.toml"), "{names:?}");
    assert!(names.contains(&"src"), "{names:?}");
}

#[tokio::test]
async fn disabling_a_root_refuses_browse_and_moves_both_copies() {
    let app = build(true, 1000).await;
    let (status, body, _) = send(
        &app.router,
        "PATCH",
        "/api/v1/discovery/roots/test-root",
        LOOPBACK,
        None,
        Some(json!({ "enabled": false })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["enabled"], false);

    let (browse, body, _) = send(
        &app.router,
        "GET",
        "/api/v1/discovery/roots/test-root/entries?path=",
        LOOPBACK,
        None,
        None,
    )
    .await;
    assert_eq!(browse, StatusCode::FORBIDDEN, "{body}");

    let (status, _, _) = send(
        &app.router,
        "PATCH",
        "/api/v1/discovery/roots/test-root",
        LOOPBACK,
        None,
        Some(json!({ "enabled": true })),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
}

#[tokio::test]
async fn traversal_is_refused_by_discovery() {
    let app = build(true, 1000).await;
    let (status, body, _) = send(
        &app.router,
        "GET",
        "/api/v1/discovery/roots/test-root/entries?path=..%2F..%2F..",
        LOOPBACK,
        None,
        None,
    )
    .await;
    assert!(
        status == StatusCode::BAD_REQUEST || status == StatusCode::FORBIDDEN,
        "{status} {body}"
    );
}

#[tokio::test]
async fn detect_returns_markers_for_a_rust_project() {
    let app = build(true, 1000).await;
    let (status, body, _) = send(
        &app.router,
        "POST",
        "/api/v1/projects/detect",
        LOOPBACK,
        None,
        Some(json!({ "root_id": "test-root", "relative_path": "" })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let types: Vec<&str> = body["project_types"]
        .as_array()
        .unwrap()
        .iter()
        .map(|t| t.as_str().unwrap_or(""))
        .collect();
    assert!(types.contains(&"rust"), "{types:?}");
    assert_eq!(body["root_id"], "test-root");
}

#[tokio::test]
async fn toggling_an_unknown_root_is_a_client_error() {
    let app = build(true, 1000).await;
    let (status, body, _) = send(
        &app.router,
        "PATCH",
        "/api/v1/discovery/roots/nope",
        LOOPBACK,
        None,
        Some(json!({ "enabled": false })),
    )
    .await;
    assert!(
        status == StatusCode::BAD_REQUEST || status == StatusCode::NOT_FOUND,
        "{status} {body}"
    );
}
