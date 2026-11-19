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

use runtime_approval::{ApprovalBroker, ApprovalBrokerImpl};
use runtime_audit::{AuditService, AuditServiceImpl};
use runtime_config::config::{DiscoveryConfig, DiscoveryRoot};
use runtime_core::types::{AgentId, Capability, ExecutionProfile, ProjectId};
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
    approvals: Arc<dyn ApprovalBroker>,
    audit: Arc<dyn AuditService>,
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
        approvals: approvals.clone(),
        identity: identity.clone(),
        audit: audit.clone(),
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
        approvals,
        audit,
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

// ---- Task 6: workspaces --------------------------------------------------

fn workspace_ids(body: &Value) -> Vec<String> {
    body["workspaces"]
        .as_array()
        .unwrap()
        .iter()
        .map(|w| w["id"].as_str().unwrap_or("").to_string())
        .collect()
}

#[tokio::test]
async fn register_then_list_then_unregister_keeps_files() {
    let app = build(true, 1000).await;
    let (status, body, _) = send(
        &app.router,
        "POST",
        "/api/v1/workspaces/register",
        LOOPBACK,
        None,
        Some(json!({ "root_id": "test-root", "relative_path": "src" })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let id = body["workspace_id"].as_str().unwrap().to_string();
    assert_eq!(body["already_registered"], false);
    assert_eq!(body["available_to_agents_after_restart"], true);

    let (status, list, _) =
        send(&app.router, "GET", "/api/v1/workspaces", LOOPBACK, None, None).await;
    assert_eq!(status, StatusCode::OK, "{list}");
    assert!(workspace_ids(&list).contains(&id), "{list}");

    let (status, body, _) = send(
        &app.router,
        "DELETE",
        &format!("/api/v1/workspaces/{id}"),
        LOOPBACK,
        None,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["state"], "unregistered");

    let (_, list, _) =
        send(&app.router, "GET", "/api/v1/workspaces", LOOPBACK, None, None).await;
    assert!(!workspace_ids(&list).contains(&id), "{list}");
    assert!(app.root.join("src").exists(), "unregister deleted files");
}

#[tokio::test]
async fn duplicate_register_reuses_the_id() {
    let app = build(true, 1000).await;
    let payload = json!({ "root_id": "test-root", "relative_path": "src" });
    let (_, first, _) = send(
        &app.router,
        "POST",
        "/api/v1/workspaces/register",
        LOOPBACK,
        None,
        Some(payload.clone()),
    )
    .await;
    let (status, second, _) = send(
        &app.router,
        "POST",
        "/api/v1/workspaces/register",
        LOOPBACK,
        None,
        Some(payload),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{second}");
    assert_eq!(first["workspace_id"], second["workspace_id"]);
    assert_eq!(second["already_registered"], true);

    let (_, list, _) =
        send(&app.router, "GET", "/api/v1/workspaces", LOOPBACK, None, None).await;
    let id = second["workspace_id"].as_str().unwrap();
    let count = workspace_ids(&list).iter().filter(|w| *w == id).count();
    assert_eq!(count, 1, "{list}");
}

#[tokio::test]
async fn register_outside_any_root_is_refused() {
    let app = build(true, 1000).await;
    for relative in ["..%2F..%2Foutside", "%2FC%3A%2FWindows"] {
        let (status, body, _) = send(
            &app.router,
            "POST",
            "/api/v1/workspaces/register",
            LOOPBACK,
            None,
            Some(json!({ "root_id": "test-root", "relative_path": relative })),
        )
        .await;
        assert!(
            status == StatusCode::BAD_REQUEST || status == StatusCode::FORBIDDEN,
            "{relative}: {status} {body}"
        );
    }
}

#[tokio::test]
async fn list_body_has_relative_paths_only() {
    let app = build(true, 1000).await;
    let (_, body, _) =
        send(&app.router, "GET", "/api/v1/workspaces", LOOPBACK, None, None).await;
    let workspaces = body["workspaces"].as_array().unwrap();
    assert!(!workspaces.is_empty(), "{body}");
    for workspace in workspaces {
        assert!(workspace.get("root").is_none(), "absolute root leaked: {body}");
        assert!(workspace.get("root_id").is_some(), "{body}");
        assert!(workspace.get("relative_path").is_some(), "{body}");
    }
    let text = body.to_string();
    let canonical = app.root.canonicalize().unwrap();
    for needle in [
        app.root.to_string_lossy().to_string(),
        canonical.to_string_lossy().to_string(),
        canonical.to_string_lossy().replace('\\', "\\\\"),
    ] {
        assert!(!text.contains(&needle), "path leaked: {needle} in {text}");
    }
}

#[tokio::test]
async fn create_makes_the_directory_and_registers_it() {
    let app = build(true, 1000).await;
    let (status, body, _) = send(
        &app.router,
        "POST",
        "/api/v1/workspaces/create",
        LOOPBACK,
        None,
        Some(json!({
            "root_id": "test-root",
            "relative_path": "",
            "name": "fresh-project",
            "subdirs": ["src", "docs"],
        })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let id = body["workspace_id"].as_str().unwrap().to_string();
    assert!(app.root.join("fresh-project").is_dir());
    assert!(app.root.join("fresh-project").join("src").is_dir());

    let (_, one, _) = send(
        &app.router,
        "GET",
        &format!("/api/v1/workspaces/{id}"),
        LOOPBACK,
        None,
        None,
    )
    .await;
    assert_eq!(one["id"], id.as_str());
    assert_eq!(one["relative_path"], "fresh-project");
    assert_eq!(one["root_id"], "test-root");
}

#[tokio::test]
async fn unknown_workspace_is_404() {
    let app = build(true, 1000).await;
    let (status, body, _) = send(
        &app.router,
        "GET",
        "/api/v1/workspaces/00000000-0000-0000-0000-000000000000",
        LOOPBACK,
        None,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND, "{body}");
}

// ---- Task 7: approvals, devices, pairings, audit -------------------------

#[tokio::test]
async fn pending_approval_can_be_approved_then_disappears() {
    let app = build(true, 1000).await;
    let agent_id = AgentId::new();
    let project_id = ProjectId::new();
    let approval_id = app
        .approvals
        .request(
            agent_id,
            project_id,
            Capability::ProcessExec,
            Some("/workspace/src".into()),
            "test approval".into(),
        )
        .await
        .unwrap();

    let (status, body, _) = send(
        &app.router,
        "GET",
        "/api/v1/approvals",
        LOOPBACK,
        None,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["approvals"].as_array().unwrap().len(), 1, "{body}");

    let (status, body, _) = send(
        &app.router,
        "POST",
        &format!("/api/v1/approvals/{approval_id}/approve"),
        LOOPBACK,
        None,
        Some(json!({})),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["state"], "approved", "{body}");

    let (status, body, _) = send(
        &app.router,
        "GET",
        "/api/v1/approvals",
        LOOPBACK,
        None,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["approvals"].as_array().unwrap().len(), 0, "{body}");
}

#[tokio::test]
async fn approve_and_reject_write_audit_events() {
    let app = build(true, 1000).await;
    let agent_id = AgentId::new();
    let project_id = ProjectId::new();
    let approval_id = app
        .approvals
        .request(
            agent_id,
            project_id,
            Capability::ProcessExec,
            None,
            "test approval".into(),
        )
        .await
        .unwrap();

    let (status, _, _) = send(
        &app.router,
        "POST",
        &format!("/api/v1/approvals/{approval_id}/approve"),
        LOOPBACK,
        None,
        Some(json!({})),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{status}");

    let events = app
        .audit
        .query(runtime_core::audit::AuditFilter {
            event_type: Some(runtime_core::audit::AuditEventType::ApprovalGranted),
            agent_id: None,
            device_id: None,
            project_id: None,
            session_id: None,
            capability: None,
            start_time: None,
            end_time: None,
            limit: None,
            offset: None,
        })
        .await
        .unwrap();
    assert!(
        events
            .iter()
            .any(|e| e.resource.as_deref() == Some(&approval_id.to_string())),
        "no approval grant audit event for {approval_id}: {events:?}"
    );
}

#[tokio::test]
async fn pairings_are_host_only() {
    let app = build(true, 1000).await;
    let token = app.token().await;

    // A remote peer with a valid token passes require_session, then is
    // rejected by the host-only check.
    let (status, _, _) = send(
        &app.router,
        "GET",
        "/api/v1/pairings",
        REMOTE,
        Some(&token),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);

    // Loopback with a token is allowed.
    let (status, body, _) = send(
        &app.router,
        "GET",
        "/api/v1/pairings",
        LOOPBACK,
        Some(&token),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert!(body.get("pairings").is_some(), "{body}");
}

#[tokio::test]
async fn revoke_kills_the_session() {
    let app = build(true, 1000).await;
    let public_key = app.signing.verifying_key().to_bytes().to_vec();
    let pairing = app
        .identity
        .request_pairing("test-device".into(), public_key)
        .await
        .unwrap();
    let device_id = app
        .identity
        .approve_pairing(pairing.pairing_code)
        .await
        .unwrap();
    let signature = app.signing.sign(device_id.to_string().as_bytes());
    let token = app
        .identity
        .authenticate_device(device_id, hex(&signature.to_bytes()))
        .await
        .unwrap();

    // Revoke via the API (loopback = host).
    let (status, _, _) = send(
        &app.router,
        "POST",
        &format!("/api/v1/devices/{device_id}/revoke"),
        LOOPBACK,
        Some(&token),
        Some(json!({})),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{status}");

    // Reuse the token from a REMOTE peer: require_session validates the token,
    // and a revoked device must invalidate it (401).
    let (status, _, _) = send(
        &app.router,
        "GET",
        "/api/v1/device",
        REMOTE,
        Some(&token),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "{status}");
}

#[tokio::test]
async fn malformed_approval_id_is_400() {
    let app = build(true, 1000).await;
    let (status, body, _) = send(
        &app.router,
        "POST",
        "/api/v1/approvals/not-a-uuid/approve",
        LOOPBACK,
        None,
        Some(json!({})),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    assert!(body.get("error").is_some(), "{body}");
}
