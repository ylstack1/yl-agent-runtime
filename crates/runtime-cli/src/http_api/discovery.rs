//! Discovery endpoints: roots, browsing and project detection.
//!
//! Every path a client names is root-relative. Containment (traversal, symlink
// and junction escapes) is decided by `DiscoveryService`/`PathValidator`, never
// by string checks here.

use axum::extract::{Path as UrlPath, Query, State};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, patch, post};
use axum::{Json, Router};
use serde::Deserialize;
use serde_json::json;
use std::path::PathBuf;

use runtime_core::error::Error;

use super::{api_error, ApiJson, ApiState};
use crate::commands::AppState;

pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/discovery/roots", get(list_roots).post(add_root))
        .route("/discovery/roots/suggestions", get(root_suggestions))
        .route("/discovery/roots/{id}", patch(toggle_root).delete(delete_root))
        .route("/discovery/roots/{id}/entries", get(browse))
        .route("/projects/detect", post(detect))
}

/// Candidate root directories an operator can grant with one click. This is a
/// fixed suggestion list, not filesystem browsing: the response never reflects
/// an arbitrary authenticated caller's probe, and it is only reachable through
/// the authenticated management API.
async fn root_suggestions() -> Response {
    let mut out: Vec<serde_json::Value> = Vec::new();
    let mut seen: std::collections::HashSet<PathBuf> = std::collections::HashSet::new();
    let mut push = |label: &str, path: PathBuf| {
        if path.is_dir() && seen.insert(path.clone()) {
            out.push(json!({ "label": label, "path": path.display().to_string() }));
        }
    };
    if let Some(home) = std::env::var_os("USERPROFILE")
        .or_else(|| std::env::var_os("HOME"))
        .map(PathBuf::from)
    {
        push("Home", home.clone());
        for (name, label) in [
            ("Desktop", "Desktop"),
            ("Documents", "Documents"),
            ("Downloads", "Downloads"),
            ("Projects", "Projects"),
            ("source", "Source"),
            ("repos", "Repos"),
        ] {
            push(label, home.join(name));
        }
    }
    if let Ok(cwd) = std::env::current_dir() {
        push("Current directory", cwd);
    }
    Json(json!({ "suggestions": out })).into_response()
}

/// Resolve a `root_id` + `relative_path` pair to an absolute host path, with
/// containment enforced by the discovery service. Used by the workspace
/// endpoints so register/create share one choke point.
pub fn resolve_root_path(
    api: &ApiState,
    root_id: &str,
    relative_path: &str,
) -> Result<PathBuf, Error> {
    api.discovery.resolve_relative(root_id, relative_path)
}

async fn list_roots(State(api): State<ApiState>) -> Response {
    let mut roots = api.discovery.list_roots();
    roots.sort_by(|a, b| a.id.cmp(&b.id));
    let roots: Vec<serde_json::Value> = roots
        .into_iter()
        .map(|root| {
            json!({
                "id": root.id,
                "label": root.label,
                "enabled": root.enabled,
                "browse": root.browse,
                "create": root.create,
                "register": root.register,
                "import": root.import,
                "clone": root.clone,
                "synthetic": root.synthetic,
            })
        })
        .collect();
    Json(json!({ "roots": roots })).into_response()
}

/// Remove an operator-added root. Both copies (browsing + register/create
/// enforcement) and the persisted sidecar are updated. Synthetic roots are
/// refused with an explanation instead of silently reappearing.
async fn delete_root(State(api): State<ApiState>, UrlPath(id): UrlPath<String>) -> Response {
    let roots = api.discovery.list_roots();
    match roots.iter().find(|root| root.id == id) {
        Some(root) if root.synthetic => {
            return api_error(&Error::Validation(format!(
                "Root {id} is derived from a workspace root; unregister the workspace instead"
            )))
            .into_response()
        }
        Some(_) => {}
        None => {
            return api_error(&Error::Validation(format!(
                "Discovery root not found: {id}"
            )))
            .into_response()
        }
    }
    if let Err(err) = api.discovery.remove_root(&id) {
        return api_error(&err).into_response();
    }
    if let Err(err) = api.fs.remove_discovery_root(&id) {
        return api_error(&err).into_response();
    }
    Json(json!({ "id": id, "state": "removed" })).into_response()
}

#[derive(Deserialize)]
struct ToggleBody {
    enabled: bool,
}

#[derive(Deserialize)]
struct AddRootBody {
    id: String,
    label: String,
    path: String,
    #[serde(default)]
    enabled: Option<bool>,
    #[serde(default)]
    browse: Option<bool>,
    #[serde(default)]
    create: Option<bool>,
    #[serde(default)]
    register: Option<bool>,
}

/// Add a new discovery root at runtime. The root path must exist on disk and is
/// persisted to `<data_dir>/discovery_roots.json`, so a console grant survives
/// restarts. Both the browsing service and the register/create enforcement copy
/// are updated together.
async fn add_root(State(api): State<ApiState>, ApiJson(body): ApiJson<AddRootBody>) -> Response {
    let path = std::path::Path::new(&body.path);
    if !path.exists() {
        return api_error(&Error::Validation(format!(
            "Root path does not exist: {}",
            body.path
        )))
        .into_response();
    }
    let canonical = path.canonicalize().unwrap_or_else(|_| path.to_path_buf());
    let root = runtime_config::config::DiscoveryRoot {
        id: body.id.clone(),
        label: body.label.clone(),
        path: canonical,
        enabled: body.enabled.unwrap_or(true),
        browse: body.browse.unwrap_or(true),
        create: body.create.unwrap_or(false),
        register: body.register.unwrap_or(false),
        import: false,
        clone: false,
        synthetic: false,
    };
    if let Err(err) = api.discovery.add_root(&root) {
        return api_error(&err).into_response();
    }
    if let Err(err) = api.fs.add_discovery_root(root) {
        // Keep browsing and enforcement in sync on failure.
        let _ = api.discovery.remove_root(&body.id);
        return api_error(&err).into_response();
    }
    Json(json!({ "id": body.id, "state": "added" })).into_response()
}

/// Enable/disable a root. Two copies exist — the browsing one and the
/// enforcement one used by register/create — so this moves both, and reverts
/// the first if the second fails.
async fn toggle_root(
    State(api): State<ApiState>,
    UrlPath(id): UrlPath<String>,
    ApiJson(body): ApiJson<ToggleBody>,
) -> Response {
    if let Err(err) = api.discovery.set_root_enabled(&id, body.enabled) {
        return api_error(&err).into_response();
    }
    if let Err(err) = api.fs.set_discovery_root_enabled(&id, body.enabled) {
        let _ = api.discovery.set_root_enabled(&id, !body.enabled);
        return api_error(&err).into_response();
    }
    Json(json!({ "id": id, "enabled": body.enabled })).into_response()
}

/// Browse entries under a discovery root. Query params: `path` (root-relative),
/// `cursor`, `limit`.
#[derive(Deserialize)]
struct BrowseQuery {
    #[serde(default)]
    path: String,
    #[serde(default)]
    cursor: Option<usize>,
    #[serde(default)]
    limit: Option<usize>,
}

async fn browse(
    State(api): State<ApiState>,
    UrlPath(root_id): UrlPath<String>,
    Query(query): Query<BrowseQuery>,
) -> Response {
    match api.discovery.browse_root(&root_id, &query.path, query.cursor, query.limit) {
        Ok(result) => {
            let entries: Vec<serde_json::Value> = result
                .entries
                .into_iter()
                .map(|e| {
                    json!({
                        "name": e.name,
                        "path": e.relative_path.to_string_lossy(),
                        "kind": format!("{:?}", e.entry_kind),
                        "size": e.size,
                        "hidden": e.hidden,
                    })
                })
                .collect();
            Json(json!({
                "root_id": result.root_id,
                "path": result.path,
                "entries": entries,
                "has_more": result.has_more,
            }))
            .into_response()
        }
        Err(err) => api_error(&err).into_response(),
    }
}

/// Detect a project under a discovery root. Body: { root_id, relative_path }.
#[derive(Deserialize)]
struct DetectBody {
    root_id: String,
    #[serde(default)]
    relative_path: String,
}

async fn detect(State(api): State<ApiState>, Json(body): Json<DetectBody>) -> Response {
    match api.discovery.detect_project(&body.root_id, &body.relative_path) {
        Ok(result) => Json(serde_json::json!({
            "root_id": result.root_id,
            "path": result.relative_path,
            "markers": result.markers,
            "project_types": result.project_types,
            "git_present": result.git_present,
            "confidence": result.confidence,
        }))
        .into_response(),
        Err(err) => api_error(&err).into_response(),
    }
}
