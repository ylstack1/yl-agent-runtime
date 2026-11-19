//! Discovery endpoints: roots, browsing and project detection.
//!
//! Every path a client names is root-relative. Containment (traversal, symlink
//! and junction escapes) is decided by `DiscoveryService`/`PathValidator`, never
//! by string checks here.

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
        .route("/discovery/roots", get(list_roots))
        .route("/discovery/roots/{id}", patch(toggle_root))
        .route("/discovery/roots/{id}/entries", get(browse))
        .route("/projects/detect", post(detect))
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

#[derive(Deserialize)]
struct ToggleBody {
    enabled: bool,
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

#[derive(Deserialize)]
struct BrowseQuery {
    #[serde(default)]
    path: String,
    cursor: Option<usize>,
    limit: Option<usize>,
}

async fn browse(
    State(api): State<ApiState>,
    UrlPath(id): UrlPath<String>,
    Query(query): Query<BrowseQuery>,
) -> Response {
    match api
        .discovery
        .browse_root(&id, &query.path, query.cursor, query.limit)
    {
        Ok(result) => Json(result).into_response(),
        Err(err) => api_error(&err).into_response(),
    }
}

#[derive(Deserialize)]
struct DetectBody {
    root_id: String,
    #[serde(default)]
    relative_path: String,
}

async fn detect(State(api): State<ApiState>, ApiJson(body): ApiJson<DetectBody>) -> Response {
    match api
        .discovery
        .detect_project(&body.root_id, &body.relative_path)
    {
        Ok(result) => Json(result).into_response(),
        Err(err) => api_error(&err).into_response(),
    }
}
