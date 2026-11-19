//! Workspace registry endpoints.
//!
//! Every response is built from `root_id` + a `/`-separated relative path;
//! absolute host paths never leave this module. The path a client sends is
//! resolved and contained by `DiscoveryService` first, then the workspace
//! service's own discovery/permission checks run unchanged.

use axum::extract::{Path as UrlPath, State};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use serde::Deserialize;
use serde_json::{json, Value};
use std::path::Path;

use runtime_core::error::Error;
use runtime_core::traits::WorkspaceService;
use runtime_core::types::{ExecutionProfile, ProjectId};
use runtime_workspace::discovery::ConfiguredRoot;
use runtime_workspace::service::RegisteredWorkspace;

use super::discovery::resolve_root_path;
use super::{api_error, ApiJson, ApiState};
use crate::commands::AppState;

pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/workspaces", get(list))
        .route("/workspaces/register", post(register))
        .route("/workspaces/create", post(create))
        .route(
            "/workspaces/{id}",
            get(get_one).delete(unregister),
        )
}

fn strip_verbatim(path: &Path) -> String {
    let text = path.to_string_lossy().to_string();
    match text.strip_prefix("\\\\?\\") {
        Some(rest) => rest.to_string(),
        None => text,
    }
}

fn parts(path: &Path) -> Vec<String> {
    Path::new(&strip_verbatim(path))
        .components()
        .map(|component| component.as_os_str().to_string_lossy().to_string())
        .collect()
}

/// `path` relative to `root`, `/`-separated, or `None` when it is not under
/// `root`. Comparison ignores a verbatim prefix and (on Windows) case.
fn relative_under(root: &Path, path: &Path) -> Option<String> {
    let root_parts = parts(root);
    let path_parts = parts(path);
    if root_parts.len() > path_parts.len() {
        return None;
    }
    for (left, right) in root_parts.iter().zip(path_parts.iter()) {
        let equal = if cfg!(windows) {
            left.eq_ignore_ascii_case(right)
        } else {
            left == right
        };
        if !equal {
            return None;
        }
    }
    Some(path_parts[root_parts.len()..].join("/"))
}

/// Longest matching root wins, so nested roots report the closest boundary.
fn locate(roots: &[ConfiguredRoot], path: &Path) -> Option<(String, String)> {
    roots
        .iter()
        .filter_map(|root| {
            relative_under(&root.canonical_path, path).map(|relative| {
                (root.id.clone(), relative, parts(&root.canonical_path).len())
            })
        })
        .max_by_key(|(_, _, depth)| *depth)
        .map(|(id, relative, _)| (id, relative))
}

fn sanitize(workspace: &RegisteredWorkspace, roots: &[ConfiguredRoot]) -> Value {
    let (root_id, relative_path) = match locate(roots, &workspace.root) {
        Some((id, relative)) => (Value::String(id), Value::String(relative)),
        None => (Value::Null, Value::Null),
    };
    json!({
        "id": workspace.id,
        "display_name": workspace.display_name,
        "profile": workspace.profile,
        "origin": workspace.origin,
        "registered_at": workspace.registered_at,
        "root_id": root_id,
        "relative_path": relative_path,
        // Console registrations are in the service registry but not in the
        // MCP server's startup snapshot; agents see them after a restart.
        "available_to_agents_after_restart": true,
    })
}

async fn list(State(api): State<ApiState>) -> Response {
    let roots = api.discovery.list_roots();
    let workspaces: Vec<Value> = api
        .fs
        .list_workspaces()
        .iter()
        .map(|record| {
            // `list_workspaces` returns display records; the sanitizer needs the
            // full record, and an id lookup is a hash map read either way.
            match api.fs.get_workspace(record.id) {
                Ok(full) => sanitize(&full, &roots),
                Err(_) => json!({ "id": record.id, "root_id": null, "relative_path": null }),
            }
        })
        .collect();
    Json(json!({ "workspaces": workspaces })).into_response()
}

async fn get_one(State(api): State<ApiState>, UrlPath(id): UrlPath<String>) -> Response {
    let project_id = match ProjectId::parse(&id) {
        Some(project_id) => project_id,
        None => return api_error(&Error::Validation("workspace id must be a UUID".into()))
            .into_response(),
    };
    match api.fs.get_workspace(project_id) {
        Ok(workspace) => {
            let roots = api.discovery.list_roots();
            Json(sanitize(&workspace, &roots)).into_response()
        }
        Err(err) => api_error(&err).into_response(),
    }
}

fn parse_profile(profile: Option<String>) -> Result<ExecutionProfile, Error> {
    match profile.as_deref().map(str::to_ascii_lowercase).as_deref() {
        None | Some("development") => Ok(ExecutionProfile::Development),
        Some("inspect") => Ok(ExecutionProfile::Inspect),
        Some("edit") => Ok(ExecutionProfile::Edit),
        Some("sandboxed-development") => Ok(ExecutionProfile::SandboxedDevelopment),
        Some("elevated-one-shot") => Ok(ExecutionProfile::ElevatedOneShot),
        Some(other) => Err(Error::Validation(format!("Unknown profile: {other}"))),
    }
}

#[derive(Deserialize)]
struct RegisterBody {
    root_id: String,
    #[serde(default)]
    relative_path: String,
    #[serde(default)]
    profile: Option<String>,
}

async fn register(State(api): State<ApiState>, ApiJson(body): ApiJson<RegisterBody>) -> Response {
    let profile = match parse_profile(body.profile) {
        Ok(profile) => profile,
        Err(err) => return api_error(&err).into_response(),
    };
    let path = match resolve_root_path(&api, &body.root_id, &body.relative_path) {
        Ok(path) => path,
        Err(err) => return api_error(&err).into_response(),
    };
    let already = path
        .canonicalize()
        .ok()
        .and_then(|canonical| api.fs.find_by_root(&canonical))
        .is_some();
    match api.fs.register(path, profile).await {
        Ok(id) => Json(json!({
            "workspace_id": id,
            "already_registered": already,
            "available_to_agents_after_restart": true,
        }))
        .into_response(),
        Err(err) => api_error(&err).into_response(),
    }
}

#[derive(Deserialize)]
struct CreateBody {
    root_id: String,
    #[serde(default)]
    relative_path: String,
    name: String,
    #[serde(default)]
    profile: Option<String>,
    #[serde(default)]
    subdirs: Option<Vec<String>>,
}

async fn create(State(api): State<ApiState>, ApiJson(body): ApiJson<CreateBody>) -> Response {
    let profile = match parse_profile(body.profile) {
        Ok(profile) => profile,
        Err(err) => return api_error(&err).into_response(),
    };
    let parent = match resolve_root_path(&api, &body.root_id, &body.relative_path) {
        Ok(path) => path,
        Err(err) => return api_error(&err).into_response(),
    };
    let subdirs = body.subdirs.unwrap_or_default();
    match api
        .fs
        .create_workspace(&parent, &body.name, profile, &subdirs)
        .await
    {
        Ok(id) => Json(json!({
            "workspace_id": id,
            "already_registered": false,
            "available_to_agents_after_restart": true,
        }))
        .into_response(),
        Err(err) => api_error(&err).into_response(),
    }
}

async fn unregister(State(api): State<ApiState>, UrlPath(id): UrlPath<String>) -> Response {
    let project_id = match ProjectId::parse(&id) {
        Some(project_id) => project_id,
        None => {
            return api_error(&Error::Validation("workspace id must be a UUID".into()))
                .into_response()
        }
    };
    match api.fs.unregister(project_id).await {
        Ok(()) => Json(json!({ "workspace_id": project_id, "state": "unregistered" }))
            .into_response(),
        Err(err) => api_error(&err).into_response(),
    }
}
