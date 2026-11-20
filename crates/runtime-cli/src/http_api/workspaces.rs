//! Workspace registry endpoints.
//!
//! Every response is built from `root_id` + a `/`-separated relative path;
//! absolute host paths never leave this module. The path a client sends is
//! resolved and contained by `DiscoveryService` first, then the workspace
//! service's own discovery/permission checks run unchanged.

use axum::extract::{Path as UrlPath, State};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, patch, post};
use axum::{Json, Router};
use serde::Deserialize;
use serde_json::{json, Value};
use std::path::{Path, PathBuf};

use runtime_core::error::Error;
use runtime_core::traits::WorkspaceService;
use runtime_core::types::{DeviceId, ExecutionProfile, ProjectId};
use runtime_workspace::discovery::ConfiguredRoot;
use runtime_workspace::service::{RegisteredWorkspace, WorkspaceSettings};
use uuid::Uuid;

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
            get(get_one).patch(edit).delete(unregister),
        )
        .route("/workspaces/{id}/clone", post(clone))
        .route(
            "/workspaces/{id}/settings",
            get(get_settings).patch(set_settings),
        )
        .route("/workspaces/{id}/devices", get(list_devices))
        .route(
            "/workspaces/{id}/devices/{device_id}",
            post(bind_device).delete(unbind_device),
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
        "tags": workspace.tags,
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
    let path = if body.root_id.is_empty() || body.root_id == "default" {
        // Auto-detect: treat relative_path as an absolute path and find the
        // discovery root that contains it.
        let abs = PathBuf::from(&body.relative_path);
        let canonical = abs.canonicalize().unwrap_or_else(|_| abs.clone());
        let roots = api.discovery.list_roots();
        let found = roots.iter().find(|root| {
            canonical.starts_with(&root.canonical_path)
        });
        match found {
            Some(root) => {
                let rel = canonical
                    .strip_prefix(&root.canonical_path)
                    .unwrap_or(&canonical)
                    .to_string_lossy()
                    .to_string();
                match resolve_root_path(&api, &root.id, &rel) {
                    Ok(p) => p,
                    Err(err) => return api_error(&err).into_response(),
                }
            }
            None => {
                return api_error(&Error::Validation(format!(
                    "Path {:?} is not within any enabled discovery root", abs
                )))
                .into_response()
            }
        }
    } else {
        match resolve_root_path(&api, &body.root_id, &body.relative_path) {
            Ok(p) => p,
            Err(err) => return api_error(&err).into_response(),
        }
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

#[derive(Deserialize)]
struct EditBody {
    #[serde(default)]
    display_name: Option<String>,
    #[serde(default)]
    profile: Option<String>,
    #[serde(default)]
    tags: Option<Vec<String>>,
}

async fn edit(State(api): State<ApiState>, UrlPath(id): UrlPath<String>, ApiJson(body): ApiJson<EditBody>) -> Response {
    let project_id = match ProjectId::parse(&id) {
        Some(project_id) => project_id,
        None => return api_error(&Error::Validation("workspace id must be a UUID".into())).into_response(),
    };
    let mut workspace = match api.fs.get_workspace(project_id) {
        Ok(w) => w,
        Err(err) => return api_error(&err).into_response(),
    };
    if let Some(name) = body.display_name {
        workspace.display_name = name;
    }
    if let Some(profile) = body.profile.and_then(|p| parse_profile(Some(p)).ok()) {
        workspace.profile = profile;
    }
    if let Some(tags) = body.tags {
        workspace.tags = tags;
    }
    // Persist the updated workspace record.
    match api.fs.update_workspace(project_id, workspace.clone()) {
        Ok(()) => {}
        Err(err) => return api_error(&err).into_response(),
    }
    let roots = api.discovery.list_roots();
    Json(sanitize(&workspace, &roots)).into_response()
}

#[derive(Deserialize)]
struct CloneBody {
    git_url: String,
    #[serde(default)]
    into_subdir: String,
}

async fn clone(State(api): State<ApiState>, UrlPath(id): UrlPath<String>, ApiJson(body): ApiJson<CloneBody>) -> Response {
    let project_id = match ProjectId::parse(&id) {
        Some(project_id) => project_id,
        None => return api_error(&Error::Validation("workspace id must be a UUID".into())).into_response(),
    };
    let into_subdir = if body.into_subdir.is_empty() {
        format!("clone-{}", &id.to_string()[..8])
    } else {
        body.into_subdir
    };
    match api.fs.clone_workspace(&project_id, &body.git_url, &into_subdir).await {
        Ok(new_id) => Json(json!({
            "workspace_id": new_id,
            "state": "cloned",
            "into_subdir": into_subdir,
        }))
        .into_response(),
        Err(err) => api_error(&err).into_response(),
    }
}

#[derive(Deserialize)]
struct SettingsBody {
    #[serde(default)]
    allow: Option<Vec<String>>,
    #[serde(default)]
    deny: Option<Vec<String>>,
    #[serde(default)]
    framework: Option<String>,
    #[serde(default)]
    toolchain: Option<String>,
    #[serde(default)]
    other: Option<serde_json::Value>,
}

async fn get_settings(State(api): State<ApiState>, UrlPath(id): UrlPath<String>) -> Response {
    let project_id = match ProjectId::parse(&id) {
        Some(project_id) => project_id,
        None => return api_error(&Error::Validation("workspace id must be a UUID".into())).into_response(),
    };
    match api.fs.get_workspace_settings(&project_id) {
        Ok(settings) => Json(settings).into_response(),
        Err(err) => api_error(&err).into_response(),
    }
}

async fn set_settings(State(api): State<ApiState>, UrlPath(id): UrlPath<String>, ApiJson(body): ApiJson<SettingsBody>) -> Response {
    let project_id = match ProjectId::parse(&id) {
        Some(project_id) => project_id,
        None => return api_error(&Error::Validation("workspace id must be a UUID".into())).into_response(),
    };
    let mut settings = match api.fs.get_workspace_settings(&project_id) {
        Ok(s) => s,
        Err(err) => return api_error(&err).into_response(),
    };
    if let Some(allow) = body.allow { settings.allow = allow; }
    if let Some(deny) = body.deny { settings.deny = deny; }
    if let Some(framework) = body.framework { settings.framework = Some(framework); }
    if let Some(toolchain) = body.toolchain { settings.toolchain = Some(toolchain); }
    if let Some(other) = body.other { settings.other = other; }
    match api.fs.set_workspace_settings(&project_id, &settings) {
        Ok(()) => Json(settings).into_response(),
        Err(err) => api_error(&err).into_response(),
    }
}

async fn list_devices(State(api): State<ApiState>, UrlPath(id): UrlPath<String>) -> Response {
    let project_id = match ProjectId::parse(&id) {
        Some(project_id) => project_id,
        None => return api_error(&Error::Validation("workspace id must be a UUID".into())).into_response(),
    };
    match api.fs.list_workspace_devices(&project_id) {
        Ok(device_ids) => Json(json!({ "device_ids": device_ids })).into_response(),
        Err(err) => api_error(&err).into_response(),
    }
}

async fn bind_device(State(api): State<ApiState>, UrlPath((id, device_id)): UrlPath<(String, String)>) -> Response {
    let project_id = match ProjectId::parse(&id) {
        Some(project_id) => project_id,
        None => return api_error(&Error::Validation("workspace id must be a UUID".into())).into_response(),
    };
    let device_uuid = match uuid::Uuid::parse_str(&device_id) {
        Ok(u) => u,
        Err(_) => return api_error(&Error::Validation("device id must be a UUID".into())).into_response(),
    };
    match api.fs.bind_device_to_workspace(&project_id, DeviceId(device_uuid)) {
        Ok(()) => Json(json!({ "state": "bound" })).into_response(),
        Err(err) => api_error(&err).into_response(),
    }
}

async fn unbind_device(State(api): State<ApiState>, UrlPath((id, device_id)): UrlPath<(String, String)>) -> Response {
    let project_id = match ProjectId::parse(&id) {
        Some(project_id) => project_id,
        None => return api_error(&Error::Validation("workspace id must be a UUID".into())).into_response(),
    };
    let device_uuid = match uuid::Uuid::parse_str(&device_id) {
        Ok(u) => u,
        Err(_) => return api_error(&Error::Validation("device id must be a UUID".into())).into_response(),
    };
    match api.fs.unbind_device_from_workspace(&project_id, &DeviceId(device_uuid)) {
        Ok(()) => Json(json!({ "state": "unbound" })).into_response(),
        Err(err) => api_error(&err).into_response(),
    }
}
