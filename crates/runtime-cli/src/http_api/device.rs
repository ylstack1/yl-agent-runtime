//! `GET /api/v1/device` — runtime facts for the console header.

use super::{ApiState, DeviceFacts};
use axum::extract::State;
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde_json::json;

pub async fn get_device(State(api): State<ApiState>) -> Response {
    let facts: &DeviceFacts = &api.facts;
    let workspaces = api.fs.list_workspaces().len();
    let roots: Vec<serde_json::Value> = api
        .discovery
        .list_roots()
        .into_iter()
        .map(|root| {
            json!({
                "id": root.id,
                "label": root.label,
                "enabled": root.enabled,
            })
        })
        .collect();
    Json(json!({
        "version": facts.version,
        "os": facts.os,
        "arch": facts.arch,
        "yolo": facts.yolo,
        "pairing_required": facts.pairing_required,
        "tls": {
            "enabled": facts.tls_enabled,
            "fingerprint": facts.cert_fingerprint,
            "urls": facts.lan_urls,
        },
        "workspace_count": workspaces,
        "discovery_roots": roots,
    }))
    .into_response()
}
