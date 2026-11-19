//! Device and pairing management endpoints (host-only).
//!
//! GET    /api/v1/devices                 -> { devices: [...] }
//! POST   /api/v1/devices/{id}/revoke     -> { id, state: "revoked" }
//! GET    /api/v1/pairings                -> { pairings: [...] }
//! POST   /api/v1/pairings/{code}/approve -> { code, state: "approved" }
//! POST   /api/v1/pairings/{code}/reject  -> { code, state: "rejected" }
//
// These mutate pairing/device state and are host-only: only a loopback peer
// may call them, mirroring the existing `/pair/approve` and `/device/revoke`
// bootstrap handlers in `commands.rs`.

use axum::extract::{Request, State};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use runtime_core::audit::AuditEventType;
use runtime_core::error::Error;
use runtime_core::types::DeviceId;
use runtime_identity::IdentityService;
use uuid::Uuid;

use super::{api_error, audit_event, session_device, ApiState};
use crate::commands::{AppState, is_host_peer, peer_ip};

pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/devices", get(list_devices))
        .route("/devices/{id}/revoke", post(revoke_device))
        .route("/pairings", get(list_pairings))
        .route("/pairings/{code}/approve", post(approve_pairing))
        .route("/pairings/{code}/reject", post(reject_pairing))
}

/// Refuse the request unless the peer is the local host. Returns the
/// forbidden response when the peer is remote, so callers can early-return.
fn require_host(req: &Request) -> Result<(), Response> {
    if !is_host_peer(peer_ip(req)) {
        Err(api_error(
            &Error::PermissionDenied("this endpoint is host-only".into()),
        )
        .into_response())
    } else {
        Ok(())
    }
}

/// The `{id}`/`{code}` segment of `/devices/{id}/revoke` or
/// `/pairings/{code}/approve|reject`.
fn segment_from_uri(req: &Request) -> Option<String> {
    req.uri().path().split('/').nth(2).map(str::to_owned)
}

async fn list_devices(State(state): State<AppState>, req: Request) -> Response {
    let api = &state.api;
    if let Err(response) = require_host(&req) {
        return response;
    }
    let devices = match api.identity.list_devices().await {
        Ok(devices) => devices,
        Err(err) => return api_error(&err).into_response(),
    };
    Json(serde_json::json!({ "devices": devices })).into_response()
}

async fn revoke_device(State(state): State<AppState>, req: Request) -> Response {
    let api = &state.api;
    if let Err(response) = require_host(&req) {
        return response;
    }
    let id = match segment_from_uri(&req) {
        Some(id) => id,
        None => {
            return api_error(&Error::Validation("missing device id".into()))
                .into_response()
        }
    };
    let device_id = match Uuid::parse_str(&id) {
        Ok(uuid) => DeviceId(uuid),
        Err(_) => {
            return api_error(&Error::Validation("device id must be a UUID".into()))
                .into_response()
        }
    };
    let audit_id = device_id.to_string();
    match api.identity.revoke_device(device_id).await {
        Ok(()) => {
            audit_event(&api, AuditEventType::DeviceRevoked, None, Some(audit_id)).await;
            Json(serde_json::json!({ "id": id, "state": "revoked" })).into_response()
        }
        Err(err) => api_error(&err).into_response(),
    }
}

async fn list_pairings(State(state): State<AppState>, req: Request) -> Response {
    let api = &state.api;
    if let Err(response) = require_host(&req) {
        return response;
    }
    let pairings = match api.identity.list_pairings().await {
        Ok(pairings) => pairings,
        Err(err) => return api_error(&err).into_response(),
    };
    Json(serde_json::json!({ "pairings": pairings })).into_response()
}

async fn approve_pairing(State(state): State<AppState>, req: Request) -> Response {
    let api = &state.api;
    if let Err(response) = require_host(&req) {
        return response;
    }
    let code = match segment_from_uri(&req) {
        Some(code) => code,
        None => {
            return api_error(&Error::Validation("missing pairing code".into()))
                .into_response()
        }
    };
    match api.identity.approve_pairing(code.clone()).await {
        Ok(device_id) => {
            audit_event(
                api,
                AuditEventType::DevicePaired,
                None,
                Some(format!("pairing code {code} -> device {device_id}")),
            )
            .await;
            Json(serde_json::json!({
                "code": code,
                "state": "approved",
                "device_id": device_id,
            }))
            .into_response()
        }
        Err(err) => api_error(&err).into_response(),
    }
}

async fn reject_pairing(State(state): State<AppState>, req: Request) -> Response {
    let api = &state.api;
    if let Err(response) = require_host(&req) {
        return response;
    }
    let code = match segment_from_uri(&req) {
        Some(code) => code,
        None => {
            return api_error(&Error::Validation("missing pairing code".into()))
                .into_response()
        }
    };
    match api.identity.reject_pairing(code.clone()).await {
        Ok(()) => {
            audit_event(
                api,
                AuditEventType::ApprovalRejected,
                None,
                Some(format!("pairing code {code} rejected")),
            )
            .await;
            Json(serde_json::json!({ "code": code, "state": "rejected" })).into_response()
        }
        Err(err) => api_error(&err).into_response(),
    }
}
