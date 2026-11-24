//! Device and pairing management endpoints (host-only).
//!
//! GET    /api/v1/devices                 -> { devices: [...] }
//! POST   /api/v1/devices                 -> { id, private_key, label, ... }
//! GET    /api/v1/devices/{id}            -> { id, label, public_key, fingerprint, ... }
//! DELETE /api/v1/devices/{id}            -> { id, state: "deleted" }
//! POST   /api/v1/devices/{id}/revoke     -> { id, state: "revoked" }
//! GET    /api/v1/pairings                -> { pairings: [...] }
//! POST   /api/v1/pairings/{code}/approve -> { code, state: "approved" }
//! POST   /api/v1/pairings/{code}/reject  -> { code, state: "rejected" }
//
// These mutate pairing/device state and are host-only: only a loopback peer
// may call them, mirroring the existing `/pair/approve` and `/device/revoke`
// bootstrap handlers in `commands.rs`.

use axum::extract::{ConnectInfo, Path as UrlPath, Request, State};
use axum::response::{IntoResponse, Response};
use axum::routing::{delete, get, post};
use axum::{Json, Router};
use runtime_core::audit::AuditEventType;
use runtime_core::error::Error;
use runtime_core::types::DeviceId;
use runtime_identity::IdentityService;
use std::net::SocketAddr;
use uuid::Uuid;

use super::{api_error, ApiJson, ApiState, audit_event};
use crate::commands::{AppState, is_host_peer, peer_ip};

/// Request body for creating a device.
#[derive(serde::Deserialize)]
struct CreateDeviceBody {
    name: String,
    #[serde(default)]
    device_id: Option<String>,
    #[serde(default)]
    label: Option<String>,
}

pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/devices", get(list_devices).post(create_device))
        .route("/devices/{id}", get(get_device))
        .route("/devices/{id}", delete(delete_device))
        .route("/devices/{id}/revoke", post(revoke_device))
        .route("/pairings", get(list_pairings))
        .route("/pairings/{code}/approve", post(approve_pairing))
        .route("/pairings/{code}/reject", post(reject_pairing))
}

/// Refuse the request unless the peer is the local host.
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

/// List all registered devices.
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

/// Create a new device with a server-generated keypair.
async fn create_device(
    State(state): State<AppState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    ApiJson(body): ApiJson<CreateDeviceBody>,
) -> Response {
    let api = &state.api;
    if !is_host_peer(Some(addr.ip())) {
        return api_error(
            &Error::PermissionDenied("this endpoint is host-only".into()),
        )
        .into_response();
    }
    let device_id_opt = body.device_id.as_deref().and_then(|s| Uuid::parse_str(s).ok());
    let device_id_param = device_id_opt.map(DeviceId).unwrap_or_else(DeviceId::new);
    match api.identity.create_device(body.name.clone(), Some(device_id_param)).await {
        Ok((device_id, private_key)) => {
            Json(serde_json::json!({
                "id": device_id,
                "label": body.label.unwrap_or_default(),
                "private_key": base64::encode(&private_key),
                "state": "pending",
            })).into_response()
        }
        Err(err) => api_error(&err).into_response(),
    }
}

/// Get device details by ID.
async fn get_device(State(state): State<AppState>, UrlPath(id): UrlPath<String>, req: Request) -> Response {
    let api = &state.api;
    if let Err(response) = require_host(&req) {
        return response;
    }
    let device_id = match Uuid::parse_str(&id) {
        Ok(uuid) => DeviceId(uuid),
        Err(_) => {
            return api_error(&Error::Validation("device id must be a UUID".into()))
                .into_response()
        }
    };
    match api.identity.get_device(device_id).await {
        Ok(device) => Json(serde_json::json!({
            "id": device.id,
            "label": device.name,
            "fingerprint": device.fingerprint,
            "created_at": device.created_at,
            "is_active": device.is_active,
            "is_revoked": device.is_revoked,
            "state": if device.is_revoked { "revoked" } else if device.is_active { "paired" } else { "pending" },
        })).into_response(),
        Err(err) => api_error(&err).into_response(),
    }
}

/// Delete a device.
async fn delete_device(State(state): State<AppState>, UrlPath(id): UrlPath<String>, req: Request) -> Response {
    let api = &state.api;
    if let Err(response) = require_host(&req) {
        return response;
    }
    let device_id = match Uuid::parse_str(&id) {
        Ok(uuid) => DeviceId(uuid),
        Err(_) => {
            return api_error(&Error::Validation("device id must be a UUID".into()))
                .into_response()
        }
    };
    match api.identity.revoke_device(device_id).await {
        Ok(()) => {
            audit_event(&api, AuditEventType::DeviceRevoked, None, Some(device_id.to_string())).await;
            Json(serde_json::json!({ "id": id, "state": "deleted" })).into_response()
        }
        Err(err) => api_error(&err).into_response(),
    }
}

/// Revoke a device (POST /devices/{id}/revoke).
async fn revoke_device(State(state): State<AppState>, UrlPath(id): UrlPath<String>, ConnectInfo(addr): ConnectInfo<SocketAddr>) -> Response {
    let api = &state.api;
    if !is_host_peer(Some(addr.ip())) {
        return api_error(
            &Error::PermissionDenied("this endpoint is host-only".into()),
        )
        .into_response();
    }
    let device_id = match Uuid::parse_str(&id) {
        Ok(uuid) => DeviceId(uuid),
        Err(_) => {
            return api_error(&Error::Validation("device id must be a UUID".into()))
                .into_response()
        }
    };
    match api.identity.revoke_device(device_id).await {
        Ok(()) => {
            audit_event(&api, AuditEventType::DeviceRevoked, None, Some(device_id.to_string())).await;
            Json(serde_json::json!({ "id": id, "state": "revoked" })).into_response()
        }
        Err(err) => api_error(&err).into_response(),
    }
}

/// List all registered pairs.
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

/// Approve a pending pairing request.
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
            })).into_response()
        }
        Err(err) => api_error(&err).into_response(),
    }
}

/// Reject a pairing request.
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
