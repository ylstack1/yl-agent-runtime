//! Versioned HTTP management API (`/api/v1`) and the web console (`/ui`).
//!
//! Handlers only authenticate (middleware), validate JSON, and call one domain
//! service method. Filesystem authorization stays inside `WorkspaceServiceImpl`,
//! `DiscoveryService` and `PolicyEngine`.

pub mod device;
pub mod discovery;
pub mod ui;
pub mod workspaces;
pub mod approvals;
pub mod devices;

use axum::extract::{FromRequest, Request, State};
use axum::http::{header, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::{Json, Router};
use runtime_approval::ApprovalBroker;
use runtime_audit::AuditService;
use runtime_core::audit::{AuditEvent, AuditEventType};
use runtime_core::error::Error as CoreError;
use runtime_core::types::DeviceId;
use runtime_identity::{IdentityService, IdentityServiceImpl};
use runtime_workspace::discovery::DiscoveryService;
use runtime_workspace::WorkspaceServiceImpl;
use serde::de::DeserializeOwned;
use serde_json::json;
use std::sync::Arc;
use tracing::warn;

use crate::commands::AppState;

/// JSON body extractor for API handlers. Axum's own rejection is plain text;
/// the console expects `{"error": "..."}` for every failure, so map it here.
pub struct ApiJson<T>(pub T);

impl<T, S> FromRequest<S> for ApiJson<T>
where
    T: DeserializeOwned,
    S: Send + Sync,
{
    type Rejection = Response;

    async fn from_request(req: Request, state: &S) -> Result<Self, Self::Rejection> {
        match Json::<T>::from_request(req, state).await {
            Ok(Json(value)) => Ok(ApiJson(value)),
            Err(rejection) => {
                let status = rejection.status();
                let message = rejection.body_text();
                Err((status, Json(json!({ "error": message }))).into_response())
            }
        }
    }
}

/// Facts about this runtime instance, shown in the console header.
#[derive(Clone, Debug)]
pub struct DeviceFacts {
    pub version: &'static str,
    pub os: &'static str,
    pub arch: &'static str,
    pub yolo: bool,
    pub pairing_required: bool,
    pub tls_enabled: bool,
    pub cert_fingerprint: Option<String>,
    pub lan_urls: Vec<String>,
}

/// Services shared by every API handler. Nothing here is protocol-specific.
#[derive(Clone)]
pub struct ApiState {
    pub fs: Arc<WorkspaceServiceImpl>,
    pub discovery: Arc<DiscoveryService>,
    pub approvals: Arc<dyn ApprovalBroker>,
    pub identity: Arc<IdentityServiceImpl>,
    pub audit: Arc<dyn AuditService>,
    pub facts: DeviceFacts,
}

/// The API version prefix is applied by the caller (`nest("/api/v1", …)`).
pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/device", get(device::get_device))
        .merge(discovery::routes())
        .merge(workspaces::routes())
        .merge(approvals::routes())
        .merge(devices::routes())
}

/// Map a service error to an HTTP status and the `{"error": "..."}` body every
/// endpoint uses. Service text passes through: root misconfiguration is only
/// diagnosable from it.
pub fn api_error(err: &CoreError) -> (StatusCode, Json<serde_json::Value>) {
    let status = match err {
        CoreError::Validation(_) => StatusCode::BAD_REQUEST,
        CoreError::PermissionDenied(_)
        | CoreError::PathNotAllowed(_)
        | CoreError::PathEscape(_) => StatusCode::FORBIDDEN,
        CoreError::WorkspaceNotFound(_)
        | CoreError::DeviceNotFound(_)
        | CoreError::ProcessNotFound(_)
        | CoreError::AgentNotFound(_) => StatusCode::NOT_FOUND,
        _ => StatusCode::INTERNAL_SERVER_ERROR,
    };
    (status, Json(json!({ "error": err.to_string() })))
}

/// Build the full backend error response for a service failure.
pub fn error_response(err: &CoreError) -> Response {
    api_error(err).into_response()
}

/// Bearer token from the `Authorization` header, if present.
pub(crate) fn api_bearer_token(req: &Request) -> Option<String> {
    req.headers()
        .get(header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Bearer "))
        .map(str::to_owned)
}

/// Resolve the device id behind an authenticated session. Loopback peers
/// present no token and map to `None` — they are the host itself.
pub(crate) async fn session_device(req: &Request, api: &ApiState) -> Option<DeviceId> {
    let token = api_bearer_token(req)?;
    api.identity.validate_session(token).await.ok()
}

/// Best-effort audit record: never fails the request that triggered it.
pub(crate) async fn audit_event(
    api: &ApiState,
    event_type: AuditEventType,
    device_id: Option<DeviceId>,
    resource: Option<String>,
) {
    let mut event = AuditEvent::new(event_type);
    if let Some(device_id) = device_id {
        event = event.with_device(device_id);
    }
    if let Some(resource) = resource {
        event = event.with_resource(resource);
    }
    if let Err(e) = api.audit.record(event).await {
        warn!("audit event {event_type:?} failed: {e}");
    }
}

#[cfg(test)]
mod tests;
