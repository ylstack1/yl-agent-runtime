//! Versioned HTTP management API (`/api/v1`) and the web console (`/ui`).
//!
//! Handlers only authenticate (middleware), validate JSON, and call one domain
//! service method. Filesystem authorization stays inside `WorkspaceServiceImpl`,
//! `DiscoveryService` and `PolicyEngine`.

pub mod device;
pub mod discovery;
pub mod ui;
pub mod workspaces;

use axum::extract::{FromRequest, Request, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::{Json, Router};
use runtime_approval::ApprovalBroker;
use runtime_audit::AuditService;
use runtime_core::error::Error as CoreError;
use runtime_identity::IdentityServiceImpl;
use runtime_workspace::discovery::DiscoveryService;
use runtime_workspace::WorkspaceServiceImpl;
use serde::de::DeserializeOwned;
use serde_json::json;
use std::sync::Arc;

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

#[cfg(test)]
mod tests;
