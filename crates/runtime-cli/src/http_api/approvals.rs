//! Approval management endpoints.
//!
//! GET    /api/v1/approvals        -> { approvals: [...] }
//! POST   /api/v1/approvals/{id}/approve   -> { id, state: "approved" }
//! POST   /api/v1/approvals/{id}/reject    -> { id, state: "rejected" }
//
// The approval broker is the source of truth; these handlers only translate
// HTTP into `ApprovalBroker` calls and write audit events. The device id is
// resolved inline from the bearer token (mirroring `pair_authenticate` in
// `commands.rs`) because wrapping `IdentityService::validate_session` in
// another async fn breaks axum's `Handler` Send-future bound.

use axum::extract::{Request, State};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use runtime_core::audit::AuditEventType;
use runtime_core::error::Error;
use runtime_core::types::ApprovalId;
use runtime_approval::ApprovalBroker;
use runtime_identity::IdentityService;
use uuid::Uuid;

use super::{api_bearer_token, api_error, audit_event, ApiState};
use crate::commands::AppState;

pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/approvals", get(list_approvals))
        .route("/approvals/{id}/approve", post(approve_approval))
        .route("/approvals/{id}/reject", post(reject_approval))
}

/// List pending (not-yet-decided) approval requests.
async fn list_approvals(State(state): State<AppState>) -> Response {
    let api = &state.api;
    let approvals = api.approvals.list_pending().await;
    Json(serde_json::json!({ "approvals": approvals })).into_response()
}

fn parse_approval_id(id: &str) -> Option<ApprovalId> {
    Uuid::parse_str(id).ok().map(ApprovalId)
}

/// The `{id}` segment of `/approvals/{id}/approve|reject`.
fn id_from_uri(req: &Request) -> Option<String> {
    req.uri().path().split('/').nth(2).map(str::to_owned)
}

async fn approve_approval(State(state): State<AppState>, req: Request) -> Response {
    let api = &state.api;
    let id = match id_from_uri(&req) {
        Some(id) => id,
        None => {
            return api_error(&Error::Validation("missing approval id".into()))
                .into_response()
        }
    };
    let approval_id = match parse_approval_id(&id) {
        Some(id) => id,
        None => {
            return api_error(&Error::Validation("approval id must be a UUID".into()))
                .into_response()
        }
    };
    let device_id = match api_bearer_token(&req) {
        Some(token) => api.identity.validate_session(token).await.ok(),
        None => None,
    };
    match api.approvals.approve(approval_id).await {
        Ok(()) => {
            audit_event(
                api,
                AuditEventType::ApprovalGranted,
                device_id,
                Some(id.clone()),
            )
            .await;
            Json(serde_json::json!({ "id": id, "state": "approved" })).into_response()
        }
        Err(err) => api_error(&err).into_response(),
    }
}

async fn reject_approval(State(state): State<AppState>, req: Request) -> Response {
    let api = &state.api;
    let id = match id_from_uri(&req) {
        Some(id) => id,
        None => {
            return api_error(&Error::Validation("missing approval id".into()))
                .into_response()
        }
    };
    let approval_id = match parse_approval_id(&id) {
        Some(id) => id,
        None => {
            return api_error(&Error::Validation("approval id must be a UUID".into()))
                .into_response()
        }
    };
    let device_id = match api_bearer_token(&req) {
        Some(token) => api.identity.validate_session(token).await.ok(),
        None => None,
    };
    match api.approvals.reject(approval_id, String::new()).await {
        Ok(()) => {
            audit_event(
                api,
                AuditEventType::ApprovalRejected,
                device_id,
                Some(id.clone()),
            )
            .await;
            Json(serde_json::json!({ "id": id, "state": "rejected" })).into_response()
        }
        Err(err) => api_error(&err).into_response(),
    }
}
