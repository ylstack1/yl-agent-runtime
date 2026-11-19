//! Static `/ui` assets, compiled into the binary. There is no dynamic path
//! join here, so a request can never read a file outside the three assets.

use axum::http::header;
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::Router;

use crate::commands::AppState;

pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/ui", get(index))
        .route("/ui/", get(index))
        .route("/ui/app.js", get(script))
        .route("/ui/app.css", get(styles))
}

async fn index() -> Response {
    (
        [(header::CONTENT_TYPE, "text/html; charset=utf-8")],
        include_str!("../ui/index.html"),
    )
        .into_response()
}

async fn script() -> Response {
    (
        [(header::CONTENT_TYPE, "text/javascript; charset=utf-8")],
        include_str!("../ui/app.js"),
    )
        .into_response()
}

async fn styles() -> Response {
    (
        [(header::CONTENT_TYPE, "text/css; charset=utf-8")],
        include_str!("../ui/app.css"),
    )
        .into_response()
}
