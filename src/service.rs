//! `SearchRegistriesByName` on the module's REST route and in its JSON, so a client moves over by
//! changing the host it calls.

use std::collections::HashMap;
use std::sync::Arc;

use anyhow::{Context, Result};
use axum::extract::{Query, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::{Json, Router};
use serde_json::{json, Value};

use crate::contract::Registry;
use crate::index::{Index, Mode};
use crate::sync::Status;

pub const SEARCH_PATH: &str = "/NVNM-Chain/nvnmchain/anchoring/v1/registries/search";

/// What the routes read: the index, and how its sync is going.
#[derive(Clone)]
pub struct App {
    pub index: Arc<Index>,
    pub status: Arc<Status>,
}

/// `defaultPageLimit` and `maxPageLimit` in the module's `keeper/query.go`.
const DEFAULT_LIMIT: u64 = 50;
const MAX_LIMIT: u64 = 200;

/// Everything the module's `SearchRegistriesByName` took. A misspelt one is refused rather than
/// ignored: dropping `pagination.limt` would answer with a default page as if it were asked for.
const PARAMETERS: [&str; 7] = [
    "name",
    "mode",
    "pagination.key",
    "pagination.offset",
    "pagination.limit",
    "pagination.count_total",
    "pagination.reverse",
];

/// The gateway's error body: a gRPC status code, and what went wrong.
struct ApiError {
    status: StatusCode,
    code: u8,
    message: String,
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let body = json!({"code": self.code, "message": self.message, "details": []});
        (self.status, Json(body)).into_response()
    }
}

/// `codes.InvalidArgument`, which the gateway answers as a 400.
fn invalid(message: impl Into<String>) -> ApiError {
    ApiError {
        status: StatusCode::BAD_REQUEST,
        code: 3,
        message: message.into(),
    }
}

impl From<anyhow::Error> for ApiError {
    /// `codes.Internal`: the index failed, not the request.
    fn from(err: anyhow::Error) -> Self {
        ApiError {
            status: StatusCode::INTERNAL_SERVER_ERROR,
            code: 13,
            message: format!("{err:#}"),
        }
    }
}

pub fn router(app: App) -> Router {
    Router::new()
        .route("/health", get(health))
        .route(SEARCH_PATH, get(search))
        .with_state(app)
}

pub async fn serve(app: App, bind: &str) -> Result<()> {
    let listener = tokio::net::TcpListener::bind(bind)
        .await
        .with_context(|| format!("bind {bind}"))?;
    tracing::info!("serving on {bind}");
    axum::serve(listener, router(app)).await?;
    Ok(())
}

/// How far the index reaches, and how the last round of sync went. A 503 while the node cannot
/// be read: the index can only fall behind from there.
async fn health(State(app): State<App>) -> Result<Response, ApiError> {
    let round = app.status.round();
    let body = json!({
        "last_id": app.index.last_id()?,
        "synced_at": round.synced_at,
        "error": round.error,
    });
    let status = if round.error.is_some() {
        StatusCode::SERVICE_UNAVAILABLE
    } else {
        StatusCode::OK
    };
    Ok((status, Json(body)).into_response())
}

async fn search(
    State(app): State<App>,
    Query(params): Query<HashMap<String, String>>,
) -> Result<Json<Value>, ApiError> {
    if let Some(key) = params.keys().find(|k| !PARAMETERS.contains(&k.as_str())) {
        return Err(invalid(format!("unknown parameter {key}")));
    }
    let name = params.get("name").map(String::as_str).unwrap_or("");
    if name.is_empty() {
        return Err(invalid("name must be provided"));
    }
    let mode = match params.get("mode") {
        None => Mode::Exact,
        Some(value) => {
            Mode::parse(value).ok_or_else(|| invalid(format!("invalid mode {value}")))?
        }
    };
    // Only offset and limit are honoured, as in the module; the rest is taken and ignored.
    let number = |key: &str| -> Result<u64, ApiError> {
        params.get(key).map_or(Ok(0), |v| {
            v.trim()
                .parse()
                .map_err(|_| invalid(format!("{key}={v}: not a number")))
        })
    };
    let offset = number("pagination.offset")?;
    let limit = match number("pagination.limit")? {
        0 => DEFAULT_LIMIT,
        n => n.min(MAX_LIMIT),
    };

    let registries: Vec<Value> = app
        .index
        .search(mode, name, limit, offset)?
        .iter()
        .map(registry_json)
        .collect();
    // The module sets a `PageResponse` only when the request carried one, and the
    // gateway writes its defaults out.
    let pagination = params
        .keys()
        .any(|k| k.starts_with("pagination."))
        .then(|| json!({"next_key": null, "total": "0"}));
    Ok(Json(
        json!({"registries": registries, "pagination": pagination}),
    ))
}

/// A registry as the gateway wrote one: proto field names, and a `uint64` as a string.
fn registry_json(r: &Registry) -> Value {
    json!({
        "id": r.id.to_string(),
        "name": r.name,
        "description": r.description,
        "creator": r.creator,
        "created_at": r.createdAt,
        "metadata": r.metadata,
    })
}
