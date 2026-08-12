//! An HTTP surface over the projections.
//!
//! What the retired `registries(...)` and `records(...)` queries answered, read
//! from the log instead of from the module that no longer serves them.
//!
//! Read-through: every request queries tidx and nothing is kept here. A second
//! store over the same log is what an explorer already is, so materializing is a
//! decision to make against numbers later, not a shape to start with.
//!
//! `/records` answers at each record's newest version, because that is what the
//! chain keeps — one word per key. Earlier versions live in the log and want
//! their own endpoint rather than a field that could quietly be short.

use std::sync::Arc;

use anyhow::{Context, Result};
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::{Json, Router};
use serde_json::{json, Value};

use crate::config::Settings;
use crate::registry::{
    parse_records, parse_registries, parse_roles, registries_sql, roles_sql, REGISTRIES_KEY,
    ROLES_KEY, ROLE_EVENTS,
};
use crate::tidx::{namespace_heads_sql, parse_heads, Tidx, HEADS_KEY};

pub struct Ctx {
    pub tidx: Tidx,
    pub cfg: Settings,
}

/// A failed request. Everything here is the caller's id being unreadable, this
/// process misconfigured, or tidx unreachable — so the status says which, and an
/// empty result set stays a legitimate answer rather than how a failure looks.
struct ApiError(StatusCode, String);

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        (self.0, Json(json!({ "error": self.1 }))).into_response()
    }
}

impl From<anyhow::Error> for ApiError {
    fn from(err: anyhow::Error) -> Self {
        Self(StatusCode::BAD_GATEWAY, format!("{err:#}"))
    }
}

/// The wrapper every projection reads from, or a 500 — this process
/// misconfigured is neither the caller's fault nor tidx's, and 502 would send an
/// operator to look at the wrong process.
fn wrapper(ctx: &Ctx) -> Result<&str, ApiError> {
    ctx.cfg.registry.as_deref().ok_or_else(|| {
        ApiError(
            StatusCode::INTERNAL_SERVER_ERROR,
            "REGISTRY_ADDRESS is not set, so there is no wrapper to read from".into(),
        )
    })
}

/// A registry id from a path segment. Rejected here rather than interpolated:
/// these queries are built by string formatting, and an id is a number.
fn registry_id(raw: &str) -> Result<u64, ApiError> {
    raw.parse().map_err(|_| {
        ApiError(
            StatusCode::BAD_REQUEST,
            format!("`{raw}` is not a registry id"),
        )
    })
}

pub fn router(ctx: Arc<Ctx>) -> Router {
    Router::new()
        .route("/health", get(health))
        .route("/registries", get(registries))
        .route("/registries/{id}/records", get(records))
        .route("/registries/{id}/roles", get(roles))
        .with_state(ctx)
}

/// How far the index this answers from has reached. A caller comparing answers
/// across time needs it: every projection is bounded at `tip_num`, so two calls
/// either side of a block legitimately differ.
async fn health(State(ctx): State<Arc<Ctx>>) -> Result<Json<Value>, ApiError> {
    let coverage = ctx.tidx.coverage().await?;
    Ok(Json(json!({
        "tip_num": coverage.tip_num,
        "lag": coverage.lag(),
        "reaches_first_block": coverage.reaches(ctx.cfg.first_block),
    })))
}

async fn registries(State(ctx): State<Arc<Ctx>>) -> Result<Json<Value>, ApiError> {
    let wrapper = wrapper(&ctx)?;
    let at = ctx.tidx.coverage().await?.tip_num;
    let table = ctx
        .tidx
        .paged(
            &[crate::registry::REGISTRY_ADDED],
            REGISTRIES_KEY,
            |after| registries_sql(ctx.cfg.engine, wrapper, at, after),
        )
        .await?;
    Ok(Json(json!({
        "wrapper": wrapper,
        "at_block": at,
        "registries": parse_registries(&table)?,
    })))
}

async fn roles(
    State(ctx): State<Arc<Ctx>>,
    Path(id): Path<String>,
) -> Result<Json<Value>, ApiError> {
    let (wrapper, id) = (wrapper(&ctx)?, registry_id(&id)?);
    let at = ctx.tidx.coverage().await?.tip_num;
    let table = ctx
        .tidx
        .paged(ROLE_EVENTS, ROLES_KEY, |after| {
            roles_sql(ctx.cfg.engine, wrapper, id, at, after)
        })
        .await?;
    Ok(Json(json!({
        "registry_id": id,
        "at_block": at,
        "roles": parse_roles(&table)?,
    })))
}

async fn records(
    State(ctx): State<Arc<Ctx>>,
    Path(id): Path<String>,
) -> Result<Json<Value>, ApiError> {
    let (wrapper, id) = (wrapper(&ctx)?, registry_id(&id)?);
    let at = ctx.tidx.coverage().await?.tip_num;
    // Every registry shares the wrapper's namespace, so this reads them all and
    // `parse_records` keeps the one asked for. The key hashes the registry id
    // in, so there is nothing here for a `WHERE` to narrow on.
    let heads = parse_heads(
        &ctx.tidx
            .paged(&[], HEADS_KEY, |after| {
                namespace_heads_sql(ctx.cfg.engine, wrapper, at, after)
            })
            .await?,
    )?;
    Ok(Json(json!({
        "registry_id": id,
        "at_block": at,
        "records": parse_records(&heads, id)?,
    })))
}

pub async fn serve(ctx: Arc<Ctx>, bind: &str) -> Result<()> {
    let listener = tokio::net::TcpListener::bind(bind)
        .await
        .with_context(|| format!("bind {bind}"))?;
    tracing::info!("listening on {}", listener.local_addr()?);
    axum::serve(listener, router(ctx)).await.context("serve")
}
