//! An HTTP surface over the projections.
//!
//! The explorer renders a link to "the anchoring decoder" on every key page
//! when `ANCHORING_URL` is set, and nothing was serving it. This is that.
//!
//! Read-through: every request queries tidx, and nothing is kept here. A second
//! store over the same log is what the explorer already is, and the measurements
//! on [`crate::registry::record_ids_sql`] say read-through is comfortable at the
//! sizes this chain has — so materializing is a decision to make against numbers
//! later, not a shape to start with.
//!
//! `/records` answers at each record's newest version, because that is what the
//! chain keeps — one word per key. Earlier versions are in the log, and want
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
use crate::eth::parse_address;
use crate::registry::{
    parse_record_ids, parse_records, parse_registries, parse_roles, record_ids_sql, registries_sql,
    roles_sql, ROLE_EVENTS,
};
use crate::tidx::{namespace_heads_sql, parse_heads, Tidx};

pub struct Ctx {
    pub tidx: Tidx,
    pub cfg: Settings,
}

/// A failed request. Everything here is either the caller's address being
/// malformed or tidx being unreachable or refusing, so the split is 400 against
/// 502 and the message says which — an empty result set is a legitimate answer
/// and must never be how a failure looks.
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

fn bad_request(message: impl Into<String>) -> ApiError {
    ApiError(StatusCode::BAD_REQUEST, message.into())
}

/// This service configured wrong, which is neither the caller's fault nor
/// tidx's — 502 would send an operator to look at the wrong process.
fn misconfigured(message: impl Into<String>) -> ApiError {
    ApiError(StatusCode::INTERNAL_SERVER_ERROR, message.into())
}

/// The registry a path segment names. Rejected here rather than filtered
/// downstream: `bytes_literal` drops non-hex, so a mangled address would query a
/// real-looking other one and answer "nothing here".
fn registry_of(address: &str) -> Result<String, ApiError> {
    parse_address(address)
        .ok_or_else(|| bad_request(format!("`{address}` is not a 20-byte hex address")))
}

pub fn router(ctx: Arc<Ctx>) -> Router {
    Router::new()
        .route("/health", get(health))
        .route("/registries", get(registries))
        .route("/registries/{address}/records", get(records))
        .route("/registries/{address}/roles", get(roles))
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
    let factory = ctx.cfg.factory.as_deref().ok_or_else(|| {
        misconfigured("FACTORY_ADDRESS is not set, so there is no factory to list from")
    })?;
    let at = ctx.tidx.coverage().await?.tip_num;
    let table = ctx
        .tidx
        .query(&registries_sql(ctx.cfg.engine, factory, at))
        .await?;
    Ok(Json(json!({
        "factory": factory,
        "at_block": at,
        "registries": parse_registries(&table)?,
    })))
}

async fn roles(
    State(ctx): State<Arc<Ctx>>,
    Path(address): Path<String>,
) -> Result<Json<Value>, ApiError> {
    let registry = registry_of(&address)?;
    let at = ctx.tidx.coverage().await?.tip_num;
    let table = ctx
        .tidx
        .query_with(&roles_sql(ctx.cfg.engine, &registry, at), ROLE_EVENTS)
        .await?;
    Ok(Json(json!({
        "registry": registry,
        "at_block": at,
        "roles": parse_roles(&table)?,
    })))
}

async fn records(
    State(ctx): State<Arc<Ctx>>,
    Path(address): Path<String>,
) -> Result<Json<Value>, ApiError> {
    let registry = registry_of(&address)?;
    let at = ctx.tidx.coverage().await?.tip_num;
    // Both bounded at the same block, so the numbering and the heads describe
    // one state of the chain rather than two.
    let ids = parse_record_ids(
        &ctx.tidx
            .query(&record_ids_sql(ctx.cfg.engine, &registry, at))
            .await?,
    )?;
    let heads = parse_heads(
        &ctx.tidx
            .query(&namespace_heads_sql(ctx.cfg.engine, &registry, at))
            .await?,
    )?;
    Ok(Json(json!({
        "registry": registry,
        "at_block": at,
        "records": parse_records(&heads, &ids)?,
    })))
}

pub async fn serve(ctx: Arc<Ctx>, bind: &str) -> Result<()> {
    let listener = tokio::net::TcpListener::bind(bind)
        .await
        .with_context(|| format!("bind {bind}"))?;
    tracing::info!("listening on {}", listener.local_addr()?);
    axum::serve(listener, router(ctx)).await.context("serve")
}
