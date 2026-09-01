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

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::sync::Arc;

use anyhow::{Context, Result};
use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::{Json, Router};
use serde_json::{json, Value};

use crate::config::Settings;
use crate::envelope::{record_key, status_key};
use crate::eth::{keccak_hex, parse_address};
use crate::registry::{
    deployment_sql, parse_record_ids, parse_records, parse_records_at, parse_registries,
    parse_roles, parse_statuses, parse_versions, record_ids_sql, registries_sql, roles_sql,
    NameFilter, RECORD_IDS_KEY, REGISTRIES_KEY, ROLES_KEY, ROLE_EVENTS,
};
use crate::tidx::{
    anchors_sql, parse_anchors, parse_heads, scoped_heads_sql, Head, Scope, Tidx, ANCHORS_KEY,
    HEADS_KEY,
};

pub struct Ctx {
    pub tidx: Tidx,
    pub cfg: Settings,
}

/// A failed request: the status it answers with, and why.
///
/// Everything here is the caller naming something the log does not have, this
/// process misconfigured, or tidx unreachable or refusing — 400/404 against 500
/// against 502, and the message says which. An empty result set is a legitimate
/// answer and must never be how a failure looks.
///
/// Public because the projections are: the same call serves an HTTP request and
/// a command line, and a caller outside the router needs the status to decide
/// what to do with it.
pub struct ApiError(pub StatusCode, pub String);

impl std::fmt::Display for ApiError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}", self.0, self.1)
    }
}

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

/// Something the caller named that the log does not have. Only for what an
/// answer over an index can actually establish — an empty projection is a
/// legitimate result, and saying "not found" for one would be a guess.
fn not_found(message: impl Into<String>) -> ApiError {
    ApiError(StatusCode::NOT_FOUND, message.into())
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
        .route("/registries/{address}/records/{checksum}", get(versions))
        .route("/records/{checksum}", get(records_for_checksum))
        .with_state(ctx)
}

/// One record's versions, oldest first — the history `/records` cannot carry.
///
/// The only projection here that does not fold to heads: the chain keeps one word
/// per key, so every version before the newest exists solely as the log row the
/// head replaced.
///
/// A checksum with nothing anchored under it here is a 404, and the one "does not
/// exist" this service can establish about a record — the query is over the
/// registry's own namespace at a derived key, so an empty answer means nothing was
/// ever anchored there rather than that something was missed.
async fn versions(
    State(ctx): State<Arc<Ctx>>,
    Path((address, checksum)): Path<(String, String)>,
) -> Result<Json<Value>, ApiError> {
    Ok(Json(record_versions(&ctx, &address, &checksum).await?))
}

/// The projection behind `GET /registries/{address}/records/{checksum}`.
pub async fn record_versions(ctx: &Ctx, address: &str, checksum: &str) -> Result<Value, ApiError> {
    let registry = registry_of(address)?;
    let hash = keccak_hex(checksum.as_bytes());
    let key = record_key(&hash).expect("a keccak digest is a 32-byte word");
    let at = ctx.tidx.coverage().await?.tip_num;
    require_deployed(ctx, &registry, at).await?;

    let anchors = parse_anchors(
        &ctx.tidx
            .paged(&[], ANCHORS_KEY, |after| {
                anchors_sql(ctx.cfg.engine, &registry, &key, at, after)
            })
            .await?,
    )?;
    let mut versions = parse_versions(&anchors)?;
    if versions.is_empty() {
        return Err(not_found(format!(
            "no record with checksum `{checksum}` in registry {registry}"
        )));
    }

    let keys = versions.iter().filter_map(|v| status_key(&hash, v.version));
    let statuses = statuses_under(ctx, keys, at).await?;
    for version in &mut versions {
        version.status = status_of(&statuses, &registry, &hash, version.version);
    }

    // The id the contract stopped assigning, so the detail view and the listing
    // agree on it.
    let numbers = numbering(ctx, &registry, at).await?;

    Ok(json!({
        "registry": registry,
        "checksum": checksum,
        "checksum_hash": hash,
        "key": key,
        "number": numbers.get(&hash),
        "at_block": at,
        "versions": versions,
    }))
}

/// Whether this address is a registry at all, when there is a factory to ask.
///
/// "registry 999 does not exist" was a number held against a counter. The address
/// that replaced the id carries no such fact, but the factory announced every
/// registry it deployed — so the same question goes to the log. Without a
/// `FACTORY_ADDRESS` there is nothing to ask and every address is answered for,
/// which is the audit-only configuration rather than a registry that exists.
async fn require_deployed(ctx: &Ctx, registry: &str, at: u64) -> Result<(), ApiError> {
    let Some(factory) = ctx.cfg.factory.as_deref() else {
        return Ok(());
    };
    let deployments = ctx
        .tidx
        .query(&deployment_sql(ctx.cfg.engine, factory, registry, at))
        .await?;
    if deployments.rows.is_empty() {
        return Err(not_found(format!(
            "{registry} is not a registry deployed by {factory}"
        )));
    }
    Ok(())
}

/// Every head under `scope`, walked to exhaustion.
async fn heads_under(ctx: &Ctx, scope: Scope<'_>, at: u64) -> Result<Vec<Head>> {
    let table = ctx
        .tidx
        .paged(&[], HEADS_KEY, |after| {
            scoped_heads_sql(ctx.cfg.engine, scope, at, after)
        })
        .await?;
    parse_heads(&table)
}

/// The numbering the contract stopped assigning. A full walk of one registry's
/// `RecordAdded` rows, which the listing and a single record's detail both pay
/// for -- a number is a property of the whole ordering.
async fn numbering(ctx: &Ctx, registry: &str, at: u64) -> Result<BTreeMap<String, u64>> {
    let table = ctx
        .tidx
        .paged(&[], RECORD_IDS_KEY, |after| {
            record_ids_sql(ctx.cfg.engine, registry, at, after)
        })
        .await?;
    parse_record_ids(&table)
}

/// What a status lookup answers: the status held against one
/// `(registry, checksum hash, version)`.
type Statuses = BTreeMap<(String, String, u64), String>;

/// The statuses currently held under `keys`, in one round trip — a status key is
/// the same word in every registry holding that record at that version, so the
/// namespace only tells the answers apart afterwards.
async fn statuses_under(
    ctx: &Ctx,
    keys: impl IntoIterator<Item = String>,
    at: u64,
) -> Result<Statuses> {
    // Deduplicated here rather than at each caller: two registries at the same
    // version are one key, and asking twice returns the same rows.
    let keys: Vec<String> = keys
        .into_iter()
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect();
    if keys.is_empty() {
        return Ok(Statuses::new());
    }
    parse_statuses(&heads_under(ctx, Scope::keyed(&keys), at).await?)
}

fn status_of(statuses: &Statuses, registry: &str, hash: &str, version: u64) -> Option<String> {
    statuses
        .get(&(registry.to_string(), hash.to_string(), version))
        .cloned()
}

/// Every registry that has anchored one checksum — the module's
/// `records(registry_id = 0, checksum, …)`, and the one lookup no per-registry
/// path can serve.
///
/// Takes the checksum rather than its hash: the key derives from
/// `keccak256(checksum)` and nothing else, which is why one filter on an indexed
/// column answers for every registry at once.
async fn records_for_checksum(
    State(ctx): State<Arc<Ctx>>,
    Path(checksum): Path<String>,
) -> Result<Json<Value>, ApiError> {
    Ok(Json(anchored_anywhere(&ctx, &checksum).await?))
}

/// The projection behind `GET /records/{checksum}`.
pub async fn anchored_anywhere(ctx: &Ctx, checksum: &str) -> Result<Value, ApiError> {
    let hash = keccak_hex(checksum.as_bytes());
    let key = record_key(&hash).expect("a keccak digest is a 32-byte word");
    let at = ctx.tidx.coverage().await?.tip_num;

    let keys = [key.clone()];
    let (mut records, other) = parse_records_at(&heads_under(ctx, Scope::keyed(&keys), at).await?)?;

    let keys = records
        .iter()
        .filter_map(|r| status_key(&hash, r.record.version));
    let statuses = statuses_under(ctx, keys, at).await?;
    for held in &mut records {
        let version = held.record.version;
        held.record.status = status_of(&statuses, &held.registry, &hash, version);
    }

    Ok(json!({
        "checksum": checksum,
        "checksum_hash": hash,
        "key": key,
        "at_block": at,
        "records": records,
        // Namespaces holding something else under this key. Anyone may anchor
        // anywhere, so this lookup leaves what is not a record out rather than
        // failing on it — and says how much it left out, since silence there
        // would be indistinguishable from a key nobody else has touched.
        "other": other,
    }))
}

/// How far the index this answers from has reached. A caller comparing answers
/// across time needs it: every projection is bounded at `tip_num`, so two calls
/// either side of a block legitimately differ.
async fn health(State(ctx): State<Arc<Ctx>>) -> Result<Json<Value>, ApiError> {
    Ok(Json(coverage(&ctx).await?))
}

/// The projection behind `GET /health`.
pub async fn coverage(ctx: &Ctx) -> Result<Value, ApiError> {
    let coverage = ctx.tidx.coverage().await?;
    Ok(json!({
        "tip_num": coverage.tip_num,
        "lag": coverage.lag(),
        "reaches_first_block": coverage.reaches(ctx.cfg.first_block),
    }))
}

/// `?name=`, `?name_prefix=`, `?name_suffix=`, `?name_contains=` — the module's
/// `registriesByName`, spelled the way its proto did so a caller moving over
/// keeps its query strings.
///
/// Anything else is a 400. A mistyped parameter that were ignored would answer
/// with every registry the factory ever deployed and look like a filter that
/// matched them all.
fn filter_of(params: &HashMap<String, String>) -> Result<NameFilter, ApiError> {
    let mut filter = NameFilter::default();
    for (key, value) in params {
        let field = match key.as_str() {
            "name" => &mut filter.name,
            "name_prefix" => &mut filter.prefix,
            "name_suffix" => &mut filter.suffix,
            "name_contains" => &mut filter.contains,
            other => {
                return Err(bad_request(format!(
                    "`{other}` is not a filter; use name, name_prefix, name_suffix or name_contains"
                )))
            }
        };
        *field = Some(value.clone());
    }
    Ok(filter)
}

async fn registries(
    State(ctx): State<Arc<Ctx>>,
    Query(params): Query<HashMap<String, String>>,
) -> Result<Json<Value>, ApiError> {
    Ok(Json(deployments(&ctx, &filter_of(&params)?).await?))
}

/// The projection behind `GET /registries`.
///
/// The numbering is deployment order across the whole factory, assigned before
/// the filter runs: a filtered listing reports the numbers the registries have,
/// not their places in the answer.
pub async fn deployments(ctx: &Ctx, filter: &NameFilter) -> Result<Value, ApiError> {
    let factory = ctx.cfg.factory.as_deref().ok_or_else(|| {
        misconfigured("FACTORY_ADDRESS is not set, so there is no factory to list from")
    })?;
    let at = ctx.tidx.coverage().await?.tip_num;
    let table = ctx
        .tidx
        .paged(&[], REGISTRIES_KEY, |after| {
            registries_sql(ctx.cfg.engine, factory, at, after)
        })
        .await?;
    let deployed = parse_registries(&table)?;
    let matched: Vec<_> = deployed
        .into_iter()
        .filter(|registry| filter.matches(&registry.name))
        .collect();
    Ok(json!({
        "factory": factory,
        "at_block": at,
        "registries": matched,
    }))
}

async fn roles(
    State(ctx): State<Arc<Ctx>>,
    Path(address): Path<String>,
) -> Result<Json<Value>, ApiError> {
    Ok(Json(roles_held(&ctx, &address).await?))
}

/// The projection behind `GET /registries/{address}/roles`.
pub async fn roles_held(ctx: &Ctx, address: &str) -> Result<Value, ApiError> {
    let registry = registry_of(address)?;
    let at = ctx.tidx.coverage().await?.tip_num;
    require_deployed(ctx, &registry, at).await?;
    let table = ctx
        .tidx
        .paged(ROLE_EVENTS, ROLES_KEY, |after| {
            roles_sql(ctx.cfg.engine, &registry, at, after)
        })
        .await?;
    Ok(json!({
        "registry": registry,
        "at_block": at,
        "roles": parse_roles(&table)?,
    }))
}

async fn records(
    State(ctx): State<Arc<Ctx>>,
    Path(address): Path<String>,
) -> Result<Json<Value>, ApiError> {
    Ok(Json(records_held(&ctx, &address).await?))
}

/// The projection behind `GET /registries/{address}/records`.
pub async fn records_held(ctx: &Ctx, address: &str) -> Result<Value, ApiError> {
    let registry = registry_of(address)?;
    let at = ctx.tidx.coverage().await?.tip_num;
    require_deployed(ctx, &registry, at).await?;
    // Both bounded at the same block, so the numbering and the heads describe
    // one state of the chain rather than two.
    let ids = numbering(ctx, &registry, at).await?;
    let heads = heads_under(ctx, Scope::of(&registry), at).await?;
    Ok(json!({
        "registry": registry,
        "at_block": at,
        "records": parse_records(&heads, &ids)?,
    }))
}

pub async fn serve(ctx: Arc<Ctx>, bind: &str) -> Result<()> {
    let listener = tokio::net::TcpListener::bind(bind)
        .await
        .with_context(|| format!("bind {bind}"))?;
    tracing::info!("listening on {}", listener.local_addr()?);
    axum::serve(listener, router(ctx)).await.context("serve")
}
