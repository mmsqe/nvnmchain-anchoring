//! An HTTP surface over the projections.
//!
//! The explorer renders a link to "the anchoring decoder" on every namespace
//! page when `ANCHORING_URL` is set, and nothing was serving it. This is that.
//!
//! Read-through: every request queries tidx, and nothing is kept here. A second
//! store over the same log is what the explorer already is, and the measurements
//! on [`crate::registry::record_ids_sql`] say read-through is comfortable at the
//! sizes this chain has — so materializing is a decision to make against numbers
//! later, not a shape to start with.
//!
//! `/records` answers at each record's newest version; every version is a leaf,
//! and history has its own endpoint rather than a field that could quietly be
//! short.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::sync::Arc;

use anyhow::{Context, Result};
use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use serde_json::{json, Value};

use crate::config::Settings;
use crate::eth::{keccak_hex, parse_address};
use crate::registry::{
    deployment_sql, pair_leaves, parse_record_events, parse_record_ids, parse_records,
    parse_registries, parse_roles, parse_status_events, record_added_sql, record_ids_sql,
    records_at, registries_sql, roles_sql, status_updated_sql, statuses_of, versions_of, Deployed,
    NameFilter, RecordEvent, StatusEvent, EVENTS_KEY, RECORD_IDS_KEY, REGISTRIES_KEY, ROLES_KEY,
    ROLE_EVENTS,
};
use crate::tidx::{
    appends_sql, leaves_in_sql, leaves_sql, parse_appends, parse_leaves, Append, Leaf, Tidx,
    APPENDS_KEY, LEAVES_KEY,
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
        .route("/registries/records", post(records_by_registry))
        .route("/registries/{address}/mmr", get(mmr))
        .with_state(ctx)
}

/// One record's versions, oldest first — the history `/records` cannot carry.
///
/// A checksum with nothing under it here is a 404, and the one "does not exist"
/// this service can establish about a record: the lookup is on the indexed
/// checksum hash under this registry's own address, so an empty answer means
/// nothing was ever added there rather than that something was missed.
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
    let at = ctx.tidx.coverage().await?.tip_num;
    require_deployed(ctx, &registry, at).await?;

    // The events say which transactions, and the leaf beside each carries the
    // version's fields: a lookup on an indexed topic rather than a walk of the
    // registry, which for one record would cost the whole of it.
    let events = record_events(ctx, Some(&registry), &hash, at).await?;
    let leaves = leaves_beside(ctx, std::slice::from_ref(&registry), &events, at).await?;
    let (mut versions, other) = versions_of(&pair_leaves(&events, &leaves))?;
    if versions.is_empty() {
        return Err(not_found(format!(
            "no record with checksum `{checksum}` in registry {registry}"
        )));
    }
    let statuses = statuses_of(&status_events(ctx, Some(&registry), &hash, at).await?);
    for version in &mut versions {
        version.status = statuses
            .get(&(registry.to_lowercase(), version.version))
            .cloned();
    }

    // The id the contract stopped assigning, so the detail view and the listing
    // agree on it.
    let numbers = numbering(ctx, &registry, at).await?;

    Ok(json!({
        "registry": registry,
        "checksum": checksum,
        "checksum_hash": hash,
        "number": numbers.get(&hash),
        "at_block": at,
        "versions": versions,
        // `RecordAdded` rows with no record leaf beside them: another contract's,
        // counted rather than renumbering this record's versions.
        "other": other,
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

/// Every `RecordAdded` for one checksum hash, oldest first — under one registry,
/// or across every emitter.
async fn record_events(
    ctx: &Ctx,
    registry: Option<&str>,
    hash: &str,
    at: u64,
) -> Result<Vec<RecordEvent>> {
    let table = ctx
        .tidx
        .paged(&[], EVENTS_KEY, |after| {
            record_added_sql(ctx.cfg.engine, registry, hash, at, after)
        })
        .await?;
    parse_record_events(&table)
}

/// The same for `RecordStatusUpdated`, whose status text is in the event itself.
async fn status_events(
    ctx: &Ctx,
    registry: Option<&str>,
    hash: &str,
    at: u64,
) -> Result<Vec<StatusEvent>> {
    let table = ctx
        .tidx
        .paged(&[], EVENTS_KEY, |after| {
            status_updated_sql(ctx.cfg.engine, registry, hash, at, after)
        })
        .await?;
    parse_status_events(&table)
}

/// The leaves in the blocks `events` landed in, under `namespaces` — what
/// [`pair_leaves`] matches each event against, fetched without walking a namespace.
async fn leaves_beside(
    ctx: &Ctx,
    namespaces: &[String],
    events: &[RecordEvent],
    at: u64,
) -> Result<Vec<Leaf>> {
    if events.is_empty() {
        return Ok(Vec::new());
    }
    let blocks: Vec<u64> = events
        .iter()
        .map(|e| e.block_num)
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect();
    let table = ctx
        .tidx
        .paged(&[], LEAVES_KEY, |after| {
            leaves_in_sql(ctx.cfg.engine, namespaces, &blocks, at, after)
        })
        .await?;
    parse_leaves(&table)
}

/// Every leaf under `scope`, walked to exhaustion, in log order.
async fn leaves_under(ctx: &Ctx, namespaces: &[String], at: u64) -> Result<Vec<Leaf>> {
    let table = ctx
        .tidx
        .paged(&[], LEAVES_KEY, |after| {
            leaves_sql(ctx.cfg.engine, namespaces, at, after)
        })
        .await?;
    parse_leaves(&table)
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

/// Every registry that has added one checksum — the module's
/// `records(registry_id = 0, checksum, …)`, and the one lookup no per-registry
/// path can serve.
///
/// Takes the checksum rather than its hash: `RecordAdded` indexes
/// `keccak256(checksum)`, which is why one filter on an indexed topic answers for
/// every registry at once without walking any of them.
async fn records_for_checksum(
    State(ctx): State<Arc<Ctx>>,
    Path(checksum): Path<String>,
) -> Result<Json<Value>, ApiError> {
    Ok(Json(anchored_anywhere(&ctx, &checksum).await?))
}

/// The projection behind `GET /records/{checksum}`.
///
/// The events say which registries and which transactions; the leaf beside each
/// event carries the version's fields. Fetched by namespace and block rather than
/// by walking a namespace, so the cost is the record's, not the registry's.
pub async fn anchored_anywhere(ctx: &Ctx, checksum: &str) -> Result<Value, ApiError> {
    let hash = keccak_hex(checksum.as_bytes());
    let at = ctx.tidx.coverage().await?.tip_num;

    let events = record_events(ctx, None, &hash, at).await?;
    let namespaces: Vec<String> = events
        .iter()
        .map(|e| e.registry.clone())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect();
    let leaves = leaves_beside(ctx, &namespaces, &events, at).await?;
    let statuses = statuses_of(&status_events(ctx, None, &hash, at).await?);
    let (records, other) = records_at(&pair_leaves(&events, &leaves), &statuses)?;

    Ok(json!({
        "checksum": checksum,
        "checksum_hash": hash,
        "at_block": at,
        "records": records,
        // Events with no record leaf beside them. Anyone may emit a `RecordAdded`,
        // so this lookup leaves what is not a registry's out rather than failing
        // on it — and says how much it left out, since silence there would be
        // indistinguishable from a checksum nobody else has touched.
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
    let matched: Vec<_> = deployed_at(ctx, factory, at)
        .await?
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
    // Both bounded at the same block, so the numbering and the leaves describe
    // one state of the chain rather than two.
    let ids = numbering(ctx, &registry, at).await?;
    let leaves = leaves_under(ctx, std::slice::from_ref(&registry), at).await?;
    let (records, other) = parse_records(&leaves, &ids)?;
    Ok(json!({
        "registry": registry,
        "at_block": at,
        "records": records,
        // Leaves that are not envelopes: what a registry-scoped writer appended
        // as a bare commitment, or what a corpus loaded as a batch never had.
        "other": other,
    }))
}

/// Every registry the factory announced, in deployment order — the walk both the
/// listing and the bulk projection's 404 check are built on.
async fn deployed_at(ctx: &Ctx, factory: &str, at: u64) -> Result<Vec<Deployed>> {
    let table = ctx
        .tidx
        .paged(&[], REGISTRIES_KEY, |after| {
            registries_sql(ctx.cfg.engine, factory, at, after)
        })
        .await?;
    parse_registries(&table)
}

async fn records_by_registry(
    State(ctx): State<Arc<Ctx>>,
    Json(addresses): Json<Vec<String>>,
) -> Result<Json<Value>, ApiError> {
    Ok(Json(records_held_by(&ctx, &addresses).await?))
}

/// The MMR each of `addresses` holds, as its newest append left it — root, count,
/// peaks and the metadata it was appended with — or null for one that has never
/// appended: what `reconcile` judges a `leaves` step by, and what a proof is
/// checked against.
pub async fn mmr_held_by(ctx: &Ctx, addresses: &[String]) -> Result<Value, ApiError> {
    let registries: Vec<String> = addresses
        .iter()
        .map(|address| registry_of(address))
        .collect::<Result<_, _>>()?;
    let at = ctx.tidx.coverage().await?.tip_num;
    let mut roots: BTreeMap<String, Value> = registries
        .iter()
        .map(|registry| (registry.to_lowercase(), Value::Null))
        .collect();
    if !registries.is_empty() {
        let table = ctx
            .tidx
            .paged(&[], APPENDS_KEY, |after| {
                appends_sql(ctx.cfg.engine, &registries, at, after)
            })
            .await?;
        for newest in parse_appends(&table)? {
            roots.insert(newest.namespace.to_lowercase(), mmr_json(&newest));
        }
    }
    Ok(json!({ "at_block": at, "registries": roots }))
}

/// A namespace's MMR as its newest append left it: every event carries the count
/// and peaks it reached, so the newest one is the whole answer.
fn mmr_json(newest: &Append) -> Value {
    json!({
        "root": newest.root,
        "count": newest.count(),
        "peaks": newest.peaks,
        "metadata": String::from_utf8_lossy(&newest.metadata),
        "block_num": newest.block_num,
    })
}

/// One registry's MMR, 404 for an address the factory never deployed.
async fn mmr(
    State(ctx): State<Arc<Ctx>>,
    Path(address): Path<String>,
) -> Result<Json<Value>, ApiError> {
    let registry = registry_of(&address)?;
    let at = ctx.tidx.coverage().await?.tip_num;
    require_deployed(&ctx, &registry, at).await?;
    let served = mmr_held_by(&ctx, std::slice::from_ref(&registry)).await?;
    let held = &served["registries"][registry.to_lowercase()];
    Ok(Json(json!({
        "registry": registry,
        "root": held["root"],
        "count": held["count"],
        "peaks": held["peaks"],
        "metadata": held["metadata"],
        "at_block": served["at_block"],
    })))
}

/// The projection behind `POST /registries/records`: several registries' records at
/// their newest version, in one walk of the index rather than one per registry.
///
/// Unnumbered, where the per-registry listing is not. A number is a full walk of one
/// registry's `RecordAdded` rows, and the caller this exists for — `reconcile`, over
/// thousands of registries — never reads it; so, like `/records/{checksum}`, `number`
/// is null here rather than paid for. An address the factory never announced fails
/// the request by name, checked against one listing rather than one lookup each.
///
/// Returns early on no addresses: an empty scope is every namespace, and the answer
/// to "which of nothing" must not be a walk of the whole chain.
pub async fn records_held_by(ctx: &Ctx, addresses: &[String]) -> Result<Value, ApiError> {
    let registries: Vec<String> = addresses
        .iter()
        .map(|address| registry_of(address))
        .collect::<Result<_, _>>()?;
    let at = ctx.tidx.coverage().await?.tip_num;
    if registries.is_empty() {
        return Ok(json!({ "at_block": at, "registries": {} }));
    }
    if let Some(factory) = ctx.cfg.factory.as_deref() {
        let announced: BTreeSet<String> = deployed_at(ctx, factory, at)
            .await?
            .into_iter()
            .map(|deployed| deployed.address.to_lowercase())
            .collect();
        if let Some(stranger) = registries
            .iter()
            .find(|registry| !announced.contains(&registry.to_lowercase()))
        {
            return Err(not_found(format!(
                "{stranger} is not a registry deployed by {factory}"
            )));
        }
    }

    let mut by_registry: BTreeMap<String, Vec<Leaf>> = BTreeMap::new();
    for leaf in leaves_under(ctx, &registries, at).await? {
        by_registry
            .entry(leaf.namespace.to_lowercase())
            .or_default()
            .push(leaf);
    }
    let unnumbered = BTreeMap::new();
    let mut records = serde_json::Map::new();
    for registry in registries {
        let leaves = by_registry
            .get(&registry.to_lowercase())
            .map(Vec::as_slice)
            .unwrap_or(&[]);
        let (held, _) = parse_records(leaves, &unnumbered)?;
        records.insert(registry, json!(held));
    }
    Ok(json!({ "at_block": at, "registries": records }))
}

pub async fn serve(ctx: Arc<Ctx>, bind: &str) -> Result<()> {
    let listener = tokio::net::TcpListener::bind(bind)
        .await
        .with_context(|| format!("bind {bind}"))?;
    tracing::info!("listening on {}", listener.local_addr()?);
    axum::serve(listener, router(ctx)).await.context("serve")
}
