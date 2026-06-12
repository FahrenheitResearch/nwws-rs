//! Self-hosted HTTP API over a live NWWS-OI archive.
//!
//! [`run_server`] runs two halves on one archive directory:
//!
//! - an ingest thread driving [`crate::daemon::run`] (connect, parse, dedupe,
//!   archive, reconnect forever), publishing every archived product to an
//!   in-process broadcast channel;
//! - an axum HTTP server exposing the archive and the live channel:
//!   `GET /v1/stream` (Server-Sent Events), `GET /v1/products/recent`,
//!   `GET /v1/products/{fingerprint}`, `GET /v1/warnings/active`,
//!   `GET /v1/timeline`, and `GET /healthz`.
//!
//! Query endpoints scope filesystem scans to the archive's `yyyy/mm/dd` date
//! partitions, so request cost is bounded by the lookback window (`days`
//! parameter), not by total archive size. The server can also run `--no-ingest`
//! over an existing archive, which needs no NWWS-OI credentials at all.

use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::{Duration, Instant};

use axum::Router;
use axum::extract::{Path as AxumPath, Query, State};
use axum::http::StatusCode;
use axum::response::sse::{Event, KeepAlive, Sse};
use axum::response::{IntoResponse, Json, Response};
use axum::routing::get;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use time::format_description::well_known::Rfc3339;
use time::{Date, OffsetDateTime};
use tokio_stream::StreamExt as _;
use tokio_stream::wrappers::BroadcastStream;
use tower_http::cors::CorsLayer;

use crate::api::active_warnings_in_files;
use crate::daemon::{DaemonEvent, DaemonOptions, run as run_daemon};
use crate::oi_client::OiClientConfig;
use crate::runtime::{
    ArchiveStore, ArchivedMetadata, DedupeStore, IngestService, MessageRouter, family_slug,
};
use crate::warning::polygon_timeline_in_files;

const MAX_LOOKBACK_DAYS: u32 = 92;
const MAX_RECENT_LIMIT: usize = 1000;

#[derive(Debug, Clone)]
pub struct ServeOptions {
    pub bind: SocketAddr,
    pub archive_dir: PathBuf,
    /// `None` serves an existing archive read-only (no credentials needed).
    pub ingest: Option<ServeIngestOptions>,
}

#[derive(Debug, Clone)]
pub struct ServeIngestOptions {
    pub client: OiClientConfig,
    pub daemon: DaemonOptions,
    pub archive_duplicates: bool,
}

/// One live product as published on `/v1/stream`.
#[derive(Debug, Clone, Serialize)]
pub struct LiveProduct {
    pub fingerprint: Option<String>,
    pub duplicate: bool,
    pub cccc: String,
    pub ttaaii: String,
    pub awips_id: String,
    pub issue: Option<String>,
    pub metadata: Option<ArchivedMetadata>,
    pub raw_bulletin: String,
}

#[derive(Debug, Default)]
pub struct IngestStatus {
    connected: AtomicBool,
    messages_read: AtomicU64,
    archived_records: AtomicU64,
    duplicate_records: AtomicU64,
    ingest_failures: AtomicU64,
    connect_failures: AtomicU64,
    reconnects: AtomicU64,
    last_message_at: std::sync::Mutex<Option<String>>,
    last_error: std::sync::Mutex<Option<String>>,
}

impl IngestStatus {
    fn snapshot(&self) -> Value {
        json!({
            "connected": self.connected.load(Ordering::Relaxed),
            "messages_read": self.messages_read.load(Ordering::Relaxed),
            "archived_records": self.archived_records.load(Ordering::Relaxed),
            "duplicate_records": self.duplicate_records.load(Ordering::Relaxed),
            "ingest_failures": self.ingest_failures.load(Ordering::Relaxed),
            "connect_failures": self.connect_failures.load(Ordering::Relaxed),
            "reconnects": self.reconnects.load(Ordering::Relaxed),
            "last_message_at": *self.last_message_at.lock().expect("status lock"),
            "last_error": *self.last_error.lock().expect("status lock"),
        })
    }
}

pub struct ServeState {
    archive_dir: PathBuf,
    started_at: Instant,
    live: tokio::sync::broadcast::Sender<Arc<LiveProduct>>,
    status: Arc<IngestStatus>,
    ingest_enabled: bool,
}

impl ServeState {
    pub fn new(archive_dir: PathBuf, ingest_enabled: bool) -> (Arc<Self>, Arc<IngestStatus>) {
        let (live, _) = tokio::sync::broadcast::channel(256);
        let status = Arc::new(IngestStatus::default());
        let state = Arc::new(Self {
            archive_dir,
            started_at: Instant::now(),
            live,
            status: status.clone(),
            ingest_enabled,
        });
        (state, status)
    }

    pub fn live_sender(&self) -> tokio::sync::broadcast::Sender<Arc<LiveProduct>> {
        self.live.clone()
    }
}

/// Build the HTTP router; separated from [`run_server`] so tests can drive it
/// with in-process requests.
pub fn app(state: Arc<ServeState>) -> Router {
    Router::new()
        .route("/", get(index))
        .route("/healthz", get(healthz))
        .route("/v1/stream", get(stream))
        .route("/v1/warnings/active", get(warnings_active))
        .route("/v1/timeline", get(timeline))
        .route("/v1/products/recent", get(products_recent))
        .route("/v1/products/{fingerprint}", get(product_by_fingerprint))
        .layer(CorsLayer::permissive())
        .with_state(state)
}

/// Run ingest (unless `--no-ingest`) plus the HTTP API until Ctrl-C.
pub fn run_server(options: ServeOptions) -> std::io::Result<()> {
    std::fs::create_dir_all(&options.archive_dir)?;
    let (state, status) = ServeState::new(options.archive_dir.clone(), options.ingest.is_some());

    let shutdown = Arc::new(AtomicBool::new(false));
    let ingest_thread = options.ingest.map(|ingest| {
        let archive_dir = options.archive_dir.clone();
        let live = state.live_sender();
        let status = status.clone();
        let shutdown = shutdown.clone();
        std::thread::Builder::new()
            .name("nwws-ingest".to_owned())
            .spawn(move || ingest_loop(archive_dir, ingest, live, status, shutdown))
            .expect("spawn ingest thread")
    });

    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;
    let result = runtime.block_on(async {
        let listener = tokio::net::TcpListener::bind(options.bind).await?;
        eprintln!("nwws serve listening on http://{}", options.bind);
        axum::serve(listener, app(state))
            .with_graceful_shutdown(async {
                let _ = tokio::signal::ctrl_c().await;
            })
            .await
    });

    shutdown.store(true, Ordering::Relaxed);
    if let Some(thread) = ingest_thread {
        let _ = thread.join();
    }
    result
}

fn ingest_loop(
    archive_dir: PathBuf,
    options: ServeIngestOptions,
    live: tokio::sync::broadcast::Sender<Arc<LiveProduct>>,
    status: Arc<IngestStatus>,
    shutdown: Arc<AtomicBool>,
) {
    let router = MessageRouter::new(Some(ArchiveStore::new(&archive_dir)));
    let dedupe = match DedupeStore::open(archive_dir.join("state").join("dedupe.txt")) {
        Ok(dedupe) => dedupe,
        Err(err) => {
            *status.last_error.lock().expect("status lock") =
                Some(format!("failed to open dedupe store: {err}"));
            return;
        }
    };
    let mut service = IngestService::new(router, dedupe);
    service.set_archive_duplicates(options.archive_duplicates);

    run_daemon(
        &options.client,
        &mut service,
        &options.daemon,
        |event| match &event {
            DaemonEvent::Connected { .. } => {
                status.connected.store(true, Ordering::Relaxed);
            }
            DaemonEvent::ConnectFailed { error, .. } => {
                status.connect_failures.fetch_add(1, Ordering::Relaxed);
                *status.last_error.lock().expect("status lock") = Some(error.to_string());
            }
            DaemonEvent::MessageProcessed {
                message,
                records,
                duplicate,
            } => {
                status.messages_read.fetch_add(1, Ordering::Relaxed);
                if *duplicate {
                    status.duplicate_records.fetch_add(1, Ordering::Relaxed);
                } else {
                    status.archived_records.fetch_add(1, Ordering::Relaxed);
                }
                let now = OffsetDateTime::now_utc().format(&Rfc3339).ok();
                *status.last_message_at.lock().expect("status lock") = now;
                if let Some(payload) = message.payload.as_ref() {
                    let record = records.first();
                    let product = LiveProduct {
                        fingerprint: record.map(|record| record.fingerprint.clone()),
                        duplicate: *duplicate,
                        cccc: payload.cccc.clone(),
                        ttaaii: payload.ttaaii.clone(),
                        awips_id: payload.awips_id.clone(),
                        issue: payload.issue.format(&Rfc3339).ok(),
                        metadata: record.map(|record| record.metadata.clone()),
                        raw_bulletin: payload.raw_bulletin.clone(),
                    };
                    // Send fails only when no subscriber is connected; fine.
                    let _ = live.send(Arc::new(product));
                }
            }
            DaemonEvent::IngestFailed { error } => {
                status.ingest_failures.fetch_add(1, Ordering::Relaxed);
                *status.last_error.lock().expect("status lock") = Some(error.clone());
            }
            DaemonEvent::Disconnected { error, .. } => {
                status.connected.store(false, Ordering::Relaxed);
                status.reconnects.fetch_add(1, Ordering::Relaxed);
                if let Some(error) = error {
                    *status.last_error.lock().expect("status lock") = Some(error.to_string());
                }
            }
            DaemonEvent::ShuttingDown => {
                status.connected.store(false, Ordering::Relaxed);
            }
            DaemonEvent::MessageSkipped { .. } | DaemonEvent::SilentRead { .. } => {}
        },
        &shutdown,
    );
}

async fn index() -> Json<Value> {
    Json(json!({
        "name": "nwws-rs",
        "version": env!("CARGO_PKG_VERSION"),
        "endpoints": {
            "GET /healthz": "server and ingest status",
            "GET /v1/stream": "live products over Server-Sent Events; filters: office, pil, family",
            "GET /v1/products/recent": "newest archived products; params: limit, days, office, pil, family",
            "GET /v1/products/{fingerprint}": "metadata and raw text of one archived product; params: days",
            "GET /v1/warnings/active": "VTEC warnings active at a reference time; params: at (RFC3339), days, families",
            "GET /v1/timeline": "warning lifecycle records; params: at (RFC3339), days",
        },
    }))
}

async fn healthz(State(state): State<Arc<ServeState>>) -> Json<Value> {
    Json(json!({
        "status": "ok",
        "uptime_seconds": state.started_at.elapsed().as_secs(),
        "archive_dir": state.archive_dir.display().to_string(),
        "ingest": state.ingest_enabled.then(|| state.status.snapshot()),
    }))
}

#[derive(Debug, Default, Deserialize)]
struct StreamFilter {
    office: Option<String>,
    pil: Option<String>,
    family: Option<String>,
}

impl StreamFilter {
    fn matches(&self, product: &LiveProduct) -> bool {
        if let Some(office) = &self.office
            && !product.cccc.eq_ignore_ascii_case(office)
        {
            return false;
        }
        if let Some(pil) = &self.pil
            && !product
                .awips_id
                .to_ascii_uppercase()
                .starts_with(&pil.to_ascii_uppercase())
        {
            return false;
        }
        if let Some(family) = &self.family {
            let Some(metadata) = &product.metadata else {
                return false;
            };
            if !family_slug(metadata.family).eq_ignore_ascii_case(family) {
                return false;
            }
        }
        true
    }
}

async fn stream(
    State(state): State<Arc<ServeState>>,
    Query(filter): Query<StreamFilter>,
) -> Response {
    if !state.ingest_enabled {
        return error_response(
            StatusCode::SERVICE_UNAVAILABLE,
            "live stream unavailable: server is running with --no-ingest",
        );
    }
    let receiver = state.live.subscribe();
    let events = BroadcastStream::new(receiver).filter_map(move |item| match item {
        Ok(product) if filter.matches(&product) => Some(Ok::<Event, std::convert::Infallible>(
            Event::default().event("product").data(
                serde_json::to_string(&*product)
                    .unwrap_or_else(|_| "{\"error\":\"serialization failed\"}".to_owned()),
            ),
        )),
        // Filtered-out products and lagged-receiver gaps both just skip.
        _ => None,
    });
    Sse::new(events)
        .keep_alive(
            KeepAlive::new()
                .interval(Duration::from_secs(15))
                .text("ping"),
        )
        .into_response()
}

#[derive(Debug, Deserialize)]
struct WarningQuery {
    at: Option<String>,
    days: Option<u32>,
    families: Option<String>,
}

async fn warnings_active(
    State(state): State<Arc<ServeState>>,
    Query(query): Query<WarningQuery>,
) -> Response {
    let reference = match parse_reference(query.at.as_deref()) {
        Ok(reference) => reference,
        Err(message) => return error_response(StatusCode::BAD_REQUEST, &message),
    };
    let days = query.days.unwrap_or(3).clamp(1, MAX_LOOKBACK_DAYS);
    let all_families = query.families.as_deref() == Some("all");
    let archive = state.archive_dir.clone();

    run_blocking(move || {
        let files = collect_scoped_files(&archive, reference, days, |family| {
            all_families || vtec_relevant_family(family)
        })?;
        let report = active_warnings_in_files(archive, files, reference, None)
            .map_err(|err| err.to_string())?;
        serde_json::to_value(report).map_err(|err| err.to_string())
    })
    .await
}

#[derive(Debug, Deserialize)]
struct TimelineQuery {
    at: Option<String>,
    days: Option<u32>,
}

async fn timeline(
    State(state): State<Arc<ServeState>>,
    Query(query): Query<TimelineQuery>,
) -> Response {
    let reference = match parse_reference(query.at.as_deref()) {
        Ok(reference) => reference,
        Err(message) => return error_response(StatusCode::BAD_REQUEST, &message),
    };
    let query_time = query.at.is_some().then_some(reference);
    let days = query.days.unwrap_or(2).clamp(1, MAX_LOOKBACK_DAYS);
    let archive = state.archive_dir.clone();

    run_blocking(move || {
        let files = collect_scoped_files(&archive, reference, days, vtec_relevant_family)?;
        let report = polygon_timeline_in_files(archive, files, query_time, None)
            .map_err(|err| err.to_string())?;
        serde_json::to_value(report).map_err(|err| err.to_string())
    })
    .await
}

#[derive(Debug, Deserialize)]
struct RecentQuery {
    limit: Option<usize>,
    days: Option<u32>,
    office: Option<String>,
    pil: Option<String>,
    family: Option<String>,
}

async fn products_recent(
    State(state): State<Arc<ServeState>>,
    Query(query): Query<RecentQuery>,
) -> Response {
    let limit = query.limit.unwrap_or(100).clamp(1, MAX_RECENT_LIMIT);
    let days = query.days.unwrap_or(2).clamp(1, MAX_LOOKBACK_DAYS);
    let archive = state.archive_dir.clone();

    run_blocking(move || {
        let reference = OffsetDateTime::now_utc();
        let mut products = Vec::new();
        for sidecar in collect_scoped_sidecars(&archive, reference, days)? {
            let Ok(bytes) = std::fs::read(&sidecar) else {
                continue;
            };
            let Ok(metadata) = serde_json::from_slice::<Value>(&bytes) else {
                continue;
            };
            if !sidecar_matches(&metadata, &query) {
                continue;
            }
            let fingerprint = sidecar
                .file_stem()
                .map(|stem| stem.to_string_lossy().into_owned());
            products.push(json!({
                "fingerprint": fingerprint,
                "metadata": metadata,
            }));
        }
        // Lexicographic sort on RFC3339 captured_at equals chronological.
        products.sort_by(|left, right| {
            let left_at = left["metadata"]["captured_at"].as_str().unwrap_or("");
            let right_at = right["metadata"]["captured_at"].as_str().unwrap_or("");
            right_at.cmp(left_at)
        });
        products.truncate(limit);
        Ok(json!({
            "count": products.len(),
            "lookback_days": days,
            "products": products,
        }))
    })
    .await
}

#[derive(Debug, Deserialize)]
struct LookupQuery {
    days: Option<u32>,
}

async fn product_by_fingerprint(
    State(state): State<Arc<ServeState>>,
    AxumPath(fingerprint): AxumPath<String>,
    Query(query): Query<LookupQuery>,
) -> Response {
    if fingerprint.is_empty() || !fingerprint.chars().all(|ch| ch.is_ascii_alphanumeric()) {
        return error_response(StatusCode::BAD_REQUEST, "invalid fingerprint");
    }
    let days = query.days.unwrap_or(31).clamp(1, MAX_LOOKBACK_DAYS);
    let archive = state.archive_dir.clone();

    let result = run_blocking_raw(move || {
        let reference = OffsetDateTime::now_utc();
        let target = format!("{fingerprint}.json");
        for sidecar in collect_scoped_sidecars(&archive, reference, days)? {
            if sidecar
                .file_name()
                .is_none_or(|name| name != target.as_str())
            {
                continue;
            }
            let metadata = std::fs::read(&sidecar)
                .ok()
                .and_then(|bytes| serde_json::from_slice::<Value>(&bytes).ok());
            let raw = raw_sibling(&sidecar)
                .and_then(|path| std::fs::read_to_string(path).ok())
                .unwrap_or_default();
            return Ok(Some(json!({
                "fingerprint": fingerprint,
                "metadata": metadata,
                "raw": raw,
            })));
        }
        Ok(None)
    })
    .await;

    match result {
        Ok(Some(value)) => Json(value).into_response(),
        Ok(None) => error_response(
            StatusCode::NOT_FOUND,
            "fingerprint not found in lookback window; widen with ?days=",
        ),
        Err(message) => error_response(StatusCode::INTERNAL_SERVER_ERROR, &message),
    }
}

fn sidecar_matches(metadata: &Value, query: &RecentQuery) -> bool {
    if let Some(office) = &query.office {
        let cccc = metadata["cccc"].as_str().unwrap_or("");
        if !cccc.eq_ignore_ascii_case(office) {
            return false;
        }
    }
    if let Some(pil) = &query.pil {
        let awips = metadata["awips_id"].as_str().unwrap_or("");
        if !awips
            .to_ascii_uppercase()
            .starts_with(&pil.to_ascii_uppercase())
        {
            return false;
        }
    }
    if let Some(family) = &query.family {
        let stored = metadata["family"].as_str().unwrap_or("");
        let slug = serde_json::from_value::<crate::product::ProductFamily>(Value::String(
            stored.to_owned(),
        ))
        .map(family_slug)
        .unwrap_or("unknown");
        if !slug.eq_ignore_ascii_case(family) && !stored.eq_ignore_ascii_case(family) {
            return false;
        }
    }
    true
}

/// Families whose archive directories can carry VTEC lifecycle messages.
/// Discussions, forecasts, and administrative chatter are the bulk of feed
/// volume and never carry warning VTEC, so warning scans skip them.
fn vtec_relevant_family(family_dir: &str) -> bool {
    !matches!(family_dir, "discussion" | "forecast" | "administrative")
}

fn parse_reference(at: Option<&str>) -> Result<OffsetDateTime, String> {
    match at {
        None | Some("now") => Ok(OffsetDateTime::now_utc()),
        Some(value) => OffsetDateTime::parse(value, &Rfc3339).map_err(|err| {
            format!("invalid 'at' (want RFC3339 UTC, e.g. 2026-06-09T05:51:00Z): {err}")
        }),
    }
}

/// Existing `yyyy/mm/dd` capture-date partition directories within `days - 1`
/// days on either side of `reference`, clamped forward to today. Partitions
/// record *capture* time; for live queries (`at` = now) this is a pure
/// lookback, while historical `at` values also scan forward because lifecycle
/// messages for an event keep arriving after the reference instant.
fn day_dirs(archive: &Path, reference: OffsetDateTime, days: u32) -> Vec<PathBuf> {
    let span = time::Duration::days(i64::from(days.saturating_sub(1)));
    let today = OffsetDateTime::now_utc().date();
    let start = reference.date().checked_sub(span).unwrap_or(Date::MIN);
    let mut end = reference.date().checked_add(span).unwrap_or(today);
    if end > today {
        end = today;
    }

    let mut dirs = Vec::new();
    let mut date = start;
    while date <= end {
        let dir = archive.join(format!(
            "{:04}/{:02}/{:02}",
            date.year(),
            u8::from(date.month()),
            date.day()
        ));
        if dir.is_dir() {
            dirs.push(dir);
        }
        match date.next_day() {
            Some(next) => date = next,
            None => break,
        }
    }
    dirs
}

/// Raw record files (not `.json` sidecars) under the scoped date partitions,
/// keeping only files whose family directory passes `keep_family`.
fn collect_scoped_files(
    archive: &Path,
    reference: OffsetDateTime,
    days: u32,
    keep_family: impl Fn(&str) -> bool,
) -> Result<Vec<PathBuf>, String> {
    let mut files = Vec::new();
    for day_dir in day_dirs(archive, reference, days) {
        walk_records(&day_dir, &mut |path| {
            if path.extension().is_some_and(|ext| ext == "json") {
                return;
            }
            let family = path
                .parent()
                .and_then(|parent| parent.file_name())
                .map(|name| name.to_string_lossy().into_owned())
                .unwrap_or_default();
            if keep_family(&family) {
                files.push(path.to_path_buf());
            }
        })
        .map_err(|err| format!("failed to scan {}: {err}", day_dir.display()))?;
    }
    files.sort();
    Ok(files)
}

/// `.json` metadata sidecars under the scoped date partitions.
fn collect_scoped_sidecars(
    archive: &Path,
    reference: OffsetDateTime,
    days: u32,
) -> Result<Vec<PathBuf>, String> {
    let mut files = Vec::new();
    for day_dir in day_dirs(archive, reference, days) {
        walk_records(&day_dir, &mut |path| {
            if path.extension().is_some_and(|ext| ext == "json") {
                files.push(path.to_path_buf());
            }
        })
        .map_err(|err| format!("failed to scan {}: {err}", day_dir.display()))?;
    }
    Ok(files)
}

fn walk_records(dir: &Path, visit: &mut impl FnMut(&Path)) -> std::io::Result<()> {
    for entry in std::fs::read_dir(dir)? {
        let entry = entry?;
        let path = entry.path();
        if entry.file_type()?.is_dir() {
            walk_records(&path, visit)?;
        } else {
            visit(&path);
        }
    }
    Ok(())
}

fn raw_sibling(sidecar: &Path) -> Option<PathBuf> {
    let stem = sidecar.file_stem()?;
    let parent = sidecar.parent()?;
    for extension in ["xml", "txt", "wmo"] {
        let candidate = parent.join(format!("{}.{extension}", stem.to_string_lossy()));
        if candidate.is_file() {
            return Some(candidate);
        }
    }
    None
}

async fn run_blocking(work: impl FnOnce() -> Result<Value, String> + Send + 'static) -> Response {
    match run_blocking_raw(work).await {
        Ok(value) => Json(value).into_response(),
        Err(message) => error_response(StatusCode::INTERNAL_SERVER_ERROR, &message),
    }
}

async fn run_blocking_raw<T: Send + 'static>(
    work: impl FnOnce() -> Result<T, String> + Send + 'static,
) -> Result<T, String> {
    tokio::task::spawn_blocking(work)
        .await
        .map_err(|err| format!("blocking task failed: {err}"))?
}

fn error_response(status: StatusCode, message: &str) -> Response {
    (status, Json(json!({ "error": message }))).into_response()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn product(cccc: &str, awips: &str) -> LiveProduct {
        LiveProduct {
            fingerprint: None,
            duplicate: false,
            cccc: cccc.to_owned(),
            ttaaii: "WUUS53".to_owned(),
            awips_id: awips.to_owned(),
            issue: None,
            metadata: None,
            raw_bulletin: String::new(),
        }
    }

    #[test]
    fn stream_filter_office_and_pil() {
        let filter = StreamFilter {
            office: Some("klot".to_owned()),
            pil: Some("tor".to_owned()),
            family: None,
        };
        assert!(filter.matches(&product("KLOT", "TORLOT")));
        assert!(!filter.matches(&product("KDMX", "TORDMX")));
        assert!(!filter.matches(&product("KLOT", "SVRLOT")));
    }

    #[test]
    fn family_filter_requires_metadata() {
        let filter = StreamFilter {
            office: None,
            pil: None,
            family: Some("tornado".to_owned()),
        };
        assert!(!filter.matches(&product("KLOT", "TORLOT")));
    }

    #[test]
    fn reference_parsing() {
        assert!(parse_reference(None).is_ok());
        assert!(parse_reference(Some("now")).is_ok());
        assert!(parse_reference(Some("2026-06-09T05:51:00Z")).is_ok());
        assert!(parse_reference(Some("yesterday")).is_err());
    }
}
