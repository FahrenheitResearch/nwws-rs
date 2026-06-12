#![cfg(feature = "serve")]

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use http_body_util::BodyExt;
use nwws_rs::serve::{LiveProduct, ServeState, app};
use nwws_rs::{ArchiveStore, DedupeStore, IngestHint, IngestService, MessageRouter};
use tower::ServiceExt;

const TORNADO_XML: &str = include_str!("fixtures/nwws_oi_tornado_warning.xml");

/// The fixture warning's VTEC window is 2026-04-21T16:00Z to 16:30Z. Server
/// day scoping is a window around `at` clamped to today, so reach from the
/// event date to the capture date with a generous `days` value.
const FIXTURE_ACTIVE_AT: &str = "2026-04-21T16:25:00Z";

fn build_archive(label: &str) -> PathBuf {
    let root = std::env::temp_dir().join(format!("nwws-serve-{label}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    std::fs::create_dir_all(&root).expect("create temp archive");
    let router = MessageRouter::new(Some(ArchiveStore::new(&root)));
    let dedupe = DedupeStore::open(root.join("state").join("dedupe.txt")).expect("dedupe");
    let mut service = IngestService::new(router, dedupe);
    let report = service
        .process_bytes(IngestHint::OpenInterface, TORNADO_XML.trim().as_bytes())
        .expect("ingest fixture");
    assert_eq!(report.records.len(), 1, "fixture must archive one record");
    root
}

async fn get_json(state: Arc<ServeState>, uri: &str) -> (StatusCode, serde_json::Value) {
    let response = app(state)
        .oneshot(Request::get(uri).body(Body::empty()).expect("request"))
        .await
        .expect("response");
    let status = response.status();
    let bytes = response
        .into_body()
        .collect()
        .await
        .expect("body")
        .to_bytes();
    let value = serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null);
    (status, value)
}

#[tokio::test]
async fn healthz_reports_no_ingest() {
    let archive = build_archive("healthz");
    let (state, _) = ServeState::new(archive.clone(), false);
    let (status, body) = get_json(state, "/healthz").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["status"], "ok");
    assert!(body["ingest"].is_null());
    let _ = std::fs::remove_dir_all(&archive);
}

#[tokio::test]
async fn recent_products_lists_and_filters() {
    let archive = build_archive("recent");
    let (state, _) = ServeState::new(archive.clone(), false);

    let (status, body) = get_json(state.clone(), "/v1/products/recent").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["count"], 1);
    let product = &body["products"][0];
    assert_eq!(product["metadata"]["cccc"], "KLOT");
    assert_eq!(product["metadata"]["awips_id"], "TORLOT");
    assert!(product["fingerprint"].is_string());

    let (_, hit) = get_json(state.clone(), "/v1/products/recent?office=klot&pil=TOR").await;
    assert_eq!(hit["count"], 1);
    let (_, family_hit) = get_json(state.clone(), "/v1/products/recent?family=tornado").await;
    assert_eq!(family_hit["count"], 1);
    let (_, miss) = get_json(state, "/v1/products/recent?office=KDMX").await;
    assert_eq!(miss["count"], 0);
    let _ = std::fs::remove_dir_all(&archive);
}

#[tokio::test]
async fn product_lookup_round_trips_raw_text() {
    let archive = build_archive("lookup");
    let (state, _) = ServeState::new(archive.clone(), false);

    let (_, listing) = get_json(state.clone(), "/v1/products/recent").await;
    let fingerprint = listing["products"][0]["fingerprint"]
        .as_str()
        .expect("fingerprint")
        .to_owned();

    let (status, body) = get_json(state.clone(), &format!("/v1/products/{fingerprint}")).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["metadata"]["ttaaii"], "WUUS53");
    assert!(
        body["raw"]
            .as_str()
            .expect("raw text")
            .contains("Tornado Warning")
    );

    let (status, _) = get_json(state, "/v1/products/00000000deadbeef").await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    let _ = std::fs::remove_dir_all(&archive);
}

#[tokio::test]
async fn active_warnings_resolves_fixture_window() {
    let archive = build_archive("active");
    let (state, _) = ServeState::new(archive.clone(), false);

    let (status, body) = get_json(
        state.clone(),
        &format!("/v1/warnings/active?at={FIXTURE_ACTIVE_AT}&days=92"),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["active_records"], 1, "report: {body}");
    assert_eq!(body["records"][0]["office"], "KLOT");

    // After VTEC expiry the same scan must come back empty.
    let (_, expired) = get_json(state, "/v1/warnings/active?at=2026-04-21T17:00:00Z&days=92").await;
    assert_eq!(expired["active_records"], 0);
    let _ = std::fs::remove_dir_all(&archive);
}

#[tokio::test]
async fn timeline_reports_lifecycle() {
    let archive = build_archive("timeline");
    let (state, _) = ServeState::new(archive.clone(), false);

    let (status, body) = get_json(
        state,
        &format!("/v1/timeline?at={FIXTURE_ACTIVE_AT}&days=92"),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["warning_records"], 1, "report: {body}");
    let _ = std::fs::remove_dir_all(&archive);
}

#[tokio::test]
async fn stream_unavailable_without_ingest() {
    let archive = build_archive("stream503");
    let (state, _) = ServeState::new(archive.clone(), false);
    let (status, body) = get_json(state, "/v1/stream").await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    assert!(body["error"].as_str().unwrap_or("").contains("no-ingest"));
    let _ = std::fs::remove_dir_all(&archive);
}

#[tokio::test]
async fn stream_delivers_filtered_live_products() {
    let archive = build_archive("sse");
    let (state, _) = ServeState::new(archive.clone(), true);
    let sender = state.live_sender();

    let response = app(state)
        .oneshot(
            Request::get("/v1/stream?office=KLOT")
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("response");
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response
            .headers()
            .get("content-type")
            .and_then(|value| value.to_str().ok()),
        Some("text/event-stream")
    );

    // Subscription exists once the handler returned; KDMX must be filtered
    // out, KLOT must arrive as the first SSE frame.
    sender
        .send(Arc::new(live_product("KDMX", "TORDMX")))
        .expect("send filtered product");
    sender
        .send(Arc::new(live_product("KLOT", "TORLOT")))
        .expect("send matching product");

    let mut body = response.into_body();
    let frame = tokio::time::timeout(Duration::from_secs(5), body.frame())
        .await
        .expect("frame before timeout")
        .expect("stream not ended")
        .expect("frame ok");
    let text = String::from_utf8_lossy(frame.data_ref().expect("data frame")).into_owned();
    assert!(text.contains("event: product"), "frame: {text}");
    assert!(text.contains("KLOT"), "frame: {text}");
    assert!(!text.contains("KDMX"), "frame: {text}");
    let _ = std::fs::remove_dir_all(&archive);
}

fn live_product(cccc: &str, awips: &str) -> LiveProduct {
    LiveProduct {
        fingerprint: Some("test".to_owned()),
        duplicate: false,
        cccc: cccc.to_owned(),
        ttaaii: "WUUS53".to_owned(),
        awips_id: awips.to_owned(),
        issue: None,
        metadata: None,
        raw_bulletin: "WUUS53 TEST".to_owned(),
    }
}
