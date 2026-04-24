use std::collections::BTreeMap;
use std::fs;
use std::io::{self, ErrorKind as IoErrorKind};
use std::ops::Range;
use std::path::{Path, PathBuf};

use serde::Serialize;
use time::format_description::well_known::Rfc3339;
use time::{Date, Month, OffsetDateTime, PrimitiveDateTime, Time, UtcOffset};

use crate::api::ApiError;
use crate::geo::GeoPoint;
use crate::ingest::{IngestHint, ParsedInput, parse_with_hint};
use crate::product::{
    NwwsContent, ProductFamily, ProductSegment, SegmentTag, WarningActionTag, WarningTextTag,
    WarningTextTagKind,
};
use crate::ugc::{UgcCode, UgcKind, UgcString};
use crate::vtec::{Phenomenon, Pvtec, Significance, VtecAction};

pub type Result<T> = std::result::Result<T, ApiError>;

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct WarningByteRange {
    pub start: usize,
    pub end: usize,
}

impl WarningByteRange {
    fn from_range(range: &Range<usize>) -> Self {
        Self {
            start: range.start,
            end: range.end,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum WarningLifecycleStatus {
    Future,
    Pending,
    Active,
    Superseded,
    Canceled,
    Expired,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct WarningPoint {
    pub lat: f32,
    pub lon: f32,
}

impl WarningPoint {
    fn from_geo_point(point: GeoPoint, office: &str) -> Self {
        Self {
            lat: round2(point.latitude_degrees()),
            lon: round2(normalize_longitude(point.longitude_degrees(), office)),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct WarningPolygon {
    pub raw: String,
    pub points: Vec<WarningPoint>,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct WarningTimeMotion {
    pub raw: String,
    pub time: String,
    pub direction_degrees: u16,
    pub speed_knots: u8,
    pub locations: Vec<WarningPoint>,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct WarningTags {
    pub tornado: Option<String>,
    pub flash_flood_observed: bool,
    pub flash_flood_emergency: bool,
    pub hail_inches: Option<f32>,
    pub wind_mph: Option<u16>,
    pub damage_threat: Option<String>,
    pub text_tags: Vec<WarningTextTag>,
    pub actions: Vec<WarningActionTag>,
}

impl WarningTags {
    fn from_segment(segment: &ProductSegment<'_>) -> Self {
        let parsed_tags = segment.warning_tags();
        let mut tornado = None;
        let mut flash_flood_observed = false;
        let mut explicit_flash_flood_emergency = false;
        let mut hail_inches = None;
        let mut wind_mph = None;
        let mut raw_damage_threat = None;

        for tag in &parsed_tags.text_tags {
            match tag.kind {
                WarningTextTagKind::Tornado => tornado = Some(tag.normalized_value.clone()),
                WarningTextTagKind::MaxHailSize => {
                    if let Some(value) = tag.numeric_value {
                        hail_inches = Some(round2(value));
                    }
                }
                WarningTextTagKind::MaxWindGust => {
                    if let Some(value) = tag.numeric_value {
                        wind_mph = Some(value.round() as u16);
                    }
                }
                WarningTextTagKind::FlashFloodDamageThreat
                | WarningTextTagKind::TstmDamageThreat
                | WarningTextTagKind::TornadoDamageThreat => {
                    raw_damage_threat = Some(tag.normalized_value.clone());
                }
                WarningTextTagKind::HailThreat
                | WarningTextTagKind::WindThreat
                | WarningTextTagKind::Threat
                | WarningTextTagKind::Source
                | WarningTextTagKind::Impact => {}
            }
        }

        for tag in &segment.tags.tags {
            match tag {
                SegmentTag::TornadoObserved => tornado = Some("OBSERVED".to_owned()),
                SegmentTag::TornadoRadarIndicated => tornado = Some("RADAR INDICATED".to_owned()),
                SegmentTag::TornadoPossible => tornado = Some("POSSIBLE".to_owned()),
                SegmentTag::FlashFloodObserved => flash_flood_observed = true,
                SegmentTag::FlashFloodEmergency => explicit_flash_flood_emergency = true,
                SegmentTag::HailInches(value) => hail_inches = Some(round2(*value)),
                SegmentTag::WindMph(value) => wind_mph = Some(*value),
                SegmentTag::DamageThreat(value) => raw_damage_threat = Some((*value).to_owned()),
            }
        }

        let is_flash_flood_product = segment
            .pvtec
            .iter()
            .any(|pvtec| pvtec.phenomenon().as_str() == "FF");
        let flash_flood_emergency = explicit_flash_flood_emergency
            || (is_flash_flood_product && raw_damage_threat.as_deref() == Some("CATASTROPHIC"));
        let damage_threat = if is_flash_flood_product {
            None
        } else {
            raw_damage_threat
        };

        Self {
            tornado,
            flash_flood_observed,
            flash_flood_emergency,
            hail_inches,
            wind_mph,
            damage_threat,
            text_tags: parsed_tags.text_tags,
            actions: parsed_tags.actions,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct WarningTimelineRecord {
    pub record_key: String,
    pub event_id: String,
    pub source_path: PathBuf,
    pub byte_range: Option<WarningByteRange>,
    pub message_index: usize,
    pub segment_index: usize,
    pub vtec_index: usize,
    pub heading: String,
    pub issued_at: Option<String>,
    pub wrapper_id: Option<String>,
    pub wrapper_issued_at: Option<String>,
    pub office: String,
    pub message_office: String,
    pub awips_id: Option<String>,
    pub product_family: String,
    pub event_family: String,
    pub event_class: String,
    pub action: String,
    pub phenomenon: String,
    pub significance: String,
    pub event_tracking_number: u16,
    pub valid_start: Option<String>,
    pub valid_end: Option<String>,
    pub expires_at: Option<String>,
    pub canceled_at: Option<String>,
    pub updated_at: Option<String>,
    pub lifecycle_status: Option<WarningLifecycleStatus>,
    pub vtec: String,
    pub ugc_raw: String,
    pub ugc_purge_time: String,
    pub ugcs: Vec<String>,
    pub headline: Option<String>,
    pub tags: WarningTags,
    pub polygon: Option<WarningPolygon>,
    pub time_mot_loc: Option<WarningTimeMotion>,
    pub raw_bulletin_blake3: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct WarningTimelineFailure {
    pub path: PathBuf,
    pub error: String,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct WarningTimelineReport {
    pub root: PathBuf,
    pub query_time_utc: Option<String>,
    pub scanned_files: usize,
    pub parsed_files: usize,
    pub messages: usize,
    pub warning_records: usize,
    pub failures: usize,
    pub records: Vec<WarningTimelineRecord>,
    pub errors: Vec<WarningTimelineFailure>,
}

pub const AREA_TIME_POLYGON_METRICS_SCHEMA: &str = "warning.area_time_polygon_metrics.v1";
pub const AREA_TIME_POLYGON_METRICS_METHOD: &str = "planar-lon-lat-shoelace-convex-clip-v1";

const AREA_TIME_POLYGON_METRICS_LIMITATIONS: &[&str] = &[
    "Polygon area is computed in lon/lat square-degrees; it is not geodesic or equal-area.",
    "Polygon overlap uses deterministic planar clipping and is returned only for simple convex polygons.",
    "Dateline, pole, and earth-curvature effects are not modeled.",
];

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct WarningAreaTimePolygonMetrics {
    pub schema: &'static str,
    pub method: &'static str,
    pub limitations: Vec<&'static str>,
    pub left_record_key: String,
    pub right_record_key: String,
    pub left_event_id: String,
    pub right_event_id: String,
    pub left_interval_start: Option<String>,
    pub left_interval_end: Option<String>,
    pub right_interval_start: Option<String>,
    pub right_interval_end: Option<String>,
    pub left_duration_seconds: Option<i64>,
    pub right_duration_seconds: Option<i64>,
    pub time_overlap_seconds: Option<i64>,
    pub time_union_seconds: Option<i64>,
    pub time_overlap_ratio: Option<f64>,
    pub left_area_square_degrees: Option<f64>,
    pub right_area_square_degrees: Option<f64>,
    pub polygon_overlap_area_square_degrees: Option<f64>,
    pub polygon_union_area_square_degrees: Option<f64>,
    pub polygon_overlap_ratio: Option<f64>,
    pub left_area_time_square_degree_seconds: Option<f64>,
    pub right_area_time_square_degree_seconds: Option<f64>,
    pub overlap_area_time_square_degree_seconds: Option<f64>,
    pub union_area_time_square_degree_seconds: Option<f64>,
    pub area_time_overlap_ratio: Option<f64>,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct TimelineSortKey {
    issued_at: Option<PrimitiveDateTime>,
    source_path: PathBuf,
    message_index: usize,
    segment_index: usize,
    vtec_index: usize,
}

#[derive(Debug, Clone)]
struct TimelineRecordState {
    sort_key: TimelineSortKey,
    issued_at: Option<PrimitiveDateTime>,
    valid_start: Option<PrimitiveDateTime>,
    valid_end: Option<PrimitiveDateTime>,
    action: VtecAction,
    record: WarningTimelineRecord,
}

#[derive(Debug, Clone)]
struct MessageContext {
    source_path: PathBuf,
    byte_range: Option<WarningByteRange>,
    message_index: usize,
    wrapper_id: Option<String>,
    wrapper_issue: Option<OffsetDateTime>,
    query_time: Option<PrimitiveDateTime>,
}

#[derive(Debug, Clone, Copy, PartialEq)]
struct WarningInterval {
    start: PrimitiveDateTime,
    end: PrimitiveDateTime,
}

#[derive(Debug, Clone, Copy, PartialEq)]
struct PlanarPoint {
    x: f64,
    y: f64,
}

pub fn polygon_timeline(
    path: impl AsRef<Path>,
    hint_override: Option<IngestHint>,
) -> Result<WarningTimelineReport> {
    polygon_timeline_impl(path.as_ref(), None, hint_override)
}

pub fn polygon_timeline_at(
    path: impl AsRef<Path>,
    query_time_utc: &str,
    hint_override: Option<IngestHint>,
) -> Result<WarningTimelineReport> {
    let query_time = parse_reference_utc(query_time_utc)?;
    polygon_timeline_at_time(path, query_time, hint_override)
}

pub fn polygon_timeline_at_time(
    path: impl AsRef<Path>,
    query_time_utc: OffsetDateTime,
    hint_override: Option<IngestHint>,
) -> Result<WarningTimelineReport> {
    polygon_timeline_impl(
        path.as_ref(),
        Some(query_time_utc.to_offset(UtcOffset::UTC)),
        hint_override,
    )
}

pub fn area_time_polygon_metrics(
    left: &WarningTimelineRecord,
    right: &WarningTimelineRecord,
) -> WarningAreaTimePolygonMetrics {
    let left_interval = warning_interval(left);
    let right_interval = warning_interval(right);
    let left_duration_seconds = left_interval.map(|interval| interval.duration_seconds());
    let right_duration_seconds = right_interval.map(|interval| interval.duration_seconds());
    let time_overlap_seconds =
        left_interval.and_then(|left| right_interval.map(|right| left.overlap_seconds(right)));
    let time_union_seconds = left_duration_seconds.and_then(|left_duration| {
        right_duration_seconds.and_then(|right_duration| {
            time_overlap_seconds.map(|overlap| left_duration + right_duration - overlap)
        })
    });

    let left_area_square_degrees = left
        .polygon
        .as_ref()
        .and_then(warning_polygon_area_square_degrees);
    let right_area_square_degrees = right
        .polygon
        .as_ref()
        .and_then(warning_polygon_area_square_degrees);
    let polygon_overlap_area_square_degrees = left.polygon.as_ref().and_then(|left_polygon| {
        right.polygon.as_ref().and_then(|right_polygon| {
            warning_polygon_overlap_area_square_degrees(left_polygon, right_polygon)
        })
    });
    let polygon_union_area_square_degrees = left_area_square_degrees.and_then(|left_area| {
        right_area_square_degrees.and_then(|right_area| {
            polygon_overlap_area_square_degrees
                .map(|overlap_area| nonnegative(left_area + right_area - overlap_area))
        })
    });

    let left_area_time_square_degree_seconds =
        area_time(left_area_square_degrees, left_duration_seconds);
    let right_area_time_square_degree_seconds =
        area_time(right_area_square_degrees, right_duration_seconds);
    let overlap_area_time_square_degree_seconds =
        area_time(polygon_overlap_area_square_degrees, time_overlap_seconds);
    let union_area_time_square_degree_seconds =
        left_area_time_square_degree_seconds.and_then(|left_area_time| {
            right_area_time_square_degree_seconds.and_then(|right_area_time| {
                overlap_area_time_square_degree_seconds.map(|overlap_area_time| {
                    nonnegative(left_area_time + right_area_time - overlap_area_time)
                })
            })
        });

    WarningAreaTimePolygonMetrics {
        schema: AREA_TIME_POLYGON_METRICS_SCHEMA,
        method: AREA_TIME_POLYGON_METRICS_METHOD,
        limitations: area_time_polygon_metric_limitations().to_vec(),
        left_record_key: left.record_key.clone(),
        right_record_key: right.record_key.clone(),
        left_event_id: left.event_id.clone(),
        right_event_id: right.event_id.clone(),
        left_interval_start: left_interval.map(|interval| format_primitive_utc(interval.start)),
        left_interval_end: left_interval.map(|interval| format_primitive_utc(interval.end)),
        right_interval_start: right_interval.map(|interval| format_primitive_utc(interval.start)),
        right_interval_end: right_interval.map(|interval| format_primitive_utc(interval.end)),
        left_duration_seconds,
        right_duration_seconds,
        time_overlap_seconds,
        time_union_seconds,
        time_overlap_ratio: ratio_i64(time_overlap_seconds, time_union_seconds),
        left_area_square_degrees,
        right_area_square_degrees,
        polygon_overlap_area_square_degrees,
        polygon_union_area_square_degrees,
        polygon_overlap_ratio: ratio_f64(
            polygon_overlap_area_square_degrees,
            polygon_union_area_square_degrees,
        ),
        left_area_time_square_degree_seconds,
        right_area_time_square_degree_seconds,
        overlap_area_time_square_degree_seconds,
        union_area_time_square_degree_seconds,
        area_time_overlap_ratio: ratio_f64(
            overlap_area_time_square_degree_seconds,
            union_area_time_square_degree_seconds,
        ),
    }
}

pub fn area_time_polygon_metric_limitations() -> &'static [&'static str] {
    AREA_TIME_POLYGON_METRICS_LIMITATIONS
}

pub fn warning_interval_duration_seconds(record: &WarningTimelineRecord) -> Option<i64> {
    warning_interval(record).map(|interval| interval.duration_seconds())
}

pub fn warning_interval_overlap_seconds(
    left: &WarningTimelineRecord,
    right: &WarningTimelineRecord,
) -> Option<i64> {
    warning_interval(left)
        .and_then(|left| warning_interval(right).map(|right| left.overlap_seconds(right)))
}

pub fn warning_polygon_area_square_degrees(polygon: &WarningPolygon) -> Option<f64> {
    let points = normalized_planar_points(&polygon.points)?;
    if polygon_self_intersects(&points) {
        return None;
    }

    Some(shoelace_area(&points))
}

pub fn warning_polygon_overlap_area_square_degrees(
    left: &WarningPolygon,
    right: &WarningPolygon,
) -> Option<f64> {
    let left_points = normalized_planar_points(&left.points)?;
    let right_points = normalized_planar_points(&right.points)?;
    if polygon_self_intersects(&left_points) || polygon_self_intersects(&right_points) {
        return None;
    }
    if !is_convex_polygon(&left_points) || !is_convex_polygon(&right_points) {
        return None;
    }

    let clipped = clip_polygon(&left_points, &right_points);
    if clipped.len() < 3 {
        return Some(0.0);
    }

    Some(shoelace_area(&clipped))
}

fn polygon_timeline_impl(
    path: &Path,
    query_time: Option<OffsetDateTime>,
    hint_override: Option<IngestHint>,
) -> Result<WarningTimelineReport> {
    if !path.exists() {
        return Err(io::Error::new(
            IoErrorKind::NotFound,
            format!("path does not exist: {}", path.display()),
        )
        .into());
    }

    let root = if path.is_file() {
        path.parent()
            .unwrap_or_else(|| Path::new("."))
            .to_path_buf()
    } else {
        resolve_scan_root(path)
    };
    let files = collect_inputs(path)?;
    let query_time = query_time.map(|value| value.to_offset(UtcOffset::UTC));
    let query_primitive = query_time.map(primitive_utc);
    let mut states = Vec::new();
    let mut report = WarningTimelineReport {
        root: root.clone(),
        query_time_utc: query_time.map(format_offset_utc),
        scanned_files: 0,
        parsed_files: 0,
        messages: 0,
        warning_records: 0,
        failures: 0,
        records: Vec::new(),
        errors: Vec::new(),
    };

    for file in files {
        report.scanned_files += 1;
        let relative_path = relative_display_path(&root, &file);
        let bytes = match fs::read(&file) {
            Ok(bytes) => bytes,
            Err(err) => {
                report.failures += 1;
                report.errors.push(WarningTimelineFailure {
                    path: relative_path,
                    error: format!("failed to read: {err}"),
                });
                continue;
            }
        };

        let hint = resolve_hint(&file, hint_override);
        match parse_with_hint(hint, &bytes) {
            Ok(parsed) => collect_parsed_records(
                relative_path,
                parsed,
                query_primitive,
                &mut report,
                &mut states,
            ),
            Err(err) => {
                report.failures += 1;
                report.errors.push(WarningTimelineFailure {
                    path: relative_path,
                    error: format!("failed to parse with {hint:?}: {err}"),
                });
            }
        }
    }

    states.sort_by(|left, right| left.sort_key.cmp(&right.sort_key));
    if let Some(query_time) = query_primitive {
        apply_lifecycle_statuses(&mut states, query_time);
    }

    report.warning_records = states.len();
    report.records = states.into_iter().map(|state| state.record).collect();
    Ok(report)
}

fn collect_parsed_records(
    relative_path: PathBuf,
    parsed: ParsedInput<'_>,
    query_time: Option<PrimitiveDateTime>,
    report: &mut WarningTimelineReport,
    states: &mut Vec<TimelineRecordState>,
) {
    match parsed {
        ParsedInput::Bulletin(value) => {
            report.parsed_files += 1;
            report.messages += 1;
            collect_content_records(
                &MessageContext {
                    source_path: relative_path,
                    byte_range: None,
                    message_index: 1,
                    wrapper_id: None,
                    wrapper_issue: None,
                    query_time,
                },
                &value.content,
                states,
            );
        }
        ParsedInput::OpenInterface(value) => match value.content() {
            Ok(content) => {
                report.parsed_files += 1;
                report.messages += 1;
                let wrapper_issue = value
                    .message
                    .payload
                    .as_ref()
                    .map(|payload| payload.issue.to_offset(UtcOffset::UTC));
                collect_content_records(
                    &MessageContext {
                        source_path: relative_path,
                        byte_range: None,
                        message_index: 1,
                        wrapper_id: value.wrapper.as_ref().map(|wrapper| wrapper.id.clone()),
                        wrapper_issue,
                        query_time,
                    },
                    &content,
                    states,
                );
            }
            Err(err) => {
                report.failures += 1;
                report.errors.push(WarningTimelineFailure {
                    path: relative_path,
                    error: err.to_string(),
                });
            }
        },
        ParsedInput::FramedStream(value) => {
            if value.chunks.is_empty() {
                report.failures += 1;
                report.errors.push(WarningTimelineFailure {
                    path: relative_path,
                    error: "no framed messages detected in stream".to_owned(),
                });
                return;
            }

            report.parsed_files += 1;
            for (index, chunk) in value.chunks.iter().enumerate() {
                match NwwsContent::parse_bulletin(chunk.bytes) {
                    Ok(content) => {
                        report.messages += 1;
                        collect_content_records(
                            &MessageContext {
                                source_path: relative_path.clone(),
                                byte_range: Some(WarningByteRange::from_range(&chunk.range)),
                                message_index: index + 1,
                                wrapper_id: None,
                                wrapper_issue: None,
                                query_time,
                            },
                            &content,
                            states,
                        );
                    }
                    Err(err) => {
                        report.failures += 1;
                        report.errors.push(WarningTimelineFailure {
                            path: relative_path.clone(),
                            error: format!("failed to parse framed message {}: {err}", index + 1),
                        });
                    }
                }
            }
        }
    }
}

fn collect_content_records(
    context: &MessageContext,
    content: &NwwsContent<'_>,
    states: &mut Vec<TimelineRecordState>,
) {
    let bulletin = &content.bulletin;
    let message_office = bulletin.heading.cccc();
    let product_family = family_name(content.product.family);
    let raw_bulletin_blake3 = blake3::hash(bulletin.bulletin.as_bytes())
        .to_hex()
        .to_string();

    for (segment_index, segment) in content.product.segments.iter().enumerate() {
        let ugcs = expand_ugc_codes(&segment.ugc);
        let tags = WarningTags::from_segment(segment);
        let polygon = segment
            .lat_lon
            .map(|block| polygon_from_block(block, message_office));
        let time_mot_loc = segment
            .time_mot_loc
            .map(|line| time_motion_from_line(line, message_office));

        for (vtec_index, pvtec) in segment.pvtec.iter().enumerate() {
            if pvtec.significance() != Significance::Warning {
                continue;
            }

            let issued_at = issue_time_for_record(
                bulletin.heading.yygggg(),
                context.wrapper_issue,
                context.query_time,
                pvtec,
            );
            let issued_at_text = issued_at.map(format_primitive_utc);
            let valid_start = pvtec.start_time().datetime();
            let valid_end = pvtec.end_time().datetime();
            let valid_start_text = valid_start.map(format_primitive_utc);
            let valid_end_text = valid_end.map(format_primitive_utc);
            let expires_at = valid_end_text.clone();
            let canceled_at = if pvtec.action() == VtecAction::Cancel {
                issued_at_text.clone()
            } else {
                None
            };
            let updated_at = if is_update_action(pvtec.action()) {
                issued_at_text.clone()
            } else {
                None
            };
            let event_family =
                family_name_for_phenomenon(pvtec.phenomenon()).unwrap_or(&product_family);
            let event_id = warning_event_id(pvtec);
            let record_key = warning_record_key(
                &event_id,
                &context.source_path,
                context.message_index,
                segment_index + 1,
                vtec_index + 1,
            );

            let record = WarningTimelineRecord {
                record_key,
                event_id: event_id.clone(),
                source_path: context.source_path.clone(),
                byte_range: context.byte_range.clone(),
                message_index: context.message_index,
                segment_index: segment_index + 1,
                vtec_index: vtec_index + 1,
                heading: bulletin.heading.to_string(),
                issued_at: issued_at_text,
                wrapper_id: context.wrapper_id.clone(),
                wrapper_issued_at: context.wrapper_issue.map(format_offset_utc),
                office: pvtec.office_id().to_owned(),
                message_office: message_office.to_owned(),
                awips_id: bulletin
                    .awips_id
                    .as_ref()
                    .map(|value| value.raw().to_owned()),
                product_family: product_family.clone(),
                event_family: event_family.to_owned(),
                event_class: pvtec.event_class().as_str().to_owned(),
                action: pvtec.action().as_str().to_owned(),
                phenomenon: pvtec.phenomenon().as_str().to_owned(),
                significance: pvtec.significance().as_str().to_owned(),
                event_tracking_number: pvtec.event_tracking_number(),
                valid_start: valid_start_text,
                valid_end: valid_end_text,
                expires_at,
                canceled_at,
                updated_at,
                lifecycle_status: None,
                vtec: pvtec.raw().to_owned(),
                ugc_raw: segment.ugc.raw().to_owned(),
                ugc_purge_time: segment.ugc.purge_time().to_string(),
                ugcs: ugcs.clone(),
                headline: segment.headline.map(str::to_owned),
                tags: tags.clone(),
                polygon: polygon.clone(),
                time_mot_loc: time_mot_loc.clone(),
                raw_bulletin_blake3: raw_bulletin_blake3.clone(),
            };

            states.push(TimelineRecordState {
                sort_key: TimelineSortKey {
                    issued_at,
                    source_path: context.source_path.clone(),
                    message_index: context.message_index,
                    segment_index: segment_index + 1,
                    vtec_index: vtec_index + 1,
                },
                issued_at,
                valid_start,
                valid_end,
                action: pvtec.action(),
                record,
            });
        }
    }
}

fn apply_lifecycle_statuses(states: &mut [TimelineRecordState], query_time: PrimitiveDateTime) {
    let mut latest_by_event = BTreeMap::<String, usize>::new();

    for (index, state) in states.iter().enumerate() {
        if state
            .issued_at
            .is_some_and(|issued_at| issued_at > query_time)
        {
            continue;
        }

        let event_id = state.record.event_id.clone();
        if latest_by_event
            .get(&event_id)
            .is_none_or(|existing| states[*existing].sort_key <= state.sort_key)
        {
            latest_by_event.insert(event_id, index);
        }
    }

    let statuses = states
        .iter()
        .enumerate()
        .map(|(index, state)| {
            if state
                .issued_at
                .is_some_and(|issued_at| issued_at > query_time)
            {
                WarningLifecycleStatus::Future
            } else if latest_by_event
                .get(&state.record.event_id)
                .is_some_and(|latest| *latest != index)
            {
                WarningLifecycleStatus::Superseded
            } else {
                latest_record_status(state, query_time)
            }
        })
        .collect::<Vec<_>>();

    for (state, status) in states.iter_mut().zip(statuses) {
        state.record.lifecycle_status = Some(status);
    }
}

fn latest_record_status(
    state: &TimelineRecordState,
    query_time: PrimitiveDateTime,
) -> WarningLifecycleStatus {
    match state.action {
        VtecAction::Cancel => return WarningLifecycleStatus::Canceled,
        VtecAction::Expire => return WarningLifecycleStatus::Expired,
        _ => {}
    }

    if state.valid_start.is_some_and(|start| query_time < start) {
        return WarningLifecycleStatus::Pending;
    }
    if state.valid_end.is_some_and(|end| query_time >= end) {
        return WarningLifecycleStatus::Expired;
    }

    WarningLifecycleStatus::Active
}

impl WarningInterval {
    fn duration_seconds(self) -> i64 {
        (self.end - self.start).whole_seconds()
    }

    fn overlap_seconds(self, other: Self) -> i64 {
        let start = if self.start >= other.start {
            self.start
        } else {
            other.start
        };
        let end = if self.end <= other.end {
            self.end
        } else {
            other.end
        };

        if end <= start {
            0
        } else {
            (end - start).whole_seconds()
        }
    }
}

const PLANAR_EPSILON: f64 = 1.0e-9;

fn warning_interval(record: &WarningTimelineRecord) -> Option<WarningInterval> {
    let start = parse_record_utc(record.valid_start.as_deref())
        .or_else(|| parse_record_utc(record.issued_at.as_deref()))
        .or_else(|| parse_record_utc(record.wrapper_issued_at.as_deref()))?;
    let valid_end = parse_record_utc(record.valid_end.as_deref())
        .or_else(|| parse_record_utc(record.expires_at.as_deref()));
    let canceled_at = parse_record_utc(record.canceled_at.as_deref());
    let end = match (valid_end, canceled_at) {
        (Some(valid_end), Some(canceled_at)) if canceled_at < valid_end => canceled_at,
        (Some(valid_end), _) => valid_end,
        (None, Some(canceled_at)) => canceled_at,
        (None, None) => return None,
    };

    (end > start).then_some(WarningInterval { start, end })
}

fn parse_record_utc(raw: Option<&str>) -> Option<PrimitiveDateTime> {
    raw.and_then(|value| OffsetDateTime::parse(value, &Rfc3339).ok())
        .map(primitive_utc)
}

fn area_time(area: Option<f64>, duration_seconds: Option<i64>) -> Option<f64> {
    area.and_then(|area| duration_seconds.map(|duration| area * duration as f64))
}

fn ratio_i64(numerator: Option<i64>, denominator: Option<i64>) -> Option<f64> {
    numerator
        .and_then(|numerator| denominator.map(|denominator| (numerator, denominator)))
        .and_then(|(numerator, denominator)| {
            (denominator > 0).then_some((numerator as f64 / denominator as f64).clamp(0.0, 1.0))
        })
}

fn ratio_f64(numerator: Option<f64>, denominator: Option<f64>) -> Option<f64> {
    numerator
        .and_then(|numerator| denominator.map(|denominator| (numerator, denominator)))
        .and_then(|(numerator, denominator)| {
            (denominator > PLANAR_EPSILON).then_some((numerator / denominator).clamp(0.0, 1.0))
        })
}

fn nonnegative(value: f64) -> f64 {
    if value.abs() <= PLANAR_EPSILON {
        0.0
    } else {
        value.max(0.0)
    }
}

fn normalized_planar_points(points: &[WarningPoint]) -> Option<Vec<PlanarPoint>> {
    let mut normalized = Vec::with_capacity(points.len());
    for point in points {
        let planar = PlanarPoint {
            x: f64::from(point.lon),
            y: f64::from(point.lat),
        };
        if !planar.x.is_finite() || !planar.y.is_finite() {
            return None;
        }
        if normalized
            .last()
            .is_none_or(|previous| !points_equal(*previous, planar))
        {
            normalized.push(planar);
        }
    }

    if normalized.len() > 1
        && points_equal(
            *normalized.first().expect("checked non-empty"),
            *normalized.last().expect("checked non-empty"),
        )
    {
        normalized.pop();
    }

    (normalized.len() >= 3).then_some(normalized)
}

fn polygon_self_intersects(points: &[PlanarPoint]) -> bool {
    for first in 0..points.len() {
        let first_next = (first + 1) % points.len();
        for second in (first + 1)..points.len() {
            let second_next = (second + 1) % points.len();
            if first == second
                || first_next == second
                || second_next == first
                || (first == 0 && second_next == 0)
            {
                continue;
            }
            if segments_intersect(
                points[first],
                points[first_next],
                points[second],
                points[second_next],
            ) {
                return true;
            }
        }
    }

    false
}

fn segments_intersect(
    first_start: PlanarPoint,
    first_end: PlanarPoint,
    second_start: PlanarPoint,
    second_end: PlanarPoint,
) -> bool {
    let first_second_start = cross(first_start, first_end, second_start);
    let first_second_end = cross(first_start, first_end, second_end);
    let second_first_start = cross(second_start, second_end, first_start);
    let second_first_end = cross(second_start, second_end, first_end);

    if ((first_second_start > PLANAR_EPSILON && first_second_end < -PLANAR_EPSILON)
        || (first_second_start < -PLANAR_EPSILON && first_second_end > PLANAR_EPSILON))
        && ((second_first_start > PLANAR_EPSILON && second_first_end < -PLANAR_EPSILON)
            || (second_first_start < -PLANAR_EPSILON && second_first_end > PLANAR_EPSILON))
    {
        return true;
    }

    (first_second_start.abs() <= PLANAR_EPSILON && on_segment(first_start, second_start, first_end))
        || (first_second_end.abs() <= PLANAR_EPSILON
            && on_segment(first_start, second_end, first_end))
        || (second_first_start.abs() <= PLANAR_EPSILON
            && on_segment(second_start, first_start, second_end))
        || (second_first_end.abs() <= PLANAR_EPSILON
            && on_segment(second_start, first_end, second_end))
}

fn on_segment(start: PlanarPoint, point: PlanarPoint, end: PlanarPoint) -> bool {
    point.x >= start.x.min(end.x) - PLANAR_EPSILON
        && point.x <= start.x.max(end.x) + PLANAR_EPSILON
        && point.y >= start.y.min(end.y) - PLANAR_EPSILON
        && point.y <= start.y.max(end.y) + PLANAR_EPSILON
}

fn is_convex_polygon(points: &[PlanarPoint]) -> bool {
    let mut sign = 0.0f64;

    for index in 0..points.len() {
        let turn = cross(
            points[index],
            points[(index + 1) % points.len()],
            points[(index + 2) % points.len()],
        );
        if turn.abs() <= PLANAR_EPSILON {
            continue;
        }
        if sign == 0.0 {
            sign = turn.signum();
        } else if sign * turn < -PLANAR_EPSILON {
            return false;
        }
    }

    sign != 0.0
}

fn clip_polygon(subject: &[PlanarPoint], clip: &[PlanarPoint]) -> Vec<PlanarPoint> {
    let mut output = subject.to_vec();
    let clip_is_counter_clockwise = signed_area(clip) >= 0.0;

    for index in 0..clip.len() {
        if output.is_empty() {
            break;
        }

        let edge_start = clip[index];
        let edge_end = clip[(index + 1) % clip.len()];
        let input = output;
        output = Vec::new();
        let mut previous = *input.last().expect("checked non-empty");
        let mut previous_inside =
            inside_clip_edge(previous, edge_start, edge_end, clip_is_counter_clockwise);

        for current in input {
            let current_inside =
                inside_clip_edge(current, edge_start, edge_end, clip_is_counter_clockwise);
            if current_inside {
                if !previous_inside
                    && let Some(intersection) =
                        line_intersection(previous, current, edge_start, edge_end)
                {
                    output.push(intersection);
                }
                output.push(current);
            } else if previous_inside
                && let Some(intersection) =
                    line_intersection(previous, current, edge_start, edge_end)
            {
                output.push(intersection);
            }

            previous = current;
            previous_inside = current_inside;
        }

        output = dedupe_planar_points(output);
    }

    output
}

fn inside_clip_edge(
    point: PlanarPoint,
    edge_start: PlanarPoint,
    edge_end: PlanarPoint,
    clip_is_counter_clockwise: bool,
) -> bool {
    let side = cross(edge_start, edge_end, point);
    if clip_is_counter_clockwise {
        side >= -PLANAR_EPSILON
    } else {
        side <= PLANAR_EPSILON
    }
}

fn line_intersection(
    segment_start: PlanarPoint,
    segment_end: PlanarPoint,
    edge_start: PlanarPoint,
    edge_end: PlanarPoint,
) -> Option<PlanarPoint> {
    let segment = subtract(segment_end, segment_start);
    let edge = subtract(edge_end, edge_start);
    let denominator = cross_vectors(segment, edge);
    if denominator.abs() <= PLANAR_EPSILON {
        return None;
    }

    let offset = subtract(edge_start, segment_start);
    let scale = cross_vectors(offset, edge) / denominator;
    Some(PlanarPoint {
        x: segment_start.x + scale * segment.x,
        y: segment_start.y + scale * segment.y,
    })
}

fn dedupe_planar_points(points: Vec<PlanarPoint>) -> Vec<PlanarPoint> {
    let mut deduped = Vec::with_capacity(points.len());
    for point in points {
        if deduped
            .last()
            .is_none_or(|previous| !points_equal(*previous, point))
        {
            deduped.push(point);
        }
    }

    if deduped.len() > 1
        && points_equal(
            *deduped.first().expect("checked non-empty"),
            *deduped.last().expect("checked non-empty"),
        )
    {
        deduped.pop();
    }

    deduped
}

fn shoelace_area(points: &[PlanarPoint]) -> f64 {
    signed_area(points).abs()
}

fn signed_area(points: &[PlanarPoint]) -> f64 {
    let mut sum = 0.0;
    for index in 0..points.len() {
        let current = points[index];
        let next = points[(index + 1) % points.len()];
        sum += current.x * next.y - next.x * current.y;
    }

    sum / 2.0
}

fn cross(start: PlanarPoint, end: PlanarPoint, point: PlanarPoint) -> f64 {
    cross_vectors(subtract(end, start), subtract(point, start))
}

fn cross_vectors(left: PlanarPoint, right: PlanarPoint) -> f64 {
    left.x * right.y - left.y * right.x
}

fn subtract(left: PlanarPoint, right: PlanarPoint) -> PlanarPoint {
    PlanarPoint {
        x: left.x - right.x,
        y: left.y - right.y,
    }
}

fn points_equal(left: PlanarPoint, right: PlanarPoint) -> bool {
    (left.x - right.x).abs() <= PLANAR_EPSILON && (left.y - right.y).abs() <= PLANAR_EPSILON
}

fn issue_time_for_record(
    yygggg: &str,
    wrapper_issue: Option<OffsetDateTime>,
    query_time: Option<PrimitiveDateTime>,
    pvtec: &Pvtec,
) -> Option<PrimitiveDateTime> {
    wrapper_issue
        .map(primitive_utc)
        .or_else(|| query_time.and_then(|anchor| infer_wmo_issue_time(yygggg, anchor)))
        .or_else(|| {
            pvtec
                .start_time()
                .datetime()
                .and_then(|anchor| infer_wmo_issue_time(yygggg, anchor))
        })
        .or_else(|| {
            pvtec
                .end_time()
                .datetime()
                .and_then(|anchor| infer_wmo_issue_time(yygggg, anchor))
        })
}

fn polygon_from_block(block: crate::LatLonBlock<'_>, office: &str) -> WarningPolygon {
    WarningPolygon {
        raw: block.raw().to_owned(),
        points: block
            .points()
            .map(|point| WarningPoint::from_geo_point(point, office))
            .collect(),
    }
}

fn time_motion_from_line(line: crate::TimeMotLoc<'_>, office: &str) -> WarningTimeMotion {
    WarningTimeMotion {
        raw: line.raw().to_owned(),
        time: format!("{:02}{:02}Z", line.hour(), line.minute()),
        direction_degrees: line.direction_degrees(),
        speed_knots: line.speed_knots(),
        locations: line
            .locations()
            .map(|point| WarningPoint::from_geo_point(point, office))
            .collect(),
    }
}

fn warning_event_id(pvtec: &Pvtec) -> String {
    format!(
        "{}.{}.{}.{}.{:04}",
        pvtec.office_id(),
        pvtec.event_class().as_str(),
        pvtec.phenomenon().as_str(),
        pvtec.significance().as_str(),
        pvtec.event_tracking_number()
    )
}

fn warning_record_key(
    event_id: &str,
    source_path: &Path,
    message_index: usize,
    segment_index: usize,
    vtec_index: usize,
) -> String {
    format!(
        "{event_id}|source={}|message={message_index}|segment={segment_index}|vtec={vtec_index}",
        source_path.display()
    )
}

fn is_update_action(action: VtecAction) -> bool {
    !matches!(
        action,
        VtecAction::New | VtecAction::Cancel | VtecAction::Expire
    )
}

fn parse_reference_utc(raw: &str) -> Result<OffsetDateTime> {
    Ok(OffsetDateTime::parse(raw, &Rfc3339)?.to_offset(UtcOffset::UTC))
}

fn primitive_utc(value: OffsetDateTime) -> PrimitiveDateTime {
    let value = value.to_offset(UtcOffset::UTC);
    PrimitiveDateTime::new(value.date(), value.time())
}

fn infer_wmo_issue_time(yygggg: &str, reference: PrimitiveDateTime) -> Option<PrimitiveDateTime> {
    let bytes = yygggg.as_bytes();
    if bytes.len() != 6 || !bytes.iter().all(|byte| byte.is_ascii_digit()) {
        return None;
    }

    let day = ascii_dec(bytes[0], bytes[1]);
    let hour = ascii_dec(bytes[2], bytes[3]);
    let minute = ascii_dec(bytes[4], bytes[5]);
    let time = Time::from_hms(hour, minute, 0).ok()?;
    let mut best: Option<(u64, bool, PrimitiveDateTime)> = None;

    for month_offset in [-1, 0, 1] {
        let (year, month) = month_with_offset(reference.year(), reference.month(), month_offset)?;
        let Ok(date) = Date::from_calendar_date(year, month, day) else {
            continue;
        };
        let candidate = PrimitiveDateTime::new(date, time);
        let delta = (candidate - reference).whole_seconds();
        let distance = delta.unsigned_abs();
        let is_future = candidate > reference;
        if best.is_none_or(|(best_distance, best_is_future, _)| {
            distance < best_distance || (distance == best_distance && best_is_future && !is_future)
        }) {
            best = Some((distance, is_future, candidate));
        }
    }

    best.map(|(_, _, candidate)| candidate)
}

fn month_with_offset(year: i32, month: Month, offset: i8) -> Option<(i32, Month)> {
    let mut year = year;
    let mut month = month as i8 + offset;
    while month < 1 {
        month += 12;
        year -= 1;
    }
    while month > 12 {
        month -= 12;
        year += 1;
    }
    Month::try_from(month as u8).ok().map(|month| (year, month))
}

fn format_offset_utc(value: OffsetDateTime) -> String {
    value
        .to_offset(UtcOffset::UTC)
        .format(&Rfc3339)
        .expect("UTC datetimes can be formatted as RFC3339")
}

fn format_primitive_utc(value: PrimitiveDateTime) -> String {
    value
        .assume_utc()
        .format(&Rfc3339)
        .expect("UTC primitive datetimes can be formatted as RFC3339")
}

fn family_name_for_phenomenon(phenomenon: Phenomenon) -> Option<&'static str> {
    match phenomenon {
        Phenomenon::Tornado => Some("tornado"),
        Phenomenon::SevereThunderstorm => Some("severe-thunderstorm"),
        Phenomenon::FlashFlood => Some("flash-flood"),
        Phenomenon::Flood | Phenomenon::FloodForecastPoint => Some("flood"),
        Phenomenon::Marine
        | Phenomenon::SmallCraft
        | Phenomenon::Gale
        | Phenomenon::Storm
        | Phenomenon::HurricaneForceWind => Some("marine"),
        _ => None,
    }
}

fn collect_inputs(path: &Path) -> io::Result<Vec<PathBuf>> {
    if path.is_file() {
        return Ok(vec![path.to_path_buf()]);
    }
    if path.is_dir() {
        return crate::replay::collect_input_paths(resolve_scan_root(path));
    }
    Err(io::Error::new(
        IoErrorKind::NotFound,
        format!("path does not exist: {}", path.display()),
    ))
}

fn resolve_scan_root(path: &Path) -> PathBuf {
    let records = path.join("records");
    if records.is_dir() {
        records
    } else {
        path.to_path_buf()
    }
}

fn resolve_hint(path: &Path, hint_override: Option<IngestHint>) -> IngestHint {
    hint_override.unwrap_or_else(|| crate::replay::infer_hint_from_path(path))
}

fn relative_display_path(root: &Path, path: &Path) -> PathBuf {
    path.strip_prefix(root).unwrap_or(path).to_path_buf()
}

fn expand_ugc_codes(ugc: &UgcString<'_>) -> Vec<String> {
    let mut values = Vec::new();

    for code in ugc.codes() {
        match code {
            UgcCode::Single { .. } | UgcCode::All { .. } | UgcCode::Unspecified { .. } => {
                values.push(code.to_string());
            }
            UgcCode::Range {
                state,
                kind,
                start,
                end,
            } => {
                let kind = ugc_kind_char(*kind);
                for number in *start..=*end {
                    values.push(format!("{state}{kind}{number:03}"));
                }
            }
        }
    }

    values
}

fn ugc_kind_char(kind: UgcKind) -> char {
    match kind {
        UgcKind::County => 'C',
        UgcKind::Zone => 'Z',
    }
}

fn normalize_longitude(raw: f32, office: &str) -> f32 {
    let mut longitude = raw;
    if longitude < 40.0 {
        longitude += 100.0;
    }
    if office == "PGUM" {
        longitude
    } else {
        -longitude
    }
}

fn round2(value: f32) -> f32 {
    (value * 100.0).round() / 100.0
}

fn family_name(family: ProductFamily) -> String {
    match family {
        ProductFamily::Tornado => "tornado",
        ProductFamily::SevereThunderstorm => "severe-thunderstorm",
        ProductFamily::FlashFlood => "flash-flood",
        ProductFamily::Flood => "flood",
        ProductFamily::Marine => "marine",
        ProductFamily::Discussion => "discussion",
        ProductFamily::Forecast => "forecast",
        ProductFamily::Statement => "statement",
        ProductFamily::Hydrology => "hydrology",
        ProductFamily::Watch => "watch",
        ProductFamily::Advisory => "advisory",
        ProductFamily::Administrative => "administrative",
        ProductFamily::Unknown => "unknown",
    }
    .to_owned()
}

fn ascii_dec(tens: u8, ones: u8) -> u8 {
    (tens - b'0') * 10 + (ones - b'0')
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::path::PathBuf;
    use std::time::{SystemTime, UNIX_EPOCH};

    use super::{
        WarningLifecycleStatus, WarningPoint, WarningPolygon, WarningTags, WarningTimelineRecord,
        area_time_polygon_metrics, polygon_timeline_at, warning_interval_overlap_seconds,
        warning_polygon_area_square_degrees, warning_polygon_overlap_area_square_degrees,
    };
    use crate::ingest::IngestHint;
    use crate::product::{WarningActionKind, WarningTextTagKind};

    #[test]
    fn area_time_polygon_metrics_returns_deterministic_pair_values() {
        let left = test_record(
            "left",
            "KAAA.O.TO.W.0001",
            "2026-04-21T16:00:00Z",
            "2026-04-21T17:00:00Z",
            square_polygon(0.0, 0.0, 2.0, 2.0),
        );
        let right = test_record(
            "right",
            "KAAA.O.TO.W.0002",
            "2026-04-21T16:30:00Z",
            "2026-04-21T17:30:00Z",
            square_polygon(1.0, 1.0, 3.0, 3.0),
        );

        let metrics = area_time_polygon_metrics(&left, &right);

        assert_eq!(metrics.schema, "warning.area_time_polygon_metrics.v1");
        assert_eq!(metrics.method, "planar-lon-lat-shoelace-convex-clip-v1");
        assert!(
            metrics
                .limitations
                .iter()
                .any(|limitation| limitation.contains("square-degrees"))
        );
        assert_eq!(metrics.left_duration_seconds, Some(3600));
        assert_eq!(metrics.right_duration_seconds, Some(3600));
        assert_eq!(metrics.time_overlap_seconds, Some(1800));
        assert_eq!(metrics.time_union_seconds, Some(5400));
        assert_approx(metrics.time_overlap_ratio.unwrap(), 1.0 / 3.0);
        assert_approx(metrics.left_area_square_degrees.unwrap(), 4.0);
        assert_approx(metrics.right_area_square_degrees.unwrap(), 4.0);
        assert_approx(metrics.polygon_overlap_area_square_degrees.unwrap(), 1.0);
        assert_approx(metrics.polygon_union_area_square_degrees.unwrap(), 7.0);
        assert_approx(metrics.polygon_overlap_ratio.unwrap(), 1.0 / 7.0);
        assert_approx(
            metrics.left_area_time_square_degree_seconds.unwrap(),
            14_400.0,
        );
        assert_approx(
            metrics.right_area_time_square_degree_seconds.unwrap(),
            14_400.0,
        );
        assert_approx(
            metrics.overlap_area_time_square_degree_seconds.unwrap(),
            1_800.0,
        );
        assert_approx(
            metrics.union_area_time_square_degree_seconds.unwrap(),
            27_000.0,
        );
        assert_approx(metrics.area_time_overlap_ratio.unwrap(), 1.0 / 15.0);
    }

    #[test]
    fn area_time_polygon_helpers_use_parsed_timeline_records() {
        let root = temp_dir_path("nwws_rs_warning_area_time_metrics");
        fs::create_dir_all(&root).unwrap();
        fs::write(
            root.join("warning.txt"),
            include_str!("../tests/fixtures/wmo_tornado_warning.txt"),
        )
        .unwrap();
        fs::write(
            root.join("svs.txt"),
            include_str!("../tests/fixtures/wmo_segmented_svs.txt"),
        )
        .unwrap();

        let report =
            polygon_timeline_at(&root, "2026-04-21T16:25:00Z", Some(IngestHint::RawBulletin))
                .unwrap();
        let tornado_records = report
            .records
            .iter()
            .filter(|record| record.event_id == "KLOT.O.TO.W.0001")
            .collect::<Vec<_>>();
        let metrics = area_time_polygon_metrics(tornado_records[0], tornado_records[1]);

        assert_eq!(metrics.left_duration_seconds, Some(1800));
        assert_eq!(metrics.right_duration_seconds, Some(600));
        assert_eq!(
            warning_interval_overlap_seconds(tornado_records[0], tornado_records[1]),
            Some(600)
        );
        assert_eq!(metrics.time_overlap_seconds, Some(600));
        assert!(metrics.left_area_square_degrees.unwrap() > 0.0);
        assert!(metrics.right_area_square_degrees.unwrap() > 0.0);
        assert!(metrics.left_area_time_square_degree_seconds.unwrap() > 0.0);
        assert!(metrics.right_area_time_square_degree_seconds.unwrap() > 0.0);

        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn polygon_overlap_skips_self_intersecting_shapes() {
        let bowtie = polygon(&[(0.0, 0.0), (2.0, 2.0), (0.0, 2.0), (2.0, 0.0)]);
        let square = square_polygon(0.0, 0.0, 3.0, 3.0);

        assert_eq!(warning_polygon_area_square_degrees(&bowtie), None);
        assert_eq!(
            warning_polygon_overlap_area_square_degrees(&bowtie, &square),
            None
        );
    }

    #[test]
    fn polygon_timeline_at_returns_versioned_warning_records() {
        let root = temp_dir_path("nwws_rs_warning_timeline");
        fs::create_dir_all(&root).unwrap();
        fs::write(
            root.join("warning.txt"),
            include_str!("../tests/fixtures/wmo_tornado_warning.txt"),
        )
        .unwrap();
        fs::write(
            root.join("svs.txt"),
            include_str!("../tests/fixtures/wmo_segmented_svs.txt"),
        )
        .unwrap();

        let report =
            polygon_timeline_at(&root, "2026-04-21T16:25:00Z", Some(IngestHint::RawBulletin))
                .unwrap();

        assert_eq!(report.scanned_files, 2);
        assert_eq!(report.parsed_files, 2);
        assert_eq!(report.messages, 2);
        assert_eq!(report.failures, 0);
        assert_eq!(report.warning_records, 3);
        assert_eq!(report.records.len(), 3);

        let tornado_records = report
            .records
            .iter()
            .filter(|record| record.event_id == "KLOT.O.TO.W.0001")
            .collect::<Vec<_>>();
        assert_eq!(tornado_records.len(), 2);
        assert_eq!(tornado_records[0].action, "NEW");
        assert_eq!(
            tornado_records[0].lifecycle_status,
            Some(WarningLifecycleStatus::Superseded)
        );
        assert_eq!(
            tornado_records[0].issued_at.as_deref(),
            Some("2026-04-21T16:00:00Z")
        );
        assert_eq!(
            tornado_records[0].valid_start.as_deref(),
            Some("2026-04-21T16:00:00Z")
        );
        assert_eq!(
            tornado_records[0].expires_at.as_deref(),
            Some("2026-04-21T16:30:00Z")
        );
        assert_eq!(
            tornado_records[0].tags.tornado.as_deref(),
            Some("RADAR INDICATED")
        );
        assert!(
            tornado_records[0]
                .tags
                .text_tags
                .iter()
                .any(|tag| tag.kind == WarningTextTagKind::Source
                    && tag.raw_value == "Radar indicated rotation.")
        );
        assert_eq!(tornado_records[0].tags.actions[0].action, "NEW");
        assert_eq!(
            tornado_records[0].tags.actions[0].normalized_action,
            WarningActionKind::New
        );
        let polygon = tornado_records[0].polygon.as_ref().unwrap();
        assert!(polygon.raw.starts_with("LAT...LON"));
        assert_eq!(polygon.points.len(), 6);
        assert_eq!(polygon.points[0].lat, 42.15);
        assert_eq!(polygon.points[0].lon, -88.5);

        assert_eq!(tornado_records[1].action, "CON");
        assert_eq!(
            tornado_records[1].lifecycle_status,
            Some(WarningLifecycleStatus::Active)
        );
        assert_eq!(
            tornado_records[1].updated_at.as_deref(),
            Some("2026-04-21T16:20:00Z")
        );
        assert_eq!(tornado_records[1].valid_start, None);
        assert_eq!(tornado_records[1].tags.actions[0].action, "CON");
        assert_eq!(
            tornado_records[1].tags.actions[0].normalized_action,
            WarningActionKind::Continue
        );

        let severe = report
            .records
            .iter()
            .find(|record| record.event_id == "KLOT.O.SV.W.0002")
            .unwrap();
        assert_eq!(severe.action, "NEW");
        assert_eq!(
            severe.lifecycle_status,
            Some(WarningLifecycleStatus::Active)
        );
        assert_eq!(severe.ugcs, vec!["ILC089", "ILC111"]);

        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn polygon_timeline_uses_open_interface_wrapper_issue() {
        let root = temp_dir_path("nwws_rs_warning_timeline_oi");
        fs::create_dir_all(&root).unwrap();
        let path = root.join("warning.xml");
        fs::write(
            &path,
            include_str!("../tests/fixtures/nwws_oi_tornado_warning.xml"),
        )
        .unwrap();

        let report = polygon_timeline_at(
            &path,
            "2026-04-21T16:05:00Z",
            Some(IngestHint::OpenInterface),
        )
        .unwrap();

        assert_eq!(report.warning_records, 1);
        let record = &report.records[0];
        assert_eq!(record.wrapper_id.as_deref(), Some("41001.17"));
        assert_eq!(
            record.wrapper_issued_at.as_deref(),
            Some("2026-04-21T16:00:00Z")
        );
        assert_eq!(record.issued_at.as_deref(), Some("2026-04-21T16:00:00Z"));
        assert_eq!(
            record.lifecycle_status,
            Some(WarningLifecycleStatus::Active)
        );

        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn polygon_timeline_marks_latest_record_expired_after_valid_end() {
        let root = temp_dir_path("nwws_rs_warning_timeline_expired");
        fs::create_dir_all(&root).unwrap();
        fs::write(
            root.join("warning.txt"),
            include_str!("../tests/fixtures/wmo_tornado_warning.txt"),
        )
        .unwrap();
        fs::write(
            root.join("svs.txt"),
            include_str!("../tests/fixtures/wmo_segmented_svs.txt"),
        )
        .unwrap();

        let report =
            polygon_timeline_at(&root, "2026-04-21T17:05:00Z", Some(IngestHint::RawBulletin))
                .unwrap();

        let tornado = report
            .records
            .iter()
            .rev()
            .find(|record| record.event_id == "KLOT.O.TO.W.0001")
            .unwrap();
        assert_eq!(tornado.action, "CON");
        assert_eq!(
            tornado.lifecycle_status,
            Some(WarningLifecycleStatus::Expired)
        );

        fs::remove_dir_all(root).unwrap();
    }

    fn temp_dir_path(prefix: &str) -> PathBuf {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        std::env::temp_dir().join(format!("{prefix}_{unique}"))
    }

    fn test_record(
        record_key: &str,
        event_id: &str,
        valid_start: &str,
        valid_end: &str,
        polygon: WarningPolygon,
    ) -> WarningTimelineRecord {
        WarningTimelineRecord {
            record_key: record_key.to_owned(),
            event_id: event_id.to_owned(),
            source_path: PathBuf::from("test.txt"),
            byte_range: None,
            message_index: 1,
            segment_index: 1,
            vtec_index: 1,
            heading: "WUUS53 KAAA 211600".to_owned(),
            issued_at: Some(valid_start.to_owned()),
            wrapper_id: None,
            wrapper_issued_at: None,
            office: "KAAA".to_owned(),
            message_office: "KAAA".to_owned(),
            awips_id: Some("TORAAA".to_owned()),
            product_family: "tornado".to_owned(),
            event_family: "tornado".to_owned(),
            event_class: "O".to_owned(),
            action: "NEW".to_owned(),
            phenomenon: "TO".to_owned(),
            significance: "W".to_owned(),
            event_tracking_number: 1,
            valid_start: Some(valid_start.to_owned()),
            valid_end: Some(valid_end.to_owned()),
            expires_at: Some(valid_end.to_owned()),
            canceled_at: None,
            updated_at: None,
            lifecycle_status: None,
            vtec: "/O.NEW.KAAA.TO.W.0001.260421T1600Z-260421T1700Z/".to_owned(),
            ugc_raw: "AAC001-211700-".to_owned(),
            ugc_purge_time: "211700".to_owned(),
            ugcs: vec!["AAC001".to_owned()],
            headline: None,
            tags: WarningTags {
                tornado: None,
                flash_flood_observed: false,
                flash_flood_emergency: false,
                hail_inches: None,
                wind_mph: None,
                damage_threat: None,
                text_tags: Vec::new(),
                actions: Vec::new(),
            },
            polygon: Some(polygon),
            time_mot_loc: None,
            raw_bulletin_blake3: "test".to_owned(),
        }
    }

    fn square_polygon(min_lat: f32, min_lon: f32, max_lat: f32, max_lon: f32) -> WarningPolygon {
        polygon(&[
            (min_lat, min_lon),
            (min_lat, max_lon),
            (max_lat, max_lon),
            (max_lat, min_lon),
        ])
    }

    fn polygon(points: &[(f32, f32)]) -> WarningPolygon {
        WarningPolygon {
            raw: "LAT...LON test".to_owned(),
            points: points
                .iter()
                .map(|(lat, lon)| WarningPoint {
                    lat: *lat,
                    lon: *lon,
                })
                .collect(),
        }
    }

    fn assert_approx(actual: f64, expected: f64) {
        assert!(
            (actual - expected).abs() <= 1.0e-9,
            "expected {actual} to be within tolerance of {expected}"
        );
    }
}
