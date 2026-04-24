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

    use super::{WarningLifecycleStatus, polygon_timeline_at};
    use crate::ingest::IngestHint;
    use crate::product::{WarningActionKind, WarningTextTagKind};

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
}
