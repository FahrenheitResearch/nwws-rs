use std::collections::BTreeMap;
use std::fs::{self, OpenOptions};
use std::io::{self, ErrorKind as IoErrorKind, Write};
use std::ops::Range;
use std::path::{Path, PathBuf};

use serde::Serialize;
use time::format_description::well_known::Rfc3339;
use time::{Date, Month, OffsetDateTime, PrimitiveDateTime, Time, UtcOffset};

use crate::error::ParseError;
use crate::geo::GeoPoint;
use crate::ingest::{
    FramedStreamIngest, IngestHint, ParsedInput, TransportDescriptor, parse_with_hint,
};
use crate::oi::NwwsOiMessage;
use crate::product::{
    NwwsContent, ProductFamily, ProductSegment, SegmentTag, WarningActionTag, WarningTextTag,
    WarningTextTagKind,
};
use crate::runtime::semantic_fingerprint;
use crate::ugc::{UgcCode, UgcKind, UgcString};
use crate::vtec::{Phenomenon, Pvtec, Significance, VtecAction, VtecTime};

pub type Result<T> = std::result::Result<T, ApiError>;

#[derive(Debug)]
pub enum ApiError {
    Parse(ParseError),
    Io(io::Error),
    Json(serde_json::Error),
    Time(time::error::Parse),
}

impl From<ParseError> for ApiError {
    fn from(value: ParseError) -> Self {
        Self::Parse(value)
    }
}

impl From<io::Error> for ApiError {
    fn from(value: io::Error) -> Self {
        Self::Io(value)
    }
}

impl From<serde_json::Error> for ApiError {
    fn from(value: serde_json::Error) -> Self {
        Self::Json(value)
    }
}

impl From<time::error::Parse> for ApiError {
    fn from(value: time::error::Parse) -> Self {
        Self::Time(value)
    }
}

impl std::fmt::Display for ApiError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Parse(err) => write!(f, "{err}"),
            Self::Io(err) => write!(f, "{err}"),
            Self::Json(err) => write!(f, "{err}"),
            Self::Time(err) => write!(f, "{err}"),
        }
    }
}

impl std::error::Error for ApiError {}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum InputKind {
    OpenInterface,
    Bulletin,
    FramedStream,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ByteRange {
    pub start: usize,
    pub end: usize,
}

impl ByteRange {
    fn from_range(range: &Range<usize>) -> Self {
        Self {
            start: range.start,
            end: range.end,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct WrapperSummary {
    pub summary: Option<String>,
    pub id: Option<String>,
    pub issue: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct TransportSummary {
    pub kind: &'static str,
    pub satellite_channel: Option<u16>,
    pub requires_authentication: bool,
    pub paired_transport_recommended: bool,
}

impl From<TransportDescriptor> for TransportSummary {
    fn from(value: TransportDescriptor) -> Self {
        Self {
            kind: transport_label(value),
            satellite_channel: value.satellite_channel,
            requires_authentication: value.requires_authentication,
            paired_transport_recommended: value.highest_availability_requires_pairing,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct PointSummary {
    pub lat: f32,
    pub lon: f32,
}

impl PointSummary {
    fn from_geo_point(point: GeoPoint, office: &str) -> Self {
        Self {
            lat: round2(point.latitude_degrees()),
            lon: round2(normalize_longitude(point.longitude_degrees(), office)),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct TimeMotLocSummary {
    pub time: String,
    pub direction_degrees: u16,
    pub speed_knots: u8,
    pub locations: Vec<PointSummary>,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct SegmentSummary {
    pub headline: Option<String>,
    pub body_lines: Vec<String>,
    pub separated_by_dollars: bool,
    pub contains_andand: bool,
    pub ugc_raw: String,
    pub ugcs: Vec<String>,
    pub pvtec: Vec<String>,
    pub hvtec: Vec<String>,
    pub tornado_tag: Option<&'static str>,
    pub flash_flood_observed: bool,
    pub flash_flood_emergency: bool,
    pub hail_inches: Option<f32>,
    pub wind_mph: Option<u16>,
    pub damage_threat: Option<String>,
    pub text_tags: Vec<WarningTextTag>,
    pub actions: Vec<WarningActionTag>,
    pub lat_lon: Option<Vec<PointSummary>>,
    pub time_mot_loc: Option<TimeMotLocSummary>,
}

impl SegmentSummary {
    fn from_segment(segment: &ProductSegment<'_>, office: &str) -> Self {
        let parsed_tags = segment.warning_tags();
        let mut tornado_tag = None;
        let mut flash_flood_observed = false;
        let mut explicit_flash_flood_emergency = false;
        let mut hail_inches = None;
        let mut wind_mph = None;
        let mut raw_damage_threat = None;

        for tag in &parsed_tags.text_tags {
            match tag.kind {
                WarningTextTagKind::Tornado => match tag.normalized_value.as_str() {
                    "OBSERVED" => tornado_tag = Some("OBSERVED"),
                    "RADAR INDICATED" => tornado_tag = Some("RADAR INDICATED"),
                    "POSSIBLE" => tornado_tag = Some("POSSIBLE"),
                    _ => {}
                },
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
                SegmentTag::TornadoObserved => tornado_tag = Some("OBSERVED"),
                SegmentTag::TornadoRadarIndicated => tornado_tag = Some("RADAR INDICATED"),
                SegmentTag::TornadoPossible => tornado_tag = Some("POSSIBLE"),
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
            headline: segment.headline.map(str::to_owned),
            body_lines: segment
                .body_lines
                .iter()
                .map(|line| (*line).to_owned())
                .collect(),
            separated_by_dollars: segment.boundaries.separated_by_dollars,
            contains_andand: segment.boundaries.contains_andand,
            ugc_raw: segment.ugc.raw().to_owned(),
            ugcs: expand_ugc_codes(&segment.ugc),
            pvtec: segment
                .pvtec
                .iter()
                .map(|value| value.raw().to_owned())
                .collect(),
            hvtec: segment
                .hvtec
                .iter()
                .map(|value| value.raw().to_owned())
                .collect(),
            tornado_tag,
            flash_flood_observed,
            flash_flood_emergency,
            hail_inches,
            wind_mph,
            damage_threat,
            text_tags: parsed_tags.text_tags,
            actions: parsed_tags.actions,
            lat_lon: segment.lat_lon.as_ref().map(|block| {
                block
                    .points()
                    .map(|point| PointSummary::from_geo_point(point, office))
                    .collect()
            }),
            time_mot_loc: segment.time_mot_loc.as_ref().map(|line| TimeMotLocSummary {
                time: format!("{:02}{:02}Z", line.hour(), line.minute()),
                direction_degrees: line.direction_degrees(),
                speed_knots: line.speed_knots(),
                locations: line
                    .locations()
                    .map(|point| PointSummary::from_geo_point(point, office))
                    .collect(),
            }),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct MessageSummary {
    pub byte_range: Option<ByteRange>,
    pub wrapper: Option<WrapperSummary>,
    pub frame_kind: &'static str,
    pub sequence_number: Option<u16>,
    pub heading: String,
    pub ttaaii: String,
    pub cccc: String,
    pub office: String,
    pub yygggg: String,
    pub bbb: Option<String>,
    pub awips_id: Option<String>,
    pub family: String,
    pub semantic_fingerprint: String,
    pub raw_bulletin_blake3: String,
    pub archive_id: String,
    pub segment_count: usize,
    pub segments: Vec<SegmentSummary>,
    pub raw_bulletin: String,
}

impl MessageSummary {
    fn from_content(
        content: &NwwsContent<'_>,
        wrapper: Option<WrapperSummary>,
        byte_range: Option<ByteRange>,
    ) -> Self {
        let bulletin = &content.bulletin;
        let office = bulletin.heading.cccc();
        let segments = content
            .product
            .segments
            .iter()
            .map(|segment| SegmentSummary::from_segment(segment, office))
            .collect::<Vec<_>>();

        Self {
            byte_range,
            wrapper,
            frame_kind: match bulletin.frame_kind {
                crate::WmoFrameKind::Bare => "bare",
                crate::WmoFrameKind::Framed => "framed",
            },
            sequence_number: bulletin.sequence_number,
            heading: bulletin.heading.to_string(),
            ttaaii: bulletin.heading.ttaaii().to_owned(),
            cccc: bulletin.heading.cccc().to_owned(),
            office: bulletin.heading.cccc().to_owned(),
            yygggg: bulletin.heading.yygggg().to_owned(),
            bbb: bulletin.heading.bbb().map(str::to_owned),
            awips_id: bulletin
                .awips_id
                .as_ref()
                .map(|value| value.raw().to_owned()),
            family: family_name(content.product.family),
            semantic_fingerprint: semantic_fingerprint(content),
            raw_bulletin_blake3: blake3::hash(bulletin.bulletin.as_bytes())
                .to_hex()
                .to_string(),
            archive_id: archive_digest(bulletin.bulletin.as_bytes()),
            segment_count: segments.len(),
            segments,
            raw_bulletin: bulletin.bulletin.to_owned(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct InspectionReport {
    pub path: Option<PathBuf>,
    pub input_kind: InputKind,
    pub transport: TransportSummary,
    pub junk_bytes: usize,
    pub pending_bytes: usize,
    pub messages: Vec<MessageSummary>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ScanCount {
    pub input_kind: InputKind,
    pub transport: &'static str,
    pub files: usize,
    pub messages: usize,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct ScanFileResult {
    pub path: PathBuf,
    pub report: Option<InspectionReport>,
    pub error: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct ScanReport {
    pub root: PathBuf,
    pub scanned_files: usize,
    pub parsed_files: usize,
    pub messages: usize,
    pub failures: usize,
    pub counts: Vec<ScanCount>,
    pub families: BTreeMap<String, usize>,
    pub files: Vec<ScanFileResult>,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct Pid201SplitRecord {
    pub index: usize,
    pub suggested_filename: String,
    pub message: MessageSummary,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct Pid201SplitReport {
    pub source_path: Option<PathBuf>,
    pub transport: TransportSummary,
    pub junk_bytes: usize,
    pub pending_bytes: usize,
    pub records: Vec<Pid201SplitRecord>,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct Pid201WriteRecord {
    pub path: PathBuf,
    pub message: MessageSummary,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct Pid201WriteReport {
    pub input_path: PathBuf,
    pub output_dir: PathBuf,
    pub junk_bytes: usize,
    pub pending_bytes: usize,
    pub written: Vec<Pid201WriteRecord>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ArchivePersistResult {
    pub source_path: PathBuf,
    pub action: &'static str,
    pub relative_path: PathBuf,
    pub transport: &'static str,
    pub heading: String,
    pub family: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ArchiveFailure {
    pub source_path: PathBuf,
    pub error: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ArchiveImportReport {
    pub archive_dir: PathBuf,
    pub scanned_inputs: usize,
    pub parsed_inputs: usize,
    pub archived_records: usize,
    pub duplicate_records: usize,
    pub failures: usize,
    pub transports: BTreeMap<String, usize>,
    pub families: BTreeMap<String, usize>,
    pub records: Vec<ArchivePersistResult>,
    pub errors: Vec<ArchiveFailure>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ArchiveVerifyRecord {
    pub path: PathBuf,
    pub status: &'static str,
    pub heading: Option<String>,
    pub family: Option<String>,
    pub error: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ArchiveVerifyReport {
    pub archive_dir: PathBuf,
    pub verified_records: usize,
    pub failures: usize,
    pub families: BTreeMap<String, usize>,
    pub records: Vec<ArchiveVerifyRecord>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ActiveWarningRecord {
    pub key: String,
    pub source_path: PathBuf,
    pub message_index: usize,
    pub segment_index: usize,
    pub vtec_index: usize,
    pub heading: String,
    pub issued_at: Option<String>,
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
    pub start_time: Option<String>,
    pub end_time: Option<String>,
    pub vtec: String,
    pub ugc_raw: String,
    pub ugcs: Vec<String>,
    pub headline: Option<String>,
    pub raw_bulletin_blake3: String,
    pub archive_id: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ActiveWarningFailure {
    pub path: PathBuf,
    pub error: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ActiveWarningReport {
    pub root: PathBuf,
    pub reference_utc: String,
    pub scanned_files: usize,
    pub parsed_files: usize,
    pub messages: usize,
    pub warning_vtec_segments: usize,
    pub future_messages: usize,
    pub active_records: usize,
    pub failures: usize,
    pub families: BTreeMap<String, usize>,
    pub records: Vec<ActiveWarningRecord>,
    pub errors: Vec<ActiveWarningFailure>,
}

pub fn inspect_path(
    path: impl AsRef<Path>,
    hint_override: Option<IngestHint>,
) -> Result<InspectionReport> {
    let path = path.as_ref();
    let bytes = fs::read(path)?;
    let mut report = inspect_bytes(&bytes, resolve_hint(path, hint_override))?;
    report.path = Some(path.to_path_buf());
    Ok(report)
}

pub fn inspect_bytes(bytes: &[u8], hint: IngestHint) -> Result<InspectionReport> {
    let parsed = parse_with_hint(hint, bytes)?;

    match parsed {
        ParsedInput::Bulletin(value) => Ok(InspectionReport {
            path: None,
            input_kind: InputKind::Bulletin,
            transport: value.transport.into(),
            junk_bytes: 0,
            pending_bytes: 0,
            messages: vec![MessageSummary::from_content(&value.content, None, None)],
        }),
        ParsedInput::OpenInterface(value) => {
            inspect_oi_message_with_transport(&value.message, value.transport)
        }
        ParsedInput::FramedStream(value) => inspect_framed_stream(value),
    }
}

pub fn inspect_text(input: &str, hint: IngestHint) -> Result<InspectionReport> {
    inspect_bytes(input.as_bytes(), hint)
}

pub fn inspect_oi_message(message: &NwwsOiMessage) -> Result<InspectionReport> {
    inspect_oi_message_with_transport(message, TransportDescriptor::open_interface())
}

pub fn scan_path(path: impl AsRef<Path>, hint_override: Option<IngestHint>) -> Result<ScanReport> {
    let path = path.as_ref();
    let root = if path.is_file() {
        path.parent()
            .unwrap_or_else(|| Path::new("."))
            .to_path_buf()
    } else if path.is_dir() {
        resolve_scan_root(path)
    } else {
        return Err(io::Error::new(
            IoErrorKind::NotFound,
            format!("path does not exist: {}", path.display()),
        )
        .into());
    };

    let files = collect_inputs(path)?;
    let mut counts = BTreeMap::<(InputKind, &'static str), ScanCount>::new();
    let mut families = BTreeMap::<String, usize>::new();
    let mut parsed_files = 0usize;
    let mut messages = 0usize;
    let mut failures = 0usize;
    let mut results = Vec::new();

    for file in files {
        match inspect_path(&file, hint_override) {
            Ok(report) => {
                parsed_files += 1;
                messages += report.messages.len();
                let transport = report.transport.kind;
                counts
                    .entry((report.input_kind, transport))
                    .and_modify(|count| {
                        count.files += 1;
                        count.messages += report.messages.len();
                    })
                    .or_insert(ScanCount {
                        input_kind: report.input_kind,
                        transport,
                        files: 1,
                        messages: report.messages.len(),
                    });
                for message in &report.messages {
                    *families.entry(message.family.clone()).or_default() += 1;
                }
                results.push(ScanFileResult {
                    path: relative_display_path(&root, &file),
                    report: Some(report),
                    error: None,
                });
            }
            Err(err) => {
                failures += 1;
                results.push(ScanFileResult {
                    path: relative_display_path(&root, &file),
                    report: None,
                    error: Some(err.to_string()),
                });
            }
        }
    }

    let mut counts = counts.into_values().collect::<Vec<_>>();
    counts.sort_by_key(|count| (count.input_kind as u8, count.transport));

    Ok(ScanReport {
        root,
        scanned_files: results.len(),
        parsed_files,
        messages,
        failures,
        counts,
        families,
        files: results,
    })
}

pub fn active_warnings_at(
    path: impl AsRef<Path>,
    reference_utc: &str,
    hint_override: Option<IngestHint>,
) -> Result<ActiveWarningReport> {
    let reference = parse_reference_utc(reference_utc)?;
    active_warnings_at_time(path, reference, hint_override)
}

pub fn active_warnings_at_time(
    path: impl AsRef<Path>,
    reference_utc: OffsetDateTime,
    hint_override: Option<IngestHint>,
) -> Result<ActiveWarningReport> {
    let path = path.as_ref();
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
    let reference_utc = reference_utc.to_offset(UtcOffset::UTC);
    let reference = primitive_utc(reference_utc);
    let reference_text = format_primitive_utc(reference);
    let mut states = BTreeMap::<String, ActiveWarningState>::new();
    let mut report = ActiveWarningReport {
        root: root.clone(),
        reference_utc: reference_text,
        scanned_files: 0,
        parsed_files: 0,
        messages: 0,
        warning_vtec_segments: 0,
        future_messages: 0,
        active_records: 0,
        failures: 0,
        families: BTreeMap::new(),
        records: Vec::new(),
        errors: Vec::new(),
    };

    for file in files {
        report.scanned_files += 1;
        match inspect_path(&file, hint_override) {
            Ok(inspection) => {
                report.parsed_files += 1;
                report.messages += inspection.messages.len();
                collect_active_warning_states(
                    &root,
                    &file,
                    &inspection,
                    reference,
                    &mut report,
                    &mut states,
                );
            }
            Err(err) => {
                report.failures += 1;
                report.errors.push(ActiveWarningFailure {
                    path: relative_display_path(&root, &file),
                    error: err.to_string(),
                });
            }
        }
    }

    report.records = states
        .into_values()
        .filter_map(|state| state.record)
        .collect();
    report.active_records = report.records.len();
    for record in &report.records {
        *report
            .families
            .entry(record.event_family.clone())
            .or_default() += 1;
    }

    Ok(report)
}

pub fn split_pid201_bytes(bytes: &[u8]) -> Result<Pid201SplitReport> {
    split_pid201_impl(None, bytes)
}

pub fn split_pid201_path(path: impl AsRef<Path>) -> Result<Pid201SplitReport> {
    let path = path.as_ref();
    let bytes = fs::read(path)?;
    split_pid201_impl(Some(path.to_path_buf()), &bytes)
}

pub fn write_pid201_split(
    input_path: impl AsRef<Path>,
    output_dir: impl AsRef<Path>,
) -> Result<Pid201WriteReport> {
    let input_path = input_path.as_ref();
    let output_dir = output_dir.as_ref();
    fs::create_dir_all(output_dir)?;

    let report = split_pid201_path(input_path)?;
    let mut written = Vec::with_capacity(report.records.len());

    for record in report.records {
        let path = output_dir.join(&record.suggested_filename);
        fs::write(&path, record.message.raw_bulletin.as_bytes())?;
        written.push(Pid201WriteRecord {
            path,
            message: record.message,
        });
    }

    Ok(Pid201WriteReport {
        input_path: input_path.to_path_buf(),
        output_dir: output_dir.to_path_buf(),
        junk_bytes: report.junk_bytes,
        pending_bytes: report.pending_bytes,
        written,
    })
}

pub fn archive_import(
    input: impl AsRef<Path>,
    archive_dir: impl AsRef<Path>,
    hint_override: Option<IngestHint>,
) -> Result<ArchiveImportReport> {
    let input = input.as_ref();
    let archive_dir = archive_dir.as_ref();
    if !input.exists() {
        return Err(io::Error::new(
            IoErrorKind::NotFound,
            format!("path does not exist: {}", input.display()),
        )
        .into());
    }

    fs::create_dir_all(archive_dir)?;

    let files = collect_inputs(input)?;
    let manifest_path = archive_dir.join("records.tsv");
    let mut report = ArchiveImportReport {
        archive_dir: archive_dir.to_path_buf(),
        scanned_inputs: 0,
        parsed_inputs: 0,
        archived_records: 0,
        duplicate_records: 0,
        failures: 0,
        transports: BTreeMap::new(),
        families: BTreeMap::new(),
        records: Vec::new(),
        errors: Vec::new(),
    };

    for file in files {
        report.scanned_inputs += 1;

        let bytes = match fs::read(&file) {
            Ok(bytes) => bytes,
            Err(err) => {
                report.failures += 1;
                report.errors.push(ArchiveFailure {
                    source_path: file,
                    error: format!("failed to read: {err}"),
                });
                continue;
            }
        };
        let hint = resolve_hint(&file, hint_override);
        let parsed = match parse_with_hint(hint, &bytes) {
            Ok(parsed) => parsed,
            Err(err) => {
                report.failures += 1;
                report.errors.push(ArchiveFailure {
                    source_path: file,
                    error: format!("failed to parse with {hint:?}: {err}"),
                });
                continue;
            }
        };

        let records = match archive_records_from_parsed(&file, parsed) {
            Ok(records) if !records.is_empty() => records,
            Ok(_) => {
                report.failures += 1;
                report.errors.push(ArchiveFailure {
                    source_path: file,
                    error: "input did not contain any archiveable records".to_owned(),
                });
                continue;
            }
            Err(err) => {
                report.failures += 1;
                report.errors.push(ArchiveFailure {
                    source_path: file,
                    error: err.to_string(),
                });
                continue;
            }
        };

        report.parsed_inputs += 1;
        for record in records {
            let outcome = persist_archive_record(archive_dir, &manifest_path, &record)?;
            match outcome.action {
                "archived" => report.archived_records += 1,
                "duplicate" => report.duplicate_records += 1,
                _ => {}
            }
            *report
                .transports
                .entry(transport_label(record.transport).to_owned())
                .or_default() += 1;
            *report
                .families
                .entry(family_name(record.family))
                .or_default() += 1;
            report.records.push(ArchivePersistResult {
                source_path: record.source_path.clone(),
                action: outcome.action,
                relative_path: outcome.relative_path,
                transport: transport_label(record.transport),
                heading: record.heading,
                family: family_name(record.family),
            });
        }
    }

    Ok(report)
}

pub fn archive_verify(archive_dir: impl AsRef<Path>) -> Result<ArchiveVerifyReport> {
    let archive_dir = archive_dir.as_ref();
    if !archive_dir.is_dir() {
        return Err(io::Error::new(
            IoErrorKind::NotFound,
            format!(
                "archive directory does not exist: {}",
                archive_dir.display()
            ),
        )
        .into());
    }

    let records_root = archive_dir.join("records");
    if !records_root.is_dir() {
        return Err(io::Error::new(
            IoErrorKind::NotFound,
            format!(
                "archive records directory does not exist: {}",
                records_root.display()
            ),
        )
        .into());
    }

    let files = crate::replay::collect_input_paths(&records_root)?;
    let mut families = BTreeMap::<String, usize>::new();
    let mut verified_records = 0usize;
    let mut failures = 0usize;
    let mut records = Vec::new();

    for file in files {
        match verify_archived_file(&records_root, &file) {
            Ok(record) => {
                if record.status == "ok" {
                    verified_records += 1;
                    if let Some(family) = record.family.as_ref() {
                        *families.entry(family.clone()).or_default() += 1;
                    }
                } else {
                    failures += 1;
                }
                records.push(record);
            }
            Err(err) => {
                failures += 1;
                records.push(ArchiveVerifyRecord {
                    path: relative_display_path(&records_root, &file),
                    status: "error",
                    heading: None,
                    family: None,
                    error: Some(err.to_string()),
                });
            }
        }
    }

    Ok(ArchiveVerifyReport {
        archive_dir: archive_dir.to_path_buf(),
        verified_records,
        failures,
        families,
        records,
    })
}

pub fn to_json<T: Serialize>(value: &T) -> Result<String> {
    Ok(serde_json::to_string(value)?)
}

fn inspect_oi_message_with_transport(
    message: &NwwsOiMessage,
    transport: TransportDescriptor,
) -> Result<InspectionReport> {
    let wrapper = Some(WrapperSummary {
        summary: message
            .summary
            .clone()
            .or_else(|| message.xhtml_summary.clone()),
        id: message
            .payload
            .as_ref()
            .map(|payload| format!("{}.{}", payload.id.process_id, payload.id.sequence)),
        issue: message
            .payload
            .as_ref()
            .and_then(|payload| payload.issue.format(&Rfc3339).ok()),
    });
    let content = NwwsContent::from_oi_message(message)?;

    Ok(InspectionReport {
        path: None,
        input_kind: InputKind::OpenInterface,
        transport: transport.into(),
        junk_bytes: 0,
        pending_bytes: 0,
        messages: vec![MessageSummary::from_content(&content, wrapper, None)],
    })
}

fn inspect_framed_stream(value: FramedStreamIngest<'_>) -> Result<InspectionReport> {
    if value.chunks.is_empty() {
        return Err(io::Error::new(
            IoErrorKind::InvalidData,
            "no framed messages detected in stream",
        )
        .into());
    }

    let contents = value.contents()?;
    let messages = value
        .chunks
        .iter()
        .zip(contents.iter())
        .map(|(chunk, content)| {
            MessageSummary::from_content(content, None, Some(ByteRange::from_range(&chunk.range)))
        })
        .collect();

    Ok(InspectionReport {
        path: None,
        input_kind: InputKind::FramedStream,
        transport: value.transport.into(),
        junk_bytes: value.leading_junk_prefix,
        pending_bytes: value.pending.len(),
        messages,
    })
}

fn split_pid201_impl(source_path: Option<PathBuf>, bytes: &[u8]) -> Result<Pid201SplitReport> {
    let parsed = parse_with_hint(IngestHint::SatellitePid201, bytes)?;
    let ParsedInput::FramedStream(stream) = parsed else {
        return Err(io::Error::new(
            IoErrorKind::InvalidData,
            "input did not parse as a PID201 framed stream",
        )
        .into());
    };
    if stream.chunks.is_empty() {
        return Err(io::Error::new(
            IoErrorKind::InvalidData,
            "input did not contain any framed bulletins",
        )
        .into());
    }

    let contents = stream.contents()?;
    let records = stream
        .chunks
        .iter()
        .zip(contents.iter())
        .enumerate()
        .map(|(index, (chunk, content))| Pid201SplitRecord {
            index: index + 1,
            suggested_filename: pid201_output_name(index, content),
            message: MessageSummary::from_content(
                content,
                None,
                Some(ByteRange::from_range(&chunk.range)),
            ),
        })
        .collect();

    Ok(Pid201SplitReport {
        source_path,
        transport: stream.transport.into(),
        junk_bytes: stream.leading_junk_prefix,
        pending_bytes: stream.pending.len(),
        records,
    })
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ActiveWarningSortKey {
    issued_at: Option<PrimitiveDateTime>,
    source_path: PathBuf,
    message_index: usize,
    segment_index: usize,
    vtec_index: usize,
}

impl PartialOrd for ActiveWarningSortKey {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for ActiveWarningSortKey {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        (
            self.issued_at,
            &self.source_path,
            self.message_index,
            self.segment_index,
            self.vtec_index,
        )
            .cmp(&(
                other.issued_at,
                &other.source_path,
                other.message_index,
                other.segment_index,
                other.vtec_index,
            ))
    }
}

#[derive(Debug, Clone)]
struct ActiveWarningState {
    sort_key: ActiveWarningSortKey,
    record: Option<ActiveWarningRecord>,
}

fn collect_active_warning_states(
    root: &Path,
    file: &Path,
    inspection: &InspectionReport,
    reference: PrimitiveDateTime,
    report: &mut ActiveWarningReport,
    states: &mut BTreeMap<String, ActiveWarningState>,
) {
    let relative_path = relative_display_path(root, file);

    for (message_index, message) in inspection.messages.iter().enumerate() {
        let issued_at = infer_wmo_issue_time(&message.yygggg, reference);
        if issued_at.is_some_and(|issued_at| issued_at > reference) {
            report.future_messages += 1;
            continue;
        }

        for (segment_index, segment) in message.segments.iter().enumerate() {
            for (vtec_index, raw_vtec) in segment.pvtec.iter().enumerate() {
                let pvtec = match Pvtec::parse(raw_vtec) {
                    Ok(pvtec) => pvtec,
                    Err(err) => {
                        report.failures += 1;
                        report.errors.push(ActiveWarningFailure {
                            path: relative_path.clone(),
                            error: format!("failed to reparse P-VTEC {raw_vtec}: {err}"),
                        });
                        continue;
                    }
                };
                if pvtec.significance() != Significance::Warning {
                    continue;
                }

                report.warning_vtec_segments += 1;
                let event_family =
                    family_name_for_phenomenon(pvtec.phenomenon()).unwrap_or(&message.family);
                let key = active_warning_key(&pvtec, &segment.ugcs, event_family);
                let sort_key = ActiveWarningSortKey {
                    issued_at,
                    source_path: relative_path.clone(),
                    message_index: message_index + 1,
                    segment_index: segment_index + 1,
                    vtec_index: vtec_index + 1,
                };

                if matches!(pvtec.action(), VtecAction::Cancel | VtecAction::Expire) {
                    upsert_active_warning_state(states, key, sort_key, None);
                    continue;
                }

                if !vtec_window_contains(&pvtec, reference) {
                    continue;
                }

                let record = ActiveWarningRecord {
                    key: key.clone(),
                    source_path: relative_path.clone(),
                    message_index: message_index + 1,
                    segment_index: segment_index + 1,
                    vtec_index: vtec_index + 1,
                    heading: message.heading.clone(),
                    issued_at: issued_at.map(format_primitive_utc),
                    office: pvtec.office_id().to_owned(),
                    message_office: message.office.clone(),
                    awips_id: message.awips_id.clone(),
                    product_family: message.family.clone(),
                    event_family: event_family.to_owned(),
                    event_class: pvtec.event_class().as_str().to_owned(),
                    action: pvtec.action().as_str().to_owned(),
                    phenomenon: pvtec.phenomenon().as_str().to_owned(),
                    significance: pvtec.significance().as_str().to_owned(),
                    event_tracking_number: pvtec.event_tracking_number(),
                    start_time: format_vtec_time(pvtec.start_time()),
                    end_time: format_vtec_time(pvtec.end_time()),
                    vtec: pvtec.raw().to_owned(),
                    ugc_raw: segment.ugc_raw.clone(),
                    ugcs: segment.ugcs.clone(),
                    headline: segment.headline.clone(),
                    raw_bulletin_blake3: message.raw_bulletin_blake3.clone(),
                    archive_id: message.archive_id.clone(),
                };
                upsert_active_warning_state(states, key, sort_key, Some(record));
            }
        }
    }
}

fn upsert_active_warning_state(
    states: &mut BTreeMap<String, ActiveWarningState>,
    key: String,
    sort_key: ActiveWarningSortKey,
    record: Option<ActiveWarningRecord>,
) {
    if let Some(existing) = states.get(&key)
        && existing.sort_key > sort_key
    {
        return;
    }

    states.insert(key, ActiveWarningState { sort_key, record });
}

fn vtec_window_contains(pvtec: &Pvtec, reference: PrimitiveDateTime) -> bool {
    if let Some(start) = pvtec.start_time().datetime()
        && reference < start
    {
        return false;
    }
    if let Some(end) = pvtec.end_time().datetime()
        && reference >= end
    {
        return false;
    }
    true
}

fn active_warning_key(pvtec: &Pvtec, ugcs: &[String], event_family: &str) -> String {
    let ugc_key = if ugcs.is_empty() {
        "UNKNOWN".to_owned()
    } else {
        ugcs.join(",")
    };
    format!(
        "office={}|vtec={}.{}.{}.{:04}|ugc={}|family={}",
        pvtec.office_id(),
        pvtec.event_class().as_str(),
        pvtec.phenomenon().as_str(),
        pvtec.significance().as_str(),
        pvtec.event_tracking_number(),
        ugc_key,
        event_family
    )
}

fn parse_reference_utc(raw: &str) -> Result<OffsetDateTime> {
    Ok(OffsetDateTime::parse(raw, &Rfc3339)?.to_offset(UtcOffset::UTC))
}

fn primitive_utc(value: OffsetDateTime) -> PrimitiveDateTime {
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

fn format_vtec_time(value: VtecTime) -> Option<String> {
    value.datetime().map(format_primitive_utc)
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

fn ascii_dec(tens: u8, ones: u8) -> u8 {
    (tens - b'0') * 10 + (ones - b'0')
}

fn verify_archived_file(records_root: &Path, file: &Path) -> Result<ArchiveVerifyRecord> {
    let bytes = fs::read(file)?;
    let report = inspect_bytes(&bytes, IngestHint::RawBulletin)?;
    if report.messages.len() != 1 {
        return Ok(ArchiveVerifyRecord {
            path: relative_display_path(records_root, file),
            status: "error",
            heading: None,
            family: None,
            error: Some(format!(
                "expected one archived bulletin, found {}",
                report.messages.len()
            )),
        });
    }

    let expected = archive_digest(&bytes);
    let stem = file
        .file_stem()
        .and_then(|value| value.to_str())
        .unwrap_or("");
    if !(stem == expected || stem.starts_with(&format!("{expected}-"))) {
        return Ok(ArchiveVerifyRecord {
            path: relative_display_path(records_root, file),
            status: "error",
            heading: Some(report.messages[0].heading.clone()),
            family: Some(report.messages[0].family.clone()),
            error: Some(format!("digest mismatch, expected {expected}")),
        });
    }

    Ok(ArchiveVerifyRecord {
        path: relative_display_path(records_root, file),
        status: "ok",
        heading: Some(report.messages[0].heading.clone()),
        family: Some(report.messages[0].family.clone()),
        error: None,
    })
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

#[derive(Debug)]
struct ArchiveRecord {
    source_path: PathBuf,
    input_kind: InputKind,
    transport: TransportDescriptor,
    wrapper_id: Option<String>,
    bulletin_text: String,
    sequence_number: Option<u16>,
    heading: String,
    ttaaii: String,
    cccc: String,
    awips_id: Option<String>,
    family: ProductFamily,
    segment_count: usize,
}

impl ArchiveRecord {
    fn from_content(
        source_path: &Path,
        input_kind: InputKind,
        transport: TransportDescriptor,
        wrapper_id: Option<String>,
        content: &NwwsContent<'_>,
    ) -> Self {
        Self {
            source_path: source_path.to_path_buf(),
            input_kind,
            transport,
            wrapper_id,
            bulletin_text: content.bulletin.bulletin.to_owned(),
            sequence_number: content.bulletin.sequence_number,
            heading: content.bulletin.heading.to_string(),
            ttaaii: content.bulletin.heading.ttaaii().to_owned(),
            cccc: content.bulletin.heading.cccc().to_owned(),
            awips_id: content
                .bulletin
                .awips_id
                .as_ref()
                .map(|value| value.raw().to_owned()),
            family: content.product.family,
            segment_count: content.product.segments.len(),
        }
    }
}

#[derive(Debug)]
struct ArchivePersistOutcome {
    action: &'static str,
    relative_path: PathBuf,
}

fn archive_records_from_parsed(
    source_path: &Path,
    parsed: ParsedInput<'_>,
) -> Result<Vec<ArchiveRecord>> {
    match parsed {
        ParsedInput::Bulletin(value) => Ok(vec![ArchiveRecord::from_content(
            source_path,
            InputKind::Bulletin,
            value.transport,
            None,
            &value.content,
        )]),
        ParsedInput::OpenInterface(value) => {
            let wrapper_id = value.wrapper.as_ref().map(|value| value.id.clone());
            let content = value.content()?;
            Ok(vec![ArchiveRecord::from_content(
                source_path,
                InputKind::OpenInterface,
                value.transport,
                wrapper_id,
                &content,
            )])
        }
        ParsedInput::FramedStream(value) => {
            let contents = value.contents()?;
            Ok(contents
                .iter()
                .map(|content| {
                    ArchiveRecord::from_content(
                        source_path,
                        InputKind::FramedStream,
                        value.transport,
                        None,
                        content,
                    )
                })
                .collect())
        }
    }
}

fn persist_archive_record(
    archive_dir: &Path,
    manifest_path: &Path,
    record: &ArchiveRecord,
) -> Result<ArchivePersistOutcome> {
    let digest = archive_digest(record.bulletin_text.as_bytes());
    let mut relative_path = canonical_record_relative_path(record, &digest);
    let mut collision_index = 0usize;

    loop {
        let path = archive_dir.join(&relative_path);
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }

        match fs::read(&path) {
            Ok(existing) => {
                if existing == record.bulletin_text.as_bytes() {
                    return Ok(ArchivePersistOutcome {
                        action: "duplicate",
                        relative_path,
                    });
                }

                collision_index += 1;
                relative_path = collision_record_relative_path(record, &digest, collision_index);
            }
            Err(err) if err.kind() == IoErrorKind::NotFound => {
                fs::write(&path, record.bulletin_text.as_bytes())?;
                append_archive_manifest(manifest_path, record, &relative_path, &digest)?;
                return Ok(ArchivePersistOutcome {
                    action: "archived",
                    relative_path,
                });
            }
            Err(err) => return Err(err.into()),
        }
    }
}

fn append_archive_manifest(
    manifest_path: &Path,
    record: &ArchiveRecord,
    relative_path: &Path,
    digest: &str,
) -> Result<()> {
    let existed = manifest_path.exists();
    let mut file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(manifest_path)?;

    if !existed {
        writeln!(
            file,
            "fingerprint\trelative_path\tinput_kind\ttransport\tsequence\tttaaii\tcccc\tawips_id\tfamily\tsegments\twrapper_id\tsource_path"
        )?;
    }

    writeln!(
        file,
        "{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}",
        digest,
        relative_path.display(),
        input_kind_label(record.input_kind),
        transport_label(record.transport),
        record
            .sequence_number
            .map(|value| value.to_string())
            .unwrap_or_default(),
        record.ttaaii,
        record.cccc,
        record.awips_id.as_deref().unwrap_or(""),
        family_name(record.family),
        record.segment_count,
        record.wrapper_id.as_deref().unwrap_or(""),
        sanitize_tsv_field(&record.source_path.display().to_string())
    )?;
    Ok(())
}

fn canonical_record_relative_path(record: &ArchiveRecord, digest: &str) -> PathBuf {
    PathBuf::from("records")
        .join(sanitize_component(&record.cccc))
        .join(sanitize_component(&record.ttaaii))
        .join(sanitize_component(
            record.awips_id.as_deref().unwrap_or("NO-AWIPS"),
        ))
        .join(format!("{digest}.txt"))
}

fn collision_record_relative_path(record: &ArchiveRecord, digest: &str, suffix: usize) -> PathBuf {
    PathBuf::from("records")
        .join(sanitize_component(&record.cccc))
        .join(sanitize_component(&record.ttaaii))
        .join(sanitize_component(
            record.awips_id.as_deref().unwrap_or("NO-AWIPS"),
        ))
        .join(format!("{digest}-{suffix}.txt"))
}

fn pid201_output_name(index: usize, content: &NwwsContent<'_>) -> String {
    format!(
        "{:05}_{}_{}_{}.txt",
        index + 1,
        content.bulletin.sequence_number.unwrap_or(0),
        sanitize_component(content.bulletin.heading.ttaaii()),
        sanitize_component(
            content
                .bulletin
                .awips_id
                .as_ref()
                .map(|value| value.raw())
                .unwrap_or("NO-AWIPS")
        )
    )
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

fn archive_digest(bytes: &[u8]) -> String {
    const OFFSET_BASIS: u64 = 0xcbf29ce484222325;
    const PRIME: u64 = 0x100000001b3;

    let mut hash = OFFSET_BASIS;
    for byte in bytes {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(PRIME);
    }

    format!("{hash:016x}")
}

fn input_kind_label(kind: InputKind) -> &'static str {
    match kind {
        InputKind::OpenInterface => "open-interface",
        InputKind::Bulletin => "bulletin",
        InputKind::FramedStream => "framed-stream",
    }
}

fn transport_label(transport: TransportDescriptor) -> &'static str {
    match transport.kind {
        crate::ingest::TransportKind::OpenInterface => "open-interface",
        crate::ingest::TransportKind::SatellitePid201 => "satellite-pid201",
        crate::ingest::TransportKind::PlainWmoText => "plain-wmo-text",
    }
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

fn sanitize_component(raw: &str) -> String {
    let mut value = String::with_capacity(raw.len());
    for ch in raw.chars() {
        if ch.is_ascii_alphanumeric() || matches!(ch, '-' | '_' | '.') {
            value.push(ch);
        } else {
            value.push('_');
        }
    }
    if value.is_empty() {
        "UNKNOWN".to_owned()
    } else {
        value
    }
}

fn sanitize_tsv_field(raw: &str) -> String {
    raw.chars()
        .map(|ch| {
            if matches!(ch, '\t' | '\r' | '\n') {
                ' '
            } else {
                ch
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::time::{SystemTime, UNIX_EPOCH};

    use super::{
        active_warnings_at, archive_import, archive_verify, inspect_bytes, scan_path,
        split_pid201_bytes, write_pid201_split,
    };
    use crate::ingest::IngestHint;
    use crate::product::WarningTextTagKind;

    #[test]
    fn inspect_bytes_returns_detailed_segment_data() {
        let report = inspect_bytes(
            include_bytes!("../tests/fixtures/wmo_tornado_warning.txt"),
            IngestHint::RawBulletin,
        )
        .unwrap();

        assert_eq!(report.messages.len(), 1);
        assert_eq!(report.messages[0].family, "tornado");
        assert_eq!(report.messages[0].office, "KLOT");
        assert_eq!(report.messages[0].raw_bulletin_blake3.len(), 64);
        assert_eq!(report.messages[0].archive_id.len(), 16);
        assert_eq!(report.messages[0].segments.len(), 1);
        assert_eq!(
            report.messages[0].segments[0].tornado_tag,
            Some("RADAR INDICATED")
        );
        assert_eq!(report.messages[0].segments[0].ugcs.len(), 3);
        assert!(
            report.messages[0].segments[0]
                .text_tags
                .iter()
                .any(|tag| tag.kind == WarningTextTagKind::Impact)
        );
        assert_eq!(report.messages[0].segments[0].actions[0].action, "NEW");
    }

    #[test]
    fn scan_path_collects_success_and_failures() {
        let root = temp_dir_path("nwws_rs_api_scan");
        fs::create_dir_all(&root).unwrap();
        fs::write(
            root.join("good.txt"),
            include_str!("../tests/fixtures/wmo_tornado_warning.txt"),
        )
        .unwrap();
        fs::write(root.join("bad.txt"), "not a bulletin").unwrap();

        let report = scan_path(&root, None).unwrap();
        assert_eq!(report.scanned_files, 2);
        assert_eq!(report.parsed_files, 1);
        assert_eq!(report.failures, 1);

        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn split_pid201_bytes_returns_records() {
        let input = format!(
            "junk\u{1}\r\r\n{}\r\r\n\u{3}",
            include_str!("../tests/fixtures/wmo_tornado_warning.txt")
                .lines()
                .collect::<Vec<_>>()
                .join("\r\r\n")
        );
        let report = split_pid201_bytes(input.as_bytes()).unwrap();

        assert_eq!(report.records.len(), 1);
        assert_eq!(report.junk_bytes, 4);
        assert!(report.records[0].suggested_filename.ends_with(".txt"));
    }

    #[test]
    fn write_pid201_split_writes_files() {
        let root = temp_dir_path("nwws_rs_api_pid201_write");
        let input_path = root.join("capture.pid201");
        let output_dir = root.join("split");
        fs::create_dir_all(&root).unwrap();
        let input = format!(
            "\u{1}\r\r\n{}\r\r\n\u{3}",
            include_str!("../tests/fixtures/wmo_tornado_warning.txt")
                .lines()
                .collect::<Vec<_>>()
                .join("\r\r\n")
        );
        fs::write(&input_path, input).unwrap();

        let report = write_pid201_split(&input_path, &output_dir).unwrap();
        assert_eq!(report.written.len(), 1);
        assert!(report.written[0].path.exists());

        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn archive_import_and_verify_round_trip() {
        let root = temp_dir_path("nwws_rs_api_archive");
        let input_dir = root.join("input");
        let archive_dir = root.join("archive");
        fs::create_dir_all(&input_dir).unwrap();
        fs::write(
            input_dir.join("warning.txt"),
            include_str!("../tests/fixtures/wmo_tornado_warning.txt"),
        )
        .unwrap();

        let import = archive_import(&input_dir, &archive_dir, None).unwrap();
        assert_eq!(import.archived_records, 1);
        assert_eq!(import.failures, 0);

        let verify = archive_verify(&archive_dir).unwrap();
        assert_eq!(verify.verified_records, 1);
        assert_eq!(verify.failures, 0);

        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn active_warnings_at_collapses_updates_by_event_key() {
        let root = temp_dir_path("nwws_rs_api_active_at");
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
            active_warnings_at(&root, "2026-04-21T16:25:00Z", Some(IngestHint::RawBulletin))
                .unwrap();

        assert_eq!(report.scanned_files, 2);
        assert_eq!(report.failures, 0);
        assert_eq!(report.active_records, 2);
        assert_eq!(report.families.get("tornado"), Some(&1));
        assert_eq!(report.families.get("severe-thunderstorm"), Some(&1));

        let tornado = report
            .records
            .iter()
            .find(|record| record.event_family == "tornado")
            .unwrap();
        assert_eq!(tornado.action, "CON");
        assert_eq!(tornado.product_family, "statement");
        assert_eq!(tornado.event_tracking_number, 1);
        assert!(tornado.key.contains("KLOT"));
        assert!(tornado.key.contains("TO.W.0001"));

        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn active_warnings_at_honors_reference_before_future_updates() {
        let root = temp_dir_path("nwws_rs_api_active_at_future");
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
            active_warnings_at(&root, "2026-04-21T16:10:00Z", Some(IngestHint::RawBulletin))
                .unwrap();

        assert_eq!(report.active_records, 1);
        assert_eq!(report.future_messages, 1);
        assert_eq!(report.records[0].action, "NEW");
        assert_eq!(report.records[0].event_family, "tornado");

        fs::remove_dir_all(root).unwrap();
    }

    fn temp_dir_path(prefix: &str) -> PathBuf {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        std::env::temp_dir().join(format!("{prefix}_{unique}"))
    }

    use std::path::PathBuf;
}
