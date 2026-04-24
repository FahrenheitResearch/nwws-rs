#![forbid(unsafe_code)]
#![doc = include_str!("../README.md")]

pub mod api;
pub mod error;
pub mod geo;
pub mod header;
pub mod ingest;
pub mod oi;
pub mod oi_client;
pub mod pid201;
pub mod product;
pub mod replay;
pub mod runtime;
pub mod stream;
pub mod ugc;
pub mod vtec;
pub mod warning;
pub mod wmo;

#[cfg(feature = "python")]
mod python;

pub use api::{
    ActiveWarningFailure, ActiveWarningRecord, ActiveWarningReport, ApiError, ArchiveFailure,
    ArchiveImportReport, ArchivePersistResult, ArchiveVerifyRecord, ArchiveVerifyReport, ByteRange,
    InputKind, InspectionReport, MessageSummary, Pid201SplitRecord, Pid201SplitReport,
    Pid201WriteRecord, Pid201WriteReport, PointSummary, Result as ApiResult, ScanCount,
    ScanFileResult, ScanReport, SegmentSummary, TimeMotLocSummary, TransportSummary,
    WrapperSummary, active_warnings_at, active_warnings_at_time, archive_import, archive_verify,
    inspect_bytes, inspect_oi_message, inspect_path, inspect_text, scan_path, split_pid201_bytes,
    split_pid201_path, to_json, write_pid201_split,
};
pub use error::{ErrorKind, ParseError, Result};
pub use geo::{LatLonBlock, MotionLocation, TimeMotLoc};
pub use header::{AwipsId, WmoHeading};
pub use ingest::{
    BulletinIngest, FramedStreamIngest, IngestHint, OiIngest, OiWrapperMetadata, ParsedInput,
    TransportDescriptor, TransportKind, parse_auto, parse_with_hint,
};
pub use oi::{NwwsOiId, NwwsOiMessage, NwwsOiPayload};
pub use oi_client::{
    NwwsOiClient, OiClientConfig, OiClientError, OiClientResult, RustlsUpgrader, TlsUpgrader,
    bind_iq, initial_stream_open, join_room_presence, sasl_plain_auth, session_iq, starttls_stanza,
};
pub use pid201::{Pid201DrainState, Pid201Record, Pid201StreamAdapter};
pub use product::{
    NwsProduct, NwwsContent, ProductFamily, ProductSegment, SegmentBoundaries, SegmentTag,
    SegmentTags, WarningActionKind, WarningActionSource, WarningActionTag, WarningParsedTags,
    WarningTextTag, WarningTextTagKind,
};
pub use replay::{
    ReplayInputKind, ReplayRecordSummary, ReplaySummary, collect_input_paths, infer_hint_from_path,
    summarize_bytes, summarize_path,
};
pub use runtime::{
    ArchiveRecord, ArchiveStore, ArchivedMetadata, DedupeStore, IngestService, MessageRouter,
    Pid201IngestSession, ProcessReport, RecordSource, Route, RouteRule, RuntimeError,
    semantic_fingerprint,
};
pub use stream::{FramedChunk, FramedMessageIter, ScanOutcome, WmoStreamScanner};
pub use ugc::{UgcCode, UgcPurgeTime, UgcString};
pub use vtec::{EventClass, Hvtec, Phenomenon, Pvtec, Significance, VtecAction};
pub use warning::{
    AREA_TIME_POLYGON_METRICS_METHOD, AREA_TIME_POLYGON_METRICS_SCHEMA,
    WarningAreaTimePolygonMetrics, WarningByteRange, WarningLifecycleStatus, WarningPoint,
    WarningPolygon, WarningTags, WarningTimeMotion, WarningTimelineFailure, WarningTimelineRecord,
    WarningTimelineReport, area_time_polygon_metric_limitations, area_time_polygon_metrics,
    polygon_timeline, polygon_timeline_at, polygon_timeline_at_time,
    warning_interval_duration_seconds, warning_interval_overlap_seconds,
    warning_polygon_area_square_degrees, warning_polygon_overlap_area_square_degrees,
};
pub use wmo::{WmoFrameKind, WmoMessage};

/// Start-of-heading control byte used by framed WMO messages.
pub const SOH: u8 = 0x01;

/// End-of-text control byte used by framed WMO messages.
pub const ETX: u8 = 0x03;

/// Carriage return byte used by WMO text framing.
pub const CR: u8 = 0x0D;

/// Line feed byte used by WMO text framing.
pub const LF: u8 = 0x0A;

/// Canonical WMO line separator.
pub const WMO_SEPARATOR: &[u8; 3] = b"\r\r\n";
