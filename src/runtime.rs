use std::collections::HashSet;
use std::fs::{self, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};

use serde::Serialize;
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;

use crate::ingest::{IngestHint, ParsedInput, TransportKind, parse_with_hint};
use crate::pid201::{Pid201DrainState, Pid201Record, Pid201StreamAdapter};
use crate::product::{NwwsContent, ProductFamily};
use crate::{NwwsOiMessage, ParseError, Result as ParseResult, WmoFrameKind};

pub type Result<T> = std::result::Result<T, RuntimeError>;

#[derive(Debug)]
pub enum RuntimeError {
    Parse(ParseError),
    Io(io::Error),
}

impl From<ParseError> for RuntimeError {
    fn from(value: ParseError) -> Self {
        Self::Parse(value)
    }
}

impl From<io::Error> for RuntimeError {
    fn from(value: io::Error) -> Self {
        Self::Io(value)
    }
}

impl std::fmt::Display for RuntimeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Parse(err) => write!(f, "{err}"),
            Self::Io(err) => write!(f, "{err}"),
        }
    }
}

impl std::error::Error for RuntimeError {}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum RecordSource {
    OpenInterface,
    RawBulletin,
    SatellitePid201,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ArchiveRecord {
    pub fingerprint: String,
    pub duplicate: bool,
    pub raw_path: PathBuf,
    pub metadata_path: PathBuf,
    pub metadata: ArchivedMetadata,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ArchivedMetadata {
    pub captured_at: String,
    pub source: RecordSource,
    pub transport: &'static str,
    pub frame_kind: &'static str,
    pub sequence_number: Option<u16>,
    pub ttaaii: String,
    pub cccc: String,
    pub awips_id: Option<String>,
    pub family: ProductFamily,
    pub segment_count: usize,
    pub wrapper_id: Option<String>,
    pub wrapper_issue: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProcessReport {
    pub records: Vec<ArchiveRecord>,
}

#[derive(Debug, Clone)]
pub struct ArchiveStore {
    root: PathBuf,
}

impl ArchiveStore {
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self { root: root.into() }
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    fn write_record(
        &self,
        fingerprint: &str,
        raw_bytes: &[u8],
        metadata: &ArchivedMetadata,
    ) -> Result<(PathBuf, PathBuf)> {
        let now = OffsetDateTime::now_utc();
        let day_path = self.root.join(format!(
            "{:04}/{:02}/{:02}",
            now.year(),
            u8::from(now.month()),
            now.day()
        ));
        let office = sanitize_path_segment(&metadata.cccc);
        let awips = sanitize_path_segment(metadata.awips_id.as_deref().unwrap_or(&metadata.ttaaii));
        let family = sanitize_path_segment(family_slug(metadata.family));
        let directory = day_path
            .join(source_slug(metadata.source))
            .join(office)
            .join(awips)
            .join(family);
        fs::create_dir_all(&directory)?;

        let extension = match metadata.source {
            RecordSource::OpenInterface => "xml",
            RecordSource::RawBulletin => "txt",
            RecordSource::SatellitePid201 => "wmo",
        };
        let raw_path = directory.join(format!("{fingerprint}.{extension}"));
        let metadata_path = directory.join(format!("{fingerprint}.json"));

        fs::write(&raw_path, raw_bytes)?;
        fs::write(&metadata_path, serde_json::to_vec_pretty(metadata)?)?;
        Ok((raw_path, metadata_path))
    }
}

#[derive(Debug, Clone)]
pub struct DedupeStore {
    index_path: PathBuf,
    seen: HashSet<String>,
}

impl DedupeStore {
    pub fn open(index_path: impl Into<PathBuf>) -> io::Result<Self> {
        let index_path = index_path.into();
        let mut seen = HashSet::new();
        if index_path.exists() {
            for line in fs::read_to_string(&index_path)?.lines() {
                if !line.trim().is_empty() {
                    seen.insert(line.trim().to_owned());
                }
            }
        }

        Ok(Self { index_path, seen })
    }

    pub fn contains(&self, fingerprint: &str) -> bool {
        self.seen.contains(fingerprint)
    }

    pub fn insert(&mut self, fingerprint: &str) -> io::Result<bool> {
        if !self.seen.insert(fingerprint.to_owned()) {
            return Ok(false);
        }

        if let Some(parent) = self.index_path.parent() {
            fs::create_dir_all(parent)?;
        }

        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.index_path)?;
        writeln!(file, "{fingerprint}")?;
        Ok(true)
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RouteRule {
    pub family: Option<ProductFamily>,
    pub cccc: Option<String>,
    pub awips_prefix: Option<String>,
}

impl RouteRule {
    pub fn matches(&self, metadata: &ArchivedMetadata) -> bool {
        if let Some(family) = self.family
            && metadata.family != family
        {
            return false;
        }
        if let Some(cccc) = &self.cccc
            && metadata.cccc != *cccc
        {
            return false;
        }
        if let Some(prefix) = &self.awips_prefix {
            let Some(awips) = metadata.awips_id.as_deref() else {
                return false;
            };
            if !awips.starts_with(prefix) {
                return false;
            }
        }
        true
    }
}

#[derive(Debug, Clone)]
pub struct Route {
    pub rule: RouteRule,
    pub archive: ArchiveStore,
}

#[derive(Debug, Clone, Default)]
pub struct MessageRouter {
    default_archive: Option<ArchiveStore>,
    routes: Vec<Route>,
}

impl MessageRouter {
    pub fn new(default_archive: Option<ArchiveStore>) -> Self {
        Self {
            default_archive,
            routes: Vec::new(),
        }
    }

    pub fn add_route(&mut self, route: Route) {
        self.routes.push(route);
    }

    fn archives_for<'a>(&'a self, metadata: &ArchivedMetadata) -> Vec<&'a ArchiveStore> {
        let mut archives = self
            .routes
            .iter()
            .filter(|route| route.rule.matches(metadata))
            .map(|route| &route.archive)
            .collect::<Vec<_>>();

        if archives.is_empty()
            && let Some(default_archive) = &self.default_archive
        {
            archives.push(default_archive);
        }

        archives
    }
}

#[derive(Debug, Clone)]
pub struct IngestService {
    router: MessageRouter,
    dedupe: DedupeStore,
    archive_duplicates: bool,
}

impl IngestService {
    pub fn new(router: MessageRouter, dedupe: DedupeStore) -> Self {
        Self {
            router,
            dedupe,
            archive_duplicates: false,
        }
    }

    pub fn set_archive_duplicates(&mut self, archive_duplicates: bool) {
        self.archive_duplicates = archive_duplicates;
    }

    pub fn process_bytes(&mut self, hint: IngestHint, input: &[u8]) -> Result<ProcessReport> {
        let parsed = parse_with_hint(hint, input)?;
        let mut records = Vec::new();

        match parsed {
            ParsedInput::Bulletin(value) => {
                let record = record_from_content(
                    RecordSource::RawBulletin,
                    value.transport.kind,
                    input.to_vec(),
                    &value.content,
                    None,
                )?;
                self.process_record(record, &mut records)?;
            }
            ParsedInput::OpenInterface(value) => {
                let content = value.content()?;
                let wrapper = value.wrapper.as_ref().map(|wrapper| WrapperRecord {
                    id: Some(wrapper.id.clone()),
                    issue: value
                        .message
                        .payload
                        .as_ref()
                        .and_then(|payload| payload.issue.format(&Rfc3339).ok()),
                });
                let record = record_from_content(
                    RecordSource::OpenInterface,
                    value.transport.kind,
                    input.to_vec(),
                    &content,
                    wrapper,
                )?;
                self.process_record(record, &mut records)?;
            }
            ParsedInput::FramedStream(value) => {
                let contents = value.contents()?;
                for (chunk, content) in value.chunks.iter().zip(contents.iter()) {
                    let record = record_from_content(
                        RecordSource::SatellitePid201,
                        value.transport.kind,
                        chunk.bytes.to_vec(),
                        content,
                        None,
                    )?;
                    self.process_record(record, &mut records)?;
                }
            }
        }

        Ok(ProcessReport { records })
    }

    fn process_record(
        &mut self,
        record: PreparedRecord,
        output: &mut Vec<ArchiveRecord>,
    ) -> Result<()> {
        let duplicate = !self.dedupe.insert(&record.fingerprint)?;
        if duplicate && !self.archive_duplicates {
            return Ok(());
        }

        for archive in self.router.archives_for(&record.metadata) {
            let (raw_path, metadata_path) =
                archive.write_record(&record.fingerprint, &record.raw_bytes, &record.metadata)?;
            output.push(ArchiveRecord {
                fingerprint: record.fingerprint.clone(),
                duplicate,
                raw_path,
                metadata_path,
                metadata: record.metadata.clone(),
            });
        }

        Ok(())
    }
}

#[derive(Debug, Clone)]
pub struct Pid201IngestSession {
    adapter: Pid201StreamAdapter,
    service: IngestService,
}

impl Pid201IngestSession {
    pub fn new(service: IngestService) -> Self {
        Self::with_adapter(Pid201StreamAdapter::new(), service)
    }

    pub fn with_adapter(adapter: Pid201StreamAdapter, service: IngestService) -> Self {
        Self { adapter, service }
    }

    pub fn push(&mut self, chunk: &[u8]) -> Result<ProcessReport> {
        let pid201_records = self.adapter.push(chunk)?;
        self.process_records(pid201_records)
    }

    pub fn pending(&self) -> &[u8] {
        self.adapter.pending()
    }

    pub fn finish(&mut self) -> Pid201DrainState {
        self.adapter.finish()
    }

    pub fn service(&self) -> &IngestService {
        &self.service
    }

    pub fn service_mut(&mut self) -> &mut IngestService {
        &mut self.service
    }

    fn process_records(&mut self, pid201_records: Vec<Pid201Record>) -> Result<ProcessReport> {
        let mut records = Vec::new();
        for pid201_record in pid201_records {
            let Pid201Record {
                transport,
                raw_message,
                ..
            } = pid201_record;
            let content = NwwsContent::parse_bulletin(&raw_message)?;
            let record = record_from_content(
                RecordSource::SatellitePid201,
                transport.kind,
                raw_message.clone(),
                &content,
                None,
            )?;
            self.service.process_record(record, &mut records)?;
        }

        Ok(ProcessReport { records })
    }
}

#[derive(Debug, Clone)]
struct WrapperRecord {
    id: Option<String>,
    issue: Option<String>,
}

#[derive(Debug, Clone)]
struct PreparedRecord {
    fingerprint: String,
    raw_bytes: Vec<u8>,
    metadata: ArchivedMetadata,
}

fn record_from_content(
    source: RecordSource,
    transport: TransportKind,
    raw_bytes: Vec<u8>,
    content: &NwwsContent<'_>,
    wrapper: Option<WrapperRecord>,
) -> Result<PreparedRecord> {
    let bulletin = &content.bulletin;
    let captured_at = OffsetDateTime::now_utc()
        .format(&Rfc3339)
        .map_err(|err| io::Error::other(format!("failed to format capture time: {err}")))?;
    let metadata = ArchivedMetadata {
        captured_at,
        source,
        transport: match transport {
            TransportKind::OpenInterface => "open-interface",
            TransportKind::SatellitePid201 => "satellite-pid201",
            TransportKind::PlainWmoText => "plain-wmo-text",
        },
        frame_kind: match bulletin.frame_kind {
            WmoFrameKind::Framed => "framed",
            WmoFrameKind::Bare => "bare",
        },
        sequence_number: bulletin.sequence_number,
        ttaaii: bulletin.heading.ttaaii().to_owned(),
        cccc: bulletin.heading.cccc().to_owned(),
        awips_id: bulletin
            .awips_id
            .as_ref()
            .map(|value| value.raw().to_owned()),
        family: content.product.family,
        segment_count: content.product.segments.len(),
        wrapper_id: wrapper.as_ref().and_then(|value| value.id.clone()),
        wrapper_issue: wrapper.and_then(|value| value.issue),
    };
    let fingerprint = semantic_fingerprint(content);

    Ok(PreparedRecord {
        fingerprint,
        raw_bytes,
        metadata,
    })
}

pub fn semantic_fingerprint(content: &NwwsContent<'_>) -> String {
    let bulletin = &content.bulletin;
    let mut canonical = String::new();

    canonical.push_str(bulletin.heading.raw());
    canonical.push('\n');
    if let Some(awips_id) = &bulletin.awips_id {
        canonical.push_str(awips_id.raw());
        canonical.push('\n');
    }
    push_normalized_newlines(&mut canonical, bulletin.body);

    blake3::hash(canonical.as_bytes()).to_hex().to_string()
}

fn push_normalized_newlines(output: &mut String, input: &str) {
    output.push_str(
        &input
            .replace("\r\r\n", "\n")
            .replace("\r\n", "\n")
            .replace('\r', "\n"),
    );
}

fn sanitize_path_segment(value: &str) -> String {
    value
        .chars()
        .map(|ch| match ch {
            'a'..='z' | 'A'..='Z' | '0'..='9' | '-' | '_' | '.' => ch,
            _ => '_',
        })
        .collect()
}

fn source_slug(source: RecordSource) -> &'static str {
    match source {
        RecordSource::OpenInterface => "open_interface",
        RecordSource::RawBulletin => "raw_bulletin",
        RecordSource::SatellitePid201 => "pid201",
    }
}

/// Stable lowercase directory/query slug for a product family; these values
/// name the family level of the archive directory layout.
pub fn family_slug(family: ProductFamily) -> &'static str {
    match family {
        ProductFamily::Tornado => "tornado",
        ProductFamily::SevereThunderstorm => "severe_thunderstorm",
        ProductFamily::FlashFlood => "flash_flood",
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
}

impl From<serde_json::Error> for RuntimeError {
    fn from(value: serde_json::Error) -> Self {
        Self::Io(io::Error::other(value))
    }
}

pub fn parse_oi_message(input: &str) -> ParseResult<NwwsOiMessage> {
    NwwsOiMessage::parse(input)
}

#[cfg(test)]
mod tests {
    use std::time::{SystemTime, UNIX_EPOCH};

    use super::{
        ArchiveStore, DedupeStore, IngestService, MessageRouter, Pid201IngestSession, RecordSource,
        Route, RouteRule, semantic_fingerprint,
    };
    use crate::ingest::IngestHint;
    use crate::product::ProductFamily;

    #[test]
    fn semantic_fingerprint_matches_bare_and_open_interface() {
        let bare = crate::NwwsContent::parse_bulletin(include_bytes!(
            "../tests/fixtures/wmo_tornado_warning.txt"
        ))
        .unwrap();
        let xml = include_str!("../tests/fixtures/nwws_oi_tornado_warning.xml");
        let message = crate::NwwsOiMessage::parse(xml).unwrap();
        let oi = crate::NwwsContent::from_oi_message(&message).unwrap();

        assert_eq!(semantic_fingerprint(&bare), semantic_fingerprint(&oi));
    }

    #[test]
    fn semantic_fingerprint_matches_bare_and_framed_bulletins() {
        let bare = crate::NwwsContent::parse_bulletin(include_bytes!(
            "../tests/fixtures/wmo_tornado_warning.txt"
        ))
        .unwrap();

        let framed = format!(
            "\u{1}\r\r\n{}\r\r\n\u{3}",
            include_str!("../tests/fixtures/wmo_tornado_warning.txt")
                .lines()
                .collect::<Vec<_>>()
                .join("\r\r\n")
        );
        let framed = crate::NwwsContent::parse_bulletin(framed.as_bytes()).unwrap();

        assert_eq!(semantic_fingerprint(&bare), semantic_fingerprint(&framed));
    }

    #[test]
    fn dedupe_store_persists_fingerprints() {
        let dir = temp_dir_path("nwws_rs_runtime_dedupe");
        let index = dir.join("dedupe").join("seen.txt");

        let mut store = DedupeStore::open(&index).unwrap();
        assert!(store.insert("abc").unwrap());
        assert!(!store.insert("abc").unwrap());

        let reopened = DedupeStore::open(&index).unwrap();
        assert!(reopened.contains("abc"));

        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn service_archives_first_copy_and_skips_duplicate() {
        let dir = temp_dir_path("nwws_rs_runtime_service");
        let archive_root = dir.join("archive");
        let dedupe_path = dir.join("state").join("dedupe.txt");

        let router = MessageRouter::new(Some(ArchiveStore::new(&archive_root)));
        let dedupe = DedupeStore::open(&dedupe_path).unwrap();
        let mut service = IngestService::new(router, dedupe);

        let first = service
            .process_bytes(
                IngestHint::RawBulletin,
                include_bytes!("../tests/fixtures/wmo_tornado_warning.txt"),
            )
            .unwrap();
        let second = service
            .process_bytes(
                IngestHint::OpenInterface,
                include_bytes!("../tests/fixtures/nwws_oi_tornado_warning.xml"),
            )
            .unwrap();

        assert_eq!(first.records.len(), 1);
        assert!(first.records[0].raw_path.exists());
        assert_eq!(first.records[0].metadata.source, RecordSource::RawBulletin);
        assert!(second.records.is_empty());

        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn router_matches_family_and_awips_prefix() {
        let dir = temp_dir_path("nwws_rs_runtime_routes");
        let default_root = dir.join("default");
        let tor_root = dir.join("tor");
        let dedupe_path = dir.join("dedupe.txt");

        let mut router = MessageRouter::new(Some(ArchiveStore::new(&default_root)));
        router.add_route(Route {
            rule: RouteRule {
                family: Some(ProductFamily::Tornado),
                cccc: Some("KLOT".to_owned()),
                awips_prefix: Some("TOR".to_owned()),
            },
            archive: ArchiveStore::new(&tor_root),
        });

        let dedupe = DedupeStore::open(&dedupe_path).unwrap();
        let mut service = IngestService::new(router, dedupe);
        let report = service
            .process_bytes(
                IngestHint::RawBulletin,
                include_bytes!("../tests/fixtures/wmo_tornado_warning.txt"),
            )
            .unwrap();

        assert_eq!(report.records.len(), 1);
        assert!(report.records[0].raw_path.starts_with(&tor_root));

        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn pid201_session_processes_chunked_stream() {
        let dir = temp_dir_path("nwws_rs_pid201_session");
        let archive_root = dir.join("archive");
        let dedupe_path = dir.join("state").join("dedupe.txt");

        let router = MessageRouter::new(Some(ArchiveStore::new(&archive_root)));
        let dedupe = DedupeStore::open(&dedupe_path).unwrap();
        let service = IngestService::new(router, dedupe);
        let mut session = Pid201IngestSession::new(service);

        let framed = format!(
            "noise\u{1}\r\r\n{}\r\r\n\u{3}",
            include_str!("../tests/fixtures/wmo_tornado_warning.txt")
                .lines()
                .collect::<Vec<_>>()
                .join("\r\r\n")
        )
        .into_bytes();
        let split = framed.len() / 2;

        let first = session.push(&framed[..split]).unwrap();
        assert!(first.records.is_empty());
        assert!(!session.pending().is_empty());

        let second = session.push(&framed[split..]).unwrap();
        assert_eq!(second.records.len(), 1);
        assert_eq!(
            second.records[0].metadata.source,
            RecordSource::SatellitePid201
        );
        assert!(second.records[0].raw_path.starts_with(&archive_root));
        assert!(
            second.records[0]
                .raw_path
                .to_string_lossy()
                .contains("pid201")
        );

        let drain = session.finish();
        assert_eq!(drain.pending_bytes, 0);
        assert!(drain.discarded_junk >= 5);

        std::fs::remove_dir_all(dir).unwrap();
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
