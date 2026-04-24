use serde::Serialize;

use crate::error::{ErrorKind, ParseError, Result};
use crate::geo::{LatLonBlock, TimeMotLoc};
use crate::header::AwipsId;
use crate::oi::{NwwsOiMessage, NwwsOiPayload};
use crate::ugc::UgcString;
use crate::vtec::{Hvtec, Phenomenon, Pvtec, VtecAction};
use crate::wmo::WmoMessage;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum ProductFamily {
    Tornado,
    SevereThunderstorm,
    FlashFlood,
    Flood,
    Marine,
    Discussion,
    Forecast,
    Statement,
    Hydrology,
    Watch,
    Advisory,
    Administrative,
    Unknown,
}

#[derive(Debug, Clone, PartialEq)]
pub struct NwsProduct<'a> {
    pub family: ProductFamily,
    pub awips_id: Option<AwipsId<'a>>,
    pub mnd_header: Option<&'a str>,
    pub preamble: Vec<&'a str>,
    pub segments: Vec<ProductSegment<'a>>,
}

impl<'a> NwsProduct<'a> {
    pub fn parse(message: &WmoMessage<'a>) -> Result<Self> {
        let lines = line_refs(message.body);
        let mut preamble = Vec::new();
        let mut segments = Vec::new();
        let mut cursor = 0usize;

        while cursor < lines.len() {
            if lines[cursor].text.trim().is_empty() {
                cursor += 1;
                continue;
            }

            if let Some((ugc, ugc_end)) = parse_ugc_block(message.body, &lines, cursor) {
                let start = cursor;
                let mut end = ugc_end;
                let mut separated_by_dollars = false;
                while end < lines.len() {
                    let text = lines[end].text.trim();
                    if text == "$$" {
                        separated_by_dollars = true;
                        break;
                    }
                    if parse_ugc_block(message.body, &lines, end).is_some() {
                        break;
                    }
                    end += 1;
                }

                segments.push(ProductSegment::parse(
                    message.body,
                    &lines[start..end],
                    ugc,
                    ugc_end - start,
                    SegmentBoundaries {
                        separated_by_dollars,
                        contains_andand: lines[start..end]
                            .iter()
                            .any(|line| line.text.trim() == "&&"),
                    },
                )?);

                cursor = end;
                if cursor < lines.len() && lines[cursor].text.trim() == "$$" {
                    cursor += 1;
                }
            } else {
                preamble.push(lines[cursor].text);
                cursor += 1;
            }
        }

        let family = classify_family(message.awips_id, &segments, preamble.first().copied());
        let mnd_header = preamble
            .iter()
            .copied()
            .find(|line| !line.trim().is_empty());

        Ok(Self {
            family,
            awips_id: message.awips_id,
            mnd_header,
            preamble,
            segments,
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SegmentBoundaries {
    pub separated_by_dollars: bool,
    pub contains_andand: bool,
}

#[derive(Debug, Clone, PartialEq)]
pub struct ProductSegment<'a> {
    pub ugc: UgcString<'a>,
    pub pvtec: Vec<Pvtec>,
    pub hvtec: Vec<Hvtec>,
    pub headline: Option<&'a str>,
    pub body_lines: Vec<&'a str>,
    pub lat_lon: Option<LatLonBlock<'a>>,
    pub time_mot_loc: Option<TimeMotLoc<'a>>,
    pub tags: SegmentTags<'a>,
    pub boundaries: SegmentBoundaries,
}

impl<'a> ProductSegment<'a> {
    pub fn warning_tags(&self) -> WarningParsedTags {
        WarningParsedTags::from_segment(self)
    }

    fn parse(
        body: &'a str,
        lines: &[LineRef<'a>],
        ugc: UgcString<'a>,
        ugc_line_count: usize,
        boundaries: SegmentBoundaries,
    ) -> Result<Self> {
        if lines.is_empty() {
            return Err(ParseError::new(ErrorKind::UnexpectedEof("product segment")));
        }

        let mut cursor = ugc_line_count;

        let mut pvtec = Vec::new();
        while cursor < lines.len() {
            let text = lines[cursor].text.trim();
            if !text.starts_with('/') {
                break;
            }
            match Pvtec::parse(text) {
                Ok(code) => {
                    pvtec.push(code);
                    cursor += 1;
                }
                Err(_) => break,
            }
        }

        let mut hvtec = Vec::new();
        while cursor < lines.len() {
            let text = lines[cursor].text.trim();
            if !text.starts_with('/') {
                break;
            }
            match Hvtec::parse(text) {
                Ok(code) => {
                    hvtec.push(code);
                    cursor += 1;
                }
                Err(_) => break,
            }
        }

        let content_lines = &lines[cursor..];
        let body_lines = content_lines
            .iter()
            .map(|line| line.text)
            .collect::<Vec<_>>();
        let headline = body_lines
            .iter()
            .copied()
            .find(|line| !line.trim().is_empty());
        let lat_lon = extract_lat_lon(body, content_lines)?;
        let time_mot_loc = extract_time_mot_loc(content_lines)?;
        let tags = SegmentTags::extract(&body_lines);

        Ok(Self {
            ugc,
            pvtec,
            hvtec,
            headline,
            body_lines,
            lat_lon,
            time_mot_loc,
            tags,
            boundaries,
        })
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct SegmentTags<'a> {
    pub tags: Vec<SegmentTag<'a>>,
}

impl<'a> SegmentTags<'a> {
    fn extract(lines: &[&'a str]) -> Self {
        let mut tags = Vec::new();
        for line in lines {
            let upper = line.trim().to_ascii_uppercase();
            if upper.contains("TORNADO...OBSERVED") {
                tags.push(SegmentTag::TornadoObserved);
            }
            if upper.contains("TORNADO...RADAR INDICATED") {
                tags.push(SegmentTag::TornadoRadarIndicated);
            }
            if upper.contains("TORNADO...POSSIBLE") {
                tags.push(SegmentTag::TornadoPossible);
            }
            if upper.contains("FLASH FLOOD...OBSERVED") {
                tags.push(SegmentTag::FlashFloodObserved);
            }
            if upper.trim_start().starts_with("FLASH FLOOD EMERGENCY") {
                tags.push(SegmentTag::FlashFloodEmergency);
            }
            if let Some(value) = parse_numeric_tag(&upper, "HAIL...", "IN")
                .or_else(|| parse_numeric_tag(&upper, "MAX HAIL SIZE...", "IN"))
            {
                tags.push(SegmentTag::HailInches(value));
            }
            if let Some(value) = parse_integer_tag(&upper, "WIND...", "MPH")
                .or_else(|| parse_integer_tag(&upper, "MAX WIND GUST...", "MPH"))
            {
                tags.push(SegmentTag::WindMph(value));
            }
            if upper.contains("CONSIDERABLE") && upper.contains("DAMAGE THREAT") {
                tags.push(SegmentTag::DamageThreat("CONSIDERABLE"));
            }
            if upper.contains("SIGNIFICANT") && upper.contains("DAMAGE THREAT") {
                tags.push(SegmentTag::DamageThreat("SIGNIFICANT"));
            }
            if upper.contains("DESTRUCTIVE") && upper.contains("DAMAGE THREAT") {
                tags.push(SegmentTag::DamageThreat("DESTRUCTIVE"));
            }
            if upper.contains("CATASTROPHIC") && upper.contains("DAMAGE THREAT") {
                tags.push(SegmentTag::DamageThreat("CATASTROPHIC"));
            }
            if upper.contains("SNOW SQUALL IMPACT...SIGNIFICANT") {
                tags.push(SegmentTag::DamageThreat("SIGNIFICANT"));
            }
            if upper.contains("SNOW SQUALL IMPACT...GENERAL") {
                tags.push(SegmentTag::DamageThreat("GENERAL"));
            }
        }
        Self { tags }
    }
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum SegmentTag<'a> {
    TornadoObserved,
    TornadoRadarIndicated,
    TornadoPossible,
    FlashFloodObserved,
    FlashFloodEmergency,
    HailInches(f32),
    WindMph(u16),
    DamageThreat(&'a str),
}

#[derive(Debug, Clone, Default, PartialEq, Serialize)]
pub struct WarningParsedTags {
    pub text_tags: Vec<WarningTextTag>,
    pub actions: Vec<WarningActionTag>,
}

impl WarningParsedTags {
    pub fn extract_text(lines: &[&str]) -> Self {
        Self {
            text_tags: extract_warning_text_tags(lines),
            actions: Vec::new(),
        }
    }

    pub fn from_segment(segment: &ProductSegment<'_>) -> Self {
        Self {
            text_tags: extract_warning_text_tags(&segment.body_lines),
            actions: extract_warning_actions(&segment.pvtec),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum WarningTextTagKind {
    Tornado,
    HailThreat,
    MaxHailSize,
    WindThreat,
    MaxWindGust,
    FlashFloodDamageThreat,
    TstmDamageThreat,
    TornadoDamageThreat,
    Threat,
    Source,
    Impact,
}

impl WarningTextTagKind {
    fn from_normalized_name(name: &str) -> Option<Self> {
        match name {
            "TORNADO" => Some(Self::Tornado),
            "HAIL THREAT" => Some(Self::HailThreat),
            "MAX HAIL SIZE" => Some(Self::MaxHailSize),
            "WIND THREAT" => Some(Self::WindThreat),
            "MAX WIND GUST" => Some(Self::MaxWindGust),
            "FLASH FLOOD DAMAGE THREAT" => Some(Self::FlashFloodDamageThreat),
            "TSTM DAMAGE THREAT" => Some(Self::TstmDamageThreat),
            "TORNADO DAMAGE THREAT" => Some(Self::TornadoDamageThreat),
            "THREAT" => Some(Self::Threat),
            "SOURCE" => Some(Self::Source),
            "IMPACT" => Some(Self::Impact),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct WarningTextTag {
    pub kind: WarningTextTagKind,
    pub raw_line: String,
    pub raw_name: String,
    pub raw_value: String,
    pub normalized_value: String,
    pub numeric_value: Option<f32>,
    pub unit: Option<String>,
    pub line_number: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum WarningActionKind {
    New,
    Continue,
    ExtendTime,
    ExtendArea,
    ExtendAreaAndTime,
    Upgrade,
    Cancel,
    Expire,
    Correction,
    Routine,
}

impl WarningActionKind {
    fn from_vtec(action: VtecAction) -> Self {
        match action {
            VtecAction::New => Self::New,
            VtecAction::Continue => Self::Continue,
            VtecAction::ExtendTime => Self::ExtendTime,
            VtecAction::ExtendArea => Self::ExtendArea,
            VtecAction::ExtendAreaAndTime => Self::ExtendAreaAndTime,
            VtecAction::Upgrade => Self::Upgrade,
            VtecAction::Cancel => Self::Cancel,
            VtecAction::Expire => Self::Expire,
            VtecAction::Correction => Self::Correction,
            VtecAction::Routine => Self::Routine,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum WarningActionSource {
    Pvtec,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct WarningActionTag {
    pub source: WarningActionSource,
    pub action: String,
    pub normalized_action: WarningActionKind,
    pub raw: String,
    pub vtec_index: usize,
}

#[derive(Debug, Clone, PartialEq)]
pub struct NwwsContent<'a> {
    pub bulletin: WmoMessage<'a>,
    pub product: NwsProduct<'a>,
}

impl<'a> NwwsContent<'a> {
    pub fn parse_bulletin(input: &'a [u8]) -> Result<Self> {
        let bulletin = WmoMessage::parse(input)?;
        let product = NwsProduct::parse(&bulletin)?;
        Ok(Self { bulletin, product })
    }

    pub fn from_oi_payload(payload: &'a NwwsOiPayload) -> Result<Self> {
        let bulletin = payload.parse_bulletin()?;
        let product = NwsProduct::parse(&bulletin)?;
        Ok(Self { bulletin, product })
    }

    pub fn from_oi_message(message: &'a NwwsOiMessage) -> Result<Self> {
        let payload = message
            .payload
            .as_ref()
            .ok_or_else(|| ParseError::new(ErrorKind::MissingField("nwws-oi payload")))?;
        Self::from_oi_payload(payload)
    }
}

#[derive(Debug, Clone, Copy)]
struct LineRef<'a> {
    text: &'a str,
    start: usize,
    end: usize,
}

fn line_refs(input: &str) -> Vec<LineRef<'_>> {
    let bytes = input.as_bytes();
    let mut lines = Vec::new();
    let mut start = 0usize;

    loop {
        let end = bytes[start..]
            .iter()
            .position(|byte| *byte == b'\n')
            .map_or(bytes.len(), |relative| start + relative);

        let mut trimmed_end = end;
        while trimmed_end > start && bytes[trimmed_end - 1] == b'\r' {
            trimmed_end -= 1;
        }

        lines.push(LineRef {
            text: &input[start..trimmed_end],
            start,
            end: trimmed_end,
        });

        if end == bytes.len() {
            break;
        }
        start = end + 1;
    }

    lines
}

fn parse_ugc_block<'a>(
    body: &'a str,
    lines: &[LineRef<'a>],
    start: usize,
) -> Option<(UgcString<'a>, usize)> {
    let first = lines.get(start)?;
    if first.text.trim().is_empty() {
        return None;
    }

    for end in start..lines.len() {
        let raw = &body[first.start..lines[end].end];
        if let Ok(ugc) = UgcString::parse(raw) {
            return Some((ugc, end + 1));
        }

        let Some(next) = lines.get(end + 1) else {
            break;
        };
        let next_text = next.text.trim();
        if next_text.is_empty()
            || next_text == "$$"
            || next_text == "&&"
            || next_text.starts_with('/')
        {
            break;
        }
    }

    None
}

fn classify_family(
    awips_id: Option<AwipsId<'_>>,
    segments: &[ProductSegment<'_>],
    mnd_header: Option<&str>,
) -> ProductFamily {
    if let Some(awips) = awips_id {
        return classify_awips_nnn(awips.nnn());
    }

    if let Some(first) = segments
        .iter()
        .flat_map(|segment| segment.pvtec.iter())
        .next()
    {
        return classify_phenomenon(first.phenomenon);
    }

    if let Some(line) = mnd_header {
        let upper = line.to_ascii_uppercase();
        if upper.contains("TORNADO WARNING") {
            return ProductFamily::Tornado;
        }
        if upper.contains("SEVERE THUNDERSTORM WARNING") {
            return ProductFamily::SevereThunderstorm;
        }
        if upper.contains("FLASH FLOOD WARNING") {
            return ProductFamily::FlashFlood;
        }
    }

    ProductFamily::Unknown
}

fn classify_awips_nnn(nnn: &str) -> ProductFamily {
    match nnn {
        "TOR" => ProductFamily::Tornado,
        "SVR" => ProductFamily::SevereThunderstorm,
        "FFW" => ProductFamily::FlashFlood,
        "FLW" | "FLS" => ProductFamily::Flood,
        "MWW" | "SMW" => ProductFamily::Marine,
        "AFD" => ProductFamily::Discussion,
        "SPS" | "SVS" => ProductFamily::Statement,
        "RVS" | "RVD" | "RVA" | "RWR" => ProductFamily::Hydrology,
        "HWO" | "NPW" | "CFW" => ProductFamily::Advisory,
        "WSW" | "FFA" => ProductFamily::Watch,
        "PNS" => ProductFamily::Administrative,
        _ => ProductFamily::Unknown,
    }
}

fn classify_phenomenon(phenomenon: Phenomenon) -> ProductFamily {
    match phenomenon.as_str() {
        "TO" => ProductFamily::Tornado,
        "SV" => ProductFamily::SevereThunderstorm,
        "FF" => ProductFamily::FlashFlood,
        "FL" => ProductFamily::Flood,
        "MA" | "SC" | "GL" | "SR" | "HF" => ProductFamily::Marine,
        _ => ProductFamily::Unknown,
    }
}

fn extract_lat_lon<'a>(body: &'a str, lines: &[LineRef<'a>]) -> Result<Option<LatLonBlock<'a>>> {
    for (index, line) in lines.iter().enumerate() {
        if line.text.trim_start().starts_with("LAT...LON") {
            let mut end_index = index;
            while end_index + 1 < lines.len() {
                let next = lines[end_index + 1].text.trim();
                if next.is_empty()
                    || next == "&&"
                    || next == "$$"
                    || next.starts_with('/')
                    || next.starts_with("TIME...MOT...LOC")
                {
                    break;
                }
                if !next
                    .split_ascii_whitespace()
                    .all(|token| token.chars().all(|ch| ch.is_ascii_digit()))
                {
                    break;
                }
                end_index += 1;
            }

            let raw = &body[lines[index].start..lines[end_index].end];
            return Ok(Some(LatLonBlock::parse(raw)?));
        }
    }

    Ok(None)
}

fn extract_time_mot_loc<'a>(lines: &[LineRef<'a>]) -> Result<Option<TimeMotLoc<'a>>> {
    for line in lines {
        if line.text.trim_start().starts_with("TIME...MOT...LOC") {
            return Ok(Some(TimeMotLoc::parse(line.text.trim())?));
        }
    }
    Ok(None)
}

fn extract_warning_text_tags(lines: &[&str]) -> Vec<WarningTextTag> {
    lines
        .iter()
        .enumerate()
        .filter_map(|(index, line)| parse_warning_text_tag(line, index + 1))
        .collect()
}

fn parse_warning_text_tag(line: &str, line_number: usize) -> Option<WarningTextTag> {
    let raw_line = line.trim();
    let (raw_name, raw_value) = raw_line.split_once("...")?;
    let raw_name = raw_name.trim().trim_start_matches('*').trim();
    let raw_value = raw_value.trim();
    let normalized_name = normalize_warning_value(raw_name);
    let kind = WarningTextTagKind::from_normalized_name(&normalized_name)?;
    let normalized_value = normalize_warning_value(raw_value);
    let (numeric_value, unit) = warning_tag_measurement(kind, raw_value);

    Some(WarningTextTag {
        kind,
        raw_line: raw_line.to_owned(),
        raw_name: raw_name.to_owned(),
        raw_value: raw_value.to_owned(),
        normalized_value,
        numeric_value,
        unit,
        line_number,
    })
}

fn extract_warning_actions(pvtec: &[Pvtec]) -> Vec<WarningActionTag> {
    pvtec
        .iter()
        .enumerate()
        .map(|(index, code)| WarningActionTag {
            source: WarningActionSource::Pvtec,
            action: code.action().as_str().to_owned(),
            normalized_action: WarningActionKind::from_vtec(code.action()),
            raw: code.raw().to_owned(),
            vtec_index: index + 1,
        })
        .collect()
}

fn warning_tag_measurement(
    kind: WarningTextTagKind,
    raw_value: &str,
) -> (Option<f32>, Option<String>) {
    match kind {
        WarningTextTagKind::MaxHailSize => measurement_value(raw_value, "IN")
            .map_or((None, None), |value| {
                (Some(round_measurement(value)), Some("in".to_owned()))
            }),
        WarningTextTagKind::MaxWindGust => measurement_value(raw_value, "MPH")
            .map_or((None, None), |value| {
                (Some(round_measurement(value)), Some("mph".to_owned()))
            }),
        _ => (None, None),
    }
}

fn measurement_value(raw_value: &str, unit: &str) -> Option<f32> {
    let compact = raw_value
        .chars()
        .filter(|ch| !ch.is_ascii_whitespace())
        .collect::<String>()
        .to_ascii_uppercase();
    let end = compact.find(unit)?;
    compact[..end]
        .trim_start_matches(['<', '>'])
        .parse::<f32>()
        .ok()
}

fn normalize_warning_value(value: &str) -> String {
    value
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
        .to_ascii_uppercase()
}

fn round_measurement(value: f32) -> f32 {
    (value * 100.0).round() / 100.0
}

fn parse_numeric_tag(line: &str, prefix: &str, suffix: &str) -> Option<f32> {
    let start = line.find(prefix)? + prefix.len();
    let tail = &line[start..];
    let end = tail.find(suffix)?;
    tail[..end]
        .trim()
        .trim_start_matches(['<', '>'])
        .parse()
        .ok()
}

fn parse_integer_tag(line: &str, prefix: &str, suffix: &str) -> Option<u16> {
    let start = line.find(prefix)? + prefix.len();
    let tail = &line[start..];
    let end = tail.find(suffix)?;
    tail[..end]
        .trim()
        .trim_start_matches(['<', '>'])
        .parse()
        .ok()
}

#[cfg(test)]
mod tests {
    use crate::product::{
        NwsProduct, ProductFamily, SegmentTag, WarningActionKind, WarningParsedTags,
        WarningTextTagKind,
    };
    use crate::wmo::WmoMessage;

    #[test]
    fn parses_segmented_warning_product() {
        let input = "123\nWUUS53 KDMX 010000\nSVRDMX\nBULLETIN - IMMEDIATE BROADCAST REQUESTED\nSevere Thunderstorm Warning\nIAC001-003-010100-\n/O.NEW.KDMX.SV.W.0001.240601T0000Z-240601T0100Z/\nSevere Thunderstorm Warning for...\nTIME...MOT...LOC 0000Z 240DEG 40KT 4187 9398 4176 9427\nLAT...LON 4187 9398 4176 9427 4186 9440 4196 9410\nHAIL...1.75IN\nWIND...70MPH\n$$";
        let bulletin = WmoMessage::parse_str(input).unwrap();
        let product = NwsProduct::parse(&bulletin).unwrap();
        assert_eq!(product.family, ProductFamily::SevereThunderstorm);
        assert_eq!(product.segments.len(), 1);
        let segment = &product.segments[0];
        assert_eq!(segment.ugc.codes.len(), 2);
        assert_eq!(segment.pvtec.len(), 1);
        assert!(segment.lat_lon.is_some());
        assert!(segment.time_mot_loc.is_some());
        assert!(segment.tags.tags.contains(&SegmentTag::HailInches(1.75)));
        assert!(segment.tags.tags.contains(&SegmentTag::WindMph(70)));
    }

    #[test]
    fn classifies_from_heading_when_awips_is_missing() {
        let input = "123\nWUUS53 KDMX 010000\nTornado Warning\nIAC001-010100-\n/O.NEW.KDMX.TO.W.0001.240601T0000Z-240601T0100Z/\nTornado...OBSERVED\n";
        let bulletin = WmoMessage::parse_str(input).unwrap();
        let product = NwsProduct::parse(&bulletin).unwrap();
        assert_eq!(product.family, ProductFamily::Tornado);
        assert!(
            product.segments[0]
                .tags
                .tags
                .contains(&SegmentTag::TornadoObserved)
        );
    }

    #[test]
    fn extracts_max_hail_and_max_wind_tags() {
        let input = "123\nWUUS53 KDMX 010000\nSVRDMX\nSevere Thunderstorm Warning\nIAC001-010100-\n/O.NEW.KDMX.SV.W.0001.240601T0000Z-240601T0100Z/\nMAX HAIL SIZE...1.25 IN\nMAX WIND GUST...70 MPH\n";
        let bulletin = WmoMessage::parse_str(input).unwrap();
        let product = NwsProduct::parse(&bulletin).unwrap();
        let tags = &product.segments[0].tags.tags;

        assert!(tags.contains(&SegmentTag::HailInches(1.25)));
        assert!(tags.contains(&SegmentTag::WindMph(70)));
    }

    #[test]
    fn parses_wrapped_multiline_ugc_segment() {
        let input = "006 \nWWUS73 KDMX 310924\nNPWDMX\n\nIAZ004-005-015-023-024-033>035-044>047-057>059-070>072-081-082-\n092-093-111730-\n/O.NEW.KDMX.WI.Y.9999.171231T1600Z-180101T2300Z/\nHeadline\n";
        let bulletin = WmoMessage::parse_str(input).unwrap();
        let product = NwsProduct::parse(&bulletin).unwrap();

        assert_eq!(product.segments.len(), 1);
        assert_eq!(product.segments[0].ugc.codes.len(), 13);
        assert_eq!(product.segments[0].pvtec.len(), 1);
    }

    #[test]
    fn extracts_possible_and_catastrophic_tags() {
        let input = "123\nWUUS53 KDMX 010000\nSVRDMX\nIAC001-010100-\n/O.NEW.KDMX.SV.W.0001.240601T0000Z-240601T0100Z/\nTORNADO...POSSIBLE\nTORNADO DAMAGE THREAT...CATASTROPHIC\nHAIL...<.75IN\n";
        let bulletin = WmoMessage::parse_str(input).unwrap();
        let product = NwsProduct::parse(&bulletin).unwrap();
        let tags = &product.segments[0].tags.tags;

        assert!(tags.contains(&SegmentTag::TornadoPossible));
        assert!(tags.contains(&SegmentTag::DamageThreat("CATASTROPHIC")));
        assert!(tags.contains(&SegmentTag::HailInches(0.75)));
    }

    #[test]
    fn extracts_structured_tornado_warning_tags_and_action() {
        let bulletin =
            WmoMessage::parse_str(include_str!("../tests/fixtures/wmo_tornado_warning.txt"))
                .unwrap();
        let product = NwsProduct::parse(&bulletin).unwrap();
        let tags = product.segments[0].warning_tags();

        assert_eq!(tags.actions.len(), 1);
        assert_eq!(tags.actions[0].action, "NEW");
        assert_eq!(tags.actions[0].normalized_action, WarningActionKind::New);

        let source = tags
            .text_tags
            .iter()
            .find(|tag| tag.kind == WarningTextTagKind::Source)
            .unwrap();
        assert_eq!(source.raw_value, "Radar indicated rotation.");
        assert_eq!(source.normalized_value, "RADAR INDICATED ROTATION.");

        let tornado = tags
            .text_tags
            .iter()
            .find(|tag| tag.kind == WarningTextTagKind::Tornado)
            .unwrap();
        assert_eq!(tornado.raw_name, "TORNADO");
        assert_eq!(tornado.raw_value, "RADAR INDICATED");
        assert_eq!(tornado.normalized_value, "RADAR INDICATED");

        let hail = tags
            .text_tags
            .iter()
            .find(|tag| tag.kind == WarningTextTagKind::MaxHailSize)
            .unwrap();
        assert_eq!(hail.raw_value, "1.00 IN");
        assert_eq!(hail.normalized_value, "1.00 IN");
        assert_eq!(hail.numeric_value, Some(1.0));
        assert_eq!(hail.unit.as_deref(), Some("in"));
    }

    #[test]
    fn extracts_structured_severe_thunderstorm_tags() {
        let input = "123\nWUUS53 KDMX 010000\nSVRDMX\nIAC001-010100-\n/O.NEW.KDMX.SV.W.0001.240601T0000Z-240601T0100Z/\nHAIL THREAT...OBSERVED\nMAX HAIL SIZE...2.75 IN\nWIND THREAT...RADAR INDICATED\nMAX WIND GUST...80 MPH\nTSTM DAMAGE THREAT...DESTRUCTIVE\nSOURCE...Trained weather spotters.\nIMPACT...Expect considerable tree damage.\n";
        let bulletin = WmoMessage::parse_str(input).unwrap();
        let product = NwsProduct::parse(&bulletin).unwrap();
        let tags = product.segments[0].warning_tags();
        let kinds = tags
            .text_tags
            .iter()
            .map(|tag| tag.kind)
            .collect::<Vec<_>>();

        assert_eq!(
            kinds,
            vec![
                WarningTextTagKind::HailThreat,
                WarningTextTagKind::MaxHailSize,
                WarningTextTagKind::WindThreat,
                WarningTextTagKind::MaxWindGust,
                WarningTextTagKind::TstmDamageThreat,
                WarningTextTagKind::Source,
                WarningTextTagKind::Impact,
            ]
        );
        assert_eq!(tags.text_tags[1].numeric_value, Some(2.75));
        assert_eq!(tags.text_tags[1].unit.as_deref(), Some("in"));
        assert_eq!(tags.text_tags[3].numeric_value, Some(80.0));
        assert_eq!(tags.text_tags[3].unit.as_deref(), Some("mph"));
        assert_eq!(tags.text_tags[4].normalized_value, "DESTRUCTIVE");
        assert_eq!(tags.actions[0].action, "NEW");
    }

    #[test]
    fn extracts_structured_flash_flood_tags() {
        let input = "123\nWGUS53 KDMX 010000\nFFWDMX\nIAC001-010100-\n/O.NEW.KDMX.FF.W.0003.240601T0000Z-240601T0100Z/\nFLASH FLOOD DAMAGE THREAT...CATASTROPHIC\nTHREAT...Life threatening flash flooding of creeks and streams.\nSOURCE...Radar indicated.\nIMPACT...This is a particularly dangerous situation.\n";
        let bulletin = WmoMessage::parse_str(input).unwrap();
        let product = NwsProduct::parse(&bulletin).unwrap();
        let tags = product.segments[0].warning_tags();

        assert_eq!(tags.text_tags.len(), 4);
        assert_eq!(
            tags.text_tags[0].kind,
            WarningTextTagKind::FlashFloodDamageThreat
        );
        assert_eq!(tags.text_tags[0].normalized_value, "CATASTROPHIC");
        assert_eq!(tags.text_tags[1].kind, WarningTextTagKind::Threat);
        assert_eq!(
            tags.text_tags[1].raw_value,
            "Life threatening flash flooding of creeks and streams."
        );
    }

    #[test]
    fn structured_tag_extraction_ignores_missing_tags() {
        let tags = WarningParsedTags::extract_text(&[
            "Plain warning narrative without a dot tag.",
            "HAZARD...60 mph wind gusts and quarter size hail.",
        ]);

        assert!(tags.text_tags.is_empty());
        assert!(tags.actions.is_empty());
    }

    #[test]
    fn structured_tag_extraction_preserves_multiple_tags_in_order() {
        let tags = WarningParsedTags::extract_text(&[
            "SOURCE...Radar indicated.",
            "SOURCE...Public report.",
            "IMPACT...First impact sentence.",
            "IMPACT...Second impact sentence.",
        ]);

        assert_eq!(tags.text_tags.len(), 4);
        assert_eq!(tags.text_tags[0].kind, WarningTextTagKind::Source);
        assert_eq!(tags.text_tags[0].line_number, 1);
        assert_eq!(tags.text_tags[1].raw_value, "Public report.");
        assert_eq!(tags.text_tags[2].kind, WarningTextTagKind::Impact);
        assert_eq!(tags.text_tags[3].line_number, 4);
    }

    #[test]
    fn extracts_continuation_cancellation_and_expiration_actions() {
        let input = "123\nWUUS53 KDMX 010000\nSVRDMX\nIAC001-010100-\n/O.CON.KDMX.TO.W.0001.000000T0000Z-240601T0100Z/\nTORNADO...POSSIBLE\n$$\nIAC003-010100-\n/O.CAN.KDMX.SV.W.0002.000000T0000Z-240601T0100Z/\nSOURCE...Radar indicated.\n$$\nIAC005-010100-\n/O.EXP.KDMX.FF.W.0003.000000T0000Z-240601T0100Z/\nFLASH FLOOD DAMAGE THREAT...CONSIDERABLE\n";
        let bulletin = WmoMessage::parse_str(input).unwrap();
        let product = NwsProduct::parse(&bulletin).unwrap();

        let actions = product
            .segments
            .iter()
            .map(|segment| segment.warning_tags().actions[0].normalized_action)
            .collect::<Vec<_>>();

        assert_eq!(
            actions,
            vec![
                WarningActionKind::Continue,
                WarningActionKind::Cancel,
                WarningActionKind::Expire,
            ]
        );
    }
}
