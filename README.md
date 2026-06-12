# nwws-rs

`nwws-rs` is a high-performance NWWS toolkit for:

- parsing raw WMO/NWS text bulletins
- parsing and validating NWWS-OI XMPP payloads
- scanning PID201/framed bulletin streams
- splitting and replaying captured feeds
- archiving, deduplicating, and verifying bulletin corpora
- using the same core from Rust, Python, or the CLI

It is built around one rule: never trust the wrapper more than the bulletin.  
NWWS-OI metadata is validated against the embedded WMO bulletin instead of being accepted at face value.

## What This Repo Is

This repo is the ingest and parsing core for NWWS text traffic.

It includes:

- a Rust library
- a Python package
- a CLI
- a blocking NWWS-OI client
- PID201 framed-stream tooling
- archive import and verification workflows

It is designed for developers building:

- alerting systems
- ingest pipelines
- archives and replay tools
- verification harnesses
- weather applications that need faithful NWS text-product parsing

## Beginner Quick Start

If you just want to see it work, do one of these first.

### Option 1: Python

```powershell
cd C:\Users\drew\nwws-rs
python -m pip install -e .
python examples/python_demo.py
```

Minimal example:

```python
from pathlib import Path
import nwws_rs

message = nwws_rs.parse_bulletin(
    Path("tests/fixtures/wmo_tornado_warning.txt").read_bytes()
)

print(message.heading)
print(message.awips_id)
print(message.family)
print(message.segments[0].tornado_tag)
```

### Option 2: CLI

```powershell
cd C:\Users\drew\nwws-rs
cargo run --bin nwws -- inspect tests/fixtures/wmo_tornado_warning.txt
cargo run --bin nwws -- inspect tests/fixtures/nwws_oi_tornado_warning.xml
```

### Option 3: Rust

```rust
use nwws_rs::NwwsContent;

let bytes = include_bytes!("tests/fixtures/wmo_tornado_warning.txt");
let content = NwwsContent::parse_bulletin(bytes)?;

assert_eq!(content.bulletin.heading.ttaaii(), "WUUS53");
assert_eq!(content.bulletin.heading.cccc(), "KLOT");
assert_eq!(content.bulletin.awips_id.unwrap().raw(), "TORLOT");
# Ok::<(), Box<dyn std::error::Error>>(())
```

## Common Tasks

### Parse one bulletin

Python:

```python
import nwws_rs

report = nwws_rs.parse_bulletin(open("tests/fixtures/wmo_tornado_warning.txt", "rb").read())
print(report.semantic_fingerprint)
```

CLI:

```powershell
cargo run --bin nwws -- inspect tests/fixtures/wmo_tornado_warning.txt
```

### Parse one NWWS-OI message

Python:

```python
import nwws_rs

xml = open("tests/fixtures/nwws_oi_tornado_warning.xml", "r", encoding="utf-8").read()
message = nwws_rs.parse_oi(xml)
print(message.wrapper.id)
print(message.heading)
```

CLI:

```powershell
cargo run --bin nwws -- inspect tests/fixtures/nwws_oi_tornado_warning.xml
```

### Split a PID201 capture into bulletin files

Python:

```python
import nwws_rs

report = nwws_rs.write_pid201_split("capture.pid201", "out/split")
print(len(report.written))
```

CLI:

```powershell
cargo run --bin nwws -- pid201 split capture.pid201 out\split
```

### Import an archive and verify it later

Python:

```python
import nwws_rs

import_report = nwws_rs.archive_import("captures", "archive")
verify_report = nwws_rs.archive_verify("archive")
active_report = nwws_rs.active_warnings_at("archive", "2026-04-21T16:25:00Z")
print(import_report.archived_records, verify_report.verified_records, active_report.active_records)
```

CLI:

```powershell
cargo run --bin nwws -- archive import captures archive
cargo run --bin nwws -- archive verify archive
cargo run --bin nwws -- archive active-at archive --at 2026-04-21T16:25:00Z --format tool-result
```

## Python API

Install from the repo:

```powershell
python -m pip install -e .
```

Main entry points:

- `parse`
- `parse_path`
- `parse_bulletin`
- `parse_oi`
- `inspect_bytes`
- `inspect_text`
- `inspect_path`
- `scan_path`
- `collect_input_paths`
- `active_warnings_at`
- `split_pid201_bytes`
- `split_pid201_file`
- `write_pid201_split`
- `archive_import`
- `archive_verify`
- `Pid201Stream`
- `OiClient`
- `OpenInterfaceClient`

The Python surface is typed and object-oriented. It returns structured objects instead of raw dicts, so you can inspect headings, families, segments, tags, geometry, and fingerprints directly.

Runnable demo:

```powershell
python examples/python_demo.py
```

## CLI

The `nwws` binary is the fastest way to inspect real captures without writing code.

```powershell
cargo run --bin nwws -- inspect <file>
cargo run --bin nwws -- replay <directory>
cargo run --bin nwws -- active-at <file-or-directory-or-archive> --at <utc-rfc3339>
cargo run --bin nwws -- timeline <file-or-directory-or-archive> --at <utc-rfc3339> --format tool-result
cargo run --bin nwws -- lead-time <file-or-directory-or-archive> --event-at <utc-rfc3339> --lat 42.05 --lon -88.20 --format tool-result
cargo run --bin nwws -- summary <file-or-directory>
cargo run --bin nwws -- oi connect <username> <password> --count 5
cargo run --bin nwws -- pid201 inspect <capture-file>
cargo run --bin nwws -- pid201 split <capture-file> <output-dir>
cargo run --bin nwws -- pid201 archive <capture-file> <archive-dir>
cargo run --bin nwws -- archive import <input-path> <archive-dir>
cargo run --bin nwws -- archive verify <archive-dir>
cargo run --bin nwws -- archive active-at <archive-dir> --at <utc-rfc3339>
cargo run --bin nwws -- archive timeline <archive-dir> --at <utc-rfc3339> --format json
cargo run --bin nwws -- archive lead-time <archive-dir> --event-at <utc-rfc3339> --lat 42.05 --lon -88.20 --format tool-result
```

Inspection, replay, active-at, timeline, lead-time, PID201 inspect/archive, and archive import/verify support machine-readable output with `--format json`, `--format jsonl`, or `--format tool-result`. JSON output uses the same API inspection/archive structures exposed to Python, including WMO heading parts, office, AWIPS/PIL, product family, UGC, VTEC, LAT/LON, TIME/MOT/LOC, semantic fingerprints, raw bulletin BLAKE3 hashes, and archive IDs. `active-at` returns warning P-VTEC records active at the supplied RFC3339 UTC reference, collapsed by office, VTEC event, UGC list, and event family. `timeline` returns warning lifecycle records, including issued/valid/canceled/expired times, tags, polygons, motion lines, and lifecycle status at an optional reference time. `lead-time` computes point-event warning lead time, missed-event, point-warning interval, and false-alarm-hook metrics from timeline records. `--format tool-result` wraps the report in a `wx.tool_result.v1` envelope with `artifacts`, `evidence`, `limitations`, and `provenance`.

`archive import` writes canonical bulletin records under `archive/records/` and appends a `records.tsv` manifest. Re-importing the same bulletin from raw WMO, NWWS-OI XML, or PID201 captures deduplicates by normalized bulletin content.

## Advanced Overview

### Parsing Model

The repo treats NWWS as multiple transport surfaces over the same underlying bulletin semantics:

- raw WMO bulletin text
- NWWS-OI wrapped XMPP stanzas
- PID201 framed bulletin streams

That means correctness depends on:

- strict heading parsing
- strict AWIPS ID parsing
- UGC parsing and expansion
- VTEC and HVTEC parsing
- segmented product parsing
- warning-tag extraction
- geometry extraction from `LAT...LON` and `TIME...MOT...LOC`
- wrapper-to-bulletin consistency checks

### Library Layers

Core modules:

- [`src/wmo.rs`](</C:/Users/drew/nwws-rs/src/wmo.rs>) parses WMO bulletin framing and headers
- [`src/oi.rs`](</C:/Users/drew/nwws-rs/src/oi.rs>) parses NWWS-OI messages and validates embedded bulletins
- [`src/product.rs`](</C:/Users/drew/nwws-rs/src/product.rs>) parses product families, segments, tags, and structure
- [`src/ugc.rs`](</C:/Users/drew/nwws-rs/src/ugc.rs>) parses and expands UGC strings
- [`src/vtec.rs`](</C:/Users/drew/nwws-rs/src/vtec.rs>) parses P-VTEC and H-VTEC
- [`src/geo.rs`](</C:/Users/drew/nwws-rs/src/geo.rs>) parses geometry and motion lines
- [`src/pid201.rs`](</C:/Users/drew/nwws-rs/src/pid201.rs>) handles incremental framed-stream ingest
- [`src/runtime.rs`](</C:/Users/drew/nwws-rs/src/runtime.rs>) handles dedupe, archive, and ingest service workflows
- [`src/oi_client.rs`](</C:/Users/drew/nwws-rs/src/oi_client.rs>) implements the blocking NWWS-OI client
- [`src/api.rs`](</C:/Users/drew/nwws-rs/src/api.rs>) exposes higher-level inspect, scan, split, and archive APIs
- [`src/python.rs`](</C:/Users/drew/nwws-rs/src/python.rs>) exposes the native Python bridge

### Verification Strategy

Verification is not hand-wavy. The repo currently checks:

- unit tests for headers, WMO framing, NWWS-OI parsing, UGC, VTEC, geometry, PID201, runtime, and API workflows
- integration tests for real warning-style fixtures and wrapper mismatch failures
- property tests over generated bulletin shapes and scanner behavior
- CLI tests for split/import/verify workflows
- Python API tests for parse, stream, archive, and demo-level usage
- differential comparison against `pyIEM` on overlapping raw-bulletin semantics
- curated corpus comparison against `pyIEM`
- bench compilation for parser throughput tracking

Current primary verification commands:

```powershell
cargo fmt --check
cargo clippy --all-targets --features python -- -D warnings
cargo test --all-targets --features python
cargo test --release --all-targets --features python
python tools/compare_pyiem.py
python tools/compare_pyiem_corpus.py --max-failures 5
python -m unittest discover -s python-tests -p "test_*.py"
cargo bench --bench parse --no-run --features python
```

Or use the combined helper:

```powershell
.\tools\verify.ps1
.\tools\verify.ps1 -Corpus -SkipBench
```

### Performance Notes

This repo is optimized around:

- byte scanning instead of regex-heavy framed-stream parsing
- strict parsing with low allocation pressure
- direct structured extraction instead of post-hoc text scraping

Criterion benches are in [benches/parse.rs](</C:/Users/drew/nwws-rs/benches/parse.rs>).

### Repo Layout

- [`examples`](</C:/Users/drew/nwws-rs/examples>) has runnable Rust and Python demos
- [`tests/fixtures`](</C:/Users/drew/nwws-rs/tests/fixtures>) has bulletin and NWWS-OI fixtures
- [`python-tests`](</C:/Users/drew/nwws-rs/python-tests>) has Python API tests
- [`tools`](</C:/Users/drew/nwws-rs/tools>) has verification and `pyIEM` comparison tooling
- [`fuzz/corpus`](</C:/Users/drew/nwws-rs/fuzz/corpus>) has seed inputs for future fuzz work

## Accuracy Scope

This repo is intentionally strict and heavily verified, but the claim is still bounded to what is implemented and tested.

It does cover:

- WMO bulletin parsing
- NWWS-OI parsing and wrapper validation
- AWIPS, UGC, VTEC, HVTEC, segment, tag, and geometry parsing
- PID201 framed-stream workflows
- archive ingest and verification
- Python, Rust, and CLI access to the same core logic

It does not pretend to be:

- a hardware satellite receiver
- a full NOAAPORT demodulator stack
- proof against every historical malformed message ever emitted

## Why This Exists

Most public weather tooling either:

- stops at feed consumption
- focuses on CAP/API layers instead of raw text products
- parses only part of the bulletin
- or is difficult to reuse from modern Rust or Python code

`nwws-rs` is meant to be the reusable NWWS parsing and ingest core that can sit under bigger systems.
