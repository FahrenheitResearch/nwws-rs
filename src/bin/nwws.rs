use std::collections::BTreeMap;
use std::env;
use std::ffi::OsString;
use std::fs::{self, OpenOptions};
use std::io::{ErrorKind as IoErrorKind, Write};
use std::ops::Range;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use nwws_rs::{
    ArchiveStore as RuntimeArchiveStore, DedupeStore, FramedStreamIngest, IngestHint,
    IngestService, MessageRouter, NwwsContent, NwwsOiClient, NwwsOiMessage, OiClientConfig,
    ParsedInput, ProductFamily, TransportDescriptor, TransportKind, WarningPoint,
    collect_input_paths, infer_hint_from_path, lead_time_event_metrics, parse_with_hint,
    polygon_timeline, polygon_timeline_at,
};
use serde::Serialize;
use serde_json::json;
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;

fn main() {
    match run(env::args_os().skip(1)) {
        Ok(()) => {}
        Err(err) => {
            eprintln!("{err}");
            std::process::exit(err.exit_code);
        }
    }
}

fn run(mut args: impl Iterator<Item = OsString>) -> Result<(), CliError> {
    let Some(command) = args.next() else {
        return Err(CliError::usage(usage()));
    };

    match command.to_string_lossy().as_ref() {
        "-h" | "--help" | "help" => {
            println!("{}", usage());
            Ok(())
        }
        "inspect" => {
            let path = take_path_arg("inspect", &mut args)?;
            let options = parse_command_options("inspect", &mut args)?;
            inspect_command(&path, options.hint, options.output)
        }
        "replay" => {
            let path = take_path_arg("replay", &mut args)?;
            let options = parse_command_options("replay", &mut args)?;
            replay_command(&path, options.hint, options.output)
        }
        "active-at" | "active" => {
            let path = take_path_arg("active-at", &mut args)?;
            let options = parse_active_at_options("active-at", &mut args)?;
            active_at_command(&path, options)
        }
        "timeline" => {
            let path = take_path_arg("timeline", &mut args)?;
            let options = parse_timeline_options("timeline", &mut args)?;
            timeline_command(&path, options)
        }
        "lead-time" | "leadtime" => {
            let path = take_path_arg("lead-time", &mut args)?;
            let options = parse_lead_time_options("lead-time", &mut args)?;
            lead_time_command(&path, options)
        }
        "summary" => {
            let path = take_path_arg("summary", &mut args)?;
            let hint = parse_optional_hint("summary", &mut args)?;
            summary_command(&path, hint)
        }
        "oi" => oi_command(&mut args),
        "pid201" => pid201_command(&mut args),
        "archive" => archive_command(&mut args),
        other => Err(CliError::usage(format!(
            "unknown command {other}\n\n{}",
            usage()
        ))),
    }
}

fn pid201_command(args: &mut impl Iterator<Item = OsString>) -> Result<(), CliError> {
    let Some(command) = args.next() else {
        return Err(CliError::usage(format!(
            "missing pid201 subcommand\n\n{}",
            usage()
        )));
    };

    match command.to_string_lossy().as_ref() {
        "inspect" => {
            let path = take_path_arg("pid201 inspect", args)?;
            let output = parse_output_options("pid201 inspect", args)?;
            inspect_command(&path, Some(IngestHint::SatellitePid201), output)
        }
        "split" => {
            let input = take_path_arg("pid201 split", args)?;
            let output = take_path_arg("pid201 split", args)?;
            ensure_no_extra_args("pid201 split", args)?;
            pid201_split_command(&input, &output)
        }
        "archive" => {
            let input = take_path_arg("pid201 archive", args)?;
            let archive = take_path_arg("pid201 archive", args)?;
            let output = parse_output_options("pid201 archive", args)?;
            archive_import_command(&input, &archive, Some(IngestHint::SatellitePid201), output)
        }
        other => Err(CliError::usage(format!(
            "unknown pid201 subcommand {other}\n\n{}",
            usage()
        ))),
    }
}

fn archive_command(args: &mut impl Iterator<Item = OsString>) -> Result<(), CliError> {
    let Some(command) = args.next() else {
        return Err(CliError::usage(format!(
            "missing archive subcommand\n\n{}",
            usage()
        )));
    };

    match command.to_string_lossy().as_ref() {
        "import" => {
            let input = take_path_arg("archive import", args)?;
            let archive = take_path_arg("archive import", args)?;
            let options = parse_command_options("archive import", args)?;
            archive_import_command(&input, &archive, options.hint, options.output)
        }
        "verify" => {
            let archive = take_path_arg("archive verify", args)?;
            let output = parse_output_options("archive verify", args)?;
            archive_verify_command(&archive, output)
        }
        "active-at" | "active" => {
            let archive = take_path_arg("archive active-at", args)?;
            let options = parse_active_at_options("archive active-at", args)?;
            active_at_command(&archive, options)
        }
        "timeline" => {
            let archive = take_path_arg("archive timeline", args)?;
            let options = parse_timeline_options("archive timeline", args)?;
            timeline_command(&archive, options)
        }
        "lead-time" | "leadtime" => {
            let archive = take_path_arg("archive lead-time", args)?;
            let options = parse_lead_time_options("archive lead-time", args)?;
            lead_time_command(&archive, options)
        }
        other => Err(CliError::usage(format!(
            "unknown archive subcommand {other}\n\n{}",
            usage()
        ))),
    }
}

fn oi_command(args: &mut impl Iterator<Item = OsString>) -> Result<(), CliError> {
    let Some(command) = args.next() else {
        return Err(CliError::usage(format!(
            "missing oi subcommand\n\n{}",
            usage()
        )));
    };

    match command.to_string_lossy().as_ref() {
        "connect" => {
            let username = args.next().ok_or_else(|| {
                CliError::usage(format!("missing username for oi connect\n\n{}", usage()))
            })?;
            let password = args.next().ok_or_else(|| {
                CliError::usage(format!("missing password for oi connect\n\n{}", usage()))
            })?;
            let options = parse_oi_connect_options(args)?;
            oi_connect_command(
                username.to_string_lossy().into_owned(),
                password.to_string_lossy().into_owned(),
                options,
            )
        }
        "archive" => {
            let username = args.next().ok_or_else(|| {
                CliError::usage(format!("missing username for oi archive\n\n{}", usage()))
            })?;
            let password = args.next().ok_or_else(|| {
                CliError::usage(format!("missing password for oi archive\n\n{}", usage()))
            })?;
            let archive = take_path_arg("oi archive", args)?;
            let options = parse_oi_archive_options(args)?;
            oi_archive_command(
                username.to_string_lossy().into_owned(),
                password.to_string_lossy().into_owned(),
                &archive,
                options,
            )
        }
        other => Err(CliError::usage(format!(
            "unknown oi subcommand {other}\n\n{}",
            usage()
        ))),
    }
}

fn usage() -> &'static str {
    "usage:
  cargo run --bin nwws -- inspect <file> [--hint <auto|oi|pid201|bulletin|stream>] [--format <text|json|jsonl|tool-result>]
  cargo run --bin nwws -- replay <directory> [--hint <auto|oi|pid201|bulletin|stream>] [--format <text|json|jsonl|tool-result>]
  cargo run --bin nwws -- active-at <file-or-directory-or-archive> --at <utc-rfc3339> [--hint <auto|oi|pid201|bulletin|stream>] [--format <text|json|jsonl|tool-result>]
  cargo run --bin nwws -- timeline <file-or-directory-or-archive> [--at <utc-rfc3339>] [--hint <auto|oi|pid201|bulletin|stream>] [--format <text|json|jsonl|tool-result>]
  cargo run --bin nwws -- lead-time <file-or-directory-or-archive> --event-at <utc-rfc3339> --lat <degrees> --lon <degrees> [--hint <auto|oi|pid201|bulletin|stream>] [--format <text|json|jsonl|tool-result>]
  cargo run --bin nwws -- summary <file-or-directory> [--hint <auto|oi|pid201|bulletin|stream>]
  cargo run --bin nwws -- oi connect <username> <password> [--count <n>] [--history <n>]
  cargo run --bin nwws -- oi archive <username> <password> <archive-dir> [--count <n>] [--duration <seconds>] [--history <n>] [--format <text|json|jsonl|tool-result>]
  cargo run --bin nwws -- pid201 inspect <capture-file> [--format <text|json|jsonl|tool-result>]
  cargo run --bin nwws -- pid201 split <capture-file> <output-dir>
  cargo run --bin nwws -- pid201 archive <capture-file> <archive-dir> [--format <text|json|jsonl|tool-result>]
  cargo run --bin nwws -- archive import <input-path> <archive-dir> [--hint <auto|oi|pid201|bulletin|stream>] [--format <text|json|jsonl|tool-result>]
  cargo run --bin nwws -- archive verify <archive-dir> [--format <text|json|jsonl|tool-result>]
  cargo run --bin nwws -- archive active-at <archive-dir> --at <utc-rfc3339> [--format <text|json|jsonl|tool-result>]
  cargo run --bin nwws -- archive timeline <archive-dir> [--at <utc-rfc3339>] [--format <text|json|jsonl|tool-result>]
  cargo run --bin nwws -- archive lead-time <archive-dir> --event-at <utc-rfc3339> --lat <degrees> --lon <degrees> [--format <text|json|jsonl|tool-result>]

commands:
  inspect          parse one file and print detailed NWWS metadata
  replay           walk a directory and print one line per parsed file
  active-at        return warning VTEC records active at a reference UTC
  timeline         return warning lifecycle/timeline records from warning P-VTEC
  lead-time        compute point-event warning lead-time metrics from timeline records
  summary          aggregate detected source, transport, and family counts
  oi connect       open a blocking NWWS-OI XMPP session and print parsed messages
  oi archive       open a bounded NWWS-OI XMPP session and ingest messages into ArchiveStore
  pid201 inspect   force a file through the PID201 framed-stream path
  pid201 split     split a PID201 capture into canonical bulletin files
  pid201 archive   archive a PID201 capture into a deduplicated record store
  archive import   ingest mixed NWWS inputs into a deduplicated record store
  archive verify   re-parse archived records and validate the stored digests
  archive active-at query archived warning records active at a reference UTC
  archive timeline query archived warning lifecycle/timeline records
  archive lead-time compute warning lead-time metrics from an archive

notes:
  Machine-readable modes are available with --format json, --format jsonl, or --format tool-result.
  The CLI supports both archived NWWS-OI XML inspection and live `oi connect` session workflows."
}

fn take_path_arg(
    command: &str,
    args: &mut impl Iterator<Item = OsString>,
) -> Result<PathBuf, CliError> {
    args.next()
        .map(PathBuf::from)
        .ok_or_else(|| CliError::usage(format!("missing path for {command}\n\n{}", usage())))
}

fn parse_optional_hint(
    command: &str,
    args: &mut impl Iterator<Item = OsString>,
) -> Result<Option<IngestHint>, CliError> {
    let mut hint = None;

    while let Some(arg) = args.next() {
        match arg.to_string_lossy().as_ref() {
            "--hint" => {
                if hint.is_some() {
                    return Err(CliError::usage(format!(
                        "duplicate --hint for {command}\n\n{}",
                        usage()
                    )));
                }
                let Some(value) = args.next() else {
                    return Err(CliError::usage(format!(
                        "missing value for --hint in {command}\n\n{}",
                        usage()
                    )));
                };
                hint = Some(parse_hint_value(&value.to_string_lossy())?);
            }
            other => {
                return Err(CliError::usage(format!(
                    "unexpected extra argument for {command}: {other}\n\n{}",
                    usage()
                )));
            }
        }
    }

    Ok(hint)
}

fn parse_command_options(
    command: &str,
    args: &mut impl Iterator<Item = OsString>,
) -> Result<CommandOptions, CliError> {
    let mut options = CommandOptions::default();

    while let Some(arg) = args.next() {
        match arg.to_string_lossy().as_ref() {
            "--hint" => {
                if options.hint.is_some() {
                    return Err(CliError::usage(format!(
                        "duplicate --hint for {command}\n\n{}",
                        usage()
                    )));
                }
                let Some(value) = args.next() else {
                    return Err(CliError::usage(format!(
                        "missing value for --hint in {command}\n\n{}",
                        usage()
                    )));
                };
                options.hint = Some(parse_hint_value(&value.to_string_lossy())?);
            }
            "--format" => {
                if options.output != OutputFormat::Text {
                    return Err(CliError::usage(format!(
                        "duplicate --format for {command}\n\n{}",
                        usage()
                    )));
                }
                let Some(value) = args.next() else {
                    return Err(CliError::usage(format!(
                        "missing value for --format in {command}\n\n{}",
                        usage()
                    )));
                };
                options.output = parse_output_format(&value.to_string_lossy())?;
            }
            "--json" => set_output_flag(command, &mut options.output, OutputFormat::Json)?,
            "--jsonl" => set_output_flag(command, &mut options.output, OutputFormat::Jsonl)?,
            "--tool-result" => {
                set_output_flag(command, &mut options.output, OutputFormat::ToolResult)?
            }
            other => {
                return Err(CliError::usage(format!(
                    "unexpected extra argument for {command}: {other}\n\n{}",
                    usage()
                )));
            }
        }
    }

    Ok(options)
}

fn parse_active_at_options(
    command: &str,
    args: &mut impl Iterator<Item = OsString>,
) -> Result<ActiveAtOptions, CliError> {
    let mut options = ActiveAtOptions::default();

    while let Some(arg) = args.next() {
        match arg.to_string_lossy().as_ref() {
            "--at" | "--reference" | "--reference-utc" => {
                if options.reference_utc.is_some() {
                    return Err(CliError::usage(format!(
                        "duplicate --at for {command}\n\n{}",
                        usage()
                    )));
                }
                options.reference_utc = Some(parse_string_arg(command, "--at", args)?);
            }
            "--hint" => {
                if options.hint.is_some() {
                    return Err(CliError::usage(format!(
                        "duplicate --hint for {command}\n\n{}",
                        usage()
                    )));
                }
                let Some(value) = args.next() else {
                    return Err(CliError::usage(format!(
                        "missing value for --hint in {command}\n\n{}",
                        usage()
                    )));
                };
                options.hint = Some(parse_hint_value(&value.to_string_lossy())?);
            }
            "--format" => {
                if options.output != OutputFormat::Text {
                    return Err(CliError::usage(format!(
                        "duplicate --format for {command}\n\n{}",
                        usage()
                    )));
                }
                let Some(value) = args.next() else {
                    return Err(CliError::usage(format!(
                        "missing value for --format in {command}\n\n{}",
                        usage()
                    )));
                };
                options.output = parse_output_format(&value.to_string_lossy())?;
            }
            "--json" => set_output_flag(command, &mut options.output, OutputFormat::Json)?,
            "--jsonl" => set_output_flag(command, &mut options.output, OutputFormat::Jsonl)?,
            "--tool-result" => {
                set_output_flag(command, &mut options.output, OutputFormat::ToolResult)?
            }
            other => {
                return Err(CliError::usage(format!(
                    "unexpected extra argument for {command}: {other}\n\n{}",
                    usage()
                )));
            }
        }
    }

    if options.reference_utc.is_none() {
        return Err(CliError::usage(format!(
            "missing --at for {command}\n\n{}",
            usage()
        )));
    }

    Ok(options)
}

fn parse_timeline_options(
    command: &str,
    args: &mut impl Iterator<Item = OsString>,
) -> Result<TimelineOptions, CliError> {
    let mut options = TimelineOptions::default();

    while let Some(arg) = args.next() {
        match arg.to_string_lossy().as_ref() {
            "--at" | "--reference" | "--reference-utc" => {
                if options.query_utc.is_some() {
                    return Err(CliError::usage(format!(
                        "duplicate --at for {command}\n\n{}",
                        usage()
                    )));
                }
                options.query_utc = Some(parse_string_arg(command, "--at", args)?);
            }
            "--hint" => {
                if options.hint.is_some() {
                    return Err(CliError::usage(format!(
                        "duplicate --hint for {command}\n\n{}",
                        usage()
                    )));
                }
                let Some(value) = args.next() else {
                    return Err(CliError::usage(format!(
                        "missing value for --hint in {command}\n\n{}",
                        usage()
                    )));
                };
                options.hint = Some(parse_hint_value(&value.to_string_lossy())?);
            }
            "--format" => {
                if options.output != OutputFormat::Text {
                    return Err(CliError::usage(format!(
                        "duplicate --format for {command}\n\n{}",
                        usage()
                    )));
                }
                let Some(value) = args.next() else {
                    return Err(CliError::usage(format!(
                        "missing value for --format in {command}\n\n{}",
                        usage()
                    )));
                };
                options.output = parse_output_format(&value.to_string_lossy())?;
            }
            "--json" => set_output_flag(command, &mut options.output, OutputFormat::Json)?,
            "--jsonl" => set_output_flag(command, &mut options.output, OutputFormat::Jsonl)?,
            "--tool-result" => {
                set_output_flag(command, &mut options.output, OutputFormat::ToolResult)?
            }
            other => {
                return Err(CliError::usage(format!(
                    "unexpected extra argument for {command}: {other}\n\n{}",
                    usage()
                )));
            }
        }
    }

    Ok(options)
}

fn parse_lead_time_options(
    command: &str,
    args: &mut impl Iterator<Item = OsString>,
) -> Result<LeadTimeOptions, CliError> {
    let mut options = LeadTimeOptions::default();

    while let Some(arg) = args.next() {
        match arg.to_string_lossy().as_ref() {
            "--event-at" | "--event-time" | "--event-utc" => {
                if options.event_utc.is_some() {
                    return Err(CliError::usage(format!(
                        "duplicate --event-at for {command}\n\n{}",
                        usage()
                    )));
                }
                options.event_utc = Some(parse_string_arg(command, "--event-at", args)?);
            }
            "--lat" | "--latitude" => {
                if options.lat.is_some() {
                    return Err(CliError::usage(format!(
                        "duplicate --lat for {command}\n\n{}",
                        usage()
                    )));
                }
                options.lat = Some(parse_f32_arg(command, "--lat", args)?);
            }
            "--lon" | "--longitude" => {
                if options.lon.is_some() {
                    return Err(CliError::usage(format!(
                        "duplicate --lon for {command}\n\n{}",
                        usage()
                    )));
                }
                options.lon = Some(parse_f32_arg(command, "--lon", args)?);
            }
            "--hint" => {
                if options.hint.is_some() {
                    return Err(CliError::usage(format!(
                        "duplicate --hint for {command}\n\n{}",
                        usage()
                    )));
                }
                let Some(value) = args.next() else {
                    return Err(CliError::usage(format!(
                        "missing value for --hint in {command}\n\n{}",
                        usage()
                    )));
                };
                options.hint = Some(parse_hint_value(&value.to_string_lossy())?);
            }
            "--format" => {
                if options.output != OutputFormat::Text {
                    return Err(CliError::usage(format!(
                        "duplicate --format for {command}\n\n{}",
                        usage()
                    )));
                }
                let Some(value) = args.next() else {
                    return Err(CliError::usage(format!(
                        "missing value for --format in {command}\n\n{}",
                        usage()
                    )));
                };
                options.output = parse_output_format(&value.to_string_lossy())?;
            }
            "--json" => set_output_flag(command, &mut options.output, OutputFormat::Json)?,
            "--jsonl" => set_output_flag(command, &mut options.output, OutputFormat::Jsonl)?,
            "--tool-result" => {
                set_output_flag(command, &mut options.output, OutputFormat::ToolResult)?
            }
            other => {
                return Err(CliError::usage(format!(
                    "unexpected extra argument for {command}: {other}\n\n{}",
                    usage()
                )));
            }
        }
    }

    if options.event_utc.is_none() {
        return Err(CliError::usage(format!(
            "missing --event-at for {command}\n\n{}",
            usage()
        )));
    }
    if options.lat.is_none() {
        return Err(CliError::usage(format!(
            "missing --lat for {command}\n\n{}",
            usage()
        )));
    }
    if options.lon.is_none() {
        return Err(CliError::usage(format!(
            "missing --lon for {command}\n\n{}",
            usage()
        )));
    }

    Ok(options)
}

fn parse_output_options(
    command: &str,
    args: &mut impl Iterator<Item = OsString>,
) -> Result<OutputFormat, CliError> {
    let mut output = OutputFormat::Text;

    while let Some(arg) = args.next() {
        match arg.to_string_lossy().as_ref() {
            "--format" => {
                if output != OutputFormat::Text {
                    return Err(CliError::usage(format!(
                        "duplicate --format for {command}\n\n{}",
                        usage()
                    )));
                }
                let Some(value) = args.next() else {
                    return Err(CliError::usage(format!(
                        "missing value for --format in {command}\n\n{}",
                        usage()
                    )));
                };
                output = parse_output_format(&value.to_string_lossy())?;
            }
            "--json" => set_output_flag(command, &mut output, OutputFormat::Json)?,
            "--jsonl" => set_output_flag(command, &mut output, OutputFormat::Jsonl)?,
            "--tool-result" => set_output_flag(command, &mut output, OutputFormat::ToolResult)?,
            other => {
                return Err(CliError::usage(format!(
                    "unexpected extra argument for {command}: {other}\n\n{}",
                    usage()
                )));
            }
        }
    }

    Ok(output)
}

fn set_output_flag(
    command: &str,
    output: &mut OutputFormat,
    value: OutputFormat,
) -> Result<(), CliError> {
    if *output != OutputFormat::Text {
        return Err(CliError::usage(format!(
            "duplicate output format for {command}\n\n{}",
            usage()
        )));
    }
    *output = value;
    Ok(())
}

fn parse_oi_connect_options(
    args: &mut impl Iterator<Item = OsString>,
) -> Result<OiConnectOptions, CliError> {
    let mut options = OiConnectOptions::default();

    while let Some(arg) = args.next() {
        match arg.to_string_lossy().as_ref() {
            "--count" => {
                options.count = parse_usize_arg("oi connect", "--count", args)?;
            }
            "--history" => {
                options.history = parse_u32_arg("oi connect", "--history", args)?;
            }
            "--host" => options.host = Some(parse_string_arg("oi connect", "--host", args)?),
            "--domain" => options.domain = Some(parse_string_arg("oi connect", "--domain", args)?),
            "--port" => options.port = Some(parse_u16_arg("oi connect", "--port", args)?),
            "--room" => options.room = Some(parse_string_arg("oi connect", "--room", args)?),
            "--room-service" => {
                options.room_service = Some(parse_string_arg("oi connect", "--room-service", args)?)
            }
            "--nickname" => {
                options.nickname = Some(parse_string_arg("oi connect", "--nickname", args)?)
            }
            "--resource" => {
                options.resource = Some(parse_string_arg("oi connect", "--resource", args)?)
            }
            other => {
                return Err(CliError::usage(format!(
                    "unexpected extra argument for oi connect: {other}\n\n{}",
                    usage()
                )));
            }
        }
    }

    Ok(options)
}

fn parse_oi_archive_options(
    args: &mut impl Iterator<Item = OsString>,
) -> Result<OiArchiveOptions, CliError> {
    let mut options = OiArchiveOptions::default();

    while let Some(arg) = args.next() {
        match arg.to_string_lossy().as_ref() {
            "--count" | "--max-messages" => {
                options.count = parse_positive_usize_arg("oi archive", "--count", args)?;
            }
            "--duration" | "--duration-seconds" | "--max-seconds" => {
                options.duration = Some(parse_duration_arg("oi archive", "--duration", args)?);
            }
            "--history" => {
                options.history = parse_u32_arg("oi archive", "--history", args)?;
            }
            "--archive-duplicates" => options.archive_duplicates = true,
            "--host" => options.host = Some(parse_string_arg("oi archive", "--host", args)?),
            "--domain" => options.domain = Some(parse_string_arg("oi archive", "--domain", args)?),
            "--port" => options.port = Some(parse_u16_arg("oi archive", "--port", args)?),
            "--room" => options.room = Some(parse_string_arg("oi archive", "--room", args)?),
            "--room-service" => {
                options.room_service = Some(parse_string_arg("oi archive", "--room-service", args)?)
            }
            "--nickname" => {
                options.nickname = Some(parse_string_arg("oi archive", "--nickname", args)?)
            }
            "--resource" => {
                options.resource = Some(parse_string_arg("oi archive", "--resource", args)?)
            }
            "--format" => {
                if options.output != OutputFormat::Text {
                    return Err(CliError::usage(format!(
                        "duplicate --format for oi archive\n\n{}",
                        usage()
                    )));
                }
                let Some(value) = args.next() else {
                    return Err(CliError::usage(format!(
                        "missing value for --format in oi archive\n\n{}",
                        usage()
                    )));
                };
                options.output = parse_output_format(&value.to_string_lossy())?;
            }
            "--json" => set_output_flag("oi archive", &mut options.output, OutputFormat::Json)?,
            "--jsonl" => set_output_flag("oi archive", &mut options.output, OutputFormat::Jsonl)?,
            "--tool-result" => {
                set_output_flag("oi archive", &mut options.output, OutputFormat::ToolResult)?
            }
            other => {
                return Err(CliError::usage(format!(
                    "unexpected extra argument for oi archive: {other}\n\n{}",
                    usage()
                )));
            }
        }
    }

    Ok(options)
}

fn parse_string_arg(
    command: &str,
    flag: &str,
    args: &mut impl Iterator<Item = OsString>,
) -> Result<String, CliError> {
    args.next()
        .map(|value| value.to_string_lossy().into_owned())
        .ok_or_else(|| {
            CliError::usage(format!(
                "missing value for {flag} in {command}\n\n{}",
                usage()
            ))
        })
}

fn parse_u32_arg(
    command: &str,
    flag: &str,
    args: &mut impl Iterator<Item = OsString>,
) -> Result<u32, CliError> {
    let value = parse_string_arg(command, flag, args)?;
    value.parse().map_err(|_| {
        CliError::usage(format!(
            "invalid numeric value for {flag} in {command}: {value}\n\n{}",
            usage()
        ))
    })
}

fn parse_u16_arg(
    command: &str,
    flag: &str,
    args: &mut impl Iterator<Item = OsString>,
) -> Result<u16, CliError> {
    let value = parse_string_arg(command, flag, args)?;
    value.parse().map_err(|_| {
        CliError::usage(format!(
            "invalid numeric value for {flag} in {command}: {value}\n\n{}",
            usage()
        ))
    })
}

fn parse_f32_arg(
    command: &str,
    flag: &str,
    args: &mut impl Iterator<Item = OsString>,
) -> Result<f32, CliError> {
    let value = parse_string_arg(command, flag, args)?;
    let parsed = value.parse::<f32>().map_err(|_| {
        CliError::usage(format!(
            "invalid numeric value for {flag} in {command}: {value}\n\n{}",
            usage()
        ))
    })?;
    if !parsed.is_finite() {
        return Err(CliError::usage(format!(
            "invalid finite value for {flag} in {command}: {value}\n\n{}",
            usage()
        )));
    }
    Ok(parsed)
}

fn parse_usize_arg(
    command: &str,
    flag: &str,
    args: &mut impl Iterator<Item = OsString>,
) -> Result<usize, CliError> {
    let value = parse_string_arg(command, flag, args)?;
    value.parse().map_err(|_| {
        CliError::usage(format!(
            "invalid numeric value for {flag} in {command}: {value}\n\n{}",
            usage()
        ))
    })
}

fn parse_positive_usize_arg(
    command: &str,
    flag: &str,
    args: &mut impl Iterator<Item = OsString>,
) -> Result<usize, CliError> {
    let value = parse_usize_arg(command, flag, args)?;
    if value == 0 {
        return Err(CliError::usage(format!(
            "{flag} must be greater than zero for {command}\n\n{}",
            usage()
        )));
    }
    Ok(value)
}

fn parse_duration_arg(
    command: &str,
    flag: &str,
    args: &mut impl Iterator<Item = OsString>,
) -> Result<Duration, CliError> {
    let value = parse_string_arg(command, flag, args)?;
    let seconds = value.parse::<u64>().map_err(|_| {
        CliError::usage(format!(
            "invalid duration seconds for {flag} in {command}: {value}\n\n{}",
            usage()
        ))
    })?;
    if seconds == 0 {
        return Err(CliError::usage(format!(
            "{flag} must be greater than zero seconds for {command}\n\n{}",
            usage()
        )));
    }
    Ok(Duration::from_secs(seconds))
}

fn parse_hint_value(raw: &str) -> Result<IngestHint, CliError> {
    match raw.to_ascii_lowercase().as_str() {
        "auto" => Ok(IngestHint::Auto),
        "oi" | "open-interface" | "openinterface" | "xmpp" => Ok(IngestHint::OpenInterface),
        "pid201" | "satellite" | "sat" => Ok(IngestHint::SatellitePid201),
        "bulletin" | "raw" | "wmo" => Ok(IngestHint::RawBulletin),
        "stream" | "framed-stream" | "framed" => Ok(IngestHint::FramedStream),
        _ => Err(CliError::usage(format!(
            "unknown hint {raw}\n\n{}",
            usage()
        ))),
    }
}

fn parse_output_format(raw: &str) -> Result<OutputFormat, CliError> {
    match raw.to_ascii_lowercase().as_str() {
        "text" => Ok(OutputFormat::Text),
        "json" => Ok(OutputFormat::Json),
        "jsonl" | "json-lines" | "ndjson" => Ok(OutputFormat::Jsonl),
        "tool-result" | "tool_result" | "wx.tool_result.v1" => Ok(OutputFormat::ToolResult),
        _ => Err(CliError::usage(format!(
            "unknown output format {raw}\n\n{}",
            usage()
        ))),
    }
}

fn ensure_no_extra_args(
    command: &str,
    args: &mut impl Iterator<Item = OsString>,
) -> Result<(), CliError> {
    if let Some(extra) = args.next() {
        return Err(CliError::usage(format!(
            "unexpected extra argument for {command}: {}\n\n{}",
            extra.to_string_lossy(),
            usage()
        )));
    }

    Ok(())
}

fn inspect_command(
    path: &Path,
    hint: Option<IngestHint>,
    output: OutputFormat,
) -> Result<(), CliError> {
    ensure_file(path, "inspect")?;
    match output {
        OutputFormat::Text => {
            let report = inspect_path(path, hint)?;
            print_inspect_report(path, &report);
        }
        OutputFormat::Json => {
            let report = nwws_rs::api::inspect_path(path, hint).map_err(|err| {
                CliError::failure(format!("failed to inspect {}: {err}", path.display()))
            })?;
            print_json(&report)?;
        }
        OutputFormat::Jsonl => {
            let report = nwws_rs::api::inspect_path(path, hint).map_err(|err| {
                CliError::failure(format!("failed to inspect {}: {err}", path.display()))
            })?;
            print_inspection_jsonl(&report)?;
        }
        OutputFormat::ToolResult => {
            let report = nwws_rs::api::inspect_path(path, hint).map_err(|err| {
                CliError::failure(format!("failed to inspect {}: {err}", path.display()))
            })?;
            print_tool_result(
                "inspect",
                "ok",
                &report,
                tool_inputs(path, None),
                tool_provenance("inspect", path, None),
            )?;
        }
    }
    Ok(())
}

fn replay_command(
    path: &Path,
    hint: Option<IngestHint>,
    output: OutputFormat,
) -> Result<(), CliError> {
    ensure_directory(path, "replay")?;
    if output != OutputFormat::Text {
        let report = nwws_rs::api::scan_path(path, hint).map_err(|err| {
            CliError::failure(format!("failed to replay {}: {err}", path.display()))
        })?;
        match output {
            OutputFormat::Json => print_json(&report)?,
            OutputFormat::Jsonl => print_scan_jsonl(&report)?,
            OutputFormat::ToolResult => {
                let status = if report.failures == 0 { "ok" } else { "error" };
                print_tool_result(
                    "replay",
                    status,
                    &report,
                    tool_inputs(path, None),
                    tool_provenance("replay", path, None),
                )?;
            }
            OutputFormat::Text => unreachable!(),
        }
        if report.failures > 0 {
            return Err(CliError::failure(format!(
                "replay finished with {} parse failure(s)",
                report.failures
            )));
        }
        return Ok(());
    }

    let scan_root = resolve_scan_root(path);
    let files = collect_files(&scan_root)?;
    let mut summary = ScanSummary::default();

    for file in files {
        summary.scanned_files += 1;
        match inspect_path(&file, hint) {
            Ok(report) => {
                summary.record_success(&report);
                println!("{}", replay_line(&scan_root, &file, &report));
            }
            Err(err) => {
                summary.record_failure();
                println!("{} | error | {err}", display_path(&scan_root, &file));
            }
        }
    }

    print_summary_report(path, &summary);
    if summary.failures > 0 {
        return Err(CliError::failure(format!(
            "replay finished with {} parse failure(s)",
            summary.failures
        )));
    }

    Ok(())
}

fn active_at_command(path: &Path, options: ActiveAtOptions) -> Result<(), CliError> {
    if !path.exists() {
        return Err(CliError::failure(format!(
            "path does not exist for active-at: {}",
            path.display()
        )));
    }

    let reference_utc = options
        .reference_utc
        .as_deref()
        .expect("active-at options require --at");
    let report =
        nwws_rs::api::active_warnings_at(path, reference_utc, options.hint).map_err(|err| {
            CliError::failure(format!(
                "failed to query active warnings in {} at {}: {err}",
                path.display(),
                reference_utc
            ))
        })?;

    match options.output {
        OutputFormat::Text => print_active_warning_report(&report),
        OutputFormat::Json => print_json(&report)?,
        OutputFormat::Jsonl => print_active_warning_jsonl(&report)?,
        OutputFormat::ToolResult => {
            let status = if report.failures == 0 { "ok" } else { "error" };
            print_tool_result(
                "active-at",
                status,
                &report,
                active_tool_inputs(path, reference_utc),
                active_tool_provenance(path, reference_utc),
            )?;
        }
    }

    if report.failures > 0 {
        return Err(CliError::failure(format!(
            "active-at finished with {} parse failure(s)",
            report.failures
        )));
    }

    Ok(())
}

fn timeline_command(path: &Path, options: TimelineOptions) -> Result<(), CliError> {
    if !path.exists() {
        return Err(CliError::failure(format!(
            "path does not exist for timeline: {}",
            path.display()
        )));
    }

    let report = if let Some(query_utc) = options.query_utc.as_deref() {
        polygon_timeline_at(path, query_utc, options.hint).map_err(|err| {
            CliError::failure(format!(
                "failed to build warning timeline in {} at {}: {err}",
                path.display(),
                query_utc
            ))
        })?
    } else {
        polygon_timeline(path, options.hint).map_err(|err| {
            CliError::failure(format!(
                "failed to build warning timeline in {}: {err}",
                path.display()
            ))
        })?
    };

    match options.output {
        OutputFormat::Text => print_timeline_report(&report),
        OutputFormat::Json => print_json(&report)?,
        OutputFormat::Jsonl => print_timeline_jsonl(&report)?,
        OutputFormat::ToolResult => {
            let status = if report.failures == 0 { "ok" } else { "error" };
            print_tool_result(
                "timeline",
                status,
                &report,
                timeline_tool_inputs(path, options.query_utc.as_deref()),
                timeline_tool_provenance(path, options.query_utc.as_deref()),
            )?;
        }
    }

    if report.failures > 0 {
        return Err(CliError::failure(format!(
            "timeline finished with {} parse failure(s)",
            report.failures
        )));
    }

    Ok(())
}

fn lead_time_command(path: &Path, options: LeadTimeOptions) -> Result<(), CliError> {
    if !path.exists() {
        return Err(CliError::failure(format!(
            "path does not exist for lead-time: {}",
            path.display()
        )));
    }

    let event_utc = options
        .event_utc
        .as_deref()
        .expect("lead-time options require --event-at");
    let point = WarningPoint {
        lat: options.lat.expect("lead-time options require --lat"),
        lon: options.lon.expect("lead-time options require --lon"),
    };
    let timeline = polygon_timeline_at(path, event_utc, options.hint).map_err(|err| {
        CliError::failure(format!(
            "failed to build warning timeline in {} at {}: {err}",
            path.display(),
            event_utc
        ))
    })?;
    let metrics = lead_time_event_metrics(&timeline.records, event_utc, &point).map_err(|err| {
        CliError::failure(format!(
            "failed to compute lead-time metrics for {} at {}: {err}",
            path.display(),
            event_utc
        ))
    })?;
    let report = LeadTimeCommandReport {
        root: &timeline.root,
        query_time_utc: timeline.query_time_utc.as_deref(),
        scanned_files: timeline.scanned_files,
        parsed_files: timeline.parsed_files,
        messages: timeline.messages,
        warning_records: timeline.warning_records,
        failures: timeline.failures,
        errors: &timeline.errors,
        metrics: &metrics,
    };

    match options.output {
        OutputFormat::Text => print_lead_time_report(&report),
        OutputFormat::Json => print_json(&report)?,
        OutputFormat::Jsonl => print_lead_time_jsonl(&report)?,
        OutputFormat::ToolResult => {
            let status = if report.failures == 0 { "ok" } else { "error" };
            print_tool_result(
                "lead-time",
                status,
                &report,
                lead_time_tool_inputs(path, event_utc, &point),
                lead_time_tool_provenance(path, event_utc, &point),
            )?;
        }
    }

    if report.failures > 0 {
        return Err(CliError::failure(format!(
            "lead-time finished with {} parse failure(s)",
            report.failures
        )));
    }

    Ok(())
}

fn summary_command(path: &Path, hint: Option<IngestHint>) -> Result<(), CliError> {
    let files = collect_inputs(path)?;
    let mut summary = ScanSummary::default();

    for file in files {
        summary.scanned_files += 1;
        match inspect_path(&file, hint) {
            Ok(report) => summary.record_success(&report),
            Err(err) => {
                summary.record_failure();
                eprintln!("{} | error | {err}", display_path(path, &file));
            }
        }
    }

    print_summary_report(path, &summary);
    if summary.failures > 0 {
        return Err(CliError::failure(format!(
            "summary finished with {} parse failure(s)",
            summary.failures
        )));
    }

    Ok(())
}

fn oi_connect_command(
    username: String,
    password: String,
    options: OiConnectOptions,
) -> Result<(), CliError> {
    let mut config = OiClientConfig::new(username, password);
    config.history_stanzas = options.history;
    if let Some(host) = options.host {
        config.host = host;
    }
    if let Some(domain) = options.domain {
        config.domain = domain;
    }
    if let Some(port) = options.port {
        config.port = port;
    }
    if let Some(room) = options.room {
        config.room = room;
    }
    if let Some(room_service) = options.room_service {
        config.room_service = room_service;
    }
    if let Some(nickname) = options.nickname {
        config.nickname = nickname;
    }
    if let Some(resource) = options.resource {
        config.resource = resource;
    }

    let mut client = NwwsOiClient::connect(config.clone())
        .map_err(|err| CliError::failure(format!("failed to connect to NWWS-OI: {err}")))?;

    println!("connected: yes");
    println!("jid: {}", client.jid().unwrap_or("-"));
    println!("room: {}", config.room_address());
    println!("requested-history: {}", config.history_stanzas);
    println!("messages-to-read: {}", options.count);

    for index in 0..options.count {
        let message = client
            .next_message()
            .map_err(|err| CliError::failure(format!("failed to read NWWS-OI message: {err}")))?;
        let report = inspect_oi_message(&message).map_err(|err| {
            CliError::failure(format!(
                "failed to inspect NWWS-OI message {}: {err}",
                index + 1
            ))
        })?;
        println!();
        println!("live-message {}:", index + 1);
        print_report_messages(&report);
    }

    Ok(())
}

fn oi_archive_command(
    username: String,
    password: String,
    archive_dir: &Path,
    options: OiArchiveOptions,
) -> Result<(), CliError> {
    fs::create_dir_all(archive_dir).map_err(|err| {
        CliError::failure(format!(
            "failed to create archive directory {}: {err}",
            archive_dir.display()
        ))
    })?;

    let mut config = OiClientConfig::new(username, password);
    config.history_stanzas = options.history;
    if let Some(host) = options.host.as_deref() {
        config.host = host.to_owned();
    }
    if let Some(domain) = options.domain.as_deref() {
        config.domain = domain.to_owned();
    }
    if let Some(port) = options.port {
        config.port = port;
    }
    if let Some(room) = options.room.as_deref() {
        config.room = room.to_owned();
    }
    if let Some(room_service) = options.room_service.as_deref() {
        config.room_service = room_service.to_owned();
    }
    if let Some(nickname) = options.nickname.as_deref() {
        config.nickname = nickname.to_owned();
    }
    if let Some(resource) = options.resource.as_deref() {
        config.resource = resource.to_owned();
    }
    if let Some(duration) = options.duration {
        config.read_timeout = Some(config.read_timeout.unwrap_or(duration).min(duration));
    }

    let mut client = NwwsOiClient::connect(config.clone())
        .map_err(|err| CliError::failure(format!("failed to connect to NWWS-OI: {err}")))?;

    let router = MessageRouter::new(Some(RuntimeArchiveStore::new(archive_dir)));
    let dedupe =
        DedupeStore::open(archive_dir.join("state").join("dedupe.txt")).map_err(|err| {
            CliError::failure(format!(
                "failed to open archive dedupe store in {}: {err}",
                archive_dir.display()
            ))
        })?;
    let mut service = IngestService::new(router, dedupe);
    service.set_archive_duplicates(options.archive_duplicates);

    let started_at_utc = format_utc_now()?;
    let output = options.output;
    let capture_start = Instant::now();
    let deadline = options
        .duration
        .and_then(|duration| capture_start.checked_add(duration));
    let mut report = OiArchiveReport {
        archive_dir: archive_dir.display().to_string(),
        jid: client.jid().map(str::to_owned),
        room: config.room_address(),
        requested_history: config.history_stanzas,
        max_messages: options.count,
        duration_seconds: options.duration.map(|duration| duration.as_secs()),
        archive_duplicates: options.archive_duplicates,
        started_at_utc,
        ended_at_utc: String::new(),
        elapsed_millis: 0,
        limit_reached: None,
        messages_read: 0,
        archived_records: 0,
        duplicate_records: 0,
        failures: 0,
        messages: Vec::new(),
        errors: Vec::new(),
    };

    if output == OutputFormat::Text {
        print_oi_archive_header(&report);
    }

    while report.messages_read < options.count {
        if deadline.is_some_and(|deadline| Instant::now() >= deadline) {
            report.limit_reached = Some("duration");
            break;
        }

        let message = match client.next_message() {
            Ok(message) => message,
            Err(nwws_rs::OiClientError::Io(err)) if is_read_timeout(&err) && deadline.is_some() => {
                if deadline.is_some_and(|deadline| Instant::now() >= deadline) {
                    report.limit_reached = Some("duration");
                    break;
                }
                continue;
            }
            Err(err) => {
                report.failures += 1;
                let error = format!("failed to read NWWS-OI message: {err}");
                if output == OutputFormat::Text {
                    eprintln!("{error}");
                }
                report.errors.push(error);
                break;
            }
        };

        report.messages_read += 1;
        match archive_live_oi_message(&mut service, report.messages_read, &message) {
            Ok(message_report) => {
                report.archived_records += message_report.archived_records;
                report.duplicate_records += message_report.duplicate_records;
                if output == OutputFormat::Text {
                    print_oi_archive_message(&message_report);
                }
                report.messages.push(message_report);
            }
            Err(err) => {
                report.failures += 1;
                let error = format!(
                    "failed to archive NWWS-OI message {}: {err}",
                    report.messages_read
                );
                if output == OutputFormat::Text {
                    eprintln!("{error}");
                }
                report.errors.push(error);
            }
        }
    }

    if report.limit_reached.is_none() && report.messages_read >= options.count {
        report.limit_reached = Some("max-messages");
    }
    report.elapsed_millis = capture_start.elapsed().as_millis();
    report.ended_at_utc = format_utc_now()?;
    let _ = client.close();

    match output {
        OutputFormat::Text => print_oi_archive_summary(&report),
        OutputFormat::Json => print_json(&report)?,
        OutputFormat::Jsonl => print_oi_archive_jsonl(&report)?,
        OutputFormat::ToolResult => {
            let status = if report.failures == 0 { "ok" } else { "error" };
            print_tool_result(
                "oi-archive",
                status,
                &report,
                oi_archive_tool_inputs(&report),
                oi_archive_tool_provenance(&report),
            )?;
        }
    }

    if report.failures > 0 {
        return Err(CliError::failure(format!(
            "oi archive finished with {} failure(s)",
            report.failures
        )));
    }

    Ok(())
}

fn archive_live_oi_message(
    service: &mut IngestService,
    message_index: usize,
    message: &NwwsOiMessage,
) -> Result<OiArchiveMessageReport, CliError> {
    let payload = message
        .payload
        .as_ref()
        .ok_or_else(|| CliError::failure("NWWS-OI message did not contain a payload"))?;
    let wrapper_id = format!("{}.{}", payload.id.process_id, payload.id.sequence);
    let issue_utc = payload
        .issue
        .format(&Rfc3339)
        .map_err(|err| CliError::failure(format!("failed to format NWWS-OI issue time: {err}")))?;
    let archive_xml = oi_message_to_archive_xml(message)?;
    let process_report = service
        .process_bytes(IngestHint::OpenInterface, archive_xml.as_bytes())
        .map_err(|err| CliError::failure(format!("runtime ingest failed: {err}")))?;

    Ok(oi_archive_message_report(
        message_index,
        wrapper_id,
        issue_utc,
        payload,
        process_report,
    ))
}

fn oi_archive_message_report(
    message_index: usize,
    wrapper_id: String,
    issue_utc: String,
    payload: &nwws_rs::NwwsOiPayload,
    process_report: nwws_rs::ProcessReport,
) -> OiArchiveMessageReport {
    let records = process_report
        .records
        .into_iter()
        .map(OiArchiveRecordReport::from_runtime)
        .collect::<Vec<_>>();
    let mut archived_records = records.iter().filter(|record| !record.duplicate).count();
    let mut duplicate_records = records.iter().filter(|record| record.duplicate).count();

    if records.is_empty() {
        duplicate_records = 1;
    }
    if archived_records + duplicate_records == 0 {
        archived_records = records.len();
    }

    OiArchiveMessageReport {
        message_index,
        wrapper_id,
        issue_utc,
        ttaaii: payload.ttaaii.clone(),
        cccc: payload.cccc.clone(),
        awips_id: payload.awips_id.clone(),
        archived_records,
        duplicate_records,
        records,
    }
}

fn oi_message_to_archive_xml(message: &NwwsOiMessage) -> Result<String, CliError> {
    let payload = message
        .payload
        .as_ref()
        .ok_or_else(|| CliError::failure("NWWS-OI message did not contain a payload"))?;
    let issue = payload
        .issue
        .format(&Rfc3339)
        .map_err(|err| CliError::failure(format!("failed to format NWWS-OI issue time: {err}")))?;
    let mut xml = String::new();

    xml.push_str("<message");
    push_xml_attr(
        &mut xml,
        "type",
        message.stanza_type.as_deref().unwrap_or("groupchat"),
    );
    if let Some(from) = message.from.as_deref() {
        push_xml_attr(&mut xml, "from", from);
    }
    if let Some(to) = message.to.as_deref() {
        push_xml_attr(&mut xml, "to", to);
    }
    xml.push('>');

    if let Some(summary) = message.summary.as_deref() {
        xml.push_str("<body>");
        xml.push_str(&escape_xml_text(summary));
        xml.push_str("</body>");
    }
    if let Some(summary) = message.xhtml_summary.as_deref() {
        xml.push_str("<html xmlns='http://jabber.org/protocol/xhtml-im'><body xmlns='http://www.w3.org/1999/xhtml'>");
        xml.push_str(&escape_xml_text(summary));
        xml.push_str("</body></html>");
    }

    xml.push_str("<x xmlns='nwws-oi'");
    push_xml_attr(&mut xml, "cccc", &payload.cccc);
    push_xml_attr(&mut xml, "ttaaii", &payload.ttaaii);
    push_xml_attr(&mut xml, "issue", &issue);
    push_xml_attr(&mut xml, "awipsid", &payload.awips_id);
    push_xml_attr(
        &mut xml,
        "id",
        &format!("{}.{}", payload.id.process_id, payload.id.sequence),
    );
    xml.push('>');
    xml.push_str(&escape_xml_text(&payload.raw_bulletin));
    xml.push_str("</x></message>");

    Ok(xml)
}

fn push_xml_attr(xml: &mut String, key: &str, value: &str) {
    xml.push(' ');
    xml.push_str(key);
    xml.push_str("='");
    xml.push_str(&escape_xml_attr(value));
    xml.push('\'');
}

fn escape_xml_attr(value: &str) -> String {
    value
        .chars()
        .flat_map(|ch| match ch {
            '&' => "&amp;".chars().collect::<Vec<_>>(),
            '<' => "&lt;".chars().collect(),
            '>' => "&gt;".chars().collect(),
            '"' => "&quot;".chars().collect(),
            '\'' => "&apos;".chars().collect(),
            _ => vec![ch],
        })
        .collect()
}

fn escape_xml_text(value: &str) -> String {
    value
        .chars()
        .flat_map(|ch| match ch {
            '&' => "&amp;".chars().collect::<Vec<_>>(),
            '<' => "&lt;".chars().collect(),
            '>' => "&gt;".chars().collect(),
            _ => vec![ch],
        })
        .collect()
}

fn format_utc_now() -> Result<String, CliError> {
    OffsetDateTime::now_utc()
        .format(&Rfc3339)
        .map_err(|err| CliError::failure(format!("failed to format UTC time: {err}")))
}

fn is_read_timeout(err: &std::io::Error) -> bool {
    matches!(
        err.kind(),
        std::io::ErrorKind::TimedOut | std::io::ErrorKind::WouldBlock
    )
}

fn pid201_split_command(input: &Path, output_dir: &Path) -> Result<(), CliError> {
    ensure_file(input, "pid201 split")?;
    fs::create_dir_all(output_dir).map_err(|err| {
        CliError::failure(format!(
            "failed to create output directory {}: {err}",
            output_dir.display()
        ))
    })?;

    let bytes = fs::read(input)
        .map_err(|err| CliError::failure(format!("failed to read {}: {err}", input.display())))?;
    let parsed = parse_with_hint(IngestHint::SatellitePid201, &bytes).map_err(|err| {
        CliError::failure(format!(
            "failed to parse PID201 capture {}: {err}",
            input.display()
        ))
    })?;

    let ParsedInput::FramedStream(stream) = parsed else {
        return Err(CliError::failure(format!(
            "{} did not parse as a PID201 framed stream",
            input.display()
        )));
    };
    if stream.chunks.is_empty() {
        return Err(CliError::failure(format!(
            "{} did not contain any framed bulletins",
            input.display()
        )));
    }

    let contents = stream.contents().map_err(|err| {
        CliError::failure(format!(
            "failed to parse framed bulletins in {}: {err}",
            input.display()
        ))
    })?;
    let root_display = input.parent().unwrap_or_else(|| Path::new("."));

    for (index, content) in contents.iter().enumerate() {
        let filename = pid201_output_name(index, content);
        let path = output_dir.join(filename);
        fs::write(&path, content.bulletin.bulletin.as_bytes()).map_err(|err| {
            CliError::failure(format!("failed to write {}: {err}", path.display()))
        })?;
        println!(
            "{} | wrote | heading={} | family={}",
            display_path(root_display, &path),
            content.bulletin.heading,
            family_name(content.product.family)
        );
    }

    println!();
    println!("capture: {}", input.display());
    println!("written-files: {}", contents.len());
    println!("output-dir: {}", output_dir.display());
    Ok(())
}

fn archive_import_command(
    input: &Path,
    archive_dir: &Path,
    hint_override: Option<IngestHint>,
    output: OutputFormat,
) -> Result<(), CliError> {
    if output != OutputFormat::Text {
        return archive_import_machine_command(input, archive_dir, hint_override, output);
    }

    if !input.exists() {
        return Err(CliError::failure(format!(
            "path does not exist for archive import: {}",
            input.display()
        )));
    }

    fs::create_dir_all(archive_dir).map_err(|err| {
        CliError::failure(format!(
            "failed to create archive directory {}: {err}",
            archive_dir.display()
        ))
    })?;

    let files = collect_inputs(input)?;
    let manifest_path = archive_dir.join("records.tsv");
    let mut summary = ArchiveImportSummary::default();
    let display_root = if input.is_dir() {
        input.to_path_buf()
    } else {
        input
            .parent()
            .unwrap_or_else(|| Path::new("."))
            .to_path_buf()
    };

    for file in files {
        summary.scanned_inputs += 1;
        let bytes = match fs::read(&file) {
            Ok(bytes) => bytes,
            Err(err) => {
                summary.failures += 1;
                println!(
                    "{} | error | failed to read: {err}",
                    display_path(&display_root, &file)
                );
                continue;
            }
        };
        let hint = resolve_hint(&file, hint_override);
        let parsed = match parse_with_hint(hint, &bytes) {
            Ok(parsed) => parsed,
            Err(err) => {
                summary.failures += 1;
                println!(
                    "{} | error | failed to parse with {:?}: {err}",
                    display_path(&display_root, &file),
                    hint
                );
                continue;
            }
        };

        let records = match archive_records_from_parsed(&file, parsed) {
            Ok(records) if !records.is_empty() => records,
            Ok(_) => {
                summary.failures += 1;
                println!(
                    "{} | error | input did not contain any archiveable records",
                    display_path(&display_root, &file)
                );
                continue;
            }
            Err(err) => {
                summary.failures += 1;
                println!("{} | error | {err}", display_path(&display_root, &file));
                continue;
            }
        };

        summary.parsed_inputs += 1;
        for record in records {
            let outcome = persist_archive_record(archive_dir, &manifest_path, &record)?;
            summary.record_outcome(&record, &outcome);
            println!(
                "{} | {} | {} | heading={} | family={}",
                display_path(&display_root, &file),
                outcome.action,
                outcome.relative_path.display(),
                record.heading,
                family_name(record.family)
            );
        }
    }

    print_archive_import_summary(archive_dir, &summary);
    if summary.failures > 0 {
        return Err(CliError::failure(format!(
            "archive import finished with {} failure(s)",
            summary.failures
        )));
    }

    Ok(())
}

fn archive_import_machine_command(
    input: &Path,
    archive_dir: &Path,
    hint_override: Option<IngestHint>,
    output: OutputFormat,
) -> Result<(), CliError> {
    let report =
        nwws_rs::api::archive_import(input, archive_dir, hint_override).map_err(|err| {
            CliError::failure(format!(
                "failed to import archive from {} into {}: {err}",
                input.display(),
                archive_dir.display()
            ))
        })?;

    match output {
        OutputFormat::Json => print_json(&report)?,
        OutputFormat::Jsonl => print_archive_import_jsonl(&report)?,
        OutputFormat::ToolResult => {
            let status = if report.failures == 0 { "ok" } else { "error" };
            print_tool_result(
                "archive-import",
                status,
                &report,
                tool_inputs(input, Some(archive_dir)),
                tool_provenance("archive-import", input, Some(archive_dir)),
            )?;
        }
        OutputFormat::Text => unreachable!(),
    }

    if report.failures > 0 {
        return Err(CliError::failure(format!(
            "archive import finished with {} failure(s)",
            report.failures
        )));
    }

    Ok(())
}

fn archive_verify_command(archive_dir: &Path, output: OutputFormat) -> Result<(), CliError> {
    if output != OutputFormat::Text {
        return archive_verify_machine_command(archive_dir, output);
    }

    ensure_directory(archive_dir, "archive verify")?;
    let records_root = archive_dir.join("records");
    ensure_directory(&records_root, "archive verify")?;
    let files = collect_files(&records_root)?;

    let mut verified = 0usize;
    let mut failures = 0usize;
    let mut families = BTreeMap::<String, usize>::new();

    for file in files {
        let bytes = match fs::read(&file) {
            Ok(bytes) => bytes,
            Err(err) => {
                failures += 1;
                println!(
                    "{} | error | failed to read: {err}",
                    display_path(&records_root, &file)
                );
                continue;
            }
        };
        let report = match inspect_bytes(&bytes, IngestHint::RawBulletin) {
            Ok(report) => report,
            Err(err) => {
                failures += 1;
                println!("{} | error | {err}", display_path(&records_root, &file));
                continue;
            }
        };
        if report.items.len() != 1 {
            failures += 1;
            println!(
                "{} | error | expected one archived bulletin, found {}",
                display_path(&records_root, &file),
                report.items.len()
            );
            continue;
        }

        let expected = fingerprint_hex(&bytes);
        let stem = file
            .file_stem()
            .and_then(|value| value.to_str())
            .unwrap_or("");
        if !(stem == expected || stem.starts_with(&format!("{expected}-"))) {
            failures += 1;
            println!(
                "{} | error | digest mismatch, expected {}",
                display_path(&records_root, &file),
                expected
            );
            continue;
        }

        verified += 1;
        if let Some(family) = report.items[0].family.as_ref() {
            *families.entry(family.clone()).or_default() += 1;
        }
        println!(
            "{} | ok | heading={} | family={}",
            display_path(&records_root, &file),
            report.items[0].heading.as_deref().unwrap_or("-"),
            report.items[0].family.as_deref().unwrap_or("unknown")
        );
    }

    println!();
    println!("archive: {}", archive_dir.display());
    println!("verified-records: {}", verified);
    println!("failures: {}", failures);
    if !families.is_empty() {
        println!();
        println!("families:");
        for (family, count) in families {
            println!("  {family}: {count}");
        }
    }

    if failures > 0 {
        return Err(CliError::failure(format!(
            "archive verify finished with {failures} failure(s)"
        )));
    }

    Ok(())
}

fn archive_verify_machine_command(
    archive_dir: &Path,
    output: OutputFormat,
) -> Result<(), CliError> {
    let report = nwws_rs::api::archive_verify(archive_dir).map_err(|err| {
        CliError::failure(format!(
            "failed to verify archive {}: {err}",
            archive_dir.display()
        ))
    })?;

    match output {
        OutputFormat::Json => print_json(&report)?,
        OutputFormat::Jsonl => print_archive_verify_jsonl(&report)?,
        OutputFormat::ToolResult => {
            let status = if report.failures == 0 { "ok" } else { "error" };
            print_tool_result(
                "archive-verify",
                status,
                &report,
                tool_inputs(archive_dir, Some(archive_dir)),
                tool_provenance("archive-verify", archive_dir, Some(archive_dir)),
            )?;
        }
        OutputFormat::Text => unreachable!(),
    }

    if report.failures > 0 {
        return Err(CliError::failure(format!(
            "archive verify finished with {} failure(s)",
            report.failures
        )));
    }

    Ok(())
}

fn collect_inputs(path: &Path) -> Result<Vec<PathBuf>, CliError> {
    if path.is_file() {
        return Ok(vec![path.to_path_buf()]);
    }
    if path.is_dir() {
        let root = resolve_scan_root(path);
        return collect_files(&root);
    }

    Err(CliError::failure(format!(
        "path does not exist: {}",
        path.display()
    )))
}

fn collect_files(root: &Path) -> Result<Vec<PathBuf>, CliError> {
    collect_input_paths(root).map_err(|err| {
        CliError::failure(format!(
            "failed to collect files under {}: {err}",
            root.display()
        ))
    })
}

fn resolve_scan_root(path: &Path) -> PathBuf {
    let records = path.join("records");
    if records.is_dir() {
        records
    } else {
        path.to_path_buf()
    }
}

fn inspect_path(
    path: &Path,
    hint_override: Option<IngestHint>,
) -> Result<InspectionReport, CliError> {
    let bytes = fs::read(path)
        .map_err(|err| CliError::failure(format!("failed to read {}: {err}", path.display())))?;
    inspect_bytes(&bytes, resolve_hint(path, hint_override))
        .map_err(|err| CliError::failure(format!("failed to inspect {}: {err}", path.display())))
}

fn inspect_bytes(bytes: &[u8], hint: IngestHint) -> Result<InspectionReport, String> {
    let parsed = parse_with_hint(hint, bytes).map_err(|err| err.to_string())?;

    match parsed {
        ParsedInput::Bulletin(value) => Ok(InspectionReport {
            input_kind: InputKind::Bulletin,
            transport: value.transport,
            items: vec![MessageRecord::from_content(&value.content, None, None)],
            junk_bytes: 0,
            pending_bytes: 0,
        }),
        ParsedInput::OpenInterface(value) => {
            inspect_oi_message_with_transport(&value.message, value.transport)
        }
        ParsedInput::FramedStream(value) => inspect_framed_stream(value),
    }
}

fn inspect_oi_message(message: &NwwsOiMessage) -> Result<InspectionReport, String> {
    inspect_oi_message_with_transport(message, TransportDescriptor::open_interface())
}

fn inspect_oi_message_with_transport(
    message: &NwwsOiMessage,
    transport: TransportDescriptor,
) -> Result<InspectionReport, String> {
    let wrapper_summary = message
        .summary
        .clone()
        .or_else(|| message.xhtml_summary.clone());
    let issue = message
        .payload
        .as_ref()
        .and_then(|payload| payload.issue.format(&Rfc3339).ok());
    let content = NwwsContent::from_oi_message(message).map_err(|err| err.to_string())?;

    Ok(InspectionReport {
        input_kind: InputKind::OpenInterface,
        transport,
        items: vec![MessageRecord::from_content(
            &content,
            wrapper_summary,
            Some(WrapperMetadata {
                byte_range: None,
                wrapper_id: message
                    .payload
                    .as_ref()
                    .map(|payload| format!("{}.{}", payload.id.process_id, payload.id.sequence)),
                issue,
            }),
        )],
        junk_bytes: 0,
        pending_bytes: 0,
    })
}

fn inspect_framed_stream(value: FramedStreamIngest<'_>) -> Result<InspectionReport, String> {
    if value.chunks.is_empty() {
        return Err("no framed messages detected in stream".to_owned());
    }

    let contents = value.contents().map_err(|err| err.to_string())?;
    let items = value
        .chunks
        .iter()
        .zip(contents.iter())
        .map(|(chunk, content)| {
            MessageRecord::from_content(
                content,
                None,
                Some(WrapperMetadata::range_only(chunk.range.clone())),
            )
        })
        .collect();

    Ok(InspectionReport {
        input_kind: InputKind::FramedStream,
        transport: value.transport,
        items,
        junk_bytes: value.leading_junk_prefix,
        pending_bytes: value.pending.len(),
    })
}

fn resolve_hint(path: &Path, hint_override: Option<IngestHint>) -> IngestHint {
    hint_override.unwrap_or_else(|| infer_hint_from_path(path))
}

fn print_inspect_report(path: &Path, report: &InspectionReport) {
    println!("path: {}", path.display());
    println!("input-kind: {}", report.input_kind);
    println!("transport: {}", transport_label(report.transport));
    if let Some(channel) = report.transport.satellite_channel {
        println!("satellite-channel: {channel}");
    }
    println!(
        "requires-authentication: {}",
        yes_no(report.transport.requires_authentication)
    );
    println!(
        "paired-transport-recommended: {}",
        yes_no(report.transport.highest_availability_requires_pairing)
    );
    println!("messages: {}", report.items.len());
    if report.junk_bytes > 0 {
        println!("junk-bytes: {}", report.junk_bytes);
    }
    if report.pending_bytes > 0 {
        println!("pending-bytes: {}", report.pending_bytes);
    }

    print_report_messages(report);
}

fn print_report_messages(report: &InspectionReport) {
    for (index, item) in report.items.iter().enumerate() {
        println!();
        println!("message {}:", index + 1);
        if let Some(range) = &item.byte_range {
            println!("  byte-range: {}..{}", range.start, range.end);
        }
        if let Some(summary) = &item.wrapper_summary {
            println!("  wrapper-summary: {summary}");
        }
        if let Some(wrapper_id) = &item.wrapper_id {
            println!("  wrapper-id: {wrapper_id}");
        }
        if let Some(wrapper_issue) = &item.wrapper_issue {
            println!("  wrapper-issue: {wrapper_issue}");
        }
        if let Some(frame_kind) = item.frame_kind {
            println!("  frame-kind: {frame_kind}");
        }
        if let Some(sequence_number) = item.sequence_number {
            println!("  sequence: {sequence_number:03}");
        }
        if let Some(heading) = &item.heading {
            println!("  heading: {heading}");
        }
        if let Some(awips_id) = &item.awips_id {
            println!("  awips-id: {awips_id}");
        }
        if let Some(family) = &item.family {
            println!("  family: {family}");
        }
        if let Some(segment_count) = item.segment_count {
            println!("  segments: {segment_count}");
        }
    }
}

fn replay_line(root: &Path, path: &Path, report: &InspectionReport) -> String {
    let mut fields = vec![
        display_path(root, path),
        format!(
            "{}/{}",
            report.input_kind,
            transport_label(report.transport)
        ),
        format!("messages={}", report.items.len()),
    ];

    if let Some(first) = report.items.first() {
        if let Some(heading) = &first.heading {
            fields.push(format!("heading={heading}"));
        }
        if let Some(awips_id) = &first.awips_id {
            fields.push(format!("awips={awips_id}"));
        }
        if let Some(family) = &first.family {
            fields.push(format!("family={family}"));
        }
        if let Some(summary) = &first.wrapper_summary {
            fields.push(format!("summary={summary}"));
        }
    }

    if report.items.len() > 1 {
        fields.push(format!("extra={}", report.items.len() - 1));
    }
    if report.junk_bytes > 0 {
        fields.push(format!("junk={}", report.junk_bytes));
    }
    if report.pending_bytes > 0 {
        fields.push(format!("pending={}", report.pending_bytes));
    }

    fields.join(" | ")
}

fn print_summary_report(path: &Path, summary: &ScanSummary) {
    println!();
    println!("target: {}", path.display());
    println!("scanned-files: {}", summary.scanned_files);
    println!("parsed-files: {}", summary.parsed_files);
    println!("messages: {}", summary.messages);
    println!("failures: {}", summary.failures);

    if !summary.counts.is_empty() {
        println!();
        println!("input-kind/transport:");
        for ((input_kind, transport), counts) in &summary.counts {
            println!(
                "  {input_kind}/{transport}: files={} messages={}",
                counts.files, counts.messages
            );
        }
    }

    if !summary.families.is_empty() {
        println!();
        println!("families:");
        for (family, count) in &summary.families {
            println!("  {family}: {count}");
        }
    }
}

fn print_archive_import_summary(archive_dir: &Path, summary: &ArchiveImportSummary) {
    println!();
    println!("archive: {}", archive_dir.display());
    println!("scanned-inputs: {}", summary.scanned_inputs);
    println!("parsed-inputs: {}", summary.parsed_inputs);
    println!("archived-records: {}", summary.archived_records);
    println!("duplicate-records: {}", summary.duplicate_records);
    println!("failures: {}", summary.failures);

    if !summary.transports.is_empty() {
        println!();
        println!("transports:");
        for (transport, count) in &summary.transports {
            println!("  {transport}: {count}");
        }
    }

    if !summary.families.is_empty() {
        println!();
        println!("families:");
        for (family, count) in &summary.families {
            println!("  {family}: {count}");
        }
    }
}

fn print_oi_archive_header(report: &OiArchiveReport) {
    println!("connected: yes");
    println!("jid: {}", report.jid.as_deref().unwrap_or("-"));
    println!("room: {}", report.room);
    println!("requested-history: {}", report.requested_history);
    println!("messages-to-read: {}", report.max_messages);
    if let Some(duration_seconds) = report.duration_seconds {
        println!("duration-seconds: {duration_seconds}");
    }
    println!("archive: {}", report.archive_dir);
    println!("archive-duplicates: {}", yes_no(report.archive_duplicates));
}

fn print_oi_archive_message(message: &OiArchiveMessageReport) {
    println!();
    println!("live-archive {}:", message.message_index);
    println!("  wrapper-id: {}", message.wrapper_id);
    println!("  wrapper-issue: {}", message.issue_utc);
    println!("  heading: {} {}", message.ttaaii, message.cccc);
    println!("  awips-id: {}", message.awips_id);
    println!("  archived-records: {}", message.archived_records);
    println!("  duplicate-records: {}", message.duplicate_records);
    for record in &message.records {
        println!(
            "  {} | {} | heading={} | family={}",
            if record.duplicate {
                "duplicate"
            } else {
                "archived"
            },
            record.raw_path,
            record.heading,
            record.family
        );
    }
}

fn print_oi_archive_summary(report: &OiArchiveReport) {
    println!();
    println!("archive-summary:");
    println!("  archive: {}", report.archive_dir);
    println!("  messages-read: {}", report.messages_read);
    println!("  archived-records: {}", report.archived_records);
    println!("  duplicate-records: {}", report.duplicate_records);
    println!("  failures: {}", report.failures);
    println!("  elapsed-millis: {}", report.elapsed_millis);
    if let Some(limit) = report.limit_reached {
        println!("  limit-reached: {limit}");
    }
}

fn print_active_warning_report(report: &nwws_rs::api::ActiveWarningReport) {
    println!("root: {}", report.root.display());
    println!("reference-utc: {}", report.reference_utc);
    println!("scanned-files: {}", report.scanned_files);
    println!("parsed-files: {}", report.parsed_files);
    println!("messages: {}", report.messages);
    println!("warning-vtec-segments: {}", report.warning_vtec_segments);
    println!("future-messages: {}", report.future_messages);
    println!("active-records: {}", report.active_records);
    println!("failures: {}", report.failures);

    for record in &report.records {
        println!();
        println!("active {}:", record.key);
        println!("  source: {}", record.source_path.display());
        println!("  heading: {}", record.heading);
        if let Some(issued_at) = &record.issued_at {
            println!("  issued-at: {issued_at}");
        }
        if let Some(awips_id) = &record.awips_id {
            println!("  awips-id: {awips_id}");
        }
        println!("  product-family: {}", record.product_family);
        println!("  event-family: {}", record.event_family);
        println!("  action: {}", record.action);
        println!("  vtec: {}", record.vtec);
        println!("  ugcs: {}", record.ugcs.join(","));
        if let Some(headline) = &record.headline {
            println!("  headline: {headline}");
        }
    }
}

fn print_timeline_report(report: &nwws_rs::WarningTimelineReport) {
    println!("root: {}", report.root.display());
    if let Some(query_time_utc) = &report.query_time_utc {
        println!("query-time-utc: {query_time_utc}");
    }
    println!("scanned-files: {}", report.scanned_files);
    println!("parsed-files: {}", report.parsed_files);
    println!("messages: {}", report.messages);
    println!("warning-records: {}", report.warning_records);
    println!("failures: {}", report.failures);

    for record in &report.records {
        println!();
        println!("warning {}:", record.record_key);
        println!("  source: {}", record.source_path.display());
        println!("  event-id: {}", record.event_id);
        println!("  heading: {}", record.heading);
        if let Some(status) = record.lifecycle_status {
            println!("  lifecycle-status: {status:?}");
        }
        if let Some(issued_at) = &record.issued_at {
            println!("  issued-at: {issued_at}");
        }
        println!("  action: {}", record.action);
        println!("  event-family: {}", record.event_family);
        println!("  vtec: {}", record.vtec);
        println!("  ugcs: {}", record.ugcs.join(","));
        if let Some(polygon) = &record.polygon {
            println!("  polygon-points: {}", polygon.points.len());
        }
    }
}

fn print_lead_time_report(report: &LeadTimeCommandReport<'_>) {
    println!("root: {}", report.root.display());
    if let Some(query_time_utc) = report.query_time_utc {
        println!("query-time-utc: {query_time_utc}");
    }
    println!("scanned-files: {}", report.scanned_files);
    println!("parsed-files: {}", report.parsed_files);
    println!("messages: {}", report.messages);
    println!("warning-records: {}", report.warning_records);
    println!("failures: {}", report.failures);

    let metrics = report.metrics;
    println!();
    println!("lead-time:");
    println!("  event-time-utc: {}", metrics.event_time_utc);
    println!(
        "  event-point: {},{}",
        metrics.event_point.lat, metrics.event_point.lon
    );
    println!("  missed-event: {}", yes_no(metrics.missed_event));
    println!(
        "  lead-time-seconds: {}",
        metrics
            .lead_time_seconds
            .map(|value| value.to_string())
            .unwrap_or_else(|| "-".to_owned())
    );
    if let Some(record_key) = &metrics.first_valid_warning_record_key {
        println!("  first-valid-warning-record-key: {record_key}");
    }
    if let Some(event_id) = &metrics.first_valid_warning_event_id {
        println!("  first-valid-warning-event-id: {event_id}");
    }
    println!("  point-warning-records: {}", metrics.point_warning_records);
    println!("  event-warning-records: {}", metrics.event_warning_records);
    println!(
        "  false-alarm-duration-seconds: {}",
        metrics.false_alarm_duration_seconds
    );
    if !metrics.quality_flags.is_empty() {
        println!("  quality-flags: {:?}", metrics.quality_flags);
    }
}

fn print_json<T: Serialize>(value: &T) -> Result<(), CliError> {
    let payload = serde_json::to_string_pretty(value)
        .map_err(|err| CliError::failure(format!("failed to serialize JSON output: {err}")))?;
    println!("{payload}");
    Ok(())
}

fn print_json_line<T: Serialize>(value: &T) -> Result<(), CliError> {
    let payload = serde_json::to_string(value)
        .map_err(|err| CliError::failure(format!("failed to serialize JSONL output: {err}")))?;
    println!("{payload}");
    Ok(())
}

fn print_inspection_jsonl(report: &nwws_rs::api::InspectionReport) -> Result<(), CliError> {
    for (index, message) in report.messages.iter().enumerate() {
        print_json_line(&InspectionJsonlRecord {
            schema: "nwws.message.v1",
            record_type: "message",
            path: report.path.as_deref(),
            input_kind: report.input_kind,
            transport: &report.transport,
            junk_bytes: report.junk_bytes,
            pending_bytes: report.pending_bytes,
            message_index: index + 1,
            message,
        })?;
    }
    Ok(())
}

fn print_scan_jsonl(report: &nwws_rs::api::ScanReport) -> Result<(), CliError> {
    for file in &report.files {
        match (&file.report, &file.error) {
            (Some(inspection), _) => {
                for (index, message) in inspection.messages.iter().enumerate() {
                    print_json_line(&ScanJsonlRecord {
                        schema: "nwws.message.v1",
                        record_type: "message",
                        path: &file.path,
                        input_kind: inspection.input_kind,
                        transport: &inspection.transport,
                        junk_bytes: inspection.junk_bytes,
                        pending_bytes: inspection.pending_bytes,
                        message_index: index + 1,
                        message,
                    })?;
                }
            }
            (None, Some(error)) => print_json_line(&ErrorJsonlRecord {
                schema: "nwws.error.v1",
                record_type: "error",
                path: &file.path,
                error,
            })?,
            (None, None) => {}
        }
    }
    Ok(())
}

fn print_archive_import_jsonl(report: &nwws_rs::api::ArchiveImportReport) -> Result<(), CliError> {
    for record in &report.records {
        print_json_line(&ArchiveImportJsonlRecord {
            schema: "nwws.archive_import.v1",
            record_type: "archive-record",
            archive_dir: &report.archive_dir,
            record,
        })?;
    }
    for error in &report.errors {
        print_json_line(&ArchiveImportErrorJsonlRecord {
            schema: "nwws.archive_import.v1",
            record_type: "error",
            archive_dir: &report.archive_dir,
            error,
        })?;
    }
    Ok(())
}

fn print_archive_verify_jsonl(report: &nwws_rs::api::ArchiveVerifyReport) -> Result<(), CliError> {
    for record in &report.records {
        print_json_line(&ArchiveVerifyJsonlRecord {
            schema: "nwws.archive_verify.v1",
            record_type: "archive-verify-record",
            archive_dir: &report.archive_dir,
            record,
        })?;
    }
    Ok(())
}

fn print_active_warning_jsonl(report: &nwws_rs::api::ActiveWarningReport) -> Result<(), CliError> {
    for record in &report.records {
        print_json_line(&ActiveWarningJsonlRecord {
            schema: "nwws.active_warnings.v1",
            record_type: "active-warning",
            reference_utc: &report.reference_utc,
            record,
        })?;
    }
    for error in &report.errors {
        print_json_line(&ActiveWarningErrorJsonlRecord {
            schema: "nwws.active_warnings.v1",
            record_type: "error",
            reference_utc: &report.reference_utc,
            error,
        })?;
    }
    Ok(())
}

fn print_timeline_jsonl(report: &nwws_rs::WarningTimelineReport) -> Result<(), CliError> {
    for record in &report.records {
        print_json_line(&TimelineJsonlRecord {
            schema: "nwws.warning_timeline.v1",
            record_type: "warning-timeline-record",
            query_time_utc: report.query_time_utc.as_deref(),
            record,
        })?;
    }
    for error in &report.errors {
        print_json_line(&TimelineErrorJsonlRecord {
            schema: "nwws.warning_timeline.v1",
            record_type: "error",
            query_time_utc: report.query_time_utc.as_deref(),
            error,
        })?;
    }
    Ok(())
}

fn print_lead_time_jsonl(report: &LeadTimeCommandReport<'_>) -> Result<(), CliError> {
    print_json_line(&LeadTimeJsonlRecord {
        schema: "nwws.warning_lead_time.v1",
        record_type: "lead-time-metrics",
        metrics: report.metrics,
    })?;
    for error in report.errors {
        print_json_line(&LeadTimeErrorJsonlRecord {
            schema: "nwws.warning_lead_time.v1",
            record_type: "error",
            error,
        })?;
    }
    Ok(())
}

fn print_oi_archive_jsonl(report: &OiArchiveReport) -> Result<(), CliError> {
    print_json_line(&OiArchiveJsonlReport {
        schema: "nwws.oi_archive.v1",
        record_type: "report",
        report,
    })
}

fn print_tool_result<T: Serialize>(
    operation: &str,
    status: &str,
    data: &T,
    inputs: serde_json::Value,
    provenance: serde_json::Value,
) -> Result<(), CliError> {
    let data = serde_json::to_value(data)
        .map_err(|err| CliError::failure(format!("failed to serialize tool result data: {err}")))?;
    let envelope = json!({
        "schema_version": "wx.tool_result.v1",
        "tool_name": tool_name(operation),
        "ok": status == "ok",
        "inputs": inputs,
        "data": data,
        "artifacts": [
            {
                "artifact_id": operation,
                "kind": "json",
                "media_type": "application/json",
                "description": "Native nwws-rs parser/API output for the requested command"
            }
        ],
        "evidence": tool_evidence(&data),
        "limitations": tool_limitations(operation),
        "provenance": provenance
    });
    print_json(&envelope)
}

fn tool_name(operation: &str) -> &'static str {
    match operation {
        "inspect" => "warning.parse_text",
        "replay" => "warning.replay",
        "active-at" => "warning.active_at_reference",
        "timeline" => "warning.timeline",
        "lead-time" => "warning.lead_time_event_metrics",
        "archive-import" => "warning.archive_import",
        "archive-verify" => "warning.archive_verify",
        "oi-archive" => "warning.oi_archive",
        _ => "warning.unknown",
    }
}

fn tool_inputs(source_path: &Path, archive_dir: Option<&Path>) -> serde_json::Value {
    json!({
        "source_path": source_path.display().to_string(),
        "archive_dir": archive_dir.map(|path| path.display().to_string())
    })
}

fn active_tool_inputs(source_path: &Path, reference_utc: &str) -> serde_json::Value {
    json!({
        "source_path": source_path.display().to_string(),
        "archive_dir": source_path.join("records").is_dir().then(|| source_path.display().to_string()),
        "reference_utc": reference_utc
    })
}

fn timeline_tool_inputs(source_path: &Path, query_utc: Option<&str>) -> serde_json::Value {
    json!({
        "source_path": source_path.display().to_string(),
        "archive_dir": source_path.join("records").is_dir().then(|| source_path.display().to_string()),
        "query_utc": query_utc
    })
}

fn lead_time_tool_inputs(
    source_path: &Path,
    event_utc: &str,
    point: &WarningPoint,
) -> serde_json::Value {
    json!({
        "source_path": source_path.display().to_string(),
        "archive_dir": source_path.join("records").is_dir().then(|| source_path.display().to_string()),
        "event_utc": event_utc,
        "event_point": {
            "lat": point.lat,
            "lon": point.lon
        }
    })
}

fn oi_archive_tool_inputs(report: &OiArchiveReport) -> serde_json::Value {
    json!({
        "archive_dir": report.archive_dir.as_str(),
        "room": report.room.as_str(),
        "history": report.requested_history,
        "max_messages": report.max_messages,
        "duration_seconds": report.duration_seconds,
        "archive_duplicates": report.archive_duplicates
    })
}

fn tool_provenance(
    operation: &str,
    source_path: &Path,
    archive_dir: Option<&Path>,
) -> serde_json::Value {
    json!({
        "producer": "nwws-rs",
        "operation": operation,
        "source_path": source_path.display().to_string(),
        "archive_dir": archive_dir.map(|path| path.display().to_string()),
        "contract": "wx.tool_result.v1"
    })
}

fn active_tool_provenance(source_path: &Path, reference_utc: &str) -> serde_json::Value {
    json!({
        "producer": "nwws-rs",
        "operation": "active-at",
        "source_path": source_path.display().to_string(),
        "archive_dir": source_path.join("records").is_dir().then(|| source_path.display().to_string()),
        "reference_utc": reference_utc,
        "contract": "wx.tool_result.v1"
    })
}

fn timeline_tool_provenance(source_path: &Path, query_utc: Option<&str>) -> serde_json::Value {
    json!({
        "producer": "nwws-rs",
        "operation": "timeline",
        "source_path": source_path.display().to_string(),
        "archive_dir": source_path.join("records").is_dir().then(|| source_path.display().to_string()),
        "query_utc": query_utc,
        "contract": "wx.tool_result.v1"
    })
}

fn lead_time_tool_provenance(
    source_path: &Path,
    event_utc: &str,
    point: &WarningPoint,
) -> serde_json::Value {
    json!({
        "producer": "nwws-rs",
        "operation": "lead-time",
        "source_path": source_path.display().to_string(),
        "archive_dir": source_path.join("records").is_dir().then(|| source_path.display().to_string()),
        "event_utc": event_utc,
        "event_point": {
            "lat": point.lat,
            "lon": point.lon
        },
        "contract": "wx.tool_result.v1"
    })
}

fn oi_archive_tool_provenance(report: &OiArchiveReport) -> serde_json::Value {
    json!({
        "producer": "nwws-rs",
        "operation": "oi-archive",
        "archive_dir": report.archive_dir.as_str(),
        "room": report.room.as_str(),
        "jid": report.jid.as_deref(),
        "started_at_utc": report.started_at_utc.as_str(),
        "ended_at_utc": report.ended_at_utc.as_str(),
        "contract": "wx.tool_result.v1"
    })
}

fn tool_limitations(operation: &str) -> Vec<&'static str> {
    if operation == "oi-archive" {
        return vec![
            "Live capture depends on NWWS-OI network availability, credentials, and XMPP room delivery.",
            "Archived XML stanzas are reconstructed from parsed NWWS-OI message fields; they preserve bulletin semantics but are not byte-for-byte XMPP captures.",
            "Dedupe is based on normalized bulletin semantics in the runtime archive service.",
        ];
    }

    let mut limitations = vec![
        "Output reflects parser results for the supplied local input only.",
        "No external NWS source-of-truth or network delivery validation is performed.",
    ];
    if operation == "active-at" {
        limitations.push(
            "Active-at queries use local WMO heading times and VTEC intervals; records without warning P-VTEC are not returned.",
        );
    }
    if operation == "timeline" || operation == "lead-time" {
        limitations.push(
            "Timeline queries return warning-significance P-VTEC records; non-warning products are not verification records.",
        );
    }
    if operation == "lead-time" {
        limitations.extend(nwws_rs::lead_time_event_metric_limitations());
    }
    limitations
}

fn tool_evidence(data: &serde_json::Value) -> Vec<serde_json::Value> {
    let mut evidence = Vec::new();
    if let Some(messages_read) = data.get("messages_read").and_then(|value| value.as_u64()) {
        evidence.push(json!({
            "evidence_type": "live_messages_read",
            "summary": format!("Read {messages_read} live NWWS-OI message(s)."),
            "count": messages_read
        }));
    }
    if let Some(archived_records) = data
        .get("archived_records")
        .and_then(|value| value.as_u64())
    {
        evidence.push(json!({
            "evidence_type": "archived_records",
            "summary": format!("Archived {archived_records} new record(s)."),
            "count": archived_records
        }));
    }
    if let Some(active_records) = data.get("active_records").and_then(|value| value.as_u64()) {
        evidence.push(json!({
            "evidence_type": "active_warning_records",
            "summary": format!("Returned {active_records} active warning record(s)."),
            "count": active_records
        }));
    }
    if let Some(warning_records) = data.get("warning_records").and_then(|value| value.as_u64()) {
        evidence.push(json!({
            "evidence_type": "warning_timeline_records",
            "summary": format!("Returned {warning_records} warning timeline record(s)."),
            "count": warning_records
        }));
    }
    if let Some(metrics) = data.get("metrics").and_then(|value| value.as_object()) {
        let lead_time = metrics
            .get("lead_time_seconds")
            .and_then(|value| value.as_i64());
        let missed = metrics
            .get("missed_event")
            .and_then(|value| value.as_bool())
            .unwrap_or(false);
        evidence.push(json!({
            "evidence_type": "warning_lead_time_metrics",
            "summary": match lead_time {
                Some(seconds) => format!("Computed warning lead time of {seconds} second(s)."),
                None if missed => "No valid warning covered the supplied event point/time.".to_owned(),
                None => "Computed warning lead-time metrics without a finite lead-time value.".to_owned(),
            },
            "lead_time_seconds": lead_time,
            "missed_event": missed
        }));
    }
    if let Some(messages) = data.get("messages").and_then(|value| value.as_array()) {
        evidence.push(json!({
            "evidence_type": "parsed_messages",
            "summary": format!("Parsed {} warning message(s).", messages.len()),
            "count": messages.len()
        }));
    }
    if let Some(files) = data.get("scanned_files").and_then(|value| value.as_u64()) {
        evidence.push(json!({
            "evidence_type": "scanned_files",
            "summary": format!("Scanned {files} input file(s)."),
            "count": files
        }));
    }
    if let Some(records) = data.get("records").and_then(|value| value.as_array()) {
        evidence.push(json!({
            "evidence_type": "records",
            "summary": format!("Returned {} archive record(s).", records.len()),
            "count": records.len()
        }));
    }
    if evidence.is_empty() {
        evidence.push(json!({
            "evidence_type": "parser_output",
            "summary": "Returned a native nwws-rs API report."
        }));
    }
    evidence
}

fn display_path(root: &Path, path: &Path) -> String {
    path.strip_prefix(root)
        .unwrap_or(path)
        .display()
        .to_string()
}

fn ensure_file(path: &Path, command: &str) -> Result<(), CliError> {
    if !path.exists() {
        return Err(CliError::failure(format!(
            "path does not exist for {command}: {}",
            path.display()
        )));
    }
    if !path.is_file() {
        return Err(CliError::failure(format!(
            "{command} expects a file: {}",
            path.display()
        )));
    }
    Ok(())
}

fn ensure_directory(path: &Path, command: &str) -> Result<(), CliError> {
    if !path.exists() {
        return Err(CliError::failure(format!(
            "path does not exist for {command}: {}",
            path.display()
        )));
    }
    if !path.is_dir() {
        return Err(CliError::failure(format!(
            "{command} expects a directory: {}",
            path.display()
        )));
    }
    Ok(())
}

fn archive_records_from_parsed(
    source_path: &Path,
    parsed: ParsedInput<'_>,
) -> Result<Vec<ArchiveRecord>, CliError> {
    match parsed {
        ParsedInput::Bulletin(value) => Ok(vec![ArchiveRecord::from_content(
            source_path,
            0,
            InputKind::Bulletin,
            value.transport,
            None,
            &value.content,
        )]),
        ParsedInput::OpenInterface(value) => {
            let wrapper_id = value.wrapper.as_ref().map(|value| value.id.clone());
            let content = value.content().map_err(|err| {
                CliError::failure(format!(
                    "failed to parse embedded bulletin from {}: {err}",
                    source_path.display()
                ))
            })?;
            Ok(vec![ArchiveRecord::from_content(
                source_path,
                0,
                InputKind::OpenInterface,
                value.transport,
                wrapper_id,
                &content,
            )])
        }
        ParsedInput::FramedStream(value) => {
            let contents = value.contents().map_err(|err| {
                CliError::failure(format!(
                    "failed to parse framed bulletin stream from {}: {err}",
                    source_path.display()
                ))
            })?;
            Ok(contents
                .iter()
                .enumerate()
                .map(|(index, content)| {
                    ArchiveRecord::from_content(
                        source_path,
                        index,
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
) -> Result<ArchivePersistOutcome, CliError> {
    let digest = fingerprint_hex(record.bulletin_text.as_bytes());
    let mut relative_path = canonical_record_relative_path(record, &digest);
    let mut collision_index = 0usize;

    loop {
        let path = archive_dir.join(&relative_path);
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).map_err(|err| {
                CliError::failure(format!(
                    "failed to create archive directory {}: {err}",
                    parent.display()
                ))
            })?;
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
                fs::write(&path, record.bulletin_text.as_bytes()).map_err(|err| {
                    CliError::failure(format!("failed to write {}: {err}", path.display()))
                })?;
                append_archive_manifest(manifest_path, record, &relative_path, &digest)?;
                return Ok(ArchivePersistOutcome {
                    action: "archived",
                    relative_path,
                });
            }
            Err(err) => {
                return Err(CliError::failure(format!(
                    "failed to check archive record {}: {err}",
                    path.display()
                )));
            }
        }
    }
}

fn append_archive_manifest(
    manifest_path: &Path,
    record: &ArchiveRecord,
    relative_path: &Path,
    digest: &str,
) -> Result<(), CliError> {
    let existed = manifest_path.exists();
    let mut file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(manifest_path)
        .map_err(|err| {
            CliError::failure(format!(
                "failed to open archive manifest {}: {err}",
                manifest_path.display()
            ))
        })?;

    if !existed {
        writeln!(
            file,
            "fingerprint\trelative_path\tinput_kind\ttransport\tsequence\tttaaii\tcccc\tawips_id\tfamily\tsegments\twrapper_id\tsource_path"
        )
        .map_err(|err| {
            CliError::failure(format!(
                "failed to write archive manifest header {}: {err}",
                manifest_path.display()
            ))
        })?;
    }

    writeln!(
        file,
        "{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}",
        digest,
        relative_path.display(),
        record.input_kind,
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
    )
    .map_err(|err| {
        CliError::failure(format!(
            "failed to append archive manifest {}: {err}",
            manifest_path.display()
        ))
    })
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

fn fingerprint_hex(bytes: &[u8]) -> String {
    const OFFSET_BASIS: u64 = 0xcbf29ce484222325;
    const PRIME: u64 = 0x100000001b3;

    let mut hash = OFFSET_BASIS;
    for byte in bytes {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(PRIME);
    }

    format!("{hash:016x}")
}

fn transport_label(transport: TransportDescriptor) -> &'static str {
    match transport.kind {
        TransportKind::OpenInterface => "open-interface",
        TransportKind::SatellitePid201 => "satellite-pid201",
        TransportKind::PlainWmoText => "plain-wmo-text",
    }
}

fn yes_no(value: bool) -> &'static str {
    if value { "yes" } else { "no" }
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum OutputFormat {
    Text,
    Json,
    Jsonl,
    ToolResult,
}

#[derive(Debug)]
struct CommandOptions {
    hint: Option<IngestHint>,
    output: OutputFormat,
}

impl Default for CommandOptions {
    fn default() -> Self {
        Self {
            hint: None,
            output: OutputFormat::Text,
        }
    }
}

#[derive(Debug)]
struct ActiveAtOptions {
    reference_utc: Option<String>,
    hint: Option<IngestHint>,
    output: OutputFormat,
}

impl Default for ActiveAtOptions {
    fn default() -> Self {
        Self {
            reference_utc: None,
            hint: None,
            output: OutputFormat::Text,
        }
    }
}

#[derive(Debug)]
struct TimelineOptions {
    query_utc: Option<String>,
    hint: Option<IngestHint>,
    output: OutputFormat,
}

impl Default for TimelineOptions {
    fn default() -> Self {
        Self {
            query_utc: None,
            hint: None,
            output: OutputFormat::Text,
        }
    }
}

#[derive(Debug)]
struct LeadTimeOptions {
    event_utc: Option<String>,
    lat: Option<f32>,
    lon: Option<f32>,
    hint: Option<IngestHint>,
    output: OutputFormat,
}

impl Default for LeadTimeOptions {
    fn default() -> Self {
        Self {
            event_utc: None,
            lat: None,
            lon: None,
            hint: None,
            output: OutputFormat::Text,
        }
    }
}

#[derive(Serialize)]
struct InspectionJsonlRecord<'a> {
    schema: &'static str,
    record_type: &'static str,
    path: Option<&'a Path>,
    input_kind: nwws_rs::api::InputKind,
    transport: &'a nwws_rs::api::TransportSummary,
    junk_bytes: usize,
    pending_bytes: usize,
    message_index: usize,
    message: &'a nwws_rs::api::MessageSummary,
}

#[derive(Serialize)]
struct ScanJsonlRecord<'a> {
    schema: &'static str,
    record_type: &'static str,
    path: &'a Path,
    input_kind: nwws_rs::api::InputKind,
    transport: &'a nwws_rs::api::TransportSummary,
    junk_bytes: usize,
    pending_bytes: usize,
    message_index: usize,
    message: &'a nwws_rs::api::MessageSummary,
}

#[derive(Serialize)]
struct ErrorJsonlRecord<'a> {
    schema: &'static str,
    record_type: &'static str,
    path: &'a Path,
    error: &'a str,
}

#[derive(Serialize)]
struct ArchiveImportJsonlRecord<'a> {
    schema: &'static str,
    record_type: &'static str,
    archive_dir: &'a Path,
    record: &'a nwws_rs::api::ArchivePersistResult,
}

#[derive(Serialize)]
struct ArchiveImportErrorJsonlRecord<'a> {
    schema: &'static str,
    record_type: &'static str,
    archive_dir: &'a Path,
    error: &'a nwws_rs::api::ArchiveFailure,
}

#[derive(Serialize)]
struct ArchiveVerifyJsonlRecord<'a> {
    schema: &'static str,
    record_type: &'static str,
    archive_dir: &'a Path,
    record: &'a nwws_rs::api::ArchiveVerifyRecord,
}

#[derive(Serialize)]
struct ActiveWarningJsonlRecord<'a> {
    schema: &'static str,
    record_type: &'static str,
    reference_utc: &'a str,
    record: &'a nwws_rs::api::ActiveWarningRecord,
}

#[derive(Serialize)]
struct ActiveWarningErrorJsonlRecord<'a> {
    schema: &'static str,
    record_type: &'static str,
    reference_utc: &'a str,
    error: &'a nwws_rs::api::ActiveWarningFailure,
}

#[derive(Serialize)]
struct TimelineJsonlRecord<'a> {
    schema: &'static str,
    record_type: &'static str,
    query_time_utc: Option<&'a str>,
    record: &'a nwws_rs::WarningTimelineRecord,
}

#[derive(Serialize)]
struct TimelineErrorJsonlRecord<'a> {
    schema: &'static str,
    record_type: &'static str,
    query_time_utc: Option<&'a str>,
    error: &'a nwws_rs::WarningTimelineFailure,
}

#[derive(Serialize)]
struct LeadTimeCommandReport<'a> {
    root: &'a Path,
    query_time_utc: Option<&'a str>,
    scanned_files: usize,
    parsed_files: usize,
    messages: usize,
    warning_records: usize,
    failures: usize,
    errors: &'a [nwws_rs::WarningTimelineFailure],
    metrics: &'a nwws_rs::WarningLeadTimeEventMetrics,
}

#[derive(Serialize)]
struct LeadTimeJsonlRecord<'a> {
    schema: &'static str,
    record_type: &'static str,
    metrics: &'a nwws_rs::WarningLeadTimeEventMetrics,
}

#[derive(Serialize)]
struct LeadTimeErrorJsonlRecord<'a> {
    schema: &'static str,
    record_type: &'static str,
    error: &'a nwws_rs::WarningTimelineFailure,
}

#[derive(Debug)]
struct CliError {
    exit_code: i32,
    message: String,
}

impl CliError {
    fn usage(message: impl Into<String>) -> Self {
        Self {
            exit_code: 2,
            message: message.into(),
        }
    }

    fn failure(message: impl Into<String>) -> Self {
        Self {
            exit_code: 1,
            message: message.into(),
        }
    }
}

impl std::fmt::Display for CliError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.message)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum InputKind {
    OpenInterface,
    Bulletin,
    FramedStream,
}

impl std::fmt::Display for InputKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::OpenInterface => f.write_str("open-interface"),
            Self::Bulletin => f.write_str("bulletin"),
            Self::FramedStream => f.write_str("framed-stream"),
        }
    }
}

#[derive(Debug)]
struct InspectionReport {
    input_kind: InputKind,
    transport: TransportDescriptor,
    items: Vec<MessageRecord>,
    junk_bytes: usize,
    pending_bytes: usize,
}

#[derive(Debug, Default)]
struct MessageRecord {
    byte_range: Option<Range<usize>>,
    wrapper_summary: Option<String>,
    wrapper_id: Option<String>,
    wrapper_issue: Option<String>,
    frame_kind: Option<&'static str>,
    sequence_number: Option<u16>,
    heading: Option<String>,
    awips_id: Option<String>,
    family: Option<String>,
    segment_count: Option<usize>,
}

impl MessageRecord {
    fn from_content(
        content: &NwwsContent<'_>,
        wrapper_summary: Option<String>,
        wrapper_metadata: Option<WrapperMetadata>,
    ) -> Self {
        let bulletin = &content.bulletin;
        let wrapper_metadata = wrapper_metadata.unwrap_or_default();

        Self {
            byte_range: wrapper_metadata.byte_range,
            wrapper_summary,
            wrapper_id: wrapper_metadata.wrapper_id,
            wrapper_issue: wrapper_metadata.issue,
            frame_kind: Some(match bulletin.frame_kind {
                nwws_rs::WmoFrameKind::Bare => "bare",
                nwws_rs::WmoFrameKind::Framed => "framed",
            }),
            sequence_number: bulletin.sequence_number,
            heading: Some(bulletin.heading.to_string()),
            awips_id: bulletin
                .awips_id
                .as_ref()
                .map(|value| value.raw().to_owned()),
            family: Some(family_name(content.product.family)),
            segment_count: Some(content.product.segments.len()),
        }
    }
}

#[derive(Debug, Default)]
struct WrapperMetadata {
    byte_range: Option<Range<usize>>,
    wrapper_id: Option<String>,
    issue: Option<String>,
}

impl WrapperMetadata {
    fn range_only(byte_range: Range<usize>) -> Self {
        Self {
            byte_range: Some(byte_range),
            wrapper_id: None,
            issue: None,
        }
    }
}

#[derive(Debug, Default)]
struct CountSummary {
    files: usize,
    messages: usize,
}

#[derive(Debug, Default)]
struct ScanSummary {
    scanned_files: usize,
    parsed_files: usize,
    messages: usize,
    failures: usize,
    counts: BTreeMap<(InputKind, &'static str), CountSummary>,
    families: BTreeMap<String, usize>,
}

impl ScanSummary {
    fn record_success(&mut self, report: &InspectionReport) {
        self.parsed_files += 1;
        self.messages += report.items.len();
        let count = self
            .counts
            .entry((report.input_kind, transport_label(report.transport)))
            .or_default();
        count.files += 1;
        count.messages += report.items.len();

        for item in &report.items {
            if let Some(family) = item.family.as_ref() {
                *self.families.entry(family.clone()).or_default() += 1;
            }
        }
    }

    fn record_failure(&mut self) {
        self.failures += 1;
    }
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
        _record_index: usize,
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

#[derive(Debug, Default)]
struct ArchiveImportSummary {
    scanned_inputs: usize,
    parsed_inputs: usize,
    archived_records: usize,
    duplicate_records: usize,
    failures: usize,
    transports: BTreeMap<&'static str, usize>,
    families: BTreeMap<String, usize>,
}

impl ArchiveImportSummary {
    fn record_outcome(&mut self, record: &ArchiveRecord, outcome: &ArchivePersistOutcome) {
        match outcome.action {
            "archived" => self.archived_records += 1,
            "duplicate" => self.duplicate_records += 1,
            _ => {}
        }
        *self
            .transports
            .entry(transport_label(record.transport))
            .or_default() += 1;
        *self.families.entry(family_name(record.family)).or_default() += 1;
    }
}

#[derive(Debug)]
struct OiConnectOptions {
    count: usize,
    history: u32,
    host: Option<String>,
    domain: Option<String>,
    port: Option<u16>,
    room: Option<String>,
    room_service: Option<String>,
    nickname: Option<String>,
    resource: Option<String>,
}

impl Default for OiConnectOptions {
    fn default() -> Self {
        Self {
            count: 1,
            history: 0,
            host: None,
            domain: None,
            port: None,
            room: None,
            room_service: None,
            nickname: None,
            resource: None,
        }
    }
}

#[derive(Debug)]
struct OiArchiveOptions {
    count: usize,
    duration: Option<Duration>,
    history: u32,
    archive_duplicates: bool,
    output: OutputFormat,
    host: Option<String>,
    domain: Option<String>,
    port: Option<u16>,
    room: Option<String>,
    room_service: Option<String>,
    nickname: Option<String>,
    resource: Option<String>,
}

impl Default for OiArchiveOptions {
    fn default() -> Self {
        Self {
            count: 1,
            duration: None,
            history: 0,
            archive_duplicates: false,
            output: OutputFormat::Text,
            host: None,
            domain: None,
            port: None,
            room: None,
            room_service: None,
            nickname: None,
            resource: None,
        }
    }
}

#[derive(Debug, Serialize)]
struct OiArchiveReport {
    archive_dir: String,
    jid: Option<String>,
    room: String,
    requested_history: u32,
    max_messages: usize,
    duration_seconds: Option<u64>,
    archive_duplicates: bool,
    started_at_utc: String,
    ended_at_utc: String,
    elapsed_millis: u128,
    limit_reached: Option<&'static str>,
    messages_read: usize,
    archived_records: usize,
    duplicate_records: usize,
    failures: usize,
    messages: Vec<OiArchiveMessageReport>,
    errors: Vec<String>,
}

#[derive(Debug, Serialize)]
struct OiArchiveMessageReport {
    message_index: usize,
    wrapper_id: String,
    issue_utc: String,
    ttaaii: String,
    cccc: String,
    awips_id: String,
    archived_records: usize,
    duplicate_records: usize,
    records: Vec<OiArchiveRecordReport>,
}

#[derive(Debug, Serialize)]
struct OiArchiveRecordReport {
    fingerprint: String,
    duplicate: bool,
    raw_path: String,
    metadata_path: String,
    source: &'static str,
    transport: &'static str,
    frame_kind: &'static str,
    sequence_number: Option<u16>,
    heading: String,
    ttaaii: String,
    cccc: String,
    awips_id: Option<String>,
    family: String,
    segment_count: usize,
    wrapper_id: Option<String>,
    wrapper_issue: Option<String>,
}

impl OiArchiveRecordReport {
    fn from_runtime(record: nwws_rs::ArchiveRecord) -> Self {
        let source = match record.metadata.source {
            nwws_rs::RecordSource::OpenInterface => "open-interface",
            nwws_rs::RecordSource::RawBulletin => "raw-bulletin",
            nwws_rs::RecordSource::SatellitePid201 => "satellite-pid201",
        };
        let heading = format!("{} {}", record.metadata.ttaaii, record.metadata.cccc);

        Self {
            fingerprint: record.fingerprint,
            duplicate: record.duplicate,
            raw_path: record.raw_path.display().to_string(),
            metadata_path: record.metadata_path.display().to_string(),
            source,
            transport: record.metadata.transport,
            frame_kind: record.metadata.frame_kind,
            sequence_number: record.metadata.sequence_number,
            heading,
            ttaaii: record.metadata.ttaaii,
            cccc: record.metadata.cccc,
            awips_id: record.metadata.awips_id,
            family: family_name(record.metadata.family),
            segment_count: record.metadata.segment_count,
            wrapper_id: record.metadata.wrapper_id,
            wrapper_issue: record.metadata.wrapper_issue,
        }
    }
}

#[derive(Serialize)]
struct OiArchiveJsonlReport<'a> {
    schema: &'static str,
    record_type: &'static str,
    report: &'a OiArchiveReport,
}

#[cfg(test)]
mod tests {
    use super::{
        InputKind, canonical_record_relative_path, fingerprint_hex, inspect_bytes,
        oi_message_to_archive_xml, parse_hint_value, sanitize_component,
    };
    use nwws_rs::{
        ArchiveStore as RuntimeArchiveStore, DedupeStore, IngestHint, IngestService, MessageRouter,
        NwwsContent, NwwsOiMessage, RecordSource, TransportDescriptor,
    };
    use std::path::PathBuf;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn frame_with_wmo_separators(bulletin: &str) -> String {
        let bulletin = bulletin.lines().collect::<Vec<_>>().join("\r\r\n");
        format!("\u{1}\r\r\n{bulletin}\r\r\n\u{3}")
    }

    #[test]
    fn parses_hint_aliases() {
        assert_eq!(parse_hint_value("oi").unwrap(), IngestHint::OpenInterface);
        assert_eq!(
            parse_hint_value("pid201").unwrap(),
            IngestHint::SatellitePid201
        );
        assert_eq!(parse_hint_value("wmo").unwrap(), IngestHint::RawBulletin);
        assert_eq!(
            parse_hint_value("framed-stream").unwrap(),
            IngestHint::FramedStream
        );
    }

    #[test]
    fn detects_open_interface_fixture() {
        let report = inspect_bytes(
            include_str!("../../tests/fixtures/nwws_oi_tornado_warning.xml").as_bytes(),
            IngestHint::OpenInterface,
        )
        .unwrap();
        assert_eq!(report.input_kind, InputKind::OpenInterface);
        assert_eq!(report.items.len(), 1);
        assert_eq!(
            report.items[0].heading.as_deref(),
            Some("WUUS53 KLOT 211600")
        );
    }

    #[test]
    fn oi_archive_xml_ingests_with_runtime_archive_store() {
        let dir = temp_dir_path("nwws_rs_cli_oi_archive_xml");
        let archive_root = dir.join("archive");
        let dedupe_path = dir.join("state").join("dedupe.txt");
        let message = NwwsOiMessage::parse(include_str!(
            "../../tests/fixtures/nwws_oi_tornado_warning.xml"
        ))
        .unwrap();
        let xml = oi_message_to_archive_xml(&message).unwrap();
        let reparsed = NwwsOiMessage::parse(&xml).unwrap();

        assert_eq!(
            reparsed.payload.as_ref().unwrap().raw_bulletin,
            message.payload.as_ref().unwrap().raw_bulletin
        );

        let router = MessageRouter::new(Some(RuntimeArchiveStore::new(&archive_root)));
        let dedupe = DedupeStore::open(&dedupe_path).unwrap();
        let mut service = IngestService::new(router, dedupe);
        let report = service
            .process_bytes(IngestHint::OpenInterface, xml.as_bytes())
            .unwrap();

        assert_eq!(report.records.len(), 1);
        assert_eq!(
            report.records[0].metadata.source,
            RecordSource::OpenInterface
        );
        assert_eq!(
            report.records[0].metadata.wrapper_id.as_deref(),
            Some("41001.17")
        );
        assert!(report.records[0].raw_path.exists());
        assert!(report.records[0].metadata_path.exists());

        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn detects_pid201_stream_with_multiple_messages() {
        let first =
            frame_with_wmo_separators(include_str!("../../tests/fixtures/wmo_tornado_warning.txt"));
        let second =
            frame_with_wmo_separators(include_str!("../../tests/fixtures/wmo_segmented_svs.txt"));
        let input = format!("junk{first}{second}tail");

        let report = inspect_bytes(input.as_bytes(), IngestHint::SatellitePid201).unwrap();
        assert_eq!(report.input_kind, InputKind::FramedStream);
        assert_eq!(report.transport, TransportDescriptor::satellite_pid201());
        assert_eq!(report.items.len(), 2);
        assert_eq!(report.junk_bytes, 4);
        assert_eq!(report.pending_bytes, 4);
    }

    #[test]
    fn canonical_archive_path_uses_digest() {
        let content = NwwsContent::parse_bulletin(
            include_str!("../../tests/fixtures/wmo_tornado_warning.txt").as_bytes(),
        )
        .unwrap();
        let record = super::ArchiveRecord::from_content(
            std::path::Path::new("fixture.txt"),
            0,
            InputKind::Bulletin,
            TransportDescriptor::plain_wmo_text(),
            None,
            &content,
        );
        let digest = fingerprint_hex(record.bulletin_text.as_bytes());
        let path = canonical_record_relative_path(&record, &digest);

        assert!(path.ends_with(format!("{digest}.txt")));
        assert!(path.to_string_lossy().contains("KLOT"));
        assert!(path.to_string_lossy().contains("WUUS53"));
        assert!(path.to_string_lossy().contains("TORLOT"));
    }

    #[test]
    fn sanitize_component_replaces_path_breakers() {
        assert_eq!(sanitize_component("TOR/LOT"), "TOR_LOT");
    }

    fn temp_dir_path(prefix: &str) -> PathBuf {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        std::env::temp_dir().join(format!("{prefix}_{unique}"))
    }
}
