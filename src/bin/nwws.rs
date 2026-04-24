use std::collections::BTreeMap;
use std::env;
use std::ffi::OsString;
use std::fs::{self, OpenOptions};
use std::io::{ErrorKind as IoErrorKind, Write};
use std::ops::Range;
use std::path::{Path, PathBuf};

use nwws_rs::{
    FramedStreamIngest, IngestHint, NwwsContent, NwwsOiClient, NwwsOiMessage, OiClientConfig,
    ParsedInput, ProductFamily, TransportDescriptor, TransportKind, collect_input_paths,
    infer_hint_from_path, parse_with_hint,
};
use serde::Serialize;
use serde_json::json;
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
  cargo run --bin nwws -- summary <file-or-directory> [--hint <auto|oi|pid201|bulletin|stream>]
  cargo run --bin nwws -- oi connect <username> <password> [--count <n>] [--history <n>]
  cargo run --bin nwws -- pid201 inspect <capture-file> [--format <text|json|jsonl|tool-result>]
  cargo run --bin nwws -- pid201 split <capture-file> <output-dir>
  cargo run --bin nwws -- pid201 archive <capture-file> <archive-dir> [--format <text|json|jsonl|tool-result>]
  cargo run --bin nwws -- archive import <input-path> <archive-dir> [--hint <auto|oi|pid201|bulletin|stream>] [--format <text|json|jsonl|tool-result>]
  cargo run --bin nwws -- archive verify <archive-dir> [--format <text|json|jsonl|tool-result>]

commands:
  inspect          parse one file and print detailed NWWS metadata
  replay           walk a directory and print one line per parsed file
  summary          aggregate detected source, transport, and family counts
  oi connect       open a blocking NWWS-OI XMPP session and print parsed messages
  pid201 inspect   force a file through the PID201 framed-stream path
  pid201 split     split a PID201 capture into canonical bulletin files
  pid201 archive   archive a PID201 capture into a deduplicated record store
  archive import   ingest mixed NWWS inputs into a deduplicated record store
  archive verify   re-parse archived records and validate the stored digests

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

fn print_tool_result<T: Serialize>(
    operation: &str,
    status: &str,
    data: &T,
    provenance: serde_json::Value,
) -> Result<(), CliError> {
    let data = serde_json::to_value(data)
        .map_err(|err| CliError::failure(format!("failed to serialize tool result data: {err}")))?;
    let envelope = json!({
        "schema": "wx.tool_result.v1",
        "tool": "nwws-rs",
        "operation": operation,
        "status": status,
        "artifacts": [
            {
                "id": operation,
                "kind": "json",
                "media_type": "application/json",
                "description": "Native nwws-rs parser/API output for the requested command"
            }
        ],
        "evidence": tool_evidence(&data),
        "limitations": [
            "Output reflects parser results for the supplied local input only.",
            "No external NWS source-of-truth or network delivery validation is performed."
        ],
        "provenance": provenance,
        "data": data
    });
    print_json(&envelope)
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

fn tool_evidence(data: &serde_json::Value) -> Vec<serde_json::Value> {
    let mut evidence = Vec::new();
    if let Some(messages) = data.get("messages").and_then(|value| value.as_array()) {
        evidence.push(json!({
            "kind": "parsed-messages",
            "count": messages.len()
        }));
    }
    if let Some(files) = data.get("scanned_files").and_then(|value| value.as_u64()) {
        evidence.push(json!({
            "kind": "scanned-files",
            "count": files
        }));
    }
    if let Some(records) = data.get("records").and_then(|value| value.as_array()) {
        evidence.push(json!({
            "kind": "records",
            "count": records.len()
        }));
    }
    if evidence.is_empty() {
        evidence.push(json!({
            "kind": "parser-output",
            "value": "nwws-rs API report"
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

#[cfg(test)]
mod tests {
    use super::{
        InputKind, canonical_record_relative_path, fingerprint_hex, inspect_bytes,
        parse_hint_value, sanitize_component,
    };
    use nwws_rs::{IngestHint, NwwsContent, TransportDescriptor};

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
}
