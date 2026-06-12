use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

use serde_json::Value;

fn bin_path() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_nwws"))
}

fn manifest_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn fixture_path(name: &str) -> PathBuf {
    manifest_dir().join("tests").join("fixtures").join(name)
}

fn temp_dir_path(prefix: &str) -> PathBuf {
    let unique = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    std::env::temp_dir().join(format!("{prefix}_{unique}"))
}

fn frame_with_wmo_separators(bulletin: &str) -> String {
    let bulletin = bulletin.lines().collect::<Vec<_>>().join("\r\r\n");
    format!("\u{1}\r\r\n{bulletin}\r\r\n\u{3}")
}

fn read_to_string(path: &Path) -> String {
    fs::read_to_string(path).unwrap()
}

#[test]
fn help_mentions_pid201_and_archive_commands() {
    let output = Command::new(bin_path()).arg("--help").output().unwrap();
    assert!(output.status.success());

    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(stdout.contains("pid201 split"));
    assert!(stdout.contains("active-at"));
    assert!(stdout.contains("archive import"));
    assert!(stdout.contains("archive verify"));
    assert!(stdout.contains("--format <text|json|jsonl|tool-result>"));
}

#[test]
fn inspect_json_emits_structured_warning_contract() {
    let output = Command::new(bin_path())
        .args(["inspect"])
        .arg(fixture_path("wmo_tornado_warning.txt"))
        .args(["--format", "json"])
        .output()
        .unwrap();

    assert!(output.status.success(), "{:?}", output);
    let payload: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(payload["input_kind"], "bulletin");
    assert_eq!(payload["messages"].as_array().unwrap().len(), 1);

    let message = &payload["messages"][0];
    assert_eq!(message["heading"], "WUUS53 KLOT 211600");
    assert_eq!(message["office"], "KLOT");
    assert_eq!(message["awips_id"], "TORLOT");
    assert_eq!(message["family"], "tornado");
    assert_eq!(message["raw_bulletin_blake3"].as_str().unwrap().len(), 64);
    assert_eq!(message["archive_id"].as_str().unwrap().len(), 16);

    let segment = &message["segments"][0];
    assert!(segment["ugc_raw"].as_str().unwrap().starts_with("ILC031"));
    assert!(
        segment["pvtec"][0]
            .as_str()
            .unwrap()
            .contains("KLOT.TO.W.0001")
    );
    assert!(segment["lat_lon"].as_array().unwrap().len() > 1);
    assert_eq!(segment["time_mot_loc"]["direction_degrees"], 265);
}

#[test]
fn replay_jsonl_emits_message_records() {
    let temp = temp_dir_path("nwws_rs_cli_replay_jsonl");
    fs::create_dir_all(&temp).unwrap();
    fs::copy(
        fixture_path("wmo_tornado_warning.txt"),
        temp.join("warning.txt"),
    )
    .unwrap();
    fs::copy(fixture_path("wmo_segmented_svs.txt"), temp.join("svs.txt")).unwrap();

    let output = Command::new(bin_path())
        .args(["replay"])
        .arg(&temp)
        .args(["--format", "jsonl"])
        .output()
        .unwrap();

    assert!(output.status.success(), "{:?}", output);
    let stdout = String::from_utf8(output.stdout).unwrap();
    let records = stdout
        .lines()
        .map(|line| serde_json::from_str::<Value>(line).unwrap())
        .collect::<Vec<_>>();
    assert_eq!(records.len(), 2);
    for record in records {
        assert_eq!(record["schema"], "nwws.message.v1");
        assert_eq!(record["record_type"], "message");
        assert!(record["path"].as_str().unwrap().ends_with(".txt"));
        assert_eq!(
            record["message"]["raw_bulletin_blake3"]
                .as_str()
                .unwrap()
                .len(),
            64
        );
    }

    fs::remove_dir_all(temp).unwrap();
}

#[test]
fn pid201_split_writes_canonical_bulletin_files() {
    let temp = temp_dir_path("nwws_rs_cli_pid201_split");
    let output_dir = temp.join("split");
    fs::create_dir_all(&temp).unwrap();

    let first = read_to_string(&fixture_path("wmo_tornado_warning.txt"));
    let second = read_to_string(&fixture_path("wmo_segmented_svs.txt"));
    let capture_path = temp.join("capture.pid201");
    fs::write(
        &capture_path,
        format!(
            "{}{}",
            frame_with_wmo_separators(&first),
            frame_with_wmo_separators(&second)
        ),
    )
    .unwrap();

    let output = Command::new(bin_path())
        .args(["pid201", "split"])
        .arg(&capture_path)
        .arg(&output_dir)
        .output()
        .unwrap();

    assert!(output.status.success(), "{:?}", output);
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(stdout.contains("written-files: 2"));

    let mut files = fs::read_dir(&output_dir)
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .collect::<Vec<_>>();
    files.sort();

    assert_eq!(files.len(), 2);
    assert!(read_to_string(&files[0]).contains("WUUS53 KLOT 211600"));
    assert!(read_to_string(&files[1]).contains("WWUS73 KLOT 211620"));

    fs::remove_dir_all(temp).unwrap();
}

#[test]
fn archive_import_and_verify_deduplicate_mixed_inputs() {
    let temp = temp_dir_path("nwws_rs_cli_archive");
    let input_dir = temp.join("input");
    let archive_dir = temp.join("archive");
    fs::create_dir_all(&input_dir).unwrap();

    fs::copy(
        fixture_path("wmo_tornado_warning.txt"),
        input_dir.join("warning.txt"),
    )
    .unwrap();
    fs::copy(
        fixture_path("nwws_oi_tornado_warning.xml"),
        input_dir.join("warning.xml"),
    )
    .unwrap();

    let segmented = read_to_string(&fixture_path("wmo_segmented_svs.txt"));
    fs::write(
        input_dir.join("capture.pid201"),
        frame_with_wmo_separators(&segmented),
    )
    .unwrap();

    let import = Command::new(bin_path())
        .args(["archive", "import"])
        .arg(&input_dir)
        .arg(&archive_dir)
        .output()
        .unwrap();

    assert!(import.status.success(), "{:?}", import);
    let import_stdout = String::from_utf8(import.stdout).unwrap();
    assert!(import_stdout.contains("archived-records: 2"));
    assert!(import_stdout.contains("duplicate-records: 1"));
    assert!(archive_dir.join("records.tsv").exists());

    let record_root = archive_dir.join("records");
    let mut record_files = Vec::new();
    collect_record_files(&record_root, &mut record_files);
    assert_eq!(record_files.len(), 2);

    let verify = Command::new(bin_path())
        .args(["archive", "verify"])
        .arg(&archive_dir)
        .output()
        .unwrap();

    assert!(verify.status.success(), "{:?}", verify);
    let verify_stdout = String::from_utf8(verify.stdout).unwrap();
    assert!(verify_stdout.contains("verified-records: 2"));
    assert!(verify_stdout.contains("failures: 0"));

    fs::remove_dir_all(temp).unwrap();
}

#[test]
fn archive_verify_tool_result_wraps_machine_report() {
    let temp = temp_dir_path("nwws_rs_cli_archive_tool_result");
    let archive_dir = temp.join("archive");
    fs::create_dir_all(&temp).unwrap();

    let import = Command::new(bin_path())
        .args(["archive", "import"])
        .arg(fixture_path("wmo_tornado_warning.txt"))
        .arg(&archive_dir)
        .args(["--format", "json"])
        .output()
        .unwrap();

    assert!(import.status.success(), "{:?}", import);
    let import_payload: Value = serde_json::from_slice(&import.stdout).unwrap();
    assert_eq!(import_payload["archived_records"], 1);
    assert_eq!(
        import_payload["records"][0]["heading"],
        "WUUS53 KLOT 211600"
    );

    let verify = Command::new(bin_path())
        .args(["archive", "verify"])
        .arg(&archive_dir)
        .args(["--format", "tool-result"])
        .output()
        .unwrap();

    assert!(verify.status.success(), "{:?}", verify);
    let payload: Value = serde_json::from_slice(&verify.stdout).unwrap();
    let top_level_keys = payload
        .as_object()
        .unwrap()
        .keys()
        .map(String::as_str)
        .collect::<Vec<_>>();
    assert_eq!(
        top_level_keys,
        vec![
            "artifacts",
            "data",
            "evidence",
            "inputs",
            "limitations",
            "ok",
            "provenance",
            "schema_version",
            "tool_name",
        ]
    );
    assert_eq!(payload["schema_version"], "wx.tool_result.v1");
    assert_eq!(payload["tool_name"], "warning.archive_verify");
    assert_eq!(payload["ok"], true);
    assert_eq!(
        payload["inputs"]["archive_dir"].as_str().unwrap(),
        archive_dir.display().to_string()
    );
    assert_eq!(payload["data"]["verified_records"], 1);
    assert_eq!(payload["data"]["records"][0]["status"], "ok");
    assert_eq!(payload["artifacts"][0]["artifact_id"], "archive-verify");
    assert_eq!(payload["artifacts"][0]["kind"], "json");
    assert_eq!(payload["evidence"][0]["evidence_type"], "records");
    assert!(
        payload["evidence"][0]["summary"]
            .as_str()
            .unwrap()
            .contains("1")
    );
    assert_eq!(
        payload["provenance"]["archive_dir"].as_str().unwrap(),
        archive_dir.display().to_string()
    );

    fs::remove_dir_all(temp).unwrap();
}

#[test]
fn active_at_tool_result_returns_archive_warning_state() {
    let temp = temp_dir_path("nwws_rs_cli_active_at_tool_result");
    let input_dir = temp.join("input");
    let archive_dir = temp.join("archive");
    fs::create_dir_all(&input_dir).unwrap();
    fs::copy(
        fixture_path("wmo_tornado_warning.txt"),
        input_dir.join("warning.txt"),
    )
    .unwrap();
    fs::copy(
        fixture_path("wmo_segmented_svs.txt"),
        input_dir.join("svs.txt"),
    )
    .unwrap();

    let import = Command::new(bin_path())
        .args(["archive", "import"])
        .arg(&input_dir)
        .arg(&archive_dir)
        .args(["--format", "json"])
        .output()
        .unwrap();

    assert!(import.status.success(), "{:?}", import);

    let active = Command::new(bin_path())
        .args(["archive", "active-at"])
        .arg(&archive_dir)
        .args(["--at", "2026-04-21T16:25:00Z"])
        .args(["--format", "tool-result"])
        .output()
        .unwrap();

    assert!(active.status.success(), "{:?}", active);
    let payload: Value = serde_json::from_slice(&active.stdout).unwrap();
    assert_eq!(payload["schema_version"], "wx.tool_result.v1");
    assert_eq!(payload["tool_name"], "warning.active_at_reference");
    assert_eq!(payload["ok"], true);
    assert_eq!(payload["inputs"]["reference_utc"], "2026-04-21T16:25:00Z");
    assert_eq!(payload["data"]["active_records"], 2);

    let records = payload["data"]["records"].as_array().unwrap();
    let tornado = records
        .iter()
        .find(|record| record["event_family"] == "tornado")
        .unwrap();
    assert_eq!(tornado["action"], "CON");
    assert_eq!(tornado["product_family"], "statement");
    assert!(tornado["key"].as_str().unwrap().contains("TO.W.0001"));
    assert_eq!(
        payload["evidence"][0]["evidence_type"],
        "active_warning_records"
    );

    fs::remove_dir_all(temp).unwrap();
}

#[test]
fn timeline_json_returns_warning_lifecycle_records() {
    let temp = temp_dir_path("nwws_rs_cli_timeline_json");
    fs::create_dir_all(&temp).unwrap();
    fs::copy(
        fixture_path("wmo_tornado_warning.txt"),
        temp.join("warning.txt"),
    )
    .unwrap();
    fs::copy(fixture_path("wmo_segmented_svs.txt"), temp.join("svs.txt")).unwrap();

    let output = Command::new(bin_path())
        .args(["timeline"])
        .arg(&temp)
        .args(["--at", "2026-04-21T16:25:00Z"])
        .args(["--format", "json"])
        .output()
        .unwrap();

    assert!(output.status.success(), "{:?}", output);
    let payload: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(payload["query_time_utc"], "2026-04-21T16:25:00Z");
    assert_eq!(payload["warning_records"], 3);
    assert_eq!(payload["failures"], 0);

    let records = payload["records"].as_array().unwrap();
    assert!(
        records
            .iter()
            .any(|record| record["lifecycle_status"] == "active")
    );
    assert!(
        records
            .iter()
            .any(|record| record["event_id"].as_str().unwrap().contains("TO.W.0001"))
    );

    fs::remove_dir_all(temp).unwrap();
}

#[test]
fn lead_time_tool_result_returns_point_event_metrics() {
    let temp = temp_dir_path("nwws_rs_cli_lead_time_tool_result");
    fs::create_dir_all(&temp).unwrap();
    fs::copy(
        fixture_path("wmo_tornado_warning.txt"),
        temp.join("warning.txt"),
    )
    .unwrap();
    fs::copy(fixture_path("wmo_segmented_svs.txt"), temp.join("svs.txt")).unwrap();

    let output = Command::new(bin_path())
        .args(["lead-time"])
        .arg(&temp)
        .args(["--event-at", "2026-04-21T16:20:00Z"])
        .args(["--lat", "42.05"])
        .args(["--lon", "-88.2"])
        .args(["--format", "tool-result"])
        .output()
        .unwrap();

    assert!(output.status.success(), "{:?}", output);
    let payload: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(payload["schema_version"], "wx.tool_result.v1");
    assert_eq!(payload["tool_name"], "warning.lead_time_event_metrics");
    assert_eq!(payload["ok"], true);
    assert_eq!(payload["data"]["metrics"]["missed_event"], false);
    assert_eq!(payload["data"]["metrics"]["lead_time_seconds"], 1200);
    assert!(
        payload["data"]["metrics"]["first_valid_warning_event_id"]
            .as_str()
            .unwrap()
            .contains("TO.W.0001")
    );
    assert_eq!(
        payload["evidence"][1]["evidence_type"],
        "warning_lead_time_metrics"
    );

    fs::remove_dir_all(temp).unwrap();
}

fn collect_record_files(root: &Path, files: &mut Vec<PathBuf>) {
    for entry in fs::read_dir(root).unwrap() {
        let entry = entry.unwrap();
        let path = entry.path();
        if entry.file_type().unwrap().is_dir() {
            collect_record_files(&path, files);
        } else {
            files.push(path);
        }
    }
}
