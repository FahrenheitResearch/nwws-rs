from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

import nwws_rs


ROOT = Path(__file__).resolve().parents[1]
FIXTURES = ROOT / "tests" / "fixtures"


def framed(path: Path) -> bytes:
    bulletin = path.read_text(encoding="utf-8").splitlines()
    body = "\r\r\n".join(bulletin)
    return f"\u0001\r\r\n{body}\r\r\n\u0003".encode("utf-8")


class ApiTests(unittest.TestCase):
    def test_parse_bulletin_fixture(self) -> None:
        message = nwws_rs.parse_bulletin((FIXTURES / "wmo_tornado_warning.txt").read_bytes())
        self.assertEqual(message.ttaaii, "WUUS53")
        self.assertEqual(message.cccc, "KLOT")
        self.assertEqual(message.awips_id, "TORLOT")
        self.assertEqual(message.family, "tornado")
        self.assertEqual(len(message.segments), 1)
        self.assertEqual(message.segments[0].tornado_tag, "RADAR INDICATED")
        self.assertIsNotNone(message.segments[0].lat_lon)

    def test_parse_oi_fixture(self) -> None:
        message = nwws_rs.parse_oi((FIXTURES / "nwws_oi_tornado_warning.xml").read_text(encoding="utf-8"))
        self.assertEqual(message.wrapper.id, "41001.17")
        self.assertEqual(message.awips_id, "TORLOT")
        self.assertEqual(message.family, "tornado")

    def test_split_pid201_and_stream(self) -> None:
        first_frame = framed(FIXTURES / "wmo_tornado_warning.txt")
        second_frame = framed(FIXTURES / "wmo_segmented_svs.txt")
        capture = b"junk" + first_frame + second_frame + b"tail"

        report = nwws_rs.split_pid201_bytes(capture)
        self.assertEqual(len(report.records), 2)
        self.assertEqual(report.junk_bytes, 4)
        self.assertEqual(report.pending_bytes, 4)

        stream = nwws_rs.Pid201Stream()
        midpoint = 4 + (len(first_frame) // 2)
        first = stream.push(capture[:midpoint])
        second = stream.push(capture[midpoint:])
        drain = stream.finish()

        self.assertEqual(len(first.records), 0)
        self.assertEqual(len(second.records), 2)
        self.assertEqual(drain.pending_bytes, 0)

    def test_scan_archive_import_and_verify(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            input_dir = root / "input"
            archive_dir = root / "archive"
            split_dir = root / "split"
            capture_path = root / "capture.pid201"
            input_dir.mkdir()

            for name in [
                "wmo_tornado_warning.txt",
                "wmo_segmented_svs.txt",
                "nwws_oi_tornado_warning.xml",
            ]:
                (input_dir / name).write_bytes((FIXTURES / name).read_bytes())
            capture_path.write_bytes(
                b"junk"
                + framed(FIXTURES / "wmo_tornado_warning.txt")
                + framed(FIXTURES / "wmo_segmented_svs.txt")
            )

            scan = nwws_rs.scan_path(input_dir)
            self.assertEqual(scan.scanned_files, 3)
            self.assertEqual(scan.failures, 0)

            split = nwws_rs.write_pid201_split(capture_path, split_dir)
            self.assertEqual(len(split.written), 2)

            import_report = nwws_rs.archive_import(input_dir, archive_dir)
            self.assertGreaterEqual(import_report.archived_records, 2)
            self.assertEqual(import_report.failures, 0)

            verify_report = nwws_rs.archive_verify(archive_dir)
            self.assertGreaterEqual(verify_report.verified_records, 2)
            self.assertEqual(verify_report.failures, 0)


if __name__ == "__main__":
    unittest.main()
