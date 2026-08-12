#!/usr/bin/env python3

from pathlib import Path
from datetime import datetime
import tempfile
import unittest
from unittest.mock import patch

from desktop.services import LsmfReadService


class LsmfReadServiceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.root = Path(self.temp_dir.name)
        (self.root / "src" / "modules").mkdir(parents=True)
        (self.root / "config").mkdir()
        self.service = LsmfReadService(self.root)

    def tearDown(self) -> None:
        self.temp_dir.cleanup()

    def test_discovers_only_real_module_scripts_and_capabilities(self) -> None:
        (self.root / "src" / "modules" / "ssh_hardening.sh").write_text(
            '\n'.join(
                (
                    'MODULE_NAME="ssh_hardening"',
                    'MODULE_VERSION="2.1.0"',
                    'run_ssh_hardening() { :; }',
                    'verify_ssh_hardening() { :; }',
                    'rollback_ssh_hardening() { :; }',
                )
            ),
            encoding="utf-8",
        )

        modules = self.service.modules()

        self.assertEqual(1, len(modules))
        self.assertEqual("ssh_hardening", modules[0].module_id)
        self.assertEqual("2.1.0", modules[0].version)
        self.assertTrue(modules[0].can_run)
        self.assertTrue(modules[0].can_verify)
        self.assertTrue(modules[0].can_rollback)

    def test_config_parser_does_not_execute_or_treat_sections_as_values(self) -> None:
        marker = self.root / "must-not-exist"
        (self.root / "config" / "lsmf.conf").write_text(
            f'LSMF_VERSION="1.0.0"\nDANGEROUS="$(touch {marker})"\nMODULE_SSH_ENABLED="true"\n',
            encoding="utf-8",
        )

        values = self.service.config_values()

        self.assertEqual("1.0.0", values["LSMF_VERSION"])
        self.assertIn("$(touch", values["DANGEROUS"])
        self.assertEqual("true", values["MODULE_SSH_ENABLED"])
        self.assertFalse(marker.exists())

    def test_invalid_config_is_reported(self) -> None:
        (self.root / "config" / "lsmf.conf").write_text(
            'LSMF_VERSION="1.0.0"\n[filesystem_hardening]\n',
            encoding="utf-8",
        )

        findings = self.service.readiness_findings()

        self.assertTrue(any(item.title == "Invalid configuration" for item in findings))

    def test_recent_files_are_sorted_and_limited(self) -> None:
        reports = self.root / "reports"
        reports.mkdir()
        older = reports / "older.txt"
        newer = reports / "newer.txt"
        older.write_text("old", encoding="utf-8")
        newer.write_text("new", encoding="utf-8")
        older.touch()
        newer.touch()
        older_stat = older.stat()
        newer_stat = newer.stat()
        older_time = min(older_stat.st_mtime, newer_stat.st_mtime) - 10
        newer_time = max(older_stat.st_mtime, newer_stat.st_mtime) + 10
        import os
        os.utime(older, (older_time, older_time))
        os.utime(newer, (newer_time, newer_time))

        result = self.service.recent_reports(limit=1)

        self.assertEqual(["newer.txt"], [item.name for item in result])

    def test_log_view_returns_bounded_tail_and_source(self) -> None:
        log = self.root / "logs" / "run-1" / "lsmf.log"
        log.parent.mkdir(parents=True)
        log.write_text("one\ntwo\nthree\nfour\n", encoding="utf-8")

        result = self.service.log_view(max_lines=2, max_bytes=1024)

        self.assertEqual("available", result.status)
        self.assertEqual(str(log), result.source)
        self.assertEqual("three\nfour", result.content)
        self.assertEqual(2, result.line_count)
        self.assertTrue(result.truncated)
        self.assertIsNone(result.error)

    def test_log_view_is_bounded_by_bytes_and_handles_malformed_utf8(self) -> None:
        log = self.root / "logs" / "run-1" / "lsmf.log"
        log.parent.mkdir(parents=True)
        log.write_bytes(b"discard-this-line\nvalid\nmalformed-\xff\n")

        result = self.service.log_view(max_lines=10, max_bytes=19)

        self.assertEqual("available", result.status)
        self.assertIn("malformed-\ufffd", result.content)
        self.assertNotIn("discard", result.content)
        self.assertTrue(result.truncated)

    def test_log_view_distinguishes_unavailable_and_read_error(self) -> None:
        unavailable = self.service.log_view()
        self.assertEqual("unavailable", unavailable.status)
        self.assertIsNone(unavailable.error)

        log = self.root / "logs" / "run-1" / "lsmf.log"
        log.parent.mkdir(parents=True)
        log.write_text("content", encoding="utf-8")
        with patch.object(Path, "open", side_effect=PermissionError("denied")):
            failed = self.service.log_view()

        self.assertEqual("error", failed.status)
        self.assertEqual(str(log), failed.source)
        self.assertIn("denied", failed.error or "")
        self.assertEqual("", failed.content)

    def test_backup_summary_counts_top_level_backup_sets(self) -> None:
        backups = self.root / "backups"
        (backups / "run-1" / "etc").mkdir(parents=True)
        (backups / "run-2").mkdir()
        (backups / "README.txt").write_text("not a backup set", encoding="utf-8")

        result = self.service.backup_summary()

        self.assertEqual("available", result.status)
        self.assertEqual(2, result.count)
        self.assertEqual((str(backups),), result.sources)
        self.assertIsNone(result.error)

    def test_backup_summary_is_explicit_when_unavailable(self) -> None:
        result = self.service.backup_summary()

        self.assertEqual("unavailable", result.status)
        self.assertEqual(0, result.count)
        self.assertEqual((), result.sources)

    def test_last_run_uses_newest_log_as_evidence_not_success(self) -> None:
        older = self.root / "logs" / "run-1" / "lsmf.log"
        newer = self.root / "logs" / "run-2" / "lsmf.log"
        older.parent.mkdir(parents=True)
        newer.parent.mkdir(parents=True)
        older.write_text("old", encoding="utf-8")
        newer.write_text("new", encoding="utf-8")
        import os
        os.utime(older, (100, 100))
        os.utime(newer, (200, 200))

        result = self.service.last_run_summary()

        self.assertEqual("available", result.status)
        self.assertEqual(str(newer), result.source)
        self.assertEqual(datetime.fromtimestamp(200).isoformat(timespec="seconds"), result.modified)
        self.assertIsNone(result.error)

    def test_system_summary_exposes_user_and_architecture(self) -> None:
        summary = self.service.system_summary()

        self.assertTrue(summary.user)
        self.assertTrue(summary.architecture)


if __name__ == "__main__":
    unittest.main()
