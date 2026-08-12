import json
import os
from pathlib import Path
import tempfile
import unittest

from lsmf.privileged_helper import AuditEvent
from lsmf.protected_audit import (
    AuditSinkError,
    ProtectedAuditSink,
    ProtectedProductionAuditSink,
    ProductionAuditEvent,
)


class ProtectedAuditSinkTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.root.chmod(0o700)
        self.path = self.root / "helper.jsonl"
        self.sink = ProtectedAuditSink(self.path, expected_uid=os.getuid())
        self.event = AuditEvent(
            "123e4567-e89b-42d3-a456-426614174000",
            "audit",
            "org.lsmf.helper.audit",
            "started",
            "executor starting",
        )

    def tearDown(self) -> None:
        self.temp.cleanup()

    def test_appends_exact_bounded_json_records_with_private_mode(self) -> None:
        self.assertTrue(self.sink(self.event))
        self.assertTrue(self.sink(self.event))
        records = self.path.read_text(encoding="ascii").splitlines()
        self.assertEqual(2, len(records))
        self.assertEqual("started", json.loads(records[0])["outcome"])
        self.assertEqual(0o600, self.path.stat().st_mode & 0o777)

    def test_rejects_unsafe_directory_file_symlink_and_hardlink(self) -> None:
        self.root.chmod(0o755)
        with self.assertRaises(AuditSinkError):
            self.sink(self.event)

        self.root.chmod(0o700)
        target = self.root / "target"
        target.write_text("", encoding="ascii")
        target.chmod(0o600)
        self.path.symlink_to(target)
        with self.assertRaises(AuditSinkError):
            self.sink(self.event)
        self.path.unlink()

        os.link(target, self.path)
        with self.assertRaises(AuditSinkError):
            self.sink(self.event)

    def test_rejects_existing_permissive_file(self) -> None:
        self.path.write_text("", encoding="ascii")
        self.path.chmod(0o644)
        with self.assertRaises(AuditSinkError):
            self.sink(self.event)

    def test_production_sink_records_credential_bound_lifecycle(self) -> None:
        event = ProductionAuditEvent(
            "2026-08-03T12:00:00Z",
            "123e4567-e89b-42d3-a456-426614174000",
            "succeeded",
            1000,
            123,
            "c2",
            "seat0",
            "audit",
            "a" * 64,
            "org.lsmf.helper.audit",
            "authorized",
            "succeeded",
            0,
            None,
            None,
        )
        sink = ProtectedProductionAuditSink(self.path, expected_uid=os.getuid())
        self.assertTrue(sink(event))
        record = json.loads(self.path.read_text(encoding="ascii"))
        self.assertEqual(1000, record["uid"])
        self.assertEqual("c2", record["session_id"])
        self.assertEqual("authorized", record["authorization_outcome"])
        self.assertNotIn("environment", record)


if __name__ == "__main__":
    unittest.main()
