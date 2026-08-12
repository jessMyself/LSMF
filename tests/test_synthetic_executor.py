from __future__ import annotations

from datetime import datetime, timezone
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from lsmf.production_protocol import ProductionRequest, ProductionStatus
from lsmf.privileged_protocol import Action
from lsmf.synthetic_executor import (
    CancellationToken,
    FileSnapshot,
    SyntheticBackupStore,
    SyntheticExecutor,
    SyntheticExecutorError,
    TrustedTree,
)
from lsmf.trusted_manifest import SyntheticModule, TrustedManifest


REQUEST_ID = "123e4567-e89b-42d3-a456-426614174000"
SECOND_ID = "123e4567-e89b-42d3-a456-426614174001"


class SyntheticExecutorTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.targets = self.root / "targets"
        self.backups = self.root / "backups"
        self.targets.mkdir(mode=0o700)
        self.backups.mkdir(mode=0o700)
        (self.targets / "nested").mkdir(mode=0o700)
        self.target = self.targets / "nested" / "toggle.conf"
        self.target.write_text("off\n", encoding="utf-8")
        self.target.chmod(0o600)
        self.manifest = TrustedManifest(1, {
            "synthetic_toggle": SyntheticModule(
                "synthetic_toggle", "nested/toggle.conf", "on\n", frozenset({"verify", "apply"})
            ),
            "synthetic_new": SyntheticModule(
                "synthetic_new", "nested/new.conf", "created\n", frozenset({"verify", "apply"})
            ),
        })
        self.executor = SyntheticExecutor(
            self.manifest,
            self.targets,
            self.backups,
            expected_uid=os.getuid(),
            clock=lambda: datetime(2026, 8, 3, 12, 0, tzinfo=timezone.utc),
        )

    def tearDown(self) -> None:
        self.temp.cleanup()

    def request(self, action: Action, *, request_id: str = REQUEST_ID, modules=(), backup_id=None):
        return ProductionRequest(1, request_id, action, tuple(modules), backup_id)

    def test_audit_and_verify_are_read_only_and_truthful(self) -> None:
        before = self.target.read_bytes()
        audit = self.executor.execute(self.request(Action.AUDIT))
        verify = self.executor.execute(self.request(Action.VERIFY_MODULE, modules=("synthetic_toggle",)))
        self.assertEqual(ProductionStatus.SUCCEEDED, audit.status)
        self.assertEqual(2, audit.finding_count)
        self.assertEqual(ProductionStatus.FAILED, verify.status)
        self.assertEqual(before, self.target.read_bytes())
        self.assertEqual([], list(self.backups.iterdir()))

    def test_apply_is_backup_first_bounded_and_idempotent(self) -> None:
        request = self.request(Action.APPLY_MODULES, modules=("synthetic_toggle", "synthetic_new"))
        result = self.executor.execute(request)
        self.assertEqual(ProductionStatus.SUCCEEDED, result.status)
        self.assertEqual("on\n", self.target.read_text())
        self.assertEqual("created\n", (self.targets / "nested" / "new.conf").read_text())
        self.assertTrue(self.executor.backups.eligible(result.backup_id))
        snapshots = self.executor.backups.load(result.backup_id)
        self.assertEqual((True, False), tuple(item.present for item in snapshots))

        repeat = self.executor.execute(self.request(Action.APPLY_MODULE, request_id=SECOND_ID, modules=("synthetic_toggle",)))
        self.assertEqual(ProductionStatus.SUCCEEDED, repeat.status)
        self.assertEqual("on\n", self.target.read_text())

    def test_exact_rollback_restores_content_mode_and_absence(self) -> None:
        apply = self.executor.execute(self.request(Action.APPLY_MODULES, modules=("synthetic_toggle", "synthetic_new")))
        self.target.chmod(0o400)
        rollback = self.executor.execute(self.request(Action.ROLLBACK_BACKUP, request_id=SECOND_ID, backup_id=apply.backup_id))
        self.assertEqual(ProductionStatus.SUCCEEDED, rollback.status)
        self.assertEqual("off\n", self.target.read_text())
        self.assertEqual(0o600, self.target.stat().st_mode & 0o777)
        self.assertFalse((self.targets / "nested" / "new.conf").exists())
        self.assertTrue((self.backups / f"recovery-{SECOND_ID}" / "manifest.json").is_file())

    def test_unknown_module_and_corrupt_backup_fail_without_mutation(self) -> None:
        unknown = self.executor.execute(self.request(Action.VERIFY_MODULE, modules=("not_manifested",)))
        self.assertEqual(ProductionStatus.FAILED, unknown.status)
        self.assertEqual("off\n", self.target.read_text())

        backup_id = f"backup-{REQUEST_ID}"
        directory = self.backups / backup_id
        directory.mkdir(mode=0o700)
        (directory / "manifest.json").write_text("{}", encoding="ascii")
        (directory / "manifest.json").chmod(0o600)
        rollback = self.executor.execute(self.request(Action.ROLLBACK_BACKUP, backup_id=backup_id))
        self.assertEqual(ProductionStatus.FAILED, rollback.status)
        self.assertEqual((), rollback.module_ids)
        self.assertEqual("off\n", self.target.read_text())

    def test_symlinks_hardlinks_and_permissive_parents_fail_closed(self) -> None:
        symlink = self.targets / "nested" / "link.conf"
        symlink.symlink_to(self.target)
        with TrustedTree(self.targets, expected_uid=os.getuid()) as tree:
            with self.assertRaises(SyntheticExecutorError):
                tree.snapshot("nested/link.conf")

        hardlink = self.targets / "nested" / "hard.conf"
        os.link(self.target, hardlink)
        with TrustedTree(self.targets, expected_uid=os.getuid()) as tree:
            with self.assertRaises(SyntheticExecutorError):
                tree.snapshot("nested/hard.conf")
        hardlink.unlink()
        (self.targets / "nested").chmod(0o777)
        result = self.executor.execute(self.request(Action.APPLY_MODULE, modules=("synthetic_toggle",)))
        self.assertEqual(ProductionStatus.FAILED, result.status)
        self.assertEqual("off\n", self.target.read_text())

    def test_failed_apply_restores_backup_before_returning_failure(self) -> None:
        original_replace = TrustedTree.replace
        calls = 0

        def fail_second(tree, snapshot):
            nonlocal calls
            calls += 1
            if calls == 2:
                raise SyntheticExecutorError("injected failure")
            return original_replace(tree, snapshot)

        request = self.request(Action.APPLY_MODULES, modules=("synthetic_toggle", "synthetic_new"))
        with mock.patch.object(TrustedTree, "replace", fail_second):
            result = self.executor.execute(request)
        self.assertEqual(ProductionStatus.FAILED, result.status)
        self.assertEqual(f"backup-{REQUEST_ID}", result.backup_id)
        self.assertEqual("off\n", self.target.read_text())
        self.assertFalse((self.targets / "nested" / "new.conf").exists())
        self.assertFalse(self.executor.backups.recovery_required())

    def test_unverified_recovery_sets_durable_lockout(self) -> None:
        request = self.request(Action.APPLY_MODULE, modules=("synthetic_toggle",))
        with mock.patch.object(TrustedTree, "replace", side_effect=SyntheticExecutorError("always fails")):
            result = self.executor.execute(request)
        self.assertEqual("recovery_required", result.error.code)
        self.assertEqual(f"backup-{REQUEST_ID}", result.backup_id)
        self.assertTrue(self.executor.backups.recovery_required())
        blocked = self.executor.execute(self.request(Action.APPLY_MODULE, request_id=SECOND_ID, modules=("synthetic_toggle",)))
        self.assertEqual("recovery_required", blocked.error.code)

    def test_exact_marked_rollback_restores_and_durably_clears_lockout(self) -> None:
        applied = self.executor.execute(
            self.request(Action.APPLY_MODULE, modules=("synthetic_toggle",))
        )
        self.executor.backups.mark_recovery_required(applied.backup_id)
        wrong = self.executor.execute(
            self.request(
                Action.ROLLBACK_BACKUP,
                request_id=SECOND_ID,
                backup_id=f"recovery-{SECOND_ID}",
            )
        )
        self.assertEqual("recovery_required", wrong.error.code)
        self.assertEqual(applied.backup_id, wrong.backup_id)
        self.assertEqual("on\n", self.target.read_text())

        recovered = self.executor.execute(
            self.request(
                Action.ROLLBACK_BACKUP,
                request_id=SECOND_ID,
                backup_id=applied.backup_id,
            )
        )
        self.assertEqual(ProductionStatus.SUCCEEDED, recovered.status)
        self.assertEqual("off\n", self.target.read_text())
        self.assertFalse(self.executor.backups.recovery_required())

    def test_damaged_recovery_markers_fail_closed(self) -> None:
        marker = self.backups / "recovery-required"
        for kind in ("malformed", "permissive", "symlink"):
            with self.subTest(kind=kind):
                if os.path.lexists(marker):
                    marker.unlink()
                if kind == "malformed":
                    marker.write_text("not-a-backup\n", encoding="ascii")
                    marker.chmod(0o600)
                elif kind == "permissive":
                    marker.write_text(f"backup-{REQUEST_ID}\n", encoding="ascii")
                    marker.chmod(0o666)
                else:
                    marker.symlink_to(self.target)
                result = self.executor.execute(
                    self.request(Action.APPLY_MODULE, modules=("synthetic_toggle",))
                )
                self.assertEqual(ProductionStatus.FAILED, result.status)
                self.assertEqual("synthetic_failed", result.error.code)
                self.assertEqual("off\n", self.target.read_text())

    def test_unsafe_audit_target_returns_typed_failure(self) -> None:
        self.target.chmod(0o666)
        result = self.executor.execute(self.request(Action.AUDIT))
        self.assertEqual(ProductionStatus.FAILED, result.status)
        self.assertEqual(0, result.finding_count)
        self.assertEqual("synthetic_failed", result.error.code)

    def test_precancelled_and_pretimed_out_requests_do_not_touch_targets(self) -> None:
        request = self.request(Action.APPLY_MODULE, modules=("synthetic_toggle",))
        for timed_out, expected in (
            (False, ProductionStatus.CANCELLED),
            (True, ProductionStatus.TIMED_OUT),
        ):
            with self.subTest(timed_out=timed_out):
                token = CancellationToken()
                token.cancel(timed_out=timed_out)
                result = self.executor.execute(request, token)
                self.assertEqual(expected, result.status)
                self.assertEqual("off\n", self.target.read_text())
                self.assertEqual([], list(self.backups.iterdir()))


class BackupValidationTests(unittest.TestCase):
    def test_snapshot_and_backup_id_reject_paths(self) -> None:
        with self.assertRaises(SyntheticExecutorError):
            FileSnapshot("../host", True, 0o600, b"x")
        with tempfile.TemporaryDirectory() as temporary:
            Path(temporary).chmod(0o700)
            store = SyntheticBackupStore(temporary, expected_uid=os.getuid())
            for backup_id in ("../backup-x", "backup-not-a-uuid", "anything"):
                with self.subTest(backup_id=backup_id), self.assertRaises(SyntheticExecutorError):
                    store.load(backup_id)


if __name__ == "__main__":
    unittest.main()
