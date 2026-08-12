from __future__ import annotations

import json
import os
from pathlib import Path
import tempfile
import unittest

from lsmf.privileged_protocol import Action
from lsmf.production_protocol import ProductionRequest, ProductionStatus
from lsmf.synthetic_executor import CancellationToken
from lsmf.sysctl_manifest import load_sysctl_manifest
from lsmf.sysctl_transaction import (
    RootedManagedFiles,
    SysctlBackupStore,
    SysctlTransactionExecutor,
)


REQUEST_ID = "123e4567-e89b-42d3-a456-426614174000"
SECOND_ID = "123e4567-e89b-42d3-a456-426614174001"
THIRD_ID = "123e4567-e89b-42d3-a456-426614174002"


class MemorySysctls:
    def __init__(self, values):
        self.values = dict(values)
        self.fail_reads = set()
        self.fail_writes = set()
        self.fail_writes_once = set()
        self.after_write = None
        self.writes = []

    def read(self, key):
        if key in self.fail_reads:
            raise OSError("injected read failure")
        return self.values[key]

    def write(self, key, value):
        if key in self.fail_writes_once:
            self.fail_writes_once.remove(key)
            raise OSError("injected one-time write failure")
        if key in self.fail_writes:
            raise OSError("injected write failure")
        self.writes.append((key, value))
        self.values[key] = value
        if self.after_write is not None:
            self.after_write(key, value)


class SysctlTransactionTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        root = Path(self.temporary.name)
        root.chmod(0o700)
        self.target_root = root / "target"
        self.backup_root = root / "backups"
        self.target_root.mkdir(mode=0o700)
        self.backup_root.mkdir(mode=0o700)
        (self.target_root / "etc" / "sysctl.d").mkdir(parents=True)
        self.manifest_path = root / "manifest.json"
        self.value = {
            "version": 2,
            "module_order": ["kernel_hardening", "network_hardening"],
            "single_apply": ["kernel_hardening"],
            "multi_apply": [["kernel_hardening", "network_hardening"]],
            "modules": {
                "kernel_hardening": {
                    "relative_target": "etc/sysctl.d/99-lsmf-kernel.conf",
                    "settings": [
                        {"key": "kernel.kptr_restrict", "value": "2"},
                        {"key": "kernel.dmesg_restrict", "value": "1"},
                    ],
                },
                "network_hardening": {
                    "relative_target": "etc/sysctl.d/99-lsmf-network.conf",
                    "settings": [{"key": "net.ipv4.ip_forward", "value": "0"}],
                },
            },
        }
        self.manifest_path.write_text(json.dumps(self.value), encoding="utf-8")
        self.manifest_path.chmod(0o600)
        self.manifest = load_sysctl_manifest(self.manifest_path, expected_uid=os.getuid())
        self.sysctls = MemorySysctls({
            "kernel.kptr_restrict": "1",
            "kernel.dmesg_restrict": "0",
            "net.ipv4.ip_forward": "1",
        })
        self.files = RootedManagedFiles(self.target_root, expected_uid=os.getuid())
        self.backups = SysctlBackupStore(self.backup_root, expected_uid=os.getuid())
        self.executor = SysctlTransactionExecutor(
            self.manifest, self.files, self.sysctls, self.backups
        )

    def tearDown(self) -> None:
        self.temporary.cleanup()

    @staticmethod
    def request(action, request_id=REQUEST_ID, modules=(), backup_id=None):
        return ProductionRequest(1, request_id, action, tuple(modules), backup_id)

    def test_apply_is_backup_first_idempotent_and_exact_rollback_restores_absence(self) -> None:
        request = self.request(Action.APPLY_MODULE, modules=["kernel_hardening"])
        applied = self.executor.execute(request, CancellationToken())
        self.assertEqual(ProductionStatus.SUCCEEDED, applied.status)
        self.assertEqual(f"backup-{REQUEST_ID}", applied.backup_id)
        target = self.target_root / "etc/sysctl.d/99-lsmf-kernel.conf"
        expected = b"kernel.kptr_restrict = 2\nkernel.dmesg_restrict = 1\n"
        self.assertEqual(expected, target.read_bytes())
        self.assertEqual("2", self.sysctls.values["kernel.kptr_restrict"])

        repeat = self.executor.execute(
            self.request(Action.APPLY_MODULE, SECOND_ID, ["kernel_hardening"]),
            CancellationToken(),
        )
        self.assertEqual(ProductionStatus.SUCCEEDED, repeat.status)
        self.assertEqual(expected, target.read_bytes())

        rolled_back = self.executor.execute(
            self.request(Action.ROLLBACK_BACKUP, THIRD_ID, backup_id=applied.backup_id),
            CancellationToken(),
        )
        self.assertEqual(ProductionStatus.SUCCEEDED, rolled_back.status)
        self.assertFalse(target.exists())
        self.assertEqual("1", self.sysctls.values["kernel.kptr_restrict"])
        self.assertEqual("0", self.sysctls.values["kernel.dmesg_restrict"])

    def test_exact_multi_apply_uses_manifest_order_and_one_snapshot(self) -> None:
        result = self.executor.execute(
            self.request(Action.APPLY_MODULES, modules=["kernel_hardening", "network_hardening"]),
            CancellationToken(),
        )
        self.assertEqual(ProductionStatus.SUCCEEDED, result.status)
        snapshot = self.backups.load(result.backup_id)
        self.assertEqual(("kernel_hardening", "network_hardening"), snapshot.module_ids)
        self.assertEqual(2, len(snapshot.files))
        self.assertEqual("0", self.sysctls.values["net.ipv4.ip_forward"])

    def test_apply_and_restore_skip_immutable_values_that_are_already_exact(self) -> None:
        self.sysctls.values["kernel.kptr_restrict"] = "2"
        self.sysctls.values["kernel.dmesg_restrict"] = "1"
        self.sysctls.fail_writes.update(self.sysctls.values)
        applied = self.executor.execute(
            self.request(Action.APPLY_MODULE, modules=["kernel_hardening"]),
            CancellationToken(),
        )
        self.assertEqual(ProductionStatus.SUCCEEDED, applied.status)
        restored = self.executor.execute(
            self.request(Action.ROLLBACK_BACKUP, SECOND_ID, backup_id=applied.backup_id),
            CancellationToken(),
        )
        self.assertEqual(ProductionStatus.SUCCEEDED, restored.status)
        self.assertEqual([], self.sysctls.writes)

    def test_numeric_whitespace_is_canonicalized_for_apply_and_restore(self) -> None:
        self.value["modules"]["kernel_hardening"]["settings"] = [
            {"key": "kernel.printk", "value": "3 3 3 3"},
        ]
        self.manifest_path.write_text(json.dumps(self.value), encoding="utf-8")
        self.manifest_path.chmod(0o600)
        manifest = load_sysctl_manifest(self.manifest_path, expected_uid=os.getuid())
        sysctls = MemorySysctls({"kernel.printk": "3\t3\t3\t3"})
        sysctls.fail_writes.add("kernel.printk")
        executor = SysctlTransactionExecutor(manifest, self.files, sysctls, self.backups)

        applied = executor.execute(
            self.request(Action.APPLY_MODULE, modules=["kernel_hardening"]),
            CancellationToken(),
        )
        self.assertEqual(ProductionStatus.SUCCEEDED, applied.status)
        restored = executor.execute(
            self.request(Action.ROLLBACK_BACKUP, SECOND_ID, backup_id=applied.backup_id),
            CancellationToken(),
        )
        self.assertEqual(ProductionStatus.SUCCEEDED, restored.status)
        self.assertEqual([], sysctls.writes)

    def test_executor_rechecks_policy_and_rejects_reversed_or_network_only_apply(self) -> None:
        requests = (
            self.request(Action.APPLY_MODULE, modules=["network_hardening"]),
            self.request(
                Action.APPLY_MODULES,
                modules=["network_hardening", "kernel_hardening"],
            ),
        )
        for request in requests:
            with self.subTest(request=request), self.assertRaises(Exception):
                self.executor.execute(request, CancellationToken())
        self.assertEqual("1", self.sysctls.values["kernel.kptr_restrict"])
        self.assertEqual([], list(self.backup_root.iterdir()))

    def test_backup_failure_prevents_all_mutation(self) -> None:
        self.sysctls.fail_reads.add("kernel.kptr_restrict")
        result = self.executor.execute(
            self.request(Action.APPLY_MODULE, modules=["kernel_hardening"]), CancellationToken()
        )
        self.assertEqual("backup_failed", result.error.code)
        self.assertEqual("1", self.sysctls.values["kernel.kptr_restrict"])
        self.assertFalse((self.target_root / "etc/sysctl.d/99-lsmf-kernel.conf").exists())
        self.assertFalse(self.backups.eligible(f"backup-{REQUEST_ID}"))

    def test_apply_failure_restores_exact_state(self) -> None:
        self.sysctls.fail_writes_once.add("kernel.dmesg_restrict")
        result = self.executor.execute(
            self.request(Action.APPLY_MODULE, modules=["kernel_hardening"]), CancellationToken()
        )
        self.assertEqual("apply_failed", result.error.code)
        self.assertEqual("1", self.sysctls.values["kernel.kptr_restrict"])
        self.assertEqual("0", self.sysctls.values["kernel.dmesg_restrict"])
        self.assertFalse((self.target_root / "etc/sysctl.d/99-lsmf-kernel.conf").exists())
        self.assertIsNone(self.backups.recovery_backup_id())

    def test_post_backup_cancellation_restores_and_is_truthful(self) -> None:
        token = CancellationToken()
        self.sysctls.after_write = lambda _key, _value: token.cancel()
        result = self.executor.execute(
            self.request(Action.APPLY_MODULE, modules=["kernel_hardening"]), token
        )
        self.assertEqual(ProductionStatus.CANCELLED, result.status)
        self.assertEqual("cancelled", result.error.code)
        self.assertEqual("1", self.sysctls.values["kernel.kptr_restrict"])
        self.assertFalse((self.target_root / "etc/sysctl.d/99-lsmf-kernel.conf").exists())

    def test_recovery_marker_blocks_apply_and_only_exact_rollback_clears_it(self) -> None:
        applied = self.executor.execute(
            self.request(Action.APPLY_MODULE, modules=["kernel_hardening"]), CancellationToken()
        )
        self.backups.mark_recovery_required(applied.backup_id)
        blocked = self.executor.execute(
            self.request(Action.APPLY_MODULE, SECOND_ID, ["kernel_hardening"]), CancellationToken()
        )
        self.assertEqual("recovery_required", blocked.error.code)
        wrong = self.executor.execute(
            self.request(Action.ROLLBACK_BACKUP, SECOND_ID, backup_id=f"backup-{SECOND_ID}"),
            CancellationToken(),
        )
        self.assertEqual("recovery_required", wrong.error.code)
        restored = self.executor.execute(
            self.request(Action.ROLLBACK_BACKUP, THIRD_ID, backup_id=applied.backup_id),
            CancellationToken(),
        )
        self.assertEqual(ProductionStatus.SUCCEEDED, restored.status)
        self.assertIsNone(self.backups.recovery_backup_id())

    def test_tampered_backup_is_ineligible_and_rollback_fails_closed(self) -> None:
        applied = self.executor.execute(
            self.request(Action.APPLY_MODULE, modules=["kernel_hardening"]), CancellationToken()
        )
        path = self.backup_root / applied.backup_id / "snapshot.json"
        path.write_text(path.read_text().replace("kernel.kptr_restrict", "kernel.sysrq"))
        self.assertFalse(self.backups.eligible(applied.backup_id))
        before = dict(self.sysctls.values)
        result = self.executor.execute(
            self.request(Action.ROLLBACK_BACKUP, SECOND_ID, backup_id=applied.backup_id),
            CancellationToken(),
        )
        self.assertEqual("rollback_failed", result.error.code)
        self.assertEqual(before, self.sysctls.values)


if __name__ == "__main__":
    unittest.main()
