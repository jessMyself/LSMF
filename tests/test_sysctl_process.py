from __future__ import annotations

import asyncio
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock

from lsmf.privileged_protocol import Action
from lsmf.production_protocol import ProductionRequest, ProductionStatus
from lsmf.synthetic_executor import CancellationToken
from lsmf.sysctl_process import SysctlProcessExecutor, SysctlProcessError
from lsmf.sysctl_transaction import (
    ManagedFileSnapshot,
    SysctlBackupStore,
    TransactionSnapshot,
)


REQUEST_ID = "123e4567-e89b-42d3-a456-426614174000"


class SysctlProcessTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        root = Path(self.temporary.name)
        root.chmod(0o700)
        self.targets = root / "targets"
        self.backups = root / "backups"
        self.proc = root / "proc/sys"
        self.targets.mkdir(mode=0o700)
        self.backups.mkdir(mode=0o700)
        (self.targets / "etc/sysctl.d").mkdir(parents=True)
        (self.proc / "kernel").mkdir(parents=True)
        self.value = self.proc / "kernel/kptr_restrict"
        self.value.write_text("1\n", encoding="ascii")
        self.manifest = root / "manifest.json"
        self.manifest.write_text(json.dumps({
            "version": 2,
            "module_order": ["kernel_hardening"],
            "single_apply": ["kernel_hardening"],
            "multi_apply": [["kernel_hardening", "kernel_extra"]],
            "modules": {
                "kernel_hardening": {
                    "relative_target": "etc/sysctl.d/99-lsmf-kernel.conf",
                    "settings": [{"key": "kernel.kptr_restrict", "value": "2"}],
                },
                "kernel_extra": {
                    "relative_target": "etc/sysctl.d/99-lsmf-extra.conf",
                    "settings": [{"key": "kernel.dmesg_restrict", "value": "1"}],
                },
            },
        }), encoding="utf-8")
        # Keep module_order exact while using only the single action in this test.
        value = json.loads(self.manifest.read_text())
        value["module_order"] = ["kernel_hardening", "kernel_extra"]
        self.manifest.write_text(json.dumps(value), encoding="utf-8")
        self.manifest.chmod(0o600)
        self.executable = Path(sys.executable).resolve()

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def executor(self, **options):
        return SysctlProcessExecutor(
            manifest_path=self.manifest,
            target_root=self.targets,
            sysctl_root=self.proc,
            backup_root=self.backups,
            expected_uid=os.getuid(),
            expected_executable_uid=self.executable.stat().st_uid,
            executable=self.executable,
            **options,
        )

    async def test_real_fixed_worker_applies_and_returns_eligible_backup(self) -> None:
        result = await self.executor().execute(
            ProductionRequest(1, REQUEST_ID, Action.APPLY_MODULE, ("kernel_hardening",)),
            CancellationToken(),
        )
        self.assertEqual(ProductionStatus.SUCCEEDED, result.status)
        self.assertEqual("2\n", self.value.read_text())
        self.assertTrue(self.executor().backup_eligible(result.backup_id))

    def test_worker_argv_is_fixed_and_contains_no_request_parameters(self) -> None:
        executor = self.executor(process_factory=mock.AsyncMock())
        argv = executor._worker_arguments()
        self.assertEqual(("-m", "lsmf.sysctl_worker"), argv[1:3])
        self.assertNotIn("kernel_hardening", argv)
        self.assertNotIn(REQUEST_ID, argv)
        self.assertEqual(str(self.proc), argv[argv.index("--sysctl-root") + 1])

    def test_backup_from_other_manifest_is_ineligible_before_dispatch(self) -> None:
        wrong_id = f"backup-{REQUEST_ID}"
        SysctlBackupStore(self.backups, expected_uid=os.getuid()).create(
            TransactionSnapshot(
                wrong_id,
                "0" * 64,
                ("kernel_hardening",),
                (ManagedFileSnapshot(
                    "etc/sysctl.d/99-lsmf-kernel.conf", False, 0o600, os.getuid(), 0, b""
                ),),
                (("kernel.kptr_restrict", "1"),),
            )
        )
        self.assertFalse(self.executor().backup_eligible(wrong_id))

    def test_rejects_relative_sysctl_root(self) -> None:
        with self.assertRaises(SysctlProcessError):
            SysctlProcessExecutor(
                manifest_path=self.manifest,
                target_root=self.targets,
                sysctl_root=Path("proc/sys"),
                backup_root=self.backups,
                expected_uid=os.getuid(),
                expected_executable_uid=self.executable.stat().st_uid,
                executable=self.executable,
            )

    async def test_forced_mutation_stop_marks_exact_durable_recovery_backup(self) -> None:
        class HangingProcess:
            stdin = mock.Mock()
            stdout = mock.Mock()

            def __init__(self):
                self.stdin.drain = mock.AsyncMock()
                async def read(_size): await asyncio.Event().wait()
                self.stdout.read = mock.AsyncMock(side_effect=read)
                self.exited = asyncio.Event()
                self.killed = False

            async def wait(self):
                await self.exited.wait()
                return -9

            def terminate(self): pass
            def send_signal(self, _signal): pass
            def kill(self):
                self.killed = True
                self.exited.set()

        backup_id = f"backup-{REQUEST_ID}"
        from lsmf.sysctl_manifest import load_sysctl_manifest
        manifest = load_sysctl_manifest(self.manifest, expected_uid=os.getuid())
        SysctlBackupStore(self.backups, expected_uid=os.getuid()).create(
            TransactionSnapshot(
                backup_id,
                manifest.digest,
                ("kernel_hardening",),
                (ManagedFileSnapshot(
                    "etc/sysctl.d/99-lsmf-kernel.conf", False, 0o600, os.getuid(), 0, b""
                ),),
                (("kernel.kptr_restrict", "1"),),
            )
        )
        process = HangingProcess()
        token = CancellationToken()
        executor = self.executor(
            process_factory=mock.AsyncMock(return_value=process),
            cancellation_grace=0.01,
            poll_interval=0.001,
        )
        task = asyncio.create_task(executor.execute(
            ProductionRequest(1, REQUEST_ID, Action.APPLY_MODULE, ("kernel_hardening",)),
            token,
        ))
        await asyncio.sleep(0.01)
        token.cancel()
        with self.assertRaises(Exception):
            await asyncio.wait_for(task, timeout=1)
        self.assertTrue(process.killed)
        self.assertEqual(
            backup_id,
            SysctlBackupStore(self.backups, expected_uid=os.getuid()).recovery_backup_id(),
        )


if __name__ == "__main__":
    unittest.main()
