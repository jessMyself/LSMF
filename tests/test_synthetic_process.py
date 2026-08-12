from __future__ import annotations

import asyncio
import json
import os
from pathlib import Path
import signal
import sys
import tempfile
import unittest
from unittest import mock

from lsmf.privileged_protocol import Action
from lsmf.production_protocol import (
    ErrorDetail,
    ProductionRequest,
    ProductionResult,
    ProductionStatus,
    encode_result,
)
from lsmf.synthetic_executor import CancellationToken, FileSnapshot, SyntheticBackupStore
from lsmf.synthetic_process import SyntheticProcessError, SyntheticProcessExecutor


REQUEST_ID = "123e4567-e89b-42d3-a456-426614174000"


class SyntheticProcessTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        root = Path(self.temporary.name)
        self.targets = root / "targets"
        self.backups = root / "backups"
        self.targets.mkdir(mode=0o700)
        self.backups.mkdir(mode=0o700)
        self.target = self.targets / "toggle.conf"
        self.target.write_text("off\n")
        self.target.chmod(0o600)
        self.manifest = root / "manifest.json"
        self.manifest.write_text(json.dumps({
            "version": 1,
            "modules": {
                "synthetic_toggle": {
                    "relative_target": "toggle.conf",
                    "desired_content": "on\n",
                    "capabilities": ["verify", "apply"],
                }
            },
        }))
        self.manifest.chmod(0o600)
        self.executable_uid = Path(sys.executable).resolve().stat().st_uid
        self.executor = SyntheticProcessExecutor(
            manifest_path=self.manifest,
            target_root=self.targets,
            backup_root=self.backups,
            expected_uid=os.getuid(),
            executable=Path(sys.executable).resolve(),
            expected_executable_uid=self.executable_uid,
        )

    def tearDown(self) -> None:
        self.temporary.cleanup()

    async def test_real_worker_applies_using_only_fixed_configuration(self) -> None:
        request = ProductionRequest(1, REQUEST_ID, Action.APPLY_MODULE, ("synthetic_toggle",))
        result = await self.executor.execute(request, CancellationToken())
        self.assertEqual(ProductionStatus.SUCCEEDED, result.status)
        self.assertEqual("on\n", self.target.read_text())
        self.assertEqual(f"backup-{REQUEST_ID}", result.backup_id)

    async def test_precancelled_worker_returns_terminal_cancelled_result(self) -> None:
        token = CancellationToken()
        token.cancel()
        request = ProductionRequest(1, REQUEST_ID, Action.AUDIT)
        result = await self.executor.execute(request, token)
        self.assertEqual(ProductionStatus.CANCELLED, result.status)
        self.assertFalse((self.backups / "recovery-required").exists())

    async def test_invalid_read_only_result_does_not_create_recovery_lockout(self) -> None:
        process = mock.Mock()
        process.stdin = mock.Mock()
        process.stdin.drain = mock.AsyncMock()
        process.stdout.read = mock.AsyncMock(side_effect=[b"not-json", b""])
        process.wait = mock.AsyncMock(return_value=0)
        factory = mock.AsyncMock(return_value=process)
        executor = SyntheticProcessExecutor(
            manifest_path=self.manifest,
            target_root=self.targets,
            backup_root=self.backups,
            expected_uid=os.getuid(),
            expected_executable_uid=self.executable_uid,
            process_factory=factory,
        )
        with self.assertRaises(SyntheticProcessError):
            await executor.execute(ProductionRequest(1, REQUEST_ID, Action.AUDIT), CancellationToken())
        self.assertFalse((self.backups / "recovery-required").exists())
        argv = factory.await_args.args
        self.assertEqual(("-m", "lsmf.synthetic_worker"), argv[1:3])
        self.assertEqual("/", factory.await_args.kwargs["cwd"])
        self.assertNotIn("HOME", factory.await_args.kwargs["env"])

    async def test_cooperative_timeout_requires_matching_terminal_result(self) -> None:
        request = ProductionRequest(1, REQUEST_ID, Action.AUDIT)
        token = CancellationToken()
        stopped = asyncio.Event()
        now = "2026-08-07T12:00:00Z"
        terminal = ProductionResult(
            1, REQUEST_ID, Action.AUDIT, ProductionStatus.TIMED_OUT,
            now, now, 1, "timed out", "", False,
            ErrorDetail("timed_out", "timed out"), finding_count=0,
        )

        class CooperativeProcess:
            returncode = None
            stdin = mock.Mock()
            stdout = mock.Mock()

            def __init__(self):
                self.stdin.drain = mock.AsyncMock()
                self.stdout.read = mock.AsyncMock(side_effect=[encode_result(terminal).encode(), b""])
                self.signal = None

            async def wait(self):
                await stopped.wait()
                return 0

            def send_signal(self, sent):
                self.signal = sent
                stopped.set()

            def terminate(self):
                raise AssertionError("timeout must use its distinct signal")

            def kill(self):
                raise AssertionError("cooperative worker must not be killed")

        process = CooperativeProcess()
        executor = SyntheticProcessExecutor(
            manifest_path=self.manifest,
            target_root=self.targets,
            backup_root=self.backups,
            expected_uid=os.getuid(),
            expected_executable_uid=self.executable_uid,
            process_factory=mock.AsyncMock(return_value=process),
            poll_interval=0.001,
        )
        execution = asyncio.create_task(executor.execute(request, token))
        await asyncio.sleep(0.01)
        token.cancel(timed_out=True)
        result = await asyncio.wait_for(execution, timeout=1)
        self.assertEqual(ProductionStatus.TIMED_OUT, result.status)
        self.assertEqual(signal.SIGUSR1, process.signal)
        self.assertFalse((self.backups / "recovery-required").exists())

    async def test_forced_kill_marks_recovery_and_never_returns_cancellation(self) -> None:
        class HangingProcess:
            returncode = None
            stdin = mock.Mock()
            stdout = mock.Mock()

            def __init__(self):
                self.stdin.drain = mock.AsyncMock()
                async def read(_size):
                    await asyncio.Event().wait()
                self.stdout.read = mock.AsyncMock(side_effect=read)
                self.wait_calls = 0
                self.killed = False
                self.exited = asyncio.Event()

            async def wait(self):
                self.wait_calls += 1
                if self.killed:
                    return -9
                await self.exited.wait()
                return -9

            def terminate(self):
                return None

            def kill(self):
                self.killed = True
                self.exited.set()

        process = HangingProcess()
        token = CancellationToken()
        backup_id = f"backup-{REQUEST_ID}"
        SyntheticBackupStore(self.backups, expected_uid=os.getuid()).create(
            backup_id, (FileSnapshot("toggle.conf", True, 0o600, b"off\n"),)
        )
        executor = SyntheticProcessExecutor(
            manifest_path=self.manifest,
            target_root=self.targets,
            backup_root=self.backups,
            expected_uid=os.getuid(),
            expected_executable_uid=self.executable_uid,
            process_factory=mock.AsyncMock(return_value=process),
            cancellation_grace=0.01,
            poll_interval=0.001,
        )
        execution = asyncio.create_task(
            executor.execute(
                ProductionRequest(1, REQUEST_ID, Action.APPLY_MODULE, ("synthetic_toggle",)),
                token,
            )
        )
        await asyncio.sleep(0.01)
        token.cancel()
        with self.assertRaises(SyntheticProcessError):
            await asyncio.wait_for(execution, timeout=1)
        self.assertTrue(process.killed)
        self.assertEqual(backup_id + "\n", (self.backups / "recovery-required").read_text())

    async def test_task_cancellation_during_read_only_transfer_stops_without_lockout(self) -> None:
        stopped = asyncio.Event()

        class TransferBlockedProcess:
            stdin = mock.Mock()

            def __init__(self):
                self.stdin.drain = mock.AsyncMock(side_effect=self.block)
                self.terminated = False

            async def block(self):
                await asyncio.Event().wait()

            async def wait(self):
                await stopped.wait()
                return -15

            def terminate(self):
                self.terminated = True
                stopped.set()

            def kill(self):
                stopped.set()

        process = TransferBlockedProcess()
        executor = SyntheticProcessExecutor(
            manifest_path=self.manifest,
            target_root=self.targets,
            backup_root=self.backups,
            expected_uid=os.getuid(),
            expected_executable_uid=self.executable_uid,
            process_factory=mock.AsyncMock(return_value=process),
        )
        execution = asyncio.create_task(
            executor.execute(ProductionRequest(1, REQUEST_ID, Action.AUDIT), CancellationToken())
        )
        await asyncio.sleep(0.01)
        execution.cancel()
        with self.assertRaises(asyncio.CancelledError):
            await execution
        self.assertTrue(process.terminated)
        self.assertFalse((self.backups / "recovery-required").exists())

    async def test_uncertain_apply_without_durable_backup_does_not_lock_out(self) -> None:
        process = mock.Mock()
        process.stdin = mock.Mock()
        process.stdin.drain = mock.AsyncMock()
        process.stdout.read = mock.AsyncMock(side_effect=[b"not-json", b""])
        process.wait = mock.AsyncMock(return_value=1)
        executor = SyntheticProcessExecutor(
            manifest_path=self.manifest,
            target_root=self.targets,
            backup_root=self.backups,
            expected_uid=os.getuid(),
            expected_executable_uid=self.executable_uid,
            process_factory=mock.AsyncMock(return_value=process),
        )
        request = ProductionRequest(1, REQUEST_ID, Action.APPLY_MODULE, ("synthetic_toggle",))
        with self.assertRaises(SyntheticProcessError):
            await executor.execute(request, CancellationToken())
        self.assertFalse((self.backups / "recovery-required").exists())

    def test_timing_bounds_reject_nonfinite_and_excessive_values(self) -> None:
        base = {
            "manifest_path": self.manifest,
            "target_root": self.targets,
            "backup_root": self.backups,
            "expected_uid": os.getuid(),
            "expected_executable_uid": self.executable_uid,
        }
        for changes in (
            {"poll_interval": float("nan")},
            {"poll_interval": float("inf")},
            {"poll_interval": 1.01},
            {"cancellation_grace": float("inf")},
            {"cancellation_grace": 30.01},
        ):
            with self.subTest(changes=changes), self.assertRaises(SyntheticProcessError):
                SyntheticProcessExecutor(**base, **changes)


if __name__ == "__main__":
    unittest.main()
