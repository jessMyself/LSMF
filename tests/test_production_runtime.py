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

from lsmf.ipc_security import PeerIdentity, RequestBinding, TransportCredentials
from lsmf.privileged_protocol import Action
from lsmf.production_protocol import ProductionRequest, ProductionStatus, decode_result, encode_request
from lsmf.production_runtime import (
    ProductionRuntimeConfig,
    ProductionRuntimeError,
    Section2RuntimeConfig,
    build_production_boundary,
    build_section2_dispatcher,
)
from lsmf.synthetic_executor import FileSnapshot, SyntheticBackupStore
from lsmf.system_bus_service import DbusNextRouter, INTERFACE, OBJECT_PATH
from lsmf.system_session import SystemdLoginSessionAdapter


REQUEST_ID = "123e4567-e89b-42d3-a456-426614174000"


class AllowAuthorizer:
    def __init__(self) -> None:
        self.calls = []

    async def authorize(self, authorization_id, binding):
        self.calls.append((authorization_id, binding))
        return True


class Credentials:
    async def credentials(self, owner):
        return TransportCredentials(123, os.getuid(), owner)


class Sessions:
    def session_for_pid(self, pid): return "c2"
    def session_uid(self, session_id): return os.getuid()
    def session_seat(self, session_id): return "seat0"
    def session_active(self, session_id): return True
    def session_remote(self, session_id): return False
    def session_type(self, session_id): return "wayland"


class ProductionRuntimeTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        root = Path(self.temporary.name)
        self.targets = root / "targets"
        self.backups = root / "backups"
        self.audit_dir = root / "audit"
        for path in (self.targets, self.backups, self.audit_dir):
            path.mkdir(mode=0o700)
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
        self.config = ProductionRuntimeConfig(
            manifest_path=self.manifest,
            target_root=self.targets,
            backup_root=self.backups,
            audit_path=self.audit_dir / "helper.jsonl",
            worker_executable=Path(sys.executable).resolve(),
            pkcheck_executable=Path("/usr/bin/false"),
            expected_uid=os.getuid(),
            worker_executable_uid=Path(sys.executable).resolve().stat().st_uid,
        )

    def tearDown(self) -> None:
        self.temporary.cleanup()

    async def test_composed_boundary_runs_real_worker_and_protected_audit(self) -> None:
        authorizer = AllowAuthorizer()
        boundary = build_production_boundary(
            self.config,
            credentials=Credentials(),
            sessions=SystemdLoginSessionAdapter(Sessions()),
            authorizer=authorizer,
        )
        request = ProductionRequest(1, REQUEST_ID, Action.APPLY_MODULE, ("synthetic_toggle",))
        result = decode_result(await boundary.submit(":1.42", encode_request(request)))
        self.assertEqual(ProductionStatus.SUCCEEDED, result.status)
        self.assertEqual("on\n", self.target.read_text())
        self.assertEqual("org.lsmf.helper.apply-module", authorizer.calls[0][0])
        records = [json.loads(line) for line in self.config.audit_path.read_text().splitlines()]
        self.assertEqual(["started", "succeeded"], [record["lifecycle"] for record in records])
        self.assertTrue(all(record["uid"] == os.getuid() for record in records))

    async def test_manifest_policy_rejects_before_authorization_or_worker(self) -> None:
        authorizer = AllowAuthorizer()
        boundary = build_production_boundary(
            self.config,
            credentials=Credentials(),
            sessions=SystemdLoginSessionAdapter(Sessions()),
            authorizer=authorizer,
        )
        request = ProductionRequest(1, REQUEST_ID, Action.APPLY_MODULE, ("unknown_module",))
        result = decode_result(await boundary.submit(":1.42", encode_request(request)))
        self.assertEqual(ProductionStatus.REJECTED, result.status)
        self.assertEqual([], authorizer.calls)
        self.assertEqual("off\n", self.target.read_text())

    async def test_external_worker_kill_returns_exact_recovery_and_boundary_stays_available(self) -> None:
        processes = []

        async def start_blocked_worker(*_argv, **options):
            process = await asyncio.create_subprocess_exec(
                "/usr/bin/sleep",
                "30",
                stdin=options["stdin"],
                stdout=options["stdout"],
                stderr=options["stderr"],
                env=options["env"],
                cwd=options["cwd"],
                start_new_session=options["start_new_session"],
            )
            processes.append(process)
            return process

        backup_id = f"backup-{REQUEST_ID}"
        backups = SyntheticBackupStore(self.backups, expected_uid=os.getuid())
        backups.create(
            backup_id,
            (FileSnapshot("toggle.conf", True, 0o600, b"off\n"),),
        )
        boundary = build_production_boundary(
            self.config,
            credentials=Credentials(),
            sessions=SystemdLoginSessionAdapter(Sessions()),
            authorizer=AllowAuthorizer(),
            process_factory=start_blocked_worker,
        )
        request = ProductionRequest(
            1, REQUEST_ID, Action.APPLY_MODULE, ("synthetic_toggle",)
        )
        class MessageType:
            METHOD_CALL = "method_call"
            SIGNAL = "signal"

        class Replies:
            @staticmethod
            def new_method_return(_message, signature, body):
                return ("return", signature, body)

            @staticmethod
            def new_error(_message, name, text):
                return ("error", name, text)

        class Bus:
            def __init__(self):
                self.sent = []

            async def send(self, reply):
                self.sent.append(reply)

        message = mock.Mock(
            message_type=MessageType.METHOD_CALL,
            path=OBJECT_PATH,
            interface=INTERFACE,
            member="Submit",
            signature="s",
            body=[encode_request(request)],
            sender=":1.42",
        )
        bus = Bus()
        router = DbusNextRouter(bus, boundary, Replies, MessageType)
        self.assertTrue(router.handle(message))
        while not processes:
            await asyncio.sleep(0)
        worker_pid = processes[0].pid
        os.kill(worker_pid, signal.SIGKILL)
        async with asyncio.timeout(2):
            while not bus.sent:
                await asyncio.sleep(0)
        self.assertEqual("return", bus.sent[0][0])
        result = decode_result(bus.sent[0][2][0])

        self.assertEqual(ProductionStatus.FAILED, result.status)
        self.assertEqual("executor_failed", result.error.code)
        self.assertEqual(backup_id, result.backup_id)
        self.assertEqual(backup_id + "\n", (self.backups / "recovery-required").read_text())
        with self.assertRaises(ProcessLookupError):
            os.kill(worker_pid, 0)

        wrong = ProductionRequest(
            1,
            "123e4567-e89b-42d3-a456-426614174001",
            Action.ROLLBACK_BACKUP,
            backup_id="backup-123e4567-e89b-42d3-a456-426614174099",
        )
        rejected = decode_result(await boundary.submit(":1.42", encode_request(wrong)))
        self.assertEqual(ProductionStatus.REJECTED, rejected.status)

        follow_up = ProductionRequest(
            1,
            "123e4567-e89b-42d3-a456-426614174002",
            Action.APPLY_MODULE,
            ("unknown_module",),
        )
        available = decode_result(
            await boundary.submit(":1.42", encode_request(follow_up))
        )
        self.assertEqual(ProductionStatus.REJECTED, available.status)

    def test_configuration_requires_absolute_helper_owned_locations(self) -> None:
        with self.assertRaises(ProductionRuntimeError):
            ProductionRuntimeConfig(
                manifest_path=Path("manifest.json"),
                target_root=self.targets,
                backup_root=self.backups,
                audit_path=self.config.audit_path,
            )

    def test_configuration_rejects_overlapping_or_aliased_security_stores(self) -> None:
        base = {
            "manifest_path": self.manifest,
            "target_root": self.targets,
            "backup_root": self.backups,
            "audit_path": self.config.audit_path,
            "worker_executable": Path(sys.executable).resolve(),
            "pkcheck_executable": Path("/usr/bin/false"),
            "expected_uid": os.getuid(),
        }
        cases = (
            {"backup_root": self.targets},
            {"backup_root": self.targets / "backups"},
            {"audit_path": self.targets / "helper.jsonl"},
            {"manifest_path": self.targets / "manifest.json"},
        )
        for changes in cases:
            with self.subTest(changes=changes), self.assertRaises(ProductionRuntimeError):
                ProductionRuntimeConfig(**(base | changes))

        alias = Path(self.temporary.name) / "target-alias"
        alias.symlink_to(self.targets, target_is_directory=True)
        with self.assertRaises(ProductionRuntimeError):
            ProductionRuntimeConfig(**(base | {"backup_root": alias}))

    async def test_section2_composition_runs_only_fixed_kernel_verification(self) -> None:
        runner = Path(__file__).resolve().parents[1] / "packaging" / "privileged-helper" / "lsmf-read-only-runner"
        process = mock.Mock()
        process.stdout.read = mock.AsyncMock(side_effect=[b"verified\n", b""])
        process.wait = mock.AsyncMock(return_value=0)
        factory = mock.AsyncMock(return_value=process)
        authorizer = AllowAuthorizer()
        config = Section2RuntimeConfig(
            runner_path=runner,
            audit_path=self.audit_dir / "section2.jsonl",
            pkcheck_executable=Path("/usr/bin/false"),
            expected_uid=runner.stat().st_uid,
        )
        dispatcher = build_section2_dispatcher(
            config, authorizer=authorizer, process_factory=factory
        )
        request = ProductionRequest(
            1, REQUEST_ID, Action.VERIFY_MODULE, ("kernel_hardening",)
        )
        peer = PeerIdentity(123, 1000, ":1.42", "c2", "seat0")
        binding = RequestBinding(
            request.request_id, request.action, request.parameter_digest(), peer
        )
        result = decode_result(await dispatcher.submit(request, binding))

        self.assertEqual(ProductionStatus.SUCCEEDED, result.status)
        self.assertEqual("org.lsmf.helper.verify-module", authorizer.calls[0][0])
        argv = factory.call_args.args
        self.assertEqual(
            (str(runner.resolve()), "verify", "kernel_hardening"), argv[:3]
        )
        apply_request = ProductionRequest(
            1, "123e4567-e89b-42d3-a456-426614174001",
            Action.APPLY_MODULE, ("kernel_hardening",),
        )
        apply_binding = RequestBinding(
            apply_request.request_id, apply_request.action,
            apply_request.parameter_digest(), peer,
        )
        rejected = decode_result(await dispatcher.submit(apply_request, apply_binding))
        self.assertEqual(ProductionStatus.REJECTED, rejected.status)
        self.assertEqual(1, factory.await_count)


if __name__ == "__main__":
    unittest.main()
