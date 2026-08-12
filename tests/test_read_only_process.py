from __future__ import annotations

import asyncio
from pathlib import Path
import shlex
import tempfile
import unittest

from lsmf.privileged_protocol import Action
from lsmf.ipc_security import PeerIdentity, RequestBinding
from lsmf.production_dispatcher import ProductionDispatcher
from lsmf.production_protocol import (
    ProductionRequest,
    ProductionStatus,
    decode_result,
)
from lsmf.read_only_process import ReadOnlyProcessError, ReadOnlyProcessExecutor
from lsmf.synthetic_executor import CancellationToken


REQUEST_ID = "123e4567-e89b-42d3-a456-426614174000"


class ReadOnlyProcessTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.runner = self.root / "runner.sh"
        self.child_pid_file = self.root / "child.pid"
        self.runner.write_text(
            "#!/usr/bin/env bash\n"
            "set -Eeuo pipefail\n"
            "case \"$1\" in\n"
            "audit) printf 'LSMF_FINDING_COUNT=2\\nfinding one\\nfinding two\\n' ;;\n"
            "verify) printf 'verified without mutation\\n' ;;\n"
            "fail) printf 'mismatch\\n'; exit 3 ;;\n"
            "wait) sleep 90 & child=$!; "
            f"printf '%s\\n' \"$child\" > {shlex.quote(str(self.child_pid_file))}; "
            "wait \"$child\" ;;\n"
            "esac\n"
        )
        self.runner.chmod(0o700)

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def executor(self, verify_action: str = "verify") -> ReadOnlyProcessExecutor:
        return ReadOnlyProcessExecutor(
            audit_command=("/usr/bin/bash", str(self.runner), "audit"),
            verification_commands={
                "kernel_hardening": ("/usr/bin/bash", str(self.runner), verify_action)
            },
            expected_executable_uid=Path("/usr/bin/bash").stat().st_uid,
            poll_interval=0.001,
        )

    async def test_typed_audit_and_one_allowlisted_verification(self) -> None:
        audit = await self.executor().execute(
            ProductionRequest(1, REQUEST_ID, Action.AUDIT), CancellationToken()
        )
        self.assertEqual(ProductionStatus.SUCCEEDED, audit.status)
        self.assertEqual(2, audit.finding_count)
        self.assertNotIn("LSMF_FINDING_COUNT", audit.output)

        verify = await self.executor().execute(
            ProductionRequest(1, REQUEST_ID, Action.VERIFY_MODULE, ("kernel_hardening",)),
            CancellationToken(),
        )
        self.assertEqual(ProductionStatus.SUCCEEDED, verify.status)
        self.assertEqual(("kernel_hardening",), verify.module_ids)

    async def test_production_dispatcher_authorizes_and_audits_exact_verify_action(self) -> None:
        class Authorizer:
            def __init__(self) -> None:
                self.calls = []

            async def authorize(self, action_id, binding):
                self.calls.append((action_id, binding))
                return True

        executor = self.executor()
        authorizer = Authorizer()
        events = []
        dispatcher = ProductionDispatcher(
            policy=executor,
            authorizer=authorizer,
            executor=executor,
            audit_sink=lambda event: events.append(event) or True,
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
        self.assertEqual(["started", "succeeded"], [event.lifecycle for event in events])

    async def test_failure_and_non_allowlisted_actions_are_truthful(self) -> None:
        result = await self.executor("fail").execute(
            ProductionRequest(1, REQUEST_ID, Action.VERIFY_MODULE, ("kernel_hardening",)),
            CancellationToken(),
        )
        self.assertEqual(ProductionStatus.FAILED, result.status)
        self.assertEqual(3, result.exit_code)
        self.assertEqual("verification_failed", result.error.code)

        executor = self.executor()
        self.assertFalse(executor.permits(
            ProductionRequest(1, REQUEST_ID, Action.APPLY_MODULE, ("kernel_hardening",))
        ))
        with self.assertRaises(ReadOnlyProcessError):
            await executor.execute(
                ProductionRequest(1, REQUEST_ID, Action.VERIFY_MODULE, ("ssh_hardening",)),
                CancellationToken(),
            )

    async def test_cancellation_stops_the_child_and_returns_terminal_state(self) -> None:
        token = CancellationToken()
        execution = asyncio.create_task(self.executor("wait").execute(
            ProductionRequest(1, REQUEST_ID, Action.VERIFY_MODULE, ("kernel_hardening",)), token
        ))
        for _ in range(200):
            if self.child_pid_file.exists():
                break
            await asyncio.sleep(0.005)
        self.assertTrue(self.child_pid_file.exists(), "worker descendant did not start")
        child_pid = int(self.child_pid_file.read_text().strip())
        self.assertTrue(Path(f"/proc/{child_pid}").exists())
        token.cancel()
        result = await asyncio.wait_for(execution, timeout=2)
        self.assertEqual(ProductionStatus.CANCELLED, result.status)
        for _ in range(200):
            if not Path(f"/proc/{child_pid}").exists():
                break
            await asyncio.sleep(0.005)
        self.assertFalse(Path(f"/proc/{child_pid}").exists(), "worker descendant survived cancellation")

    def test_configuration_requires_absolute_fixed_commands_and_valid_ids(self) -> None:
        with self.assertRaises(ReadOnlyProcessError):
            ReadOnlyProcessExecutor(
                audit_command=("relative",),
                verification_commands={
                    "kernel_hardening": ("/usr/bin/bash", str(self.runner), "verify")
                },
            )
        with self.assertRaises(ReadOnlyProcessError):
            ReadOnlyProcessExecutor(
                audit_command=("/usr/bin/bash", str(self.runner), "audit"),
                verification_commands={
                    "kernel_hardening": ("/usr/bin/bash", str(self.runner), "verify")
                },
                expected_executable_uid=Path("/usr/bin/bash").stat().st_uid + 1,
            )
        with self.assertRaises(ReadOnlyProcessError):
            ReadOnlyProcessExecutor(
                audit_command=("/usr/bin/bash", str(self.runner), "audit"),
                verification_commands={
                    "bad/id": ("/usr/bin/bash", str(self.runner), "verify")
                },
                expected_executable_uid=Path("/usr/bin/bash").stat().st_uid,
            )


if __name__ == "__main__":
    unittest.main()
