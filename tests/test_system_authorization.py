import asyncio
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest import mock

from lsmf.ipc_security import PeerIdentity, RequestBinding
from lsmf.privileged_protocol import Action
from lsmf.system_authorization import (
    AuthorizationAdapterError,
    AsyncPkcheckAuthorizer,
    PkcheckAuthorizer,
    SystemBusCredentialAdapter,
    process_start_time,
)


class SystemAuthorizationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.executable = self.root / "pkcheck"
        self.executable.write_text("#!/bin/sh\n", encoding="ascii")
        self.executable.chmod(0o700)
        self.proc = self.root / "proc"
        (self.proc / "123").mkdir(parents=True)
        suffix = ["S"] + ["0"] * 18 + ["98765"] + ["0"] * 4
        (self.proc / "123" / "stat").write_text(
            "123 (name with ) spaces) " + " ".join(suffix), encoding="ascii"
        )
        peer = PeerIdentity(123, 1000, ":1.42", "c2", "seat0")
        self.binding = RequestBinding(
            "123e4567-e89b-42d3-a456-426614174000",
            Action.AUDIT,
            "a" * 64,
            peer,
        )

    def tearDown(self) -> None:
        self.temp.cleanup()

    def test_bus_credentials_come_only_from_unique_owner_lookups(self) -> None:
        adapter = SystemBusCredentialAdapter(lambda owner: 123, lambda owner: 1000)
        credentials = adapter.credentials(":1.42")
        self.assertEqual((123, 1000, ":1.42"), (credentials.pid, credentials.uid, credentials.unique_owner))
        with self.assertRaises(AuthorizationAdapterError):
            adapter.credentials("caller-supplied-name")

    def test_process_start_time_handles_parentheses_and_rejects_malformed(self) -> None:
        self.assertEqual(98765, process_start_time(123, proc_root=self.proc))
        (self.proc / "123" / "stat").write_text("bad", encoding="ascii")
        with self.assertRaises(AuthorizationAdapterError):
            process_start_time(123, proc_root=self.proc)

    def authorizer(self, runner):
        return PkcheckAuthorizer(
            executable=self.executable,
            expected_executable_uid=os.getuid(),
            runner=runner,
            proc_root=self.proc,
            timeout=3,
        )

    def test_pkcheck_uses_fixed_argv_clean_environment_and_exact_subject(self) -> None:
        runner = mock.Mock(return_value=subprocess.CompletedProcess([], 0))
        self.assertTrue(self.authorizer(runner).authorize("org.lsmf.helper.audit", self.binding))
        argv = runner.call_args.args[0]
        self.assertEqual(str(self.executable), argv[0])
        self.assertIn("123,98765,1000", argv)
        self.assertNotIn(":1.42", argv)
        self.assertEqual({"PATH": "/usr/sbin:/usr/bin", "LANG": "C", "LC_ALL": "C"}, runner.call_args.kwargs["env"])
        self.assertTrue(runner.call_args.kwargs["close_fds"])

    def test_denial_error_and_pid_reuse_fail_closed(self) -> None:
        denied = mock.Mock(return_value=subprocess.CompletedProcess([], 1))
        self.assertFalse(self.authorizer(denied).authorize("org.lsmf.helper.audit", self.binding))
        indeterminate = mock.Mock(return_value=subprocess.CompletedProcess([], 2))
        with self.assertRaises(AuthorizationAdapterError):
            self.authorizer(indeterminate).authorize("org.lsmf.helper.audit", self.binding)

        runner = mock.Mock(return_value=subprocess.CompletedProcess([], 0))
        authorizer = self.authorizer(runner)
        with mock.patch(
            "lsmf.system_authorization.process_start_time", side_effect=[98765, 98766]
        ), self.assertRaises(AuthorizationAdapterError):
            authorizer.authorize("org.lsmf.helper.audit", self.binding)

    def test_rejects_untrusted_executable_and_action(self) -> None:
        self.executable.chmod(0o722)
        with self.assertRaises(AuthorizationAdapterError):
            self.authorizer(mock.Mock())
        self.executable.chmod(0o700)
        with self.assertRaises(AuthorizationAdapterError):
            self.authorizer(mock.Mock()).authorize("org.example.anything", self.binding)
        with self.assertRaises(AuthorizationAdapterError):
            self.authorizer(mock.Mock()).authorize("org.lsmf.helper.unlisted", self.binding)


class FakeProcess:
    def __init__(self, returncode=None) -> None:
        self.returncode = returncode
        self.terminated = False
        self.killed = False
        self.release = asyncio.Event()
        if returncode is not None:
            self.release.set()

    async def wait(self):
        await self.release.wait()
        return self.returncode

    def terminate(self):
        self.terminated = True
        self.returncode = -15
        self.release.set()

    def kill(self):
        self.killed = True
        self.returncode = -9
        self.release.set()


class AsyncSystemAuthorizationTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.executable = self.root / "pkcheck"
        self.executable.write_text("#!/bin/sh\n", encoding="ascii")
        self.executable.chmod(0o700)
        self.proc = self.root / "proc"
        (self.proc / "123").mkdir(parents=True)
        suffix = ["S"] + ["0"] * 18 + ["98765"] + ["0"] * 4
        (self.proc / "123" / "stat").write_text(
            "123 (client) " + " ".join(suffix), encoding="ascii"
        )
        peer = PeerIdentity(123, 1000, ":1.42", "c2", "seat0")
        self.binding = RequestBinding(
            "123e4567-e89b-42d3-a456-426614174000",
            Action.AUDIT,
            "a" * 64,
            peer,
        )
        self.calls = []

    def tearDown(self) -> None:
        self.temp.cleanup()

    def authorizer(self, process, **changes):
        async def factory(*argv, **kwargs):
            self.calls.append((argv, kwargs))
            return process
        values = {
            "executable": self.executable,
            "expected_executable_uid": os.getuid(),
            "process_factory": factory,
            "proc_root": self.proc,
            "timeout": 1,
            "termination_timeout": 0.1,
        }
        values.update(changes)
        return AsyncPkcheckAuthorizer(**values)

    async def test_async_pkcheck_uses_fixed_argv_and_clean_process(self) -> None:
        process = FakeProcess(0)
        self.assertTrue(await self.authorizer(process).authorize("org.lsmf.helper.audit", self.binding))
        argv, kwargs = self.calls[0]
        self.assertEqual(str(self.executable), argv[0])
        self.assertIn("123,98765,1000", argv)
        self.assertNotIn(":1.42", argv)
        self.assertEqual({"PATH": "/usr/sbin:/usr/bin", "LANG": "C", "LC_ALL": "C"}, kwargs["env"])
        self.assertEqual("/", kwargs["cwd"])
        self.assertTrue(kwargs["start_new_session"])

    async def test_denial_indeterminate_and_pid_reuse_fail_closed(self) -> None:
        self.assertFalse(await self.authorizer(FakeProcess(1)).authorize("org.lsmf.helper.audit", self.binding))
        with self.assertRaises(AuthorizationAdapterError):
            await self.authorizer(FakeProcess(2)).authorize("org.lsmf.helper.audit", self.binding)
        with mock.patch("lsmf.system_authorization.process_start_time", side_effect=[98765, 98766]):
            with self.assertRaises(AuthorizationAdapterError):
                await self.authorizer(FakeProcess(0)).authorize("org.lsmf.helper.audit", self.binding)

    async def test_timeout_and_coroutine_cancellation_terminate_child(self) -> None:
        timed = FakeProcess()
        with self.assertRaises(AuthorizationAdapterError):
            await self.authorizer(timed, timeout=0.01).authorize("org.lsmf.helper.audit", self.binding)
        self.assertTrue(timed.terminated)

        cancelled = FakeProcess()
        task = asyncio.create_task(
            self.authorizer(cancelled).authorize("org.lsmf.helper.audit", self.binding)
        )
        await asyncio.sleep(0)
        task.cancel()
        with self.assertRaises(asyncio.CancelledError):
            await task
        self.assertTrue(cancelled.terminated)
        with self.assertRaises(AuthorizationAdapterError):
            await self.authorizer(FakeProcess(0)).authorize("org.lsmf.helper.unlisted", self.binding)

    async def test_unresponsive_child_is_killed_after_termination_grace(self) -> None:
        class StubbornProcess(FakeProcess):
            def terminate(self):
                self.terminated = True

        process = StubbornProcess()
        with self.assertRaises(AuthorizationAdapterError):
            await self.authorizer(
                process, timeout=0.01, termination_timeout=0.01
            ).authorize("org.lsmf.helper.audit", self.binding)
        self.assertTrue(process.terminated)
        self.assertTrue(process.killed)


if __name__ == "__main__":
    unittest.main()
