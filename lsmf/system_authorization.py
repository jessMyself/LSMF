"""Credential and Polkit adapters for the Gate-2 system-bus boundary."""

from __future__ import annotations

import asyncio
from collections.abc import Callable
import os
from pathlib import Path
import stat
import subprocess

from .ipc_security import (
    PeerSecurityError,
    RequestBinding,
    TransportCredentials,
    polkit_details,
)


class AuthorizationAdapterError(RuntimeError):
    """Raised when transport identity or authorization cannot be trusted."""


POLKIT_ACTION_IDS = frozenset({
    "org.lsmf.helper.audit",
    "org.lsmf.helper.verify-module",
    "org.lsmf.helper.apply-module",
    "org.lsmf.helper.apply-modules",
    "org.lsmf.helper.rollback-backup",
})


class SystemBusCredentialAdapter:
    """Derive credentials only from bus-daemon lookups for one unique owner."""

    def __init__(
        self,
        get_unix_pid: Callable[[str], int],
        get_unix_uid: Callable[[str], int],
    ) -> None:
        if not callable(get_unix_pid) or not callable(get_unix_uid):
            raise AuthorizationAdapterError("bus credential lookups are required")
        self._get_unix_pid = get_unix_pid
        self._get_unix_uid = get_unix_uid

    def credentials(self, unique_owner: str) -> TransportCredentials:
        if not isinstance(unique_owner, str) or not unique_owner.startswith(":"):
            raise AuthorizationAdapterError("a system-bus unique owner is required")
        try:
            pid = self._get_unix_pid(unique_owner)
            uid = self._get_unix_uid(unique_owner)
            return TransportCredentials(pid=pid, uid=uid, unique_owner=unique_owner)
        except (PeerSecurityError, TypeError, ValueError, OSError) as error:
            raise AuthorizationAdapterError("bus credentials are unavailable or invalid") from error


def process_start_time(pid: int, *, proc_root: Path = Path("/proc")) -> int:
    """Read Linux /proc start time without trusting the process command name."""
    if isinstance(pid, bool) or not isinstance(pid, int) or pid <= 0:
        raise AuthorizationAdapterError("PID must be a positive integer")
    try:
        raw = (proc_root / str(pid) / "stat").read_text(encoding="ascii")
    except (OSError, UnicodeError) as error:
        raise AuthorizationAdapterError("process start time is unavailable") from error
    closing = raw.rfind(")")
    if closing < 0:
        raise AuthorizationAdapterError("process stat record is malformed")
    fields = raw[closing + 1 :].split()
    # The suffix begins at field 3 (state); starttime is field 22.
    if len(fields) <= 19:
        raise AuthorizationAdapterError("process stat record is incomplete")
    try:
        value = int(fields[19], 10)
    except ValueError as error:
        raise AuthorizationAdapterError("process start time is malformed") from error
    if value <= 0:
        raise AuthorizationAdapterError("process start time is invalid")
    return value


def _trusted_executable(path: Path, expected_uid: int) -> None:
    try:
        metadata = path.stat(follow_symlinks=False)
    except OSError as error:
        raise AuthorizationAdapterError("pkcheck executable is unavailable") from error
    if (
        not stat.S_ISREG(metadata.st_mode)
        or metadata.st_uid != expected_uid
        or metadata.st_mode & 0o022
        or not metadata.st_mode & 0o111
    ):
        raise AuthorizationAdapterError("pkcheck executable ownership or mode is unsafe")


class PkcheckAuthorizer:
    """Run one exact Polkit check bound to peer PID start time and UID."""

    def __init__(
        self,
        *,
        executable: Path = Path("/usr/bin/pkcheck"),
        expected_executable_uid: int = 0,
        runner: Callable[..., subprocess.CompletedProcess[str]] = subprocess.run,
        proc_root: Path = Path("/proc"),
        timeout: float = 120.0,
    ) -> None:
        if not callable(runner) or timeout <= 0:
            raise AuthorizationAdapterError("authorization runner or timeout is invalid")
        _trusted_executable(executable, expected_executable_uid)
        self._executable = executable
        self._runner = runner
        self._proc_root = proc_root
        self._timeout = timeout

    def authorize(self, authorization_id: str, binding: RequestBinding) -> bool:
        if not isinstance(binding, RequestBinding):
            raise AuthorizationAdapterError("a complete request binding is required")
        if authorization_id not in POLKIT_ACTION_IDS:
            raise AuthorizationAdapterError("authorization ID is not allowlisted")
        start_time = process_start_time(binding.peer.pid, proc_root=self._proc_root)
        argv = _pkcheck_argv(self._executable, authorization_id, binding, start_time)
        try:
            completed = self._runner(
                argv,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                env={"PATH": "/usr/sbin:/usr/bin", "LANG": "C", "LC_ALL": "C"},
                close_fds=True,
                timeout=self._timeout,
                check=False,
                text=True,
            )
        except (OSError, subprocess.SubprocessError) as error:
            raise AuthorizationAdapterError("Polkit authorization failed closed") from error
        if completed.returncode == 0:
            # Re-read after the prompt so PID reuse cannot inherit authorization.
            if process_start_time(binding.peer.pid, proc_root=self._proc_root) != start_time:
                raise AuthorizationAdapterError("authorized process identity changed")
            return True
        if completed.returncode == 1:
            return False
        raise AuthorizationAdapterError("Polkit returned an indeterminate result")


class AsyncPkcheckAuthorizer:
    """Nonblocking fixed-argv Polkit check with bounded child cleanup."""

    def __init__(
        self,
        *,
        executable: Path = Path("/usr/bin/pkcheck"),
        expected_executable_uid: int = 0,
        process_factory: Callable[..., object] = asyncio.create_subprocess_exec,
        proc_root: Path = Path("/proc"),
        timeout: float = 120.0,
        termination_timeout: float = 5.0,
    ) -> None:
        if not callable(process_factory) or timeout <= 0 or termination_timeout <= 0:
            raise AuthorizationAdapterError("authorization process settings are invalid")
        _trusted_executable(executable, expected_executable_uid)
        self._executable = executable
        self._process_factory = process_factory
        self._proc_root = proc_root
        self._timeout = timeout
        self._termination_timeout = termination_timeout

    async def authorize(self, authorization_id: str, binding: RequestBinding) -> bool:
        if not isinstance(binding, RequestBinding):
            raise AuthorizationAdapterError("a complete request binding is required")
        if authorization_id not in POLKIT_ACTION_IDS:
            raise AuthorizationAdapterError("authorization ID is not allowlisted")
        start_time = process_start_time(binding.peer.pid, proc_root=self._proc_root)
        argv = _pkcheck_argv(self._executable, authorization_id, binding, start_time)
        try:
            process = await self._process_factory(
                *argv,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                env={"PATH": "/usr/sbin:/usr/bin", "LANG": "C", "LC_ALL": "C"},
                cwd="/",
                start_new_session=True,
            )
        except (OSError, subprocess.SubprocessError) as error:
            raise AuthorizationAdapterError("Polkit authorization failed closed") from error
        try:
            return_code = await asyncio.wait_for(process.wait(), timeout=self._timeout)
        except TimeoutError as error:
            await self._stop(process)
            raise AuthorizationAdapterError("Polkit authorization timed out") from error
        except asyncio.CancelledError:
            await self._stop(process)
            raise
        except Exception as error:
            await self._stop(process)
            raise AuthorizationAdapterError("Polkit authorization failed closed") from error
        if return_code == 0:
            if process_start_time(binding.peer.pid, proc_root=self._proc_root) != start_time:
                raise AuthorizationAdapterError("authorized process identity changed")
            return True
        if return_code == 1:
            return False
        raise AuthorizationAdapterError("Polkit returned an indeterminate result")

    async def _stop(self, process: object) -> None:
        if getattr(process, "returncode", None) is not None:
            return
        try:
            process.terminate()
        except ProcessLookupError:
            return
        try:
            await asyncio.wait_for(process.wait(), timeout=self._termination_timeout)
            return
        except (TimeoutError, ProcessLookupError):
            pass
        try:
            process.kill()
        except ProcessLookupError:
            return
        try:
            await process.wait()
        except ProcessLookupError:
            pass


def _pkcheck_argv(
    executable: Path,
    authorization_id: str,
    binding: RequestBinding,
    start_time: int,
) -> list[str]:
    subject = f"{binding.peer.pid},{start_time},{binding.peer.uid}"
    argv = [
        str(executable),
        "--action-id", authorization_id,
        "--process", subject,
        "--allow-user-interaction",
    ]
    for key, value in sorted(polkit_details(binding).items()):
        argv.extend(("--detail", key, value))
    return argv
