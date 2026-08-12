"""Bounded fixed-command executor for helper-owned audit and verification actions."""

from __future__ import annotations

import asyncio
from contextlib import suppress
from datetime import datetime, timezone
import os
from pathlib import Path
import re
import signal
import stat
import subprocess
from typing import Callable, Mapping, Sequence

from .privileged_protocol import Action
from .production_protocol import (
    ErrorDetail,
    MAX_OUTPUT_BYTES,
    ProductionRequest,
    ProductionResult,
    ProductionStatus,
)
from .synthetic_executor import CancellationToken


_MODULE_ID = re.compile(r"^[a-z][a-z0-9_]{0,63}$")
_FINDING_COUNT = re.compile(br"^LSMF_FINDING_COUNT=([0-9]{1,5})\n")


class ReadOnlyProcessError(RuntimeError):
    """Raised when fixed read-only process configuration is unsafe."""


def _command(value: Sequence[str], expected_uid: int) -> tuple[str, ...]:
    command = tuple(value)
    if (
        not command
        or any(not isinstance(item, str) or not item or "\x00" in item for item in command)
        or not Path(command[0]).is_absolute()
    ):
        raise ReadOnlyProcessError("read-only command is invalid")
    executable = Path(command[0]).resolve(strict=True)
    metadata = executable.stat()
    if (
        not stat.S_ISREG(metadata.st_mode)
        or metadata.st_uid != expected_uid
        or metadata.st_mode & 0o022
        or not metadata.st_mode & 0o111
    ):
        raise ReadOnlyProcessError("read-only command executable ownership or mode is unsafe")
    return (str(executable), *command[1:])


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


class ReadOnlyProcessExecutor:
    """Run only preconfigured audit and single-module verification commands."""

    def __init__(
        self,
        *,
        audit_command: Sequence[str],
        verification_commands: Mapping[str, Sequence[str]],
        process_factory: Callable[..., object] = asyncio.create_subprocess_exec,
        expected_executable_uid: int = 0,
        cancellation_grace: float = 2.0,
        poll_interval: float = 0.01,
    ) -> None:
        if (
            not callable(process_factory)
            or isinstance(expected_executable_uid, bool)
            or not isinstance(expected_executable_uid, int)
            or expected_executable_uid < 0
            or isinstance(cancellation_grace, bool)
            or not isinstance(cancellation_grace, (int, float))
            or not 0 < cancellation_grace <= 30
            or isinstance(poll_interval, bool)
            or not isinstance(poll_interval, (int, float))
            or not 0 < poll_interval <= 1
        ):
            raise ReadOnlyProcessError("read-only process settings are invalid")
        commands: dict[str, tuple[str, ...]] = {}
        for module_id, command in verification_commands.items():
            if not isinstance(module_id, str) or not _MODULE_ID.fullmatch(module_id):
                raise ReadOnlyProcessError("verification module ID is invalid")
            commands[module_id] = _command(command, expected_executable_uid)
        if not commands:
            raise ReadOnlyProcessError("one or more verification commands are required")
        self._audit_command = _command(audit_command, expected_executable_uid)
        self._verification_commands = commands
        self._process_factory = process_factory
        self._cancellation_grace = float(cancellation_grace)
        self._poll_interval = float(poll_interval)
        self._environment = {"LANG": "C.UTF-8", "LC_ALL": "C.UTF-8", "PATH": "/usr/sbin:/usr/bin"}

    def permits(self, request: ProductionRequest) -> bool:
        if request.action is Action.AUDIT:
            return True
        return (
            request.action is Action.VERIFY_MODULE
            and len(request.module_ids) == 1
            and request.module_ids[0] in self._verification_commands
        )

    def validate(self, request: ProductionRequest) -> bool:
        """Expose the same fixed allowlist to the production dispatcher policy gate."""
        return isinstance(request, ProductionRequest) and self.permits(request)

    async def execute(
        self, request: ProductionRequest, cancellation: CancellationToken
    ) -> ProductionResult:
        if not isinstance(request, ProductionRequest) or not isinstance(cancellation, CancellationToken):
            raise ReadOnlyProcessError("typed request and cancellation token are required")
        if not self.permits(request):
            raise ReadOnlyProcessError("action is not in the read-only command allowlist")
        if cancellation.cancelled:
            return self._cancelled(request, cancellation.timed_out)
        command = (
            self._audit_command
            if request.action is Action.AUDIT
            else self._verification_commands[request.module_ids[0]]
        )
        try:
            process = await self._process_factory(
                *command,
                stdin=subprocess.DEVNULL,
                stdout=asyncio.subprocess.PIPE,
                stderr=subprocess.STDOUT,
                env=self._environment,
                cwd="/",
                start_new_session=True,
            )
        except Exception as error:
            raise ReadOnlyProcessError("read-only worker could not be started") from error

        output_task = asyncio.create_task(self._read_bounded(process.stdout))
        wait_task = asyncio.create_task(process.wait())
        try:
            while not wait_task.done():
                if cancellation.cancelled:
                    await self._stop(process, wait_task)
                    output_task.cancel()
                    with suppress(asyncio.CancelledError):
                        await output_task
                    return self._cancelled(request, cancellation.timed_out)
                await asyncio.sleep(self._poll_interval)
            exit_code = await wait_task
            output, truncated = await output_task
        except asyncio.CancelledError:
            await self._stop(process, wait_task)
            output_task.cancel()
            with suppress(asyncio.CancelledError):
                await output_task
            raise
        except Exception as error:
            await self._stop(process, wait_task)
            output_task.cancel()
            with suppress(asyncio.CancelledError):
                await output_task
            raise ReadOnlyProcessError("read-only worker failed closed") from error
        return self._result(request, exit_code, output, truncated)

    async def _stop(self, process: object, wait_task: asyncio.Task[int]) -> None:
        if wait_task.done():
            return
        self._signal_process_group(process, signal.SIGTERM)
        try:
            await asyncio.wait_for(asyncio.shield(wait_task), self._cancellation_grace)
            return
        except TimeoutError:
            pass
        self._signal_process_group(process, signal.SIGKILL)
        await wait_task

    @staticmethod
    def _signal_process_group(process: object, requested_signal: signal.Signals) -> None:
        pid = getattr(process, "pid", None)
        if isinstance(pid, int) and not isinstance(pid, bool) and pid > 0:
            with suppress(ProcessLookupError):
                os.killpg(pid, requested_signal)
            return
        # Preserve dependency-injected process compatibility in unit tests;
        # production workers always expose a PID and start a new session.
        method = "terminate" if requested_signal == signal.SIGTERM else "kill"
        with suppress(ProcessLookupError):
            getattr(process, method)()

    @staticmethod
    async def _read_bounded(stream: object) -> tuple[bytes, bool]:
        output = bytearray()
        truncated = False
        while True:
            chunk = await stream.read(8192)
            if not isinstance(chunk, bytes):
                raise ReadOnlyProcessError("read-only worker output has the wrong type")
            if not chunk:
                break
            remaining = MAX_OUTPUT_BYTES - len(output)
            if remaining > 0:
                output.extend(chunk[:remaining])
            if len(chunk) > remaining:
                truncated = True
        return bytes(output), truncated

    @staticmethod
    def _result(
        request: ProductionRequest, exit_code: int, raw_output: bytes, truncated: bool
    ) -> ProductionResult:
        finished = _now()
        finding_count = None
        if request.action is Action.AUDIT:
            match = _FINDING_COUNT.match(raw_output)
            if match is None:
                return ReadOnlyProcessExecutor._failure(request, "invalid_audit_output", raw_output, truncated)
            finding_count = int(match.group(1))
            raw_output = raw_output[match.end():]
        output = raw_output.decode("utf-8", errors="replace")
        succeeded = exit_code == 0
        return ProductionResult(
            request.protocol_version,
            request.request_id,
            request.action,
            ProductionStatus.SUCCEEDED if succeeded else ProductionStatus.FAILED,
            finished,
            finished,
            exit_code if 0 <= exit_code <= 255 else 1,
            "Audit completed" if request.action is Action.AUDIT and succeeded else
            "Module verification passed" if succeeded else
            "Audit failed" if request.action is Action.AUDIT else "Module verification failed",
            output,
            truncated,
            None if succeeded else ErrorDetail("verification_failed", "Read-only command reported failure"),
            request.module_ids,
            None,
            finding_count,
        )

    @staticmethod
    def _failure(
        request: ProductionRequest, code: str, raw_output: bytes, truncated: bool
    ) -> ProductionResult:
        now = _now()
        return ProductionResult(
            request.protocol_version, request.request_id, request.action,
            ProductionStatus.FAILED, now, now, 1, "Audit result was invalid",
            raw_output.decode("utf-8", errors="replace"), truncated,
            ErrorDetail(code, "Audit worker did not provide a typed finding count"),
            request.module_ids, None, 0,
        )

    @staticmethod
    def _cancelled(request: ProductionRequest, timed_out: bool) -> ProductionResult:
        now = _now()
        status = ProductionStatus.TIMED_OUT if timed_out else ProductionStatus.CANCELLED
        return ProductionResult(
            request.protocol_version, request.request_id, request.action, status,
            now, now, 1, "Read-only operation timed out" if timed_out else "Read-only operation cancelled",
            "", False, ErrorDetail("timed_out" if timed_out else "cancelled", "Read-only command was stopped"),
            request.module_ids, None, 0 if request.action is Action.AUDIT else None,
        )
