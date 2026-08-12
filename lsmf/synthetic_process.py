"""Controlled subprocess boundary for the trusted synthetic executor."""

from __future__ import annotations

import asyncio
from contextlib import suppress
import math
from pathlib import Path
import signal
import stat
import subprocess
import sys
from typing import Callable

from .privileged_protocol import Action
from .production_protocol import (
    ErrorDetail,
    MAX_REQUEST_BYTES,
    MAX_RESULT_BYTES,
    ProductionRequest,
    ProductionResult,
    ProductionStatus,
    decode_result,
    encode_request,
)
from .synthetic_executor import CancellationToken, SyntheticBackupStore, SyntheticExecutorError


class SyntheticProcessError(SyntheticExecutorError):
    """Raised when the isolated worker cannot provide a trusted result."""


MAX_CANCELLATION_GRACE = 30.0
MAX_POLL_INTERVAL = 1.0


def _bounded_seconds(value: object, maximum: float) -> bool:
    return (
        not isinstance(value, bool)
        and isinstance(value, (int, float))
        and math.isfinite(value)
        and 0 < value <= maximum
    )


def _trusted_executable(path: Path, expected_uid: int) -> None:
    try:
        metadata = path.stat(follow_symlinks=False)
    except OSError as error:
        raise SyntheticProcessError("synthetic worker executable is unavailable") from error
    if (
        not stat.S_ISREG(metadata.st_mode)
        or metadata.st_uid != expected_uid
        or metadata.st_mode & 0o022
        or not metadata.st_mode & 0o111
    ):
        raise SyntheticProcessError("synthetic worker executable ownership or mode is unsafe")


def _trusted_code_root(path: Path, expected_uid: int) -> None:
    try:
        metadata = path.stat(follow_symlinks=False)
        sources = tuple(path.glob("*.py"))
    except OSError as error:
        raise SyntheticProcessError("synthetic worker code is unavailable") from error
    if not stat.S_ISDIR(metadata.st_mode) or metadata.st_uid != expected_uid or metadata.st_mode & 0o022:
        raise SyntheticProcessError("synthetic worker code directory is unsafe")
    if not sources:
        raise SyntheticProcessError("synthetic worker code is unavailable")
    for source in sources:
        source_metadata = source.stat(follow_symlinks=False)
        if (
            not stat.S_ISREG(source_metadata.st_mode)
            or source_metadata.st_uid != expected_uid
            or source_metadata.st_mode & 0o022
        ):
            raise SyntheticProcessError("synthetic worker code ownership or mode is unsafe")


class SyntheticProcessExecutor:
    """Execute one typed request in a fixed, helper-configured child process."""

    def __init__(
        self,
        *,
        manifest_path: str | Path,
        target_root: str | Path,
        backup_root: str | Path,
        expected_uid: int = 0,
        expected_executable_uid: int = 0,
        executable: str | Path = sys.executable,
        process_factory: Callable[..., object] = asyncio.create_subprocess_exec,
        cancellation_grace: float = 2.0,
        poll_interval: float = 0.01,
    ) -> None:
        if (
            isinstance(expected_uid, bool)
            or not isinstance(expected_uid, int)
            or expected_uid < 0
            or isinstance(expected_executable_uid, bool)
            or not isinstance(expected_executable_uid, int)
            or expected_executable_uid < 0
            or not callable(process_factory)
            or not _bounded_seconds(cancellation_grace, MAX_CANCELLATION_GRACE)
            or not _bounded_seconds(poll_interval, MAX_POLL_INTERVAL)
        ):
            raise SyntheticProcessError("synthetic process settings are invalid")
        paths = tuple(Path(value) for value in (manifest_path, target_root, backup_root))
        executable_path = Path(executable)
        if not executable_path.is_absolute() or "\x00" in str(executable_path):
            raise SyntheticProcessError("synthetic process path is invalid")
        executable_path = executable_path.resolve(strict=True)
        paths = (*paths, executable_path)
        if any("\x00" in str(value) or not value.is_absolute() for value in paths):
            raise SyntheticProcessError("synthetic process path is invalid")
        self._manifest_path, self._target_root, self._backup_root, self._executable = paths
        self._expected_uid = expected_uid
        self._process_factory = process_factory
        self._cancellation_grace = cancellation_grace
        self._poll_interval = poll_interval
        self._backups = SyntheticBackupStore(self._backup_root, expected_uid=expected_uid)
        package_root = Path(__file__).resolve().parent.parent
        _trusted_executable(self._executable, expected_executable_uid)
        # A root helper must never import its worker from a writable checkout.
        # Non-root temporary roots remain available solely for isolated tests.
        if expected_uid == 0:
            _trusted_code_root(package_root / "lsmf", expected_uid)
        self._environment = {
            "LANG": "C.UTF-8",
            "LC_ALL": "C.UTF-8",
            "PATH": "/usr/sbin:/usr/bin",
            "PYTHONPATH": str(package_root),
        }

    def _worker_arguments(self) -> tuple[str, ...]:
        """Return only helper-owned fixed arguments for the isolated worker."""
        return (
            str(self._executable),
            "-m",
            "lsmf.synthetic_worker",
            "--manifest",
            str(self._manifest_path),
            "--target-root",
            str(self._target_root),
            "--backup-root",
            str(self._backup_root),
            "--expected-uid",
            str(self._expected_uid),
        )

    def backup_eligible(self, backup_id: str) -> bool:
        """Expose only validated synthetic-backup eligibility to policy."""
        return self._backups.eligible(backup_id)

    async def execute(
        self, request: ProductionRequest, cancellation: CancellationToken
    ) -> ProductionResult:
        if not isinstance(request, ProductionRequest) or not isinstance(cancellation, CancellationToken):
            raise SyntheticProcessError("typed request and cancellation token are required")
        payload = encode_request(request).encode("utf-8")
        if len(payload) > MAX_REQUEST_BYTES:
            raise SyntheticProcessError("worker request exceeds its size limit")
        if cancellation.cancelled:
            return self._cancelled_result(request, cancellation.timed_out)
        argv = self._worker_arguments()
        try:
            process = await self._process_factory(
                *argv,
                stdin=asyncio.subprocess.PIPE,
                stdout=asyncio.subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                env=self._environment,
                cwd="/",
                start_new_session=True,
            )
        except Exception as error:
            raise SyntheticProcessError("synthetic worker could not be started") from error
        try:
            process.stdin.write(payload)
            await process.stdin.drain()
            process.stdin.close()
        except asyncio.CancelledError:
            wait = asyncio.create_task(process.wait())
            await self._stop(process, wait)
            await self._mark_uncertain(request)
            raise
        except Exception as error:
            wait = asyncio.create_task(process.wait())
            await self._stop(process, wait)
            await self._mark_uncertain(request)
            raise SyntheticProcessError("synthetic worker request transfer failed") from error

        communicate = asyncio.create_task(self._read_bounded(process.stdout))
        wait = asyncio.create_task(process.wait())
        forced = False
        try:
            while not wait.done():
                if cancellation.cancelled:
                    forced = await self._stop(process, wait, timed_out=cancellation.timed_out)
                    break
                await asyncio.sleep(self._poll_interval)
            return_code = await wait
            if forced:
                communicate.cancel()
                with suppress(asyncio.CancelledError):
                    await communicate
                output = b""
            else:
                output = await communicate
        except asyncio.CancelledError:
            forced = await self._stop(process, wait)
            await self._mark_uncertain(request)
            communicate.cancel()
            with suppress(asyncio.CancelledError):
                await communicate
            raise
        except Exception as error:
            await self._stop(process, wait)
            await self._mark_uncertain(request)
            communicate.cancel()
            with suppress(asyncio.CancelledError):
                await communicate
            raise SyntheticProcessError("synthetic worker failed closed") from error

        if forced or return_code != 0 or len(output) > MAX_RESULT_BYTES:
            communicate.cancel()
            with suppress(asyncio.CancelledError):
                await communicate
            backup_id = await self._mark_uncertain(request)
            raise SyntheticProcessError(
                "synthetic worker terminated without a trusted result",
                backup_id=backup_id,
            )
        try:
            result = decode_result(output)
        except Exception as error:
            await self._mark_uncertain(request)
            raise SyntheticProcessError("synthetic worker returned an invalid result") from error
        if (
            result.protocol_version != request.protocol_version
            or result.request_id != request.request_id
            or result.action is not request.action
        ):
            await self._mark_uncertain(request)
            raise SyntheticProcessError("synthetic worker returned a mismatched result")
        if cancellation.cancelled:
            expected = ProductionStatus.TIMED_OUT if cancellation.timed_out else ProductionStatus.CANCELLED
            if result.status is not expected:
                await self._mark_uncertain(request)
                raise SyntheticProcessError("synthetic worker did not confirm cancellation")
        return result

    async def _stop(
        self, process: object, wait: asyncio.Task[int], *, timed_out: bool = False
    ) -> bool:
        if wait.done():
            return False
        try:
            if timed_out:
                process.send_signal(signal.SIGUSR1)
            else:
                process.terminate()
        except ProcessLookupError:
            return False
        try:
            await asyncio.wait_for(asyncio.shield(wait), timeout=self._cancellation_grace)
            return False
        except TimeoutError:
            pass
        try:
            process.kill()
        except ProcessLookupError:
            return False
        await wait
        return True

    @staticmethod
    def _cancelled_result(request: ProductionRequest, timed_out: bool) -> ProductionResult:
        from datetime import datetime, timezone

        now = datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")
        status = ProductionStatus.TIMED_OUT if timed_out else ProductionStatus.CANCELLED
        code = "timed_out" if timed_out else "cancelled"
        finding_count = 0 if request.action is Action.AUDIT else None
        return ProductionResult(
            request.protocol_version,
            request.request_id,
            request.action,
            status,
            now,
            now,
            1,
            "Synthetic operation timed out" if timed_out else "Synthetic operation cancelled",
            "",
            False,
            ErrorDetail(code, "Synthetic operation did not start"),
            request.module_ids,
            request.backup_id,
            finding_count,
        )

    async def _mark_uncertain(self, request: ProductionRequest) -> str | None:
        # This synchronous durable write is deliberately kept on the event-loop
        # thread; prior thread-executor use was unreliable in the target sandbox.
        if request.action in {Action.AUDIT, Action.VERIFY_MODULE}:
            return None
        prefix = "recovery" if request.action is Action.ROLLBACK_BACKUP else "backup"
        backup_id = f"{prefix}-{request.request_id}"
        # Backup-first execution makes absence proof that mutation had not yet
        # begun. Only a fully validated durable snapshot becomes recovery authority.
        if self._backups.eligible(backup_id):
            self._backups.mark_recovery_required(backup_id)
            return backup_id
        return None

    @staticmethod
    async def _read_bounded(stream: object) -> bytes:
        chunks: list[bytes] = []
        total = 0
        while total <= MAX_RESULT_BYTES:
            chunk = await stream.read(min(8192, MAX_RESULT_BYTES + 1 - total))
            if not isinstance(chunk, bytes):
                raise SyntheticProcessError("synthetic worker output has the wrong type")
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
        return b"".join(chunks)
