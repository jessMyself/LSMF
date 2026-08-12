"""Protected append-only JSONL audit sink for privileged-helper events."""

from __future__ import annotations

import json
import os
from pathlib import Path
import stat
from dataclasses import dataclass

from .privileged_helper import AuditEvent


MAX_AUDIT_RECORD_BYTES = 4096


class AuditSinkError(OSError):
    """Raised when protected audit storage cannot be trusted."""


@dataclass(frozen=True, slots=True)
class ProductionAuditEvent:
    timestamp: str
    request_id: str
    lifecycle: str
    uid: int
    pid: int
    session_id: str
    seat_id: str
    action: str
    parameter_digest: str
    authorization_id: str
    authorization_outcome: str
    terminal_status: str | None = None
    exit_code: int | None = None
    backup_id: str | None = None
    error_code: str | None = None


class ProtectedAuditSink:
    def __init__(self, path: str | os.PathLike[str], *, expected_uid: int = 0) -> None:
        if isinstance(expected_uid, bool) or not isinstance(expected_uid, int) or expected_uid < 0:
            raise AuditSinkError("expected_uid must be a non-negative integer")
        self.path = Path(path)
        self.expected_uid = expected_uid

    def __call__(self, event: AuditEvent) -> bool:
        if not isinstance(event, AuditEvent):
            raise AuditSinkError("audit event has the wrong type")
        return self._append({
            "action": event.action,
            "authorization_id": event.authorization_id,
            "detail": event.detail,
            "outcome": event.outcome,
            "request_id": event.request_id,
        })

    def _append(self, value: dict[str, object]) -> bool:
        parent = self.path.parent
        try:
            parent_metadata = parent.stat(follow_symlinks=False)
        except OSError as error:
            raise AuditSinkError("audit directory is unavailable") from error
        if (
            not stat.S_ISDIR(parent_metadata.st_mode)
            or parent_metadata.st_uid != self.expected_uid
            or parent_metadata.st_mode & 0o077
        ):
            raise AuditSinkError("audit directory ownership or mode is unsafe")

        record = json.dumps(
            value,
            ensure_ascii=True,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("ascii") + b"\n"
        if len(record) > MAX_AUDIT_RECORD_BYTES:
            raise AuditSinkError("audit record exceeds its size limit")

        flags = (
            os.O_WRONLY
            | os.O_APPEND
            | os.O_CREAT
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOFOLLOW", 0)
        )
        try:
            descriptor = os.open(self.path, flags, 0o600)
        except OSError as error:
            raise AuditSinkError("audit file cannot be opened safely") from error
        try:
            metadata = os.fstat(descriptor)
            if (
                not stat.S_ISREG(metadata.st_mode)
                or metadata.st_uid != self.expected_uid
                or metadata.st_mode & 0o177
                or metadata.st_nlink != 1
            ):
                raise AuditSinkError("audit file ownership, mode, or link count is unsafe")
            view = memoryview(record)
            while view:
                written = os.write(descriptor, view)
                if written <= 0:
                    raise AuditSinkError("audit write did not make progress")
                view = view[written:]
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        return True


class ProtectedProductionAuditSink(ProtectedAuditSink):
    """Protected writer for credential-bound production lifecycle events."""

    def __call__(self, event: ProductionAuditEvent) -> bool:
        if not isinstance(event, ProductionAuditEvent):
            raise AuditSinkError("production audit event has the wrong type")
        return self._append({
            "action": event.action,
            "authorization_id": event.authorization_id,
            "authorization_outcome": event.authorization_outcome,
            "backup_id": event.backup_id,
            "error_code": event.error_code,
            "exit_code": event.exit_code,
            "lifecycle": event.lifecycle,
            "parameter_digest": event.parameter_digest,
            "pid": event.pid,
            "request_id": event.request_id,
            "seat_id": event.seat_id,
            "session_id": event.session_id,
            "terminal_status": event.terminal_status,
            "timestamp": event.timestamp,
            "uid": event.uid,
        })
