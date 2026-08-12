"""Backup-first Section 3 sysctl apply and exact rollback transaction."""

from __future__ import annotations

import base64
from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
from typing import Callable, Protocol

from .privileged_protocol import Action
from .production_protocol import (
    ErrorDetail,
    PRODUCTION_PROTOCOL_VERSION,
    ProductionRequest,
    ProductionResult,
    ProductionStatus,
)
from .synthetic_executor import CancellationToken, SyntheticCancelled
from .sysctl_manifest import SysctlManifest, SysctlManifestPolicy, SysctlModule


_BACKUP_ID = re.compile(r"^(?:backup|recovery)-[0-9a-f]{8}-[0-9a-f-]{27}$")
MAX_FILE_BYTES = 65_536
MAX_BACKUP_BYTES = 1_048_576


class SysctlTransactionError(RuntimeError):
    """Raised when a Section 3 transaction cannot remain exact and bounded."""


@dataclass(frozen=True, slots=True)
class ManagedFileSnapshot:
    relative_path: str
    existed: bool
    mode: int
    uid: int
    gid: int
    content: bytes


@dataclass(frozen=True, slots=True)
class TransactionSnapshot:
    backup_id: str
    manifest_digest: str
    module_ids: tuple[str, ...]
    files: tuple[ManagedFileSnapshot, ...]
    sysctls: tuple[tuple[str, str], ...]


class SysctlValues(Protocol):
    def read(self, key: str) -> str: ...
    def write(self, key: str, value: str) -> None: ...


def _canonical_json(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")


def _validate_backup_id(value: str) -> None:
    if not isinstance(value, str) or not _BACKUP_ID.fullmatch(value):
        raise SysctlTransactionError("backup ID is invalid")


def _canonical_sysctl_value(value: str) -> str:
    """Normalize procfs whitespace while preserving exact numeric tokens."""
    if not isinstance(value, str):
        raise SysctlTransactionError("sysctl value is invalid")
    return " ".join(value.split())


class RootedManagedFiles:
    """Fixed-root file adapter that rejects symlink traversal and special files."""

    def __init__(self, root: str | Path, *, expected_uid: int) -> None:
        self.root = Path(root)
        if not self.root.is_absolute() or self.root.is_symlink() or not self.root.is_dir():
            raise SysctlTransactionError("managed file root is unsafe")
        metadata = self.root.stat(follow_symlinks=False)
        if metadata.st_uid != expected_uid or metadata.st_mode & 0o022:
            raise SysctlTransactionError("managed file root ownership or mode is unsafe")
        self.expected_uid = expected_uid

    def _path(self, relative: str) -> Path:
        pure = PurePosixPath(relative)
        if pure.is_absolute() or any(part in {"", ".", ".."} for part in pure.parts):
            raise SysctlTransactionError("managed path is invalid")
        path = self.root.joinpath(*pure.parts)
        current = self.root
        for part in pure.parts[:-1]:
            current = current / part
            if current.is_symlink() or not current.is_dir():
                raise SysctlTransactionError("managed path parent is unsafe")
        return path

    def snapshot(self, relative: str) -> ManagedFileSnapshot:
        path = self._path(relative)
        if not path.exists():
            return ManagedFileSnapshot(relative, False, 0o600, self.expected_uid, 0, b"")
        if path.is_symlink():
            raise SysctlTransactionError("managed target symlink is unsafe")
        metadata = path.stat(follow_symlinks=False)
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_uid != self.expected_uid:
            raise SysctlTransactionError("managed target ownership or type is unsafe")
        content = path.read_bytes()
        if len(content) > MAX_FILE_BYTES:
            raise SysctlTransactionError("managed target exceeds its size limit")
        return ManagedFileSnapshot(
            relative, True, stat.S_IMODE(metadata.st_mode), metadata.st_uid, metadata.st_gid, content
        )

    def write(self, relative: str, content: bytes, *, mode: int = 0o600) -> None:
        if not isinstance(content, bytes) or len(content) > MAX_FILE_BYTES or mode & ~0o777:
            raise SysctlTransactionError("managed write is invalid")
        path = self._path(relative)
        if path.exists() and (path.is_symlink() or not path.is_file()):
            raise SysctlTransactionError("managed target changed type")
        temporary = path.with_name(f".{path.name}.lsmf-{os.getpid()}")
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0)
        try:
            descriptor = os.open(temporary, flags, mode)
            try:
                offset = 0
                while offset < len(content):
                    offset += os.write(descriptor, content[offset:])
                os.fsync(descriptor)
            finally:
                os.close(descriptor)
            os.replace(temporary, path)
            directory = os.open(path.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
            try:
                os.fsync(directory)
            finally:
                os.close(directory)
        except OSError as error:
            try:
                temporary.unlink(missing_ok=True)
            except OSError:
                pass
            raise SysctlTransactionError("managed target write failed") from error

    def restore(self, snapshot: ManagedFileSnapshot) -> None:
        path = self._path(snapshot.relative_path)
        if snapshot.existed:
            self.write(snapshot.relative_path, snapshot.content, mode=snapshot.mode)
            try:
                os.chown(path, snapshot.uid, snapshot.gid, follow_symlinks=False)
                os.chmod(path, snapshot.mode, follow_symlinks=False)
            except OSError as error:
                raise SysctlTransactionError("managed metadata restore failed") from error
        elif path.exists():
            if path.is_symlink() or not path.is_file():
                raise SysctlTransactionError("managed absent target changed type")
            try:
                path.unlink()
            except OSError as error:
                raise SysctlTransactionError("managed absence restore failed") from error


class ProcSysctlValues:
    """Fixed `/proc/sys` adapter; tests inject an in-memory implementation."""

    def __init__(self, root: str | Path = "/proc/sys") -> None:
        self.root = Path(root)
        if (
            not self.root.is_absolute()
            or self.root.is_symlink()
            or not self.root.is_dir()
        ):
            raise SysctlTransactionError("sysctl root must be an absolute real directory")

    def _path(self, key: str) -> Path:
        if not re.fullmatch(r"[a-z][a-z0-9_]*(?:\.[a-z0-9_]+)+", key):
            raise SysctlTransactionError("sysctl key is invalid")
        return self.root.joinpath(*key.split("."))

    def read(self, key: str) -> str:
        try:
            descriptor = os.open(
                self._path(key),
                os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0),
            )
            try:
                raw = os.read(descriptor, 1025)
            finally:
                os.close(descriptor)
            if len(raw) > 1024:
                raise SysctlTransactionError("sysctl value exceeds its size limit")
            return raw.decode("ascii").strip()
        except (OSError, UnicodeError) as error:
            raise SysctlTransactionError("sysctl read failed") from error

    def write(self, key: str, value: str) -> None:
        try:
            raw = (value + "\n").encode("ascii")
            descriptor = os.open(
                self._path(key),
                os.O_WRONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0),
            )
            try:
                offset = 0
                while offset < len(raw):
                    offset += os.write(descriptor, raw[offset:])
            finally:
                os.close(descriptor)
        except (OSError, UnicodeError) as error:
            raise SysctlTransactionError("sysctl write failed") from error


class SysctlBackupStore:
    """Durable, integrity-checked snapshots and one exact recovery marker."""

    def __init__(self, root: str | Path, *, expected_uid: int) -> None:
        self.root = Path(root)
        if not self.root.is_absolute() or self.root.is_symlink() or not self.root.is_dir():
            raise SysctlTransactionError("backup root is unsafe")
        metadata = self.root.stat(follow_symlinks=False)
        if metadata.st_uid != expected_uid or metadata.st_mode & 0o077:
            raise SysctlTransactionError("backup root ownership or mode is unsafe")
        self.expected_uid = expected_uid

    def _directory(self, backup_id: str) -> Path:
        _validate_backup_id(backup_id)
        return self.root / backup_id

    def _fsync_root(self) -> None:
        descriptor = os.open(self.root, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)

    def create(self, snapshot: TransactionSnapshot) -> None:
        _validate_backup_id(snapshot.backup_id)
        directory = self._directory(snapshot.backup_id)
        try:
            directory.mkdir(mode=0o700)
            self._fsync_root()
        except OSError as error:
            raise SysctlTransactionError("backup ID already exists or cannot be created") from error
        payload = {
            "version": 1,
            "backup_id": snapshot.backup_id,
            "manifest_digest": snapshot.manifest_digest,
            "module_ids": list(snapshot.module_ids),
            "files": [
                {
                    "relative_path": item.relative_path,
                    "existed": item.existed,
                    "mode": item.mode,
                    "uid": item.uid,
                    "gid": item.gid,
                    "content": base64.b64encode(item.content).decode("ascii"),
                    "sha256": hashlib.sha256(item.content).hexdigest(),
                }
                for item in snapshot.files
            ],
            "sysctls": [{"key": key, "value": value} for key, value in snapshot.sysctls],
        }
        encoded_payload = _canonical_json(payload)
        envelope = _canonical_json({
            "payload": payload,
            "sha256": hashlib.sha256(encoded_payload).hexdigest(),
        })
        if len(envelope) > MAX_BACKUP_BYTES:
            raise SysctlTransactionError("backup exceeds its size limit")
        path = directory / "snapshot.json"
        try:
            descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            try:
                offset = 0
                while offset < len(envelope):
                    offset += os.write(descriptor, envelope[offset:])
                os.fsync(descriptor)
            finally:
                os.close(descriptor)
            parent = os.open(directory, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
            try:
                os.fsync(parent)
            finally:
                os.close(parent)
            if self.load(snapshot.backup_id) != snapshot:
                raise SysctlTransactionError("backup validation mismatch")
        except Exception:
            raise

    def load(self, backup_id: str) -> TransactionSnapshot:
        path = self._directory(backup_id) / "snapshot.json"
        try:
            metadata = path.stat(follow_symlinks=False)
            if (
                not stat.S_ISREG(metadata.st_mode)
                or metadata.st_uid != self.expected_uid
                or metadata.st_mode & 0o077
                or metadata.st_nlink != 1
                or metadata.st_size > MAX_BACKUP_BYTES
            ):
                raise SysctlTransactionError("backup snapshot metadata is unsafe")
            envelope = json.loads(path.read_text(encoding="ascii"))
        except (OSError, UnicodeError, json.JSONDecodeError) as error:
            raise SysctlTransactionError("backup snapshot is unavailable") from error
        if not isinstance(envelope, dict) or set(envelope) != {"payload", "sha256"}:
            raise SysctlTransactionError("backup envelope is invalid")
        payload = envelope["payload"]
        if hashlib.sha256(_canonical_json(payload)).hexdigest() != envelope["sha256"]:
            raise SysctlTransactionError("backup integrity check failed")
        if not isinstance(payload, dict) or set(payload) != {
            "version", "backup_id", "manifest_digest", "module_ids", "files", "sysctls"
        } or payload["version"] != 1 or payload["backup_id"] != backup_id:
            raise SysctlTransactionError("backup payload is invalid")
        try:
            files = []
            for item in payload["files"]:
                if set(item) != {"relative_path", "existed", "mode", "uid", "gid", "content", "sha256"}:
                    raise SysctlTransactionError("backup file record is invalid")
                content = base64.b64decode(item["content"], validate=True)
                if hashlib.sha256(content).hexdigest() != item["sha256"]:
                    raise SysctlTransactionError("backup file integrity check failed")
                files.append(ManagedFileSnapshot(
                    item["relative_path"], item["existed"], item["mode"], item["uid"], item["gid"], content
                ))
            sysctls = tuple((item["key"], item["value"]) for item in payload["sysctls"])
            snapshot = TransactionSnapshot(
                backup_id,
                payload["manifest_digest"],
                tuple(payload["module_ids"]),
                tuple(files),
                sysctls,
            )
        except (KeyError, TypeError, ValueError) as error:
            raise SysctlTransactionError("backup record types are invalid") from error
        if len(set(snapshot.module_ids)) != len(snapshot.module_ids) or len(set(sysctls)) != len(sysctls):
            raise SysctlTransactionError("backup contains duplicate records")
        return snapshot

    def eligible(self, backup_id: str, manifest_digest: str | None = None) -> bool:
        try:
            snapshot = self.load(backup_id)
            return manifest_digest is None or snapshot.manifest_digest == manifest_digest
        except Exception:
            return False

    def recovery_backup_id(self) -> str | None:
        marker = self.root / "recovery-required"
        if not marker.exists():
            return None
        try:
            metadata = marker.stat(follow_symlinks=False)
            if not stat.S_ISREG(metadata.st_mode) or metadata.st_uid != self.expected_uid or metadata.st_mode & 0o077:
                raise SysctlTransactionError("recovery marker is unsafe")
            backup_id = marker.read_text(encoding="ascii")
        except (OSError, UnicodeError) as error:
            raise SysctlTransactionError("recovery marker is unavailable") from error
        if not backup_id.endswith("\n") or "\n" in backup_id[:-1]:
            raise SysctlTransactionError("recovery marker is malformed")
        backup_id = backup_id[:-1]
        if not self.eligible(backup_id):
            raise SysctlTransactionError("recovery backup is ineligible")
        return backup_id

    def mark_recovery_required(self, backup_id: str) -> None:
        if not self.eligible(backup_id):
            raise SysctlTransactionError("recovery backup is ineligible")
        current = self.recovery_backup_id()
        if current is not None and current != backup_id:
            raise SysctlTransactionError("a different recovery backup is already required")
        if current == backup_id:
            return
        marker = self.root / "recovery-required"
        descriptor = os.open(marker, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        try:
            raw = (backup_id + "\n").encode("ascii")
            offset = 0
            while offset < len(raw):
                offset += os.write(descriptor, raw[offset:])
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        self._fsync_root()

    def clear_recovery_required(self, backup_id: str) -> None:
        if self.recovery_backup_id() != backup_id:
            raise SysctlTransactionError("recovery marker does not match exact rollback")
        try:
            (self.root / "recovery-required").unlink()
            self._fsync_root()
        except OSError as error:
            raise SysctlTransactionError("recovery marker could not be cleared") from error


class SysctlTransactionExecutor:
    """Execute only the exact typed actions allowed by a prevalidated manifest."""

    def __init__(
        self,
        manifest: SysctlManifest,
        files: RootedManagedFiles,
        sysctls: SysctlValues,
        backups: SysctlBackupStore,
        *,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        if not isinstance(manifest, SysctlManifest):
            raise SysctlTransactionError("typed sysctl manifest is required")
        self.manifest = manifest
        self.files = files
        self.sysctls = sysctls
        self.backups = backups
        self.clock = clock or (lambda: datetime.now(timezone.utc))

    def backup_eligible(self, backup_id: str) -> bool:
        return self.backups.eligible(backup_id, self.manifest.digest)

    def execute(self, request: ProductionRequest, cancellation: CancellationToken) -> ProductionResult:
        if request.action is not Action.ROLLBACK_BACKUP and not SysctlManifestPolicy(
            self.manifest, backup_eligible=self.backup_eligible
        ).validate(request):
            raise SysctlTransactionError("request is outside the exact sysctl manifest policy")
        started = self._now()
        if request.action in {Action.APPLY_MODULE, Action.APPLY_MODULES}:
            return self._apply(request, cancellation, started)
        if request.action is Action.ROLLBACK_BACKUP:
            return self._rollback(request, cancellation, started)
        raise SysctlTransactionError("action is outside the sysctl transaction boundary")

    def _snapshot(self, backup_id: str, modules: tuple[SysctlModule, ...]) -> TransactionSnapshot:
        return TransactionSnapshot(
            backup_id,
            self.manifest.digest,
            tuple(module.module_id for module in modules),
            tuple(self.files.snapshot(module.relative_target) for module in modules),
            tuple((setting.key, self.sysctls.read(setting.key)) for module in modules for setting in module.settings),
        )

    @staticmethod
    def _content(module: SysctlModule) -> bytes:
        return "".join(f"{item.key} = {item.desired_value}\n" for item in module.settings).encode("ascii")

    def _restore(self, snapshot: TransactionSnapshot) -> None:
        for file_snapshot in snapshot.files:
            self.files.restore(file_snapshot)
        for key, value in snapshot.sysctls:
            if _canonical_sysctl_value(self.sysctls.read(key)) != _canonical_sysctl_value(value):
                self.sysctls.write(key, value)
        for file_snapshot in snapshot.files:
            if self.files.snapshot(file_snapshot.relative_path) != file_snapshot:
                raise SysctlTransactionError("file restoration verification failed")
        for key, value in snapshot.sysctls:
            if _canonical_sysctl_value(self.sysctls.read(key)) != _canonical_sysctl_value(value):
                raise SysctlTransactionError("sysctl restoration verification failed")

    def _apply(self, request: ProductionRequest, token: CancellationToken, started: str) -> ProductionResult:
        recovery_id = self.backups.recovery_backup_id()
        if recovery_id is not None:
            return self._failure(request, started, "recovery_required", "Exact rollback is required", recovery_id)
        modules = self.manifest.selected(request.module_ids)
        backup_id = f"backup-{request.request_id}"
        try:
            token.checkpoint()
            snapshot = self._snapshot(backup_id, modules)
            self.backups.create(snapshot)
            token.checkpoint(backup_id=backup_id)
            for module in modules:
                self.files.write(module.relative_target, self._content(module))
                for setting in module.settings:
                    if _canonical_sysctl_value(self.sysctls.read(setting.key)) != setting.desired_value:
                        self.sysctls.write(setting.key, setting.desired_value)
                    token.checkpoint(backup_id=backup_id)
            for module in modules:
                if self.files.snapshot(module.relative_target).content != self._content(module):
                    raise SysctlTransactionError("managed file verification failed")
                for setting in module.settings:
                    if _canonical_sysctl_value(self.sysctls.read(setting.key)) != setting.desired_value:
                        raise SysctlTransactionError("sysctl apply verification failed")
        except SyntheticCancelled as error:
            if error.backup_id is None:
                return self._cancelled(request, started, error.timed_out, None)
            try:
                self._restore(snapshot)
                return self._cancelled(request, started, error.timed_out, backup_id)
            except Exception:
                self.backups.mark_recovery_required(backup_id)
                return self._failure(request, started, "recovery_required", "Cancellation recovery is required", backup_id)
        except Exception:
            if "snapshot" not in locals() or not self.backups.eligible(backup_id):
                return self._failure(request, started, "backup_failed", "Durable backup failed before mutation", None)
            try:
                self._restore(snapshot)
                return self._failure(request, started, "apply_failed", "Apply failed and exact state was restored", backup_id)
            except Exception:
                self.backups.mark_recovery_required(backup_id)
                return self._failure(request, started, "recovery_required", "Apply recovery is required", backup_id)
        return self._success(request, started, "Sysctl apply complete", request.module_ids, backup_id)

    def _rollback(self, request: ProductionRequest, token: CancellationToken, started: str) -> ProductionResult:
        assert request.backup_id is not None
        required = self.backups.recovery_backup_id()
        if required is not None and required != request.backup_id:
            return self._failure(request, started, "recovery_required", "A different exact rollback is required", required)
        try:
            target = self.backups.load(request.backup_id)
            if target.manifest_digest != self.manifest.digest:
                raise SysctlTransactionError("backup belongs to a different manifest")
            modules = self.manifest.selected(target.module_ids)
            recovery_id = f"recovery-{request.request_id}"
            recovery = self._snapshot(recovery_id, modules)
            self.backups.create(recovery)
            token.checkpoint(backup_id=request.backup_id)
            self._restore(target)
            token.checkpoint(backup_id=request.backup_id)
            if required is not None:
                self.backups.clear_recovery_required(request.backup_id)
        except SyntheticCancelled as error:
            try:
                self._restore(recovery)
                return self._cancelled(request, started, error.timed_out, request.backup_id)
            except Exception:
                self.backups.mark_recovery_required(recovery_id)
                return self._failure(request, started, "recovery_required", "Rollback cancellation recovery is required", recovery_id)
        except Exception:
            if "recovery" not in locals() or not self.backups.eligible(recovery_id):
                return self._failure(request, started, "rollback_failed", "Rollback was rejected before mutation", request.backup_id)
            try:
                self._restore(recovery)
                return self._failure(request, started, "rollback_failed", "Rollback failed and current state was restored", request.backup_id)
            except Exception:
                self.backups.mark_recovery_required(recovery_id)
                return self._failure(request, started, "recovery_required", "Rollback recovery is required", recovery_id)
        return self._success(request, started, "Exact rollback complete", target.module_ids, request.backup_id)

    def _success(self, request, started, summary, modules, backup_id):
        return ProductionResult(
            PRODUCTION_PROTOCOL_VERSION, request.request_id, request.action, ProductionStatus.SUCCEEDED,
            started, self._now(), 0, summary, "", False, None, modules, backup_id, None,
        )

    def _failure(self, request, started, code, summary, backup_id):
        return ProductionResult(
            PRODUCTION_PROTOCOL_VERSION, request.request_id, request.action, ProductionStatus.FAILED,
            started, self._now(), 1, summary, "", False, ErrorDetail(code, summary),
            request.module_ids, backup_id, None,
        )

    def _cancelled(self, request, started, timed_out, backup_id):
        status = ProductionStatus.TIMED_OUT if timed_out else ProductionStatus.CANCELLED
        code = "timed_out" if timed_out else "cancelled"
        summary = "Sysctl transaction timed out" if timed_out else "Sysctl transaction cancelled"
        return ProductionResult(
            PRODUCTION_PROTOCOL_VERSION, request.request_id, request.action, status,
            started, self._now(), 1, summary, "", False, ErrorDetail(code, summary),
            request.module_ids, backup_id, None,
        )

    def _now(self) -> str:
        return self.clock().astimezone(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")
