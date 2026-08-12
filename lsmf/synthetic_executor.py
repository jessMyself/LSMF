"""Manifest-only synthetic executor for disposable Gate-2 fixture targets.

This engine runs no subprocess and accepts no path from a request. All target
paths and desired bytes come from a prevalidated trusted manifest. Filesystem
access is descriptor-relative beneath explicitly supplied synthetic roots.
"""

from __future__ import annotations

import base64
from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import PurePosixPath
import re
import stat
import threading
from typing import Callable

from .production_protocol import (
    ErrorDetail,
    PRODUCTION_PROTOCOL_VERSION,
    ProductionRequest,
    ProductionResult,
    ProductionStatus,
)
from .privileged_protocol import Action
from .trusted_manifest import SyntheticModule, TrustedManifest


MAX_TARGET_BYTES = 65_536
BACKUP_VERSION = 1
_BACKUP_ID = re.compile(r"^(?:backup|recovery)-[0-9a-f]{8}-[0-9a-f-]{27}$")


class SyntheticExecutorError(RuntimeError):
    """Raised when a synthetic operation cannot be completed safely."""

    def __init__(self, message: str, *, backup_id: str | None = None) -> None:
        super().__init__(message)
        self.backup_id = backup_id


class SyntheticRecoveryRequired(SyntheticExecutorError):
    """Raised when verified restoration failed and mutation must stay blocked."""


class SyntheticCancelled(SyntheticExecutorError):
    """Raised at a safe checkpoint after cancellation or timeout was requested."""

    def __init__(self, timed_out: bool, *, backup_id: str | None = None) -> None:
        super().__init__("synthetic operation timed out" if timed_out else "synthetic operation cancelled", backup_id=backup_id)
        self.timed_out = timed_out


class CancellationToken:
    """Thread-safe one-way cancellation state shared with the async dispatcher."""

    def __init__(self) -> None:
        self._event = threading.Event()
        self._timed_out = False

    def cancel(self, *, timed_out: bool = False) -> None:
        if timed_out:
            self._timed_out = True
        self._event.set()

    def checkpoint(self, *, backup_id: str | None = None) -> None:
        if self._event.is_set():
            raise SyntheticCancelled(self._timed_out, backup_id=backup_id)

    @property
    def cancelled(self) -> bool:
        return self._event.is_set()

    @property
    def timed_out(self) -> bool:
        return self._timed_out


@dataclass(frozen=True, slots=True)
class FileSnapshot:
    relative_target: str
    present: bool
    mode: int | None
    content: bytes

    def __post_init__(self) -> None:
        path = PurePosixPath(self.relative_target)
        if path.is_absolute() or not path.parts or any(part in {"", ".", ".."} for part in path.parts):
            raise SyntheticExecutorError("snapshot target is unsafe")
        if not isinstance(self.present, bool) or not isinstance(self.content, bytes) or len(self.content) > MAX_TARGET_BYTES:
            raise SyntheticExecutorError("snapshot content is invalid")
        if self.present:
            if isinstance(self.mode, bool) or not isinstance(self.mode, int) or not 0 <= self.mode <= 0o777:
                raise SyntheticExecutorError("snapshot mode is invalid")
        elif self.mode is not None or self.content:
            raise SyntheticExecutorError("absent snapshot contains file data")

    @property
    def digest(self) -> str:
        return hashlib.sha256(self.content).hexdigest()


class TrustedTree:
    """No-follow descriptor-relative access to one private synthetic tree."""

    def __init__(self, root: str | os.PathLike[str], *, expected_uid: int = 0) -> None:
        self.expected_uid = expected_uid
        flags = os.O_RDONLY | os.O_DIRECTORY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
        try:
            self._root_fd = os.open(root, flags)
        except OSError as error:
            raise SyntheticExecutorError("synthetic root cannot be opened safely") from error
        try:
            self._validate_directory(self._root_fd)
        except Exception:
            os.close(self._root_fd)
            raise

    def close(self) -> None:
        if self._root_fd >= 0:
            os.close(self._root_fd)
            self._root_fd = -1

    def __enter__(self) -> TrustedTree:
        return self

    def __exit__(self, *args: object) -> None:
        self.close()

    def snapshot(self, relative_target: str) -> FileSnapshot:
        parent, name = self._open_parent(relative_target)
        try:
            try:
                descriptor = os.open(
                    name,
                    os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0),
                    dir_fd=parent,
                )
            except FileNotFoundError:
                return FileSnapshot(relative_target, False, None, b"")
            except OSError as error:
                raise SyntheticExecutorError("synthetic target cannot be opened safely") from error
            try:
                before = self._validate_file(descriptor)
                content = self._read_bounded(descriptor)
                after = os.fstat(descriptor)
                if (before.st_dev, before.st_ino, before.st_size) != (after.st_dev, after.st_ino, after.st_size):
                    raise SyntheticExecutorError("synthetic target changed while reading")
                return FileSnapshot(relative_target, True, stat.S_IMODE(before.st_mode), content)
            finally:
                os.close(descriptor)
        finally:
            os.close(parent)

    def replace(self, snapshot: FileSnapshot) -> None:
        parent, name = self._open_parent(snapshot.relative_target)
        temporary = f".{name}.lsmf-{os.getpid()}"
        try:
            current = self.snapshot(snapshot.relative_target)
            if not snapshot.present:
                if current.present:
                    os.unlink(name, dir_fd=parent)
                    os.fsync(parent)
                return
            if len(snapshot.content) > MAX_TARGET_BYTES:
                raise SyntheticExecutorError("synthetic content exceeds its size limit")
            try:
                descriptor = os.open(
                    temporary,
                    os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0),
                    snapshot.mode if snapshot.mode is not None else 0o600,
                    dir_fd=parent,
                )
            except OSError as error:
                raise SyntheticExecutorError("temporary synthetic target cannot be created") from error
            try:
                self._write_all(descriptor, snapshot.content)
                os.fchmod(descriptor, snapshot.mode if snapshot.mode is not None else 0o600)
                os.fsync(descriptor)
            finally:
                os.close(descriptor)
            os.replace(temporary, name, src_dir_fd=parent, dst_dir_fd=parent)
            os.fsync(parent)
            if self.snapshot(snapshot.relative_target) != snapshot:
                raise SyntheticExecutorError("synthetic target verification failed")
        finally:
            try:
                os.unlink(temporary, dir_fd=parent)
            except FileNotFoundError:
                pass
            os.close(parent)

    def _open_parent(self, relative_target: str) -> tuple[int, str]:
        path = PurePosixPath(relative_target)
        if path.is_absolute() or len(path.parts) < 1 or any(part in {"", ".", ".."} for part in path.parts):
            raise SyntheticExecutorError("manifest target is not canonical and relative")
        descriptor = os.dup(self._root_fd)
        try:
            for component in path.parts[:-1]:
                next_fd = os.open(
                    component,
                    os.O_RDONLY | os.O_DIRECTORY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0),
                    dir_fd=descriptor,
                )
                os.close(descriptor)
                descriptor = next_fd
                self._validate_directory(descriptor)
            return descriptor, path.parts[-1]
        except Exception as error:
            os.close(descriptor)
            if isinstance(error, SyntheticExecutorError):
                raise
            raise SyntheticExecutorError("synthetic target parent is unsafe") from error

    def _validate_directory(self, descriptor: int) -> None:
        metadata = os.fstat(descriptor)
        if not stat.S_ISDIR(metadata.st_mode) or metadata.st_uid != self.expected_uid or metadata.st_mode & 0o022:
            raise SyntheticExecutorError("synthetic directory ownership or mode is unsafe")

    def _validate_file(self, descriptor: int) -> os.stat_result:
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_uid != self.expected_uid
            or metadata.st_mode & 0o022
            or metadata.st_nlink != 1
            or metadata.st_size > MAX_TARGET_BYTES
        ):
            raise SyntheticExecutorError("synthetic target ownership, mode, or type is unsafe")
        return metadata

    @staticmethod
    def _read_bounded(descriptor: int) -> bytes:
        chunks: list[bytes] = []
        remaining = MAX_TARGET_BYTES + 1
        while remaining:
            chunk = os.read(descriptor, min(remaining, 8192))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        content = b"".join(chunks)
        if len(content) > MAX_TARGET_BYTES:
            raise SyntheticExecutorError("synthetic target exceeds its size limit")
        return content

    @staticmethod
    def _write_all(descriptor: int, content: bytes) -> None:
        view = memoryview(content)
        while view:
            written = os.write(descriptor, view)
            if written <= 0:
                raise SyntheticExecutorError("synthetic write did not make progress")
            view = view[written:]


class SyntheticBackupStore:
    """Exact, private backup manifests containing only synthetic snapshots."""

    def __init__(self, root: str | os.PathLike[str], *, expected_uid: int = 0) -> None:
        self.root = os.fspath(root)
        self.expected_uid = expected_uid
        self._validate_root()

    def create(self, backup_id: str, snapshots: tuple[FileSnapshot, ...]) -> None:
        self._validate_id(backup_id)
        try:
            os.mkdir(os.path.join(self.root, backup_id), 0o700)
        except OSError as error:
            raise SyntheticExecutorError("backup set cannot be created") from error
        directory = os.path.join(self.root, backup_id)
        try:
            payload = {
                "version": BACKUP_VERSION,
                "backup_id": backup_id,
                "files": [
                    {
                        "relative_target": item.relative_target,
                        "present": item.present,
                        "mode": item.mode,
                        "content": base64.b64encode(item.content).decode("ascii"),
                        "sha256": item.digest,
                    }
                    for item in snapshots
                ],
            }
            raw = json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("ascii")
            descriptor = os.open(
                os.path.join(directory, "manifest.json"),
                os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0),
                0o600,
            )
            try:
                TrustedTree._write_all(descriptor, raw)
                os.fsync(descriptor)
            finally:
                os.close(descriptor)
            directory_fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY | getattr(os, "O_NOFOLLOW", 0))
            try:
                os.fsync(directory_fd)
            finally:
                os.close(directory_fd)
            if self.load(backup_id) != snapshots:
                raise SyntheticExecutorError("backup validation failed")
            self._fsync_root()
        except Exception:
            raise

    def load(self, backup_id: str) -> tuple[FileSnapshot, ...]:
        self._validate_id(backup_id)
        directory = os.path.join(self.root, backup_id)
        try:
            directory_fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY | getattr(os, "O_NOFOLLOW", 0))
        except OSError as error:
            raise SyntheticExecutorError("backup set is unavailable") from error
        try:
            self._validate_metadata(os.fstat(directory_fd), directory=True)
            descriptor = os.open("manifest.json", os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0), dir_fd=directory_fd)
            try:
                metadata = os.fstat(descriptor)
                self._validate_metadata(metadata, directory=False)
                if metadata.st_size > MAX_TARGET_BYTES:
                    raise SyntheticExecutorError("backup manifest exceeds its size limit")
                raw = TrustedTree._read_bounded(descriptor)
            finally:
                os.close(descriptor)
        except (OSError, UnicodeError, ValueError, KeyError, TypeError) as error:
            raise SyntheticExecutorError("backup manifest is unsafe or malformed") from error
        finally:
            os.close(directory_fd)
        return self._decode(raw, backup_id)

    def eligible(self, backup_id: str) -> bool:
        try:
            self.load(backup_id)
            return True
        except SyntheticExecutorError:
            return False

    def mark_recovery_required(self, backup_id: str) -> None:
        self._validate_id(backup_id)
        if not self.eligible(backup_id):
            raise SyntheticExecutorError("recovery backup is unavailable")
        path = os.path.join(self.root, "recovery-required")
        try:
            descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
        except FileExistsError:
            self.recovery_backup_id()
            return
        try:
            TrustedTree._write_all(descriptor, (backup_id + "\n").encode("ascii"))
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        self._fsync_root()

    def recovery_required(self) -> bool:
        return self.recovery_backup_id() is not None

    def recovery_backup_id(self) -> str | None:
        """Return the exact eligible recovery snapshot, failing closed on damage."""
        root_fd = os.open(
            self.root,
            os.O_RDONLY | os.O_DIRECTORY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0),
        )
        try:
            self._validate_metadata(os.fstat(root_fd), directory=True)
            try:
                descriptor = os.open(
                    "recovery-required",
                    os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0),
                    dir_fd=root_fd,
                )
            except FileNotFoundError:
                return None
            try:
                metadata = os.fstat(descriptor)
                self._validate_metadata(metadata, directory=False)
                if metadata.st_size > 64:
                    raise SyntheticExecutorError("recovery marker exceeds its size limit")
                raw = os.read(descriptor, 65)
            finally:
                os.close(descriptor)
        except OSError as error:
            raise SyntheticExecutorError("recovery marker is unsafe") from error
        finally:
            os.close(root_fd)
        try:
            backup_id = raw.decode("ascii")
        except UnicodeError as error:
            raise SyntheticExecutorError("recovery marker is malformed") from error
        if not backup_id.endswith("\n") or "\n" in backup_id[:-1]:
            raise SyntheticExecutorError("recovery marker is malformed")
        backup_id = backup_id[:-1]
        self._validate_id(backup_id)
        if not self.eligible(backup_id):
            raise SyntheticExecutorError("recovery backup is unavailable")
        return backup_id

    def clear_recovery_required(self, expected_backup_id: str) -> None:
        """Durably clear only the validated marker that was just recovered."""
        self._validate_id(expected_backup_id)
        if self.recovery_backup_id() != expected_backup_id:
            raise SyntheticExecutorError("recovery marker does not match the restored backup")
        try:
            os.unlink(os.path.join(self.root, "recovery-required"))
        except OSError as error:
            raise SyntheticExecutorError("recovery marker could not be cleared") from error
        self._fsync_root()

    def _fsync_root(self) -> None:
        root_fd = os.open(
            self.root,
            os.O_RDONLY | os.O_DIRECTORY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0),
        )
        try:
            self._validate_metadata(os.fstat(root_fd), directory=True)
            os.fsync(root_fd)
        finally:
            os.close(root_fd)

    def _decode(self, raw: bytes, backup_id: str) -> tuple[FileSnapshot, ...]:
        try:
            value = json.loads(raw.decode("ascii"), object_pairs_hook=self._reject_duplicates)
            if set(value) != {"version", "backup_id", "files"} or value["version"] != 1 or value["backup_id"] != backup_id:
                raise ValueError
            if not isinstance(value["files"], list) or not value["files"] or len(value["files"]) > 32:
                raise ValueError
            snapshots = []
            for item in value["files"]:
                if set(item) != {"relative_target", "present", "mode", "content", "sha256"}:
                    raise ValueError
                content = base64.b64decode(item["content"], validate=True)
                snapshot = FileSnapshot(item["relative_target"], item["present"], item["mode"], content)
                if snapshot.digest != item["sha256"] or not isinstance(snapshot.present, bool):
                    raise ValueError
                snapshots.append(snapshot)
            if len({item.relative_target for item in snapshots}) != len(snapshots):
                raise ValueError
            return tuple(snapshots)
        except Exception as error:
            raise SyntheticExecutorError("backup manifest is unsafe or malformed") from error

    @staticmethod
    def _reject_duplicates(pairs: list[tuple[str, object]]) -> dict[str, object]:
        value: dict[str, object] = {}
        for key, item in pairs:
            if key in value:
                raise ValueError("duplicate backup manifest field")
            value[key] = item
        return value

    def _validate_root(self) -> None:
        metadata = os.stat(self.root, follow_symlinks=False)
        self._validate_metadata(metadata, directory=True)

    def _validate_metadata(self, metadata: os.stat_result, *, directory: bool) -> None:
        expected_type = stat.S_ISDIR(metadata.st_mode) if directory else stat.S_ISREG(metadata.st_mode)
        if not expected_type or metadata.st_uid != self.expected_uid or metadata.st_mode & 0o077:
            raise SyntheticExecutorError("backup ownership or mode is unsafe")
        if not directory and metadata.st_nlink != 1:
            raise SyntheticExecutorError("backup manifest link count is unsafe")

    @staticmethod
    def _validate_id(backup_id: str) -> None:
        if not isinstance(backup_id, str) or not _BACKUP_ID.fullmatch(backup_id):
            raise SyntheticExecutorError("backup ID is not synthetic and canonical")


class SyntheticExecutor:
    """Execute typed production requests only against manifest fixture files."""

    def __init__(
        self,
        manifest: TrustedManifest,
        target_root: str | os.PathLike[str],
        backup_root: str | os.PathLike[str],
        *,
        expected_uid: int = 0,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        if not isinstance(manifest, TrustedManifest):
            raise SyntheticExecutorError("trusted manifest is required")
        self.manifest = manifest
        self.target_root = os.fspath(target_root)
        self.backups = SyntheticBackupStore(backup_root, expected_uid=expected_uid)
        self.expected_uid = expected_uid
        self.clock = clock if clock is not None else lambda: datetime.now(timezone.utc)

    def execute(self, request: ProductionRequest, cancellation: CancellationToken | None = None) -> ProductionResult:
        started = self._timestamp()
        token = cancellation if cancellation is not None else CancellationToken()
        try:
            token.checkpoint()
            modules = self._modules(request)
            if request.action is Action.AUDIT:
                with TrustedTree(self.target_root, expected_uid=self.expected_uid) as tree:
                    findings = 0
                    for item in modules:
                        token.checkpoint()
                        findings += not self._matches(tree.snapshot(item.relative_target), item)
                return self._result(request, started, ProductionStatus.SUCCEEDED, "Synthetic audit complete", finding_count=findings)
            if request.action is Action.VERIFY_MODULE:
                token.checkpoint()
                with TrustedTree(self.target_root, expected_uid=self.expected_uid) as tree:
                    matches = self._matches(tree.snapshot(modules[0].relative_target), modules[0])
                status = ProductionStatus.SUCCEEDED if matches else ProductionStatus.FAILED
                return self._result(request, started, status, "Synthetic verification complete" if matches else "Synthetic verification found a mismatch", exit_code=0 if matches else 1, module_ids=request.module_ids)
            recovery_backup_id = self.backups.recovery_backup_id()
            if request.action in {Action.APPLY_MODULE, Action.APPLY_MODULES}:
                if recovery_backup_id is not None:
                    raise SyntheticRecoveryRequired(
                        "synthetic recovery is required", backup_id=recovery_backup_id
                    )
                return self._apply(request, modules, started, token)
            if recovery_backup_id is not None and request.backup_id != recovery_backup_id:
                raise SyntheticRecoveryRequired(
                    "exact synthetic recovery is required", backup_id=recovery_backup_id
                )
            result = self._rollback(request, started, token)
            if recovery_backup_id is not None:
                self.backups.clear_recovery_required(recovery_backup_id)
            return result
        except SyntheticCancelled as error:
            status = ProductionStatus.TIMED_OUT if error.timed_out else ProductionStatus.CANCELLED
            code = "timed_out" if error.timed_out else "cancelled"
            summary = "Synthetic operation timed out" if error.timed_out else "Synthetic operation cancelled"
            return self._failure_result(request, started, summary, code, summary, error.backup_id, status=status)
        except SyntheticRecoveryRequired as error:
            return self._failure_result(request, started, "Synthetic recovery is required", "recovery_required", "Verified recovery is required", error.backup_id)
        except SyntheticExecutorError as error:
            return self._failure_result(request, started, "Synthetic execution failed", "synthetic_failed", "Synthetic operation failed", error.backup_id)
        except Exception:
            return self._failure_result(request, started, "Synthetic execution failed", "synthetic_failed", "Synthetic operation failed", None)

    def _apply(self, request: ProductionRequest, modules: tuple[SyntheticModule, ...], started: str, token: CancellationToken) -> ProductionResult:
        backup_id = f"backup-{request.request_id}"
        with TrustedTree(self.target_root, expected_uid=self.expected_uid) as tree:
            token.checkpoint()
            snapshots = tuple(tree.snapshot(item.relative_target) for item in modules)
            token.checkpoint()
            self.backups.create(backup_id, snapshots)
            try:
                for item in modules:
                    token.checkpoint(backup_id=backup_id)
                    current = tree.snapshot(item.relative_target)
                    mode = current.mode if current.mode is not None else 0o600
                    desired = FileSnapshot(item.relative_target, True, mode, item.desired_content.encode())
                    if current != desired:
                        tree.replace(desired)
                if any(not self._matches(tree.snapshot(item.relative_target), item) for item in modules):
                    raise SyntheticExecutorError("apply verification failed")
                token.checkpoint(backup_id=backup_id)
            except SyntheticCancelled as error:
                try:
                    self._restore(tree, snapshots)
                except Exception:
                    self.backups.mark_recovery_required(backup_id)
                    raise SyntheticRecoveryRequired("apply cancellation recovery failed", backup_id=backup_id) from error
                raise
            except Exception as error:
                try:
                    self._restore(tree, snapshots)
                except Exception:
                    self.backups.mark_recovery_required(backup_id)
                    raise SyntheticRecoveryRequired("apply recovery failed", backup_id=backup_id) from error
                raise SyntheticExecutorError("apply failed and was restored", backup_id=backup_id) from error
        return self._result(request, started, ProductionStatus.SUCCEEDED, "Synthetic apply complete", module_ids=request.module_ids, backup_id=backup_id)

    def _rollback(self, request: ProductionRequest, started: str, token: CancellationToken) -> ProductionResult:
        if request.backup_id is None:
            raise SyntheticExecutorError("backup ID is required")
        snapshots = self.backups.load(request.backup_id)
        allowed_targets = {item.relative_target for item in self.manifest.modules.values()}
        if not snapshots or any(item.relative_target not in allowed_targets for item in snapshots):
            raise SyntheticExecutorError("backup contains a non-manifest target", backup_id=request.backup_id)
        recovery_id = f"recovery-{request.request_id}"
        with TrustedTree(self.target_root, expected_uid=self.expected_uid) as tree:
            token.checkpoint()
            current = tuple(tree.snapshot(item.relative_target) for item in snapshots)
            token.checkpoint()
            self.backups.create(recovery_id, current)
            try:
                token.checkpoint(backup_id=request.backup_id)
                self._restore(tree, snapshots)
                token.checkpoint(backup_id=request.backup_id)
            except SyntheticCancelled as error:
                try:
                    self._restore(tree, current)
                except Exception:
                    self.backups.mark_recovery_required(recovery_id)
                    raise SyntheticRecoveryRequired("rollback cancellation recovery failed", backup_id=recovery_id) from error
                raise
            except Exception as error:
                try:
                    self._restore(tree, current)
                except Exception:
                    self.backups.mark_recovery_required(recovery_id)
                    raise SyntheticRecoveryRequired("rollback recovery failed", backup_id=recovery_id) from error
                raise SyntheticExecutorError("rollback failed and was restored", backup_id=request.backup_id) from error
        module_ids = self._module_ids_for_snapshots(snapshots)
        return self._result(request, started, ProductionStatus.SUCCEEDED, "Synthetic rollback complete", module_ids=module_ids, backup_id=request.backup_id)

    @staticmethod
    def _restore(tree: TrustedTree, snapshots: tuple[FileSnapshot, ...]) -> None:
        for snapshot in snapshots:
            tree.replace(snapshot)
        if any(tree.snapshot(item.relative_target) != item for item in snapshots):
            raise SyntheticExecutorError("restored synthetic state did not verify")

    def _modules(self, request: ProductionRequest) -> tuple[SyntheticModule, ...]:
        if request.action is Action.AUDIT:
            return tuple(self.manifest.modules.values())
        if request.action is Action.ROLLBACK_BACKUP:
            return ()
        try:
            modules = tuple(self.manifest.modules[module_id] for module_id in request.module_ids)
        except KeyError as error:
            raise SyntheticExecutorError("module is not in the trusted manifest") from error
        capability = "verify" if request.action is Action.VERIFY_MODULE else "apply"
        if any(capability not in item.capabilities for item in modules):
            raise SyntheticExecutorError("module capability is not allowlisted")
        return modules

    def _backup_modules(self, backup_id: str | None) -> tuple[str, ...]:
        if backup_id is None:
            return ()
        try:
            return self._module_ids_for_snapshots(self.backups.load(backup_id))
        except Exception:
            return ()

    def _module_ids_for_snapshots(self, snapshots: tuple[FileSnapshot, ...]) -> tuple[str, ...]:
        targets = {item.relative_target for item in snapshots}
        return tuple(item.module_id for item in self.manifest.modules.values() if item.relative_target in targets)

    @staticmethod
    def _matches(snapshot: FileSnapshot, module: SyntheticModule) -> bool:
        return snapshot.present and snapshot.content == module.desired_content.encode()

    def _result(self, request: ProductionRequest, started: str, status: ProductionStatus, summary: str, *, exit_code: int | None = 0, module_ids: tuple[str, ...] = (), backup_id: str | None = None, finding_count: int | None = None, error: ErrorDetail | None = None) -> ProductionResult:
        return ProductionResult(PRODUCTION_PROTOCOL_VERSION, request.request_id, request.action, status, started, self._timestamp(), exit_code, summary, "", False, error, module_ids, backup_id, finding_count)

    def _failure_result(self, request: ProductionRequest, started: str, summary: str, code: str, message: str, committed_backup_id: str | None, *, status: ProductionStatus = ProductionStatus.FAILED) -> ProductionResult:
        finding_count = 0 if request.action is Action.AUDIT else None
        backup_id = committed_backup_id
        if request.action is Action.ROLLBACK_BACKUP and backup_id is None:
            backup_id = request.backup_id
        module_ids = request.module_ids
        if request.action is Action.ROLLBACK_BACKUP:
            module_ids = self._backup_modules(request.backup_id)
        return self._result(
            request,
            started,
            status,
            summary,
            exit_code=1,
            module_ids=module_ids,
            backup_id=backup_id,
            finding_count=finding_count,
            error=ErrorDetail(code, message),
        )

    def _timestamp(self) -> str:
        value = self.clock().astimezone(timezone.utc)
        return value.isoformat(timespec="seconds").replace("+00:00", "Z")
