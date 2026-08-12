"""Fixed subprocess boundary for Section 3 sysctl transactions."""

from __future__ import annotations

from pathlib import Path
import sys
from typing import Callable

from .synthetic_process import SyntheticProcessExecutor, SyntheticProcessError
from .sysctl_manifest import load_sysctl_manifest
from .sysctl_transaction import SysctlBackupStore


class SysctlProcessError(SyntheticProcessError):
    """Raised when the Section 3 worker cannot provide a trusted result."""


class SysctlProcessExecutor(SyntheticProcessExecutor):
    """Reuse the proven bounded lifecycle with a distinct fixed worker module."""

    def __init__(
        self,
        *,
        manifest_path: str | Path,
        target_root: str | Path,
        sysctl_root: str | Path,
        backup_root: str | Path,
        expected_uid: int = 0,
        expected_executable_uid: int = 0,
        executable: str | Path = sys.executable,
        process_factory: Callable[..., object] | None = None,
        cancellation_grace: float = 2.0,
        poll_interval: float = 0.01,
    ) -> None:
        options = {}
        if process_factory is not None:
            options["process_factory"] = process_factory
        super().__init__(
            manifest_path=manifest_path,
            target_root=target_root,
            backup_root=backup_root,
            expected_uid=expected_uid,
            expected_executable_uid=expected_executable_uid,
            executable=executable,
            cancellation_grace=cancellation_grace,
            poll_interval=poll_interval,
            **options,
        )
        self._sysctl_root = Path(sysctl_root)
        if not self._sysctl_root.is_absolute() or "\x00" in str(self._sysctl_root):
            raise SysctlProcessError("sysctl root is invalid")
        self._backups = SysctlBackupStore(self._backup_root, expected_uid=expected_uid)
        self._manifest_digest = load_sysctl_manifest(
            self._manifest_path, expected_uid=expected_uid
        ).digest

    def backup_eligible(self, backup_id: str) -> bool:
        """Reject backups from any other installed manifest before authorization."""
        return self._backups.eligible(backup_id, self._manifest_digest)

    def _worker_arguments(self) -> tuple[str, ...]:
        return (
            str(self._executable),
            "-m",
            "lsmf.sysctl_worker",
            "--manifest",
            str(self._manifest_path),
            "--target-root",
            str(self._target_root),
            "--sysctl-root",
            str(self._sysctl_root),
            "--backup-root",
            str(self._backup_root),
            "--expected-uid",
            str(self._expected_uid),
        )
