"""Reusable, unprivileged read services for LSMF interfaces.

This module deliberately uses only the Python standard library and never
executes hardening commands. A later privileged helper can expose a small,
authenticated mutation API while the Qt process remains unprivileged.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
from datetime import datetime
import getpass
import os
from pathlib import Path
import platform
from typing import Iterable

from lsmf.configuration import ConfigError, parse_config
from lsmf.module_catalog import ModuleCatalog, ModuleInfo, discover_modules


@dataclass(frozen=True)
class SystemSummary:
    user: str
    hostname: str
    operating_system: str
    release: str
    architecture: str
    is_linux: bool
    is_root: bool


@dataclass(frozen=True)
class FileSummary:
    name: str
    path: str
    modified: str
    size_bytes: int


@dataclass(frozen=True)
class ReadinessFinding:
    severity: str
    title: str
    detail: str


@dataclass(frozen=True)
class LogView:
    status: str
    source: str | None
    content: str
    line_count: int
    truncated: bool
    error: str | None


@dataclass(frozen=True)
class BackupSummary:
    status: str
    count: int
    sources: tuple[str, ...]
    error: str | None


@dataclass(frozen=True)
class LastRunSummary:
    status: str
    source: str | None
    modified: str | None
    error: str | None


class LsmfReadService:
    """Collects display data without changing system or project state."""

    def __init__(self, project_root: Path | str | None = None) -> None:
        default_root = Path(__file__).resolve().parent.parent
        self.project_root = Path(project_root or default_root).resolve()

    def system_summary(self) -> SystemSummary:
        return SystemSummary(
            user=getpass.getuser(),
            hostname=platform.node() or "Unknown",
            operating_system=platform.system() or "Unknown",
            release=platform.release() or "Unknown",
            architecture=platform.machine() or "Unknown",
            is_linux=platform.system() == "Linux",
            is_root=hasattr(os, "geteuid") and os.geteuid() == 0,
        )

    def module_catalog(self) -> ModuleCatalog:
        return discover_modules(
            self.project_root / "src" / "modules",
            self.project_root / "config" / "lsmf.conf",
        )

    def modules(self) -> list[ModuleInfo]:
        return list(self.module_catalog().modules)

    def config_values(self) -> dict[str, str]:
        """Parse canonical assignment values without executing configuration."""
        config_file = self.project_root / "config" / "lsmf.conf"
        if not config_file.is_file():
            return {}
        return parse_config(config_file)

    def recent_reports(self, limit: int = 20) -> list[FileSummary]:
        candidates = (
            self.project_root / "reports",
            self.project_root / "logs",
            Path("/var/lib/lsmf/reports"),
        )
        return self._recent_files(candidates, limit)

    def recent_backups(self, limit: int = 20) -> list[FileSummary]:
        candidates = (
            self.project_root / "backups",
            Path("/var/backups/lsmf"),
        )
        return self._recent_files(candidates, limit)

    def log_view(self, max_lines: int = 100, max_bytes: int = 128 * 1024) -> LogView:
        """Return a bounded tail of the newest real LSMF log."""
        logs, errors = self._log_files()
        if not logs:
            error = "; ".join(errors) if errors else None
            return LogView("error" if error else "unavailable", None, "", 0, False, error)

        source = logs[0]
        line_limit = max(0, max_lines)
        byte_limit = max(0, max_bytes)
        try:
            size = source.stat().st_size
            if line_limit == 0 or byte_limit == 0:
                return LogView("available", str(source), "", 0, size > 0, None)
            with source.open("rb") as stream:
                start = max(0, size - byte_limit)
                stream.seek(start)
                data = stream.read(byte_limit)
        except OSError as error:
            return LogView("error", str(source), "", 0, False, str(error))

        byte_truncated = start > 0
        if byte_truncated:
            first_newline = data.find(b"\n")
            data = data[first_newline + 1 :] if first_newline >= 0 else b""
        lines = data.decode("utf-8", errors="replace").splitlines()
        line_truncated = len(lines) > line_limit
        lines = lines[-line_limit:]
        return LogView(
            "available",
            str(source),
            "\n".join(lines),
            len(lines),
            byte_truncated or line_truncated,
            None,
        )

    def backup_summary(self) -> BackupSummary:
        """Count distinct top-level backup sets without reading their content."""
        directories = (self.project_root / "backups", Path("/var/backups/lsmf"))
        sources: list[str] = []
        backups: set[Path] = set()
        errors: list[str] = []
        for directory in directories:
            try:
                if directory.is_dir():
                    sources.append(str(directory))
                    backups.update(path.resolve() for path in directory.iterdir() if path.is_dir())
            except OSError as error:
                errors.append(f"{directory}: {error}")
        if errors:
            return BackupSummary("error", len(backups), tuple(sources), "; ".join(errors))
        return BackupSummary("available" if sources else "unavailable", len(backups), tuple(sources), None)

    def last_run_summary(self) -> LastRunSummary:
        """Expose the newest log timestamp as evidence, without claiming success."""
        logs, errors = self._log_files()
        if not logs:
            error = "; ".join(errors) if errors else None
            return LastRunSummary("error" if error else "unavailable", None, None, error)
        source = logs[0]
        try:
            modified = datetime.fromtimestamp(source.stat().st_mtime).isoformat(timespec="seconds")
        except OSError as error:
            return LastRunSummary("error", str(source), None, str(error))
        return LastRunSummary("available", str(source), modified, None)

    def readiness_findings(self) -> list[ReadinessFinding]:
        findings: list[ReadinessFinding] = []
        system = self.system_summary()
        catalog = self.module_catalog()
        modules = catalog.modules
        config_file = self.project_root / "config" / "lsmf.conf"

        if not system.is_linux:
            findings.append(
                ReadinessFinding(
                    "Info",
                    "Local hardening unavailable",
                    "The desktop interface is portable, but the current LSMF engine targets Linux.",
                )
            )
        if system.is_root:
            findings.append(
                ReadinessFinding(
                    "Warning",
                    "Desktop application is running as root",
                    "Close it and run as a normal user. Privileged actions are intentionally unavailable.",
                )
            )
        if not modules:
            findings.append(
                ReadinessFinding("Error", "No modules found", "src/modules contains no module scripts.")
            )
        for module in modules:
            missing = []
            if not module.can_run:
                missing.append("run")
            if not module.can_verify:
                missing.append("verify")
            if not module.can_rollback:
                missing.append("rollback")
            if missing:
                findings.append(
                    ReadinessFinding(
                        "Warning",
                        f"Incomplete module: {module.name}",
                        "Missing expected functions: " + ", ".join(missing),
                    )
                )
        for error in catalog.errors:
            findings.append(ReadinessFinding("Error", "Module catalog issue", error))
        if config_file.is_file():
            try:
                parse_config(config_file)
            except (ConfigError, OSError) as error:
                findings.append(
                    ReadinessFinding("Error", "Invalid configuration", str(error))
                )
        if not findings:
            findings.append(
                ReadinessFinding("Ready", "Read-only checks passed", "No interface readiness issue was found.")
            )
        return findings

    def snapshot(self) -> dict[str, object]:
        return {
            "system": asdict(self.system_summary()),
            "modules": [
                {**asdict(module), "script": str(module.script)} for module in self.modules()
            ],
            "config": self.config_values(),
            "reports": [asdict(item) for item in self.recent_reports()],
            "backups": [asdict(item) for item in self.recent_backups()],
            "backup_summary": asdict(self.backup_summary()),
            "last_run": asdict(self.last_run_summary()),
            "log": asdict(self.log_view()),
            "findings": [asdict(item) for item in self.readiness_findings()],
        }

    @staticmethod
    def _recent_files(directories: Iterable[Path], limit: int) -> list[FileSummary]:
        files: dict[Path, Path] = {}
        for directory in directories:
            try:
                if directory.is_dir():
                    for path in directory.rglob("*"):
                        if path.is_file():
                            files[path.resolve()] = path
            except OSError:
                continue

        available: list[tuple[float, int, Path]] = []
        for path in files.values():
            try:
                stat = path.stat()
                available.append((stat.st_mtime, stat.st_size, path))
            except OSError:
                continue
        available.sort(key=lambda item: item[0], reverse=True)
        return [
            FileSummary(
                name=path.name,
                path=str(path),
                modified=datetime.fromtimestamp(modified).isoformat(timespec="seconds"),
                size_bytes=size,
            )
            for modified, size, path in available[: max(0, limit)]
        ]

    def _log_files(self) -> tuple[list[Path], list[str]]:
        directories = (self.project_root / "logs", Path("/var/log/lsmf"))
        files: dict[Path, Path] = {}
        errors: list[str] = []
        for directory in directories:
            try:
                if directory.is_dir():
                    for path in directory.rglob("lsmf.log"):
                        if path.is_file():
                            files[path.resolve()] = path
            except OSError as error:
                errors.append(f"{directory}: {error}")

        def modified(path: Path) -> float:
            try:
                return path.stat().st_mtime
            except OSError as error:
                errors.append(f"{path}: {error}")
                return float("-inf")

        return sorted(files.values(), key=modified, reverse=True), errors
