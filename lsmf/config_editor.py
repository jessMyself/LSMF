"""Unprivileged, conflict-aware editing of explicitly authorized config files."""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import os
from pathlib import Path
import stat
from typing import Callable, Mapping

from lsmf import configuration


class ConfigEditError(RuntimeError):
    """Base error for configuration editing failures."""


class TargetRejectedError(ConfigEditError):
    """Raised when a target is outside the editor's security boundary."""


class StaleConfigError(ConfigEditError):
    """Raised when the file changed after the editor loaded it."""


@dataclass(frozen=True)
class ConfigChange:
    key: str
    old_value: str | None
    new_value: str | None


@dataclass(frozen=True)
class ConfigPreview:
    target: Path
    changes: tuple[ConfigChange, ...]
    values: Mapping[str, str]


@dataclass(frozen=True)
class _Fingerprint:
    exists: bool
    device: int | None
    inode: int | None
    size: int | None
    modified_ns: int | None
    digest: str | None


Writer = Callable[[Path, Mapping[str, object]], None]


class SafeConfigEditor:
    """Edit one project/user configuration without privilege or path traversal.

    ``allowed_roots`` must be explicit directories controlled by the caller. The
    target is checked again immediately before saving, but callers must still
    avoid sharing an allowed directory with an untrusted process.
    """

    def __init__(
        self,
        target: Path | str,
        *,
        allowed_roots: tuple[Path | str, ...] | list[Path | str],
        writer: Writer = configuration.write_config_atomic,
    ) -> None:
        if not allowed_roots:
            raise TargetRejectedError("At least one allowed configuration root is required")
        self.target = Path(os.path.abspath(os.fspath(target)))
        self.allowed_roots = tuple(
            Path(os.path.abspath(os.fspath(root))) for root in allowed_roots
        )
        self._writer = writer
        self._loaded: dict[str, str] = {}
        self._values: dict[str, str] = {}
        self._fingerprint = _Fingerprint(False, None, None, None, None, None)
        self.load()

    def load(self) -> Mapping[str, str]:
        self._validate_target()
        values = configuration.parse_config(self.target) if self.target.exists() else {}
        self._loaded = dict(values)
        self._values = dict(values)
        self._fingerprint = self._current_fingerprint()
        return dict(self._values)

    @property
    def values(self) -> Mapping[str, str]:
        return dict(self._values)

    @property
    def revision(self) -> str:
        fingerprint = self._fingerprint
        return ":".join(
            str(value)
            for value in (
                fingerprint.exists,
                fingerprint.device,
                fingerprint.inode,
                fingerprint.size,
                fingerprint.modified_ns,
                fingerprint.digest,
            )
        )

    def set(self, key: str, value: object) -> None:
        if not configuration.KEY_PATTERN.fullmatch(key):
            raise configuration.ConfigError(f"Invalid configuration key: {key}")
        normalized = str(value).lower() if isinstance(value, bool) else str(value)
        configuration.validate_value(key, normalized)
        self._values[key] = normalized

    def preview(self) -> ConfigPreview:
        keys = sorted(self._loaded.keys() | self._values.keys())
        changes = tuple(
            ConfigChange(key, self._loaded.get(key), self._values.get(key))
            for key in keys
            if self._loaded.get(key) != self._values.get(key)
        )
        return ConfigPreview(self.target, changes, dict(self._values))

    def save(self) -> ConfigPreview:
        self._validate_target()
        if self._current_fingerprint() != self._fingerprint:
            raise StaleConfigError(f"Configuration changed since load: {self.target}")
        preview = self.preview()
        self._writer(self.target, self._values)
        self._loaded = dict(self._values)
        self._fingerprint = self._current_fingerprint()
        return preview

    def _validate_target(self) -> None:
        if self.target == Path("/etc/lsmf") or Path("/etc/lsmf") in self.target.parents:
            raise TargetRejectedError("Installed /etc/lsmf configuration is not editable")
        if not any(_is_within(self.target, root) for root in self.allowed_roots):
            raise TargetRejectedError(f"Target is outside the allowed roots: {self.target}")

        for root in self.allowed_roots:
            if _is_within(self.target, root):
                _reject_symlink_chain(root, self.target)

        parent = self.target.parent
        if not parent.exists() or not parent.is_dir():
            raise TargetRejectedError(f"Configuration parent must be an existing directory: {parent}")
        parent_stat = parent.stat()
        parent_mode = parent_stat.st_mode
        effective_gid = os.getegid() if hasattr(os, "getegid") else None
        unsafe_world_write = bool(parent_mode & stat.S_IWOTH) and not bool(
            parent_mode & stat.S_ISVTX
        )
        unsafe_group_write = (
            bool(parent_mode & stat.S_IWGRP)
            and effective_gid is not None
            and parent_stat.st_gid != effective_gid
        )
        if unsafe_world_write or unsafe_group_write:
            raise TargetRejectedError(f"Configuration parent has unsafe write permissions: {parent}")
        effective_uid = os.geteuid() if hasattr(os, "geteuid") else None
        if effective_uid is not None and parent_stat.st_uid != effective_uid:
            raise TargetRejectedError(
                f"Configuration parent is not owned by the current user: {parent}"
            )
        if self.target.exists():
            target_stat = self.target.stat()
            if not stat.S_ISREG(target_stat.st_mode):
                raise TargetRejectedError("Configuration target must be a regular file")
            if target_stat.st_uid == 0:
                raise TargetRejectedError("Root-owned configuration targets are not editable")
            if effective_uid is not None and target_stat.st_uid != effective_uid:
                raise TargetRejectedError(
                    "Configuration target is not owned by the current user"
                )

    def _current_fingerprint(self) -> _Fingerprint:
        if not self.target.exists():
            return _Fingerprint(False, None, None, None, None, None)
        data = self.target.read_bytes()
        metadata = self.target.stat()
        return _Fingerprint(
            True,
            metadata.st_dev,
            metadata.st_ino,
            metadata.st_size,
            metadata.st_mtime_ns,
            hashlib.sha256(data).hexdigest(),
        )


def _is_within(path: Path, root: Path) -> bool:
    try:
        path.relative_to(root)
    except ValueError:
        return False
    return True


def _reject_symlink_chain(root: Path, target: Path) -> None:
    current = root
    chain_items = [root]
    for part in target.relative_to(root).parts:
        current = current / part
        chain_items.append(current)
    for item in chain_items:
        try:
            if stat.S_ISLNK(item.lstat().st_mode):
                raise TargetRejectedError(f"Symlinks are not allowed in configuration paths: {item}")
        except FileNotFoundError:
            continue
