"""Root-trusted synthetic module allowlist for the privileged helper.

The manifest maps opaque module IDs to fixed synthetic targets.  Request data
never supplies a path, command, capability, or executable.
"""

from __future__ import annotations

from dataclasses import dataclass
import json
import os
from pathlib import Path, PurePosixPath
import stat
from typing import Callable

from .privileged_protocol import Action, PrivilegedRequest
from .production_protocol import ProductionRequest


class ManifestError(ValueError):
    """Raised when trusted policy material is unsafe or malformed."""


@dataclass(frozen=True, slots=True)
class SyntheticModule:
    module_id: str
    relative_target: str
    desired_content: str
    capabilities: frozenset[str]


@dataclass(frozen=True, slots=True)
class TrustedManifest:
    version: int
    modules: dict[str, SyntheticModule]


def _reject_duplicates(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ManifestError(f"duplicate manifest field: {key}")
        result[key] = value
    return result


def _safe_relative_target(value: object) -> str:
    if not isinstance(value, str) or not value or "\x00" in value:
        raise ManifestError("relative_target must be a non-empty string")
    path = PurePosixPath(value)
    if path.is_absolute() or any(part in {"", ".", ".."} for part in path.parts):
        raise ManifestError("relative_target must be canonical and relative")
    if len(value.encode("utf-8")) > 256:
        raise ManifestError("relative_target exceeds its length limit")
    return value


def _validate_trusted_file(path: Path, expected_uid: int) -> int:
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as error:
        raise ManifestError("trusted manifest cannot be opened safely") from error
    metadata = os.fstat(descriptor)
    if not stat.S_ISREG(metadata.st_mode):
        os.close(descriptor)
        raise ManifestError("trusted manifest must be a regular file")
    if metadata.st_uid != expected_uid:
        os.close(descriptor)
        raise ManifestError("trusted manifest has the wrong owner")
    if metadata.st_mode & 0o022:
        os.close(descriptor)
        raise ManifestError("trusted manifest must not be group/other writable")
    return descriptor


def load_trusted_manifest(
    path: str | os.PathLike[str], *, expected_uid: int = 0, maximum_bytes: int = 65_536
) -> TrustedManifest:
    """Load one exact-schema manifest through a no-follow descriptor."""
    if isinstance(expected_uid, bool) or not isinstance(expected_uid, int) or expected_uid < 0:
        raise ManifestError("expected_uid must be a non-negative integer")
    manifest_path = Path(path)
    descriptor = _validate_trusted_file(manifest_path, expected_uid)
    try:
        raw = os.read(descriptor, maximum_bytes + 1)
    finally:
        os.close(descriptor)
    if len(raw) > maximum_bytes:
        raise ManifestError("trusted manifest exceeds its size limit")
    try:
        value = json.loads(raw.decode("utf-8"), object_pairs_hook=_reject_duplicates)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ManifestError("trusted manifest is not valid UTF-8 JSON") from error
    if not isinstance(value, dict) or set(value) != {"version", "modules"}:
        raise ManifestError("trusted manifest fields are invalid")
    if value["version"] != 1 or isinstance(value["version"], bool):
        raise ManifestError("trusted manifest version is unsupported")
    raw_modules = value["modules"]
    if not isinstance(raw_modules, dict) or not raw_modules or len(raw_modules) > 32:
        raise ManifestError("trusted manifest must contain 1 to 32 modules")

    modules: dict[str, SyntheticModule] = {}
    for module_id, raw_module in raw_modules.items():
        if not isinstance(raw_module, dict) or set(raw_module) != {
            "relative_target", "desired_content", "capabilities"
        }:
            raise ManifestError("module fields are invalid")
        # Reuse the protocol model as the canonical module-ID validator.
        PrivilegedRequest(1, "123e4567-e89b-42d3-a456-426614174000", Action.VERIFY_MODULE, (module_id,))
        desired = raw_module["desired_content"]
        capabilities = raw_module["capabilities"]
        if not isinstance(desired, str) or len(desired.encode("utf-8")) > 4096 or "\x00" in desired:
            raise ManifestError("desired_content is invalid")
        if (
            not isinstance(capabilities, list)
            or not capabilities
            or len(set(capabilities)) != len(capabilities)
            or not set(capabilities) <= {"verify", "apply"}
        ):
            raise ManifestError("module capabilities are invalid")
        modules[module_id] = SyntheticModule(
            module_id,
            _safe_relative_target(raw_module["relative_target"]),
            desired,
            frozenset(capabilities),
        )
    return TrustedManifest(1, modules)


class TrustedManifestPolicy:
    """Validate typed requests only against installed trusted policy."""

    def __init__(
        self,
        manifest: TrustedManifest,
        *,
        backup_eligible: Callable[[str], bool] | None = None,
    ) -> None:
        if not isinstance(manifest, TrustedManifest):
            raise ManifestError("a trusted manifest is required")
        self.manifest = manifest
        self._backup_eligible = backup_eligible

    def validate(self, request: PrivilegedRequest | ProductionRequest) -> bool:
        if not isinstance(request, (PrivilegedRequest, ProductionRequest)):
            return False
        if request.action is Action.AUDIT:
            return True
        if request.action is Action.ROLLBACK_BACKUP:
            if self._backup_eligible is None or request.backup_id is None:
                return False
            try:
                return self._backup_eligible(request.backup_id) is True
            except Exception:
                return False
        capability = "verify" if request.action is Action.VERIFY_MODULE else "apply"
        return all(
            module_id in self.manifest.modules
            and capability in self.manifest.modules[module_id].capabilities
            for module_id in request.module_ids
        )
