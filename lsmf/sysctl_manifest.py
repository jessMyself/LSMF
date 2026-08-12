"""Root-trusted, command-free manifest for Section 3 sysctl transactions."""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat

from .privileged_protocol import Action
from .production_protocol import ProductionRequest


_MODULE_ID = re.compile(r"^[a-z][a-z0-9_]{0,63}$")
_SYSCTL_KEY = re.compile(r"^[a-z][a-z0-9_]*(?:\.[a-z0-9_]+)+$")
_VALUE = re.compile(r"^[0-9]+(?: [0-9]+)*$")
MAX_MODULES = 8
MAX_SETTINGS = 128
_NON_ROLLBACKABLE_KEYS = frozenset({
    "kernel.kexec_load_disabled",
    "kernel.unprivileged_bpf_disabled",
})


class SysctlManifestError(ValueError):
    """Raised when the fixed Section 3 manifest is unsafe or malformed."""


@dataclass(frozen=True, slots=True)
class SysctlSetting:
    key: str
    desired_value: str


@dataclass(frozen=True, slots=True)
class SysctlModule:
    module_id: str
    relative_target: str
    settings: tuple[SysctlSetting, ...]


@dataclass(frozen=True, slots=True)
class SysctlManifest:
    version: int
    module_order: tuple[str, ...]
    single_apply: tuple[str, ...]
    multi_apply: tuple[tuple[str, ...], ...]
    modules: dict[str, SysctlModule]
    digest: str

    def selected(self, module_ids: tuple[str, ...]) -> tuple[SysctlModule, ...]:
        return tuple(self.modules[module_id] for module_id in module_ids)


def _reject_duplicates(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise SysctlManifestError(f"duplicate manifest field: {key}")
        result[key] = value
    return result


def _read_trusted(path: Path, expected_uid: int, maximum_bytes: int) -> bytes:
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as error:
        raise SysctlManifestError("sysctl manifest cannot be opened safely") from error
    try:
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_uid != expected_uid
            or metadata.st_mode & 0o022
        ):
            raise SysctlManifestError("sysctl manifest ownership or mode is unsafe")
        raw = os.read(descriptor, maximum_bytes + 1)
    finally:
        os.close(descriptor)
    if len(raw) > maximum_bytes:
        raise SysctlManifestError("sysctl manifest exceeds its size limit")
    return raw


def _module_id(value: object) -> str:
    if not isinstance(value, str) or not _MODULE_ID.fullmatch(value):
        raise SysctlManifestError("module ID is invalid")
    return value


def _module_sequence(value: object, *, allow_single: bool) -> tuple[str, ...]:
    if not isinstance(value, list) or not value or len(value) > MAX_MODULES:
        raise SysctlManifestError("module sequence is invalid")
    result = tuple(_module_id(item) for item in value)
    if len(set(result)) != len(result) or (not allow_single and len(result) < 2):
        raise SysctlManifestError("module sequence contains duplicates or is too short")
    return result


def _relative_target(value: object) -> str:
    if not isinstance(value, str) or not value or "\x00" in value:
        raise SysctlManifestError("relative target is invalid")
    path = PurePosixPath(value)
    if path.is_absolute() or any(part in {"", ".", ".."} for part in path.parts):
        raise SysctlManifestError("relative target must be canonical")
    if not value.startswith("etc/sysctl.d/") or path.suffix != ".conf":
        raise SysctlManifestError("sysctl target is outside the fixed drop-in directory")
    if len(value.encode("utf-8")) > 256:
        raise SysctlManifestError("relative target exceeds its size limit")
    return value


def load_sysctl_manifest(
    path: str | os.PathLike[str], *, expected_uid: int = 0, maximum_bytes: int = 65_536
) -> SysctlManifest:
    if isinstance(expected_uid, bool) or not isinstance(expected_uid, int) or expected_uid < 0:
        raise SysctlManifestError("expected UID is invalid")
    raw = _read_trusted(Path(path), expected_uid, maximum_bytes)
    try:
        value = json.loads(raw.decode("utf-8"), object_pairs_hook=_reject_duplicates)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise SysctlManifestError("sysctl manifest is not valid UTF-8 JSON") from error
    if not isinstance(value, dict) or set(value) != {
        "version", "module_order", "single_apply", "multi_apply", "modules"
    }:
        raise SysctlManifestError("sysctl manifest fields are invalid")
    if value["version"] != 2 or isinstance(value["version"], bool):
        raise SysctlManifestError("sysctl manifest version is unsupported")
    module_order = _module_sequence(value["module_order"], allow_single=True)
    single_apply = _module_sequence(value["single_apply"], allow_single=True)
    raw_multi = value["multi_apply"]
    if not isinstance(raw_multi, list) or not raw_multi or len(raw_multi) > MAX_MODULES:
        raise SysctlManifestError("multi-apply policy is invalid")
    multi_apply = tuple(_module_sequence(item, allow_single=False) for item in raw_multi)
    if len(set(multi_apply)) != len(multi_apply):
        raise SysctlManifestError("multi-apply policy contains duplicates")

    raw_modules = value["modules"]
    if not isinstance(raw_modules, dict) or not raw_modules or len(raw_modules) > MAX_MODULES:
        raise SysctlManifestError("sysctl manifest module set is invalid")
    modules: dict[str, SysctlModule] = {}
    targets: set[str] = set()
    all_keys: set[str] = set()
    setting_count = 0
    for raw_id, raw_module in raw_modules.items():
        module_id = _module_id(raw_id)
        if not isinstance(raw_module, dict) or set(raw_module) != {"relative_target", "settings"}:
            raise SysctlManifestError("sysctl module fields are invalid")
        target = _relative_target(raw_module["relative_target"])
        if target in targets:
            raise SysctlManifestError("sysctl modules must have disjoint targets")
        targets.add(target)
        raw_settings = raw_module["settings"]
        if not isinstance(raw_settings, list) or not raw_settings:
            raise SysctlManifestError("sysctl module settings are invalid")
        settings: list[SysctlSetting] = []
        local_keys: set[str] = set()
        for raw_setting in raw_settings:
            if not isinstance(raw_setting, dict) or set(raw_setting) != {"key", "value"}:
                raise SysctlManifestError("sysctl setting fields are invalid")
            key = raw_setting["key"]
            desired = raw_setting["value"]
            if not isinstance(key, str) or not _SYSCTL_KEY.fullmatch(key):
                raise SysctlManifestError("sysctl key is invalid")
            if key in _NON_ROLLBACKABLE_KEYS:
                raise SysctlManifestError("sysctl key is not rollback-capable")
            if not isinstance(desired, str) or not _VALUE.fullmatch(desired) or len(desired) > 128:
                raise SysctlManifestError("sysctl value is invalid")
            if key in local_keys or key in all_keys:
                raise SysctlManifestError("sysctl keys must be unique across modules")
            local_keys.add(key)
            all_keys.add(key)
            settings.append(SysctlSetting(key, desired))
            setting_count += 1
        modules[module_id] = SysctlModule(module_id, target, tuple(settings))
    if setting_count > MAX_SETTINGS:
        raise SysctlManifestError("sysctl manifest has too many settings")
    if set(module_order) != set(modules) or tuple(module_order) != tuple(modules):
        raise SysctlManifestError("module order must exactly match manifest module order")
    allowed = set(modules)
    if not set(single_apply) <= allowed or any(not set(sequence) <= allowed for sequence in multi_apply):
        raise SysctlManifestError("apply policy names an unknown module")
    order_index = {module_id: index for index, module_id in enumerate(module_order)}
    if any(tuple(sorted(sequence, key=order_index.__getitem__)) != sequence for sequence in multi_apply):
        raise SysctlManifestError("multi-apply sequence violates fixed module order")
    digest = hashlib.sha256(raw).hexdigest()
    return SysctlManifest(2, module_order, single_apply, multi_apply, modules, digest)


class SysctlManifestPolicy:
    """Enforce exact Section 3 action shapes before authorization."""

    def __init__(self, manifest: SysctlManifest, *, backup_eligible=None) -> None:
        if not isinstance(manifest, SysctlManifest):
            raise SysctlManifestError("typed sysctl manifest is required")
        self.manifest = manifest
        self._backup_eligible = backup_eligible

    def validate(self, request: ProductionRequest) -> bool:
        if not isinstance(request, ProductionRequest):
            return False
        if request.action is Action.APPLY_MODULE:
            return request.module_ids in {(module_id,) for module_id in self.manifest.single_apply}
        if request.action is Action.APPLY_MODULES:
            return request.module_ids in self.manifest.multi_apply
        if request.action is Action.ROLLBACK_BACKUP:
            if self._backup_eligible is None or request.backup_id is None:
                return False
            try:
                return self._backup_eligible(request.backup_id) is True
            except Exception:
                return False
        return False
