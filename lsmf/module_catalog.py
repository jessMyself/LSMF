"""Read-only discovery of implemented LSMF Bash modules."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
import re

from lsmf.configuration import ConfigError, parse_config


_ASSIGNMENT = re.compile(
    r'^\s*(MODULE_NAME|MODULE_VERSION)=["\']([^"\']+)["\']\s*$'
)
_DESCRIPTION = re.compile(r"^\s*#\s*Description:\s*(.+?)\s*$", re.IGNORECASE)


@dataclass(frozen=True)
class ModuleInfo:
    """Truthful metadata and capabilities for one implemented module."""

    module_id: str
    name: str
    version: str
    script: Path
    description: str | None
    can_run: bool
    can_verify: bool
    can_rollback: bool
    enabled: bool | None
    config_key: str


@dataclass(frozen=True)
class ModuleCatalog:
    """Discovered modules plus non-fatal discovery/configuration errors."""

    modules: tuple[ModuleInfo, ...]
    errors: tuple[str, ...]


def _configured_key(module_id: str) -> str:
    short_id = module_id.removesuffix("_hardening")
    return f"MODULE_{short_id.upper()}_ENABLED"


def _function_present(source: str, function_name: str) -> bool:
    pattern = re.compile(
        rf"^\s*(?:function\s+)?{re.escape(function_name)}\s*(?:\(\s*\))?\s*\{{",
        re.MULTILINE,
    )
    return pattern.search(source) is not None


def _read_module(script: Path, config: dict[str, str] | None) -> ModuleInfo:
    try:
        source = script.read_text(encoding="utf-8")
    except (OSError, UnicodeError) as error:
        raise ValueError(f"cannot read {script}: {error}") from error

    metadata: dict[str, str] = {}
    description: str | None = None
    for line in source.splitlines():
        assignment = _ASSIGNMENT.fullmatch(line)
        if assignment:
            key, value = assignment.groups()
            if key in metadata:
                raise ValueError(f"{script}: duplicate {key}")
            metadata[key] = value
        if description is None:
            match = _DESCRIPTION.fullmatch(line)
            if match:
                description = match.group(1)

    missing = [key for key in ("MODULE_NAME", "MODULE_VERSION") if key not in metadata]
    if missing:
        raise ValueError(f"{script}: missing {', '.join(missing)} literal assignment")

    module_id = metadata["MODULE_NAME"]
    if module_id != script.stem:
        raise ValueError(
            f"{script}: MODULE_NAME {module_id!r} does not match filename {script.stem!r}"
        )
    if not re.fullmatch(r"[a-z][a-z0-9_]*", module_id):
        raise ValueError(f"{script}: invalid MODULE_NAME {module_id!r}")

    config_key = _configured_key(module_id)
    configured_value = None if config is None else config.get(config_key)
    enabled = None if configured_value is None else configured_value == "true"
    return ModuleInfo(
        module_id=module_id,
        name=module_id.replace("_", " ").title(),
        version=metadata["MODULE_VERSION"],
        script=script,
        description=description,
        can_run=_function_present(source, f"run_{module_id}"),
        can_verify=_function_present(source, f"verify_{module_id}"),
        can_rollback=_function_present(source, f"rollback_{module_id}"),
        enabled=enabled,
        config_key=config_key,
    )


def discover_modules(
    module_dir: Path | str, config_file: Path | str | None = None
) -> ModuleCatalog:
    """Discover ``*.sh`` modules without sourcing or executing any content.

    Invalid scripts are omitted and reported in ``errors``. A missing or invalid
    configuration leaves enabled state unknown instead of applying a false default.
    """
    directory = Path(module_dir)
    errors: list[str] = []
    config: dict[str, str] | None = None

    if config_file is not None:
        path = Path(config_file)
        if not path.is_file():
            errors.append(f"configuration file not found: {path}")
        else:
            try:
                config = parse_config(path)
            except (ConfigError, OSError, UnicodeError) as error:
                errors.append(f"cannot load configuration {path}: {error}")

    if not directory.is_dir():
        errors.append(f"module directory not found: {directory}")
        return ModuleCatalog((), tuple(errors))

    modules: list[ModuleInfo] = []
    for script in sorted(directory.glob("*.sh"), key=lambda path: path.name):
        try:
            modules.append(_read_module(script, config))
        except ValueError as error:
            errors.append(str(error))
    return ModuleCatalog(tuple(modules), tuple(errors))
