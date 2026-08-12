"""Safe, interface-neutral configuration support for LSMF consumers."""

from __future__ import annotations

from collections.abc import Mapping
import os
from pathlib import Path
import re
import tempfile


KEY_PATTERN = re.compile(r"^[A-Z][A-Z0-9_]*$")
ASSIGNMENT_PATTERN = re.compile(r'^([A-Z][A-Z0-9_]*)="([^"\\]*)"$')
LEGACY_ASSIGNMENT_PATTERN = re.compile(r"^([A-Za-z_][A-Za-z0-9_]*)=(.*)$")
BOOLEAN_KEYS = {
    "AUTOMATIC_UPDATES",
    "BACKUP_ENABLED",
    "CIS_COMPLIANCE_CHECK",
    "DISABLE_IPV6",
    "DRY_RUN",
    "FIREWALL_ENABLED",
    "INTERACTIVE_MODE",
    "KERNEL_HARDENING",
    "LOGGING_VERBOSE",
    "NETWORK_HARDENING",
    "ROLLBACK_ENABLED",
    "SSH_HARDENING",
}
ENUMS = {
    "LOGGING_LEVEL": {"DEBUG", "INFO", "WARNING", "ERROR"},
    "MAC_SYSTEM": {"auto", "apparmor", "selinux", "none"},
    "SYSTEM_ROLE": {"auto", "desktop", "server"},
}


class ConfigError(ValueError):
    """Raised when a configuration file violates the canonical schema."""


def module_key(module_id: str) -> str:
    return f"MODULE_{_identifier(module_id)}_ENABLED"


def feature_key(module_id: str, feature_id: str) -> str:
    return f"FEATURE_{_identifier(module_id)}_{_identifier(feature_id)}"


def _identifier(value: str) -> str:
    identifier = re.sub(r"[^A-Za-z0-9]+", "_", value).strip("_").upper()
    if not identifier:
        raise ConfigError("Configuration identifiers must contain a letter or digit")
    return identifier


def validate_value(key: str, value: str) -> None:
    if any(character in value for character in ('"', "\\", "\n", "\r")):
        raise ConfigError(f"{key} contains a forbidden quote, backslash, or newline")
    if key in BOOLEAN_KEYS or key.startswith("MODULE_") or key.startswith("FEATURE_"):
        if value not in {"true", "false"}:
            raise ConfigError(f"{key} must be true or false")
    elif key == "BACKUP_RETENTION_DAYS":
        if not value.isdigit() or int(value) < 1:
            raise ConfigError("BACKUP_RETENTION_DAYS must be a positive integer")
    elif key in ENUMS and value not in ENUMS[key]:
        allowed = ", ".join(sorted(ENUMS[key]))
        raise ConfigError(f"{key} must be one of: {allowed}")


def parse_config(path: Path | str) -> dict[str, str]:
    """Parse canonical assignments strictly as data, never as Python or shell."""
    config_path = Path(path)
    values: dict[str, str] = {}
    for line_number, raw_line in enumerate(
        config_path.read_text(encoding="utf-8").splitlines(), 1
    ):
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        match = ASSIGNMENT_PATTERN.fullmatch(line)
        if not match:
            raise ConfigError(f"{config_path}:{line_number}: invalid configuration line")
        key, value = match.groups()
        if key in values:
            raise ConfigError(f"{config_path}:{line_number}: duplicate key {key}")
        validate_value(key, value)
        values[key] = value
    return values


def parse_legacy_mixed(path: Path | str) -> dict[str, str]:
    """Read the former mixed assignment/INI format without executing it."""
    config_path = Path(path)
    values: dict[str, str] = {}
    section: str | None = None
    for line_number, raw_line in enumerate(
        config_path.read_text(encoding="utf-8").splitlines(), 1
    ):
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("[") and line.endswith("]"):
            section = line[1:-1].strip()
            if not section:
                raise ConfigError(f"{config_path}:{line_number}: empty section")
            continue
        match = LEGACY_ASSIGNMENT_PATTERN.fullmatch(line)
        if not match:
            raise ConfigError(f"{config_path}:{line_number}: invalid legacy line")
        key, raw_value = match.groups()
        raw_value = raw_value.strip()
        if len(raw_value) >= 2 and raw_value[0] == raw_value[-1] and raw_value[0] in {'"', "'"}:
            raw_value = raw_value[1:-1]
        if section:
            section_id = section.removesuffix("_hardening")
            if key == "module_enabled":
                canonical_key = module_key(section_id)
            elif key.startswith("feature_"):
                canonical_key = feature_key(section_id, key.removeprefix("feature_"))
            else:
                canonical_key = f"{_identifier(section)}_{_identifier(key)}"
        else:
            canonical_key = _identifier(key)
        if canonical_key in values:
            raise ConfigError(
                f"{config_path}:{line_number}: duplicate migrated key {canonical_key}"
            )
        validate_value(canonical_key, raw_value)
        values[canonical_key] = raw_value
    return values


def write_config_atomic(path: Path | str, values: Mapping[str, object]) -> None:
    """Validate and replace a configuration file without an in-place write."""
    config_path = Path(path)
    normalized: dict[str, str] = {}
    for key, raw_value in values.items():
        if not KEY_PATTERN.fullmatch(key):
            raise ConfigError(f"Invalid configuration key: {key}")
        value = str(raw_value)
        validate_value(key, value)
        normalized[key] = value

    config_path.parent.mkdir(parents=True, exist_ok=True)
    mode = config_path.stat().st_mode & 0o777 if config_path.exists() else 0o600
    descriptor, temporary_name = tempfile.mkstemp(
        dir=config_path.parent, prefix=f".{config_path.name}.", text=True
    )
    temporary_path = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            handle.write("# LSMF configuration. Parsed as data; never source this file.\n")
            for key, value in normalized.items():
                handle.write(f'{key}="{value}"\n')
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(temporary_path, mode)
        os.replace(temporary_path, config_path)
    except BaseException:
        temporary_path.unlink(missing_ok=True)
        raise


class ConfigStore:
    """In-memory configuration view that preserves unrecognized keys."""

    def __init__(self, config_file: Path | str):
        self.config_file = Path(config_file)
        self.config: dict[str, str] = {}
        self.load()

    def load(self) -> None:
        self.config = parse_config(self.config_file) if self.config_file.exists() else {}

    def get(self, key: str, default: str | None = None) -> str | None:
        return self.config.get(key, default)

    def get_bool(self, key: str, default: bool = False) -> bool:
        value = self.get(key)
        return default if value is None else value == "true"

    def set(self, key: str, value: object) -> None:
        text_value = str(value).lower() if isinstance(value, bool) else str(value)
        if not KEY_PATTERN.fullmatch(key):
            raise ConfigError(f"Invalid configuration key: {key}")
        validate_value(key, text_value)
        self.config[key] = text_value

    def save(self) -> None:
        write_config_atomic(self.config_file, self.config)
