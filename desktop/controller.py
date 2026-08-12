"""Unprivileged desktop controller for typed project configuration changes."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from desktop.services import LsmfReadService
from lsmf import configuration
from lsmf.config_editor import ConfigEditError, SafeConfigEditor, StaleConfigError
from lsmf.profiles import Profile, discover_profiles, preview_profile


@dataclass(frozen=True)
class ConfigField:
    key: str
    label: str
    kind: str
    description: str
    choices: tuple[str, ...] = ()
    minimum: int = 0
    maximum: int = 0


@dataclass(frozen=True)
class ConfigEditorState:
    revision: str
    path: str
    writable: bool
    error: str | None
    values: dict[str, object]
    fields: tuple[ConfigField, ...]


@dataclass(frozen=True)
class ProfileChoice:
    identifier: str
    name: str


@dataclass(frozen=True)
class ProfileChange:
    key: str
    current: object
    proposed: object


@dataclass(frozen=True)
class DesktopProfilePreview:
    summary: str
    changes: tuple[ProfileChange, ...]
    warnings: tuple[str, ...]


@dataclass(frozen=True)
class SaveResult:
    status: str
    message: str


_CHOICES = {
    "LOGGING_LEVEL": ("DEBUG", "INFO", "WARNING", "ERROR"),
    "MAC_SYSTEM": ("auto", "apparmor", "selinux", "none"),
    "SYSTEM_ROLE": ("auto", "desktop", "server"),
    "SSH_PERMIT_ROOT_LOGIN": ("no", "prohibit-password", "yes"),
    "SSH_PASSWORD_AUTH": ("no", "yes"),
}


class LsmfDesktopController:
    """Combine read services with a narrow editor for the project config only."""

    def __init__(self, project_root: Path | str | None = None) -> None:
        self.reader = LsmfReadService(project_root)
        self.project_root = self.reader.project_root
        self.config_path = self.project_root / "config" / "lsmf.conf"
        self.profiles_path = self.project_root / "config" / "profiles"
        self._editor: SafeConfigEditor | None = None

    def __getattr__(self, name: str) -> object:
        return getattr(self.reader, name)

    def configuration_editor_state(self) -> ConfigEditorState:
        try:
            editor = SafeConfigEditor(
                self.config_path,
                allowed_roots=[self.project_root / "config"],
            )
            fields = tuple(
                field
                for key in sorted(editor.values)
                if (field := _field_for(key)) is not None
            )
            values = {
                field.key: _typed_value(field, editor.values[field.key]) for field in fields
            }
            self._editor = editor
            return ConfigEditorState(
                editor.revision, str(self.config_path), True, None, values, fields
            )
        except (ConfigEditError, configuration.ConfigError, OSError) as error:
            self._editor = None
            return ConfigEditorState("", str(self.config_path), False, str(error), {}, ())

    def profiles(self) -> tuple[ProfileChoice, ...]:
        base = self.reader.config_values()
        discovery = discover_profiles(self.profiles_path, base)
        return tuple(
            ProfileChoice(profile.profile_id, profile.name)
            for profile in discovery.profiles
            if profile.valid
        )

    def profile_preview(self, identifier: str) -> DesktopProfilePreview:
        base = self.reader.config_values()
        discovery = discover_profiles(self.profiles_path, base)
        profile = next(
            (item for item in discovery.profiles if item.profile_id == identifier), None
        )
        if profile is None:
            raise ValueError(f"Unknown profile: {identifier}")
        preview = preview_profile(profile, base)
        warnings = list(preview.validation_errors)
        if preview.unknown_keys:
            warnings.append("Unknown settings: " + ", ".join(preview.unknown_keys))
        warnings.extend(error.message for error in discovery.errors)
        return DesktopProfilePreview(
            profile.description,
            tuple(
                ProfileChange(
                    change.key,
                    _typed_for_key(change.key, change.before),
                    _typed_for_key(change.key, change.after),
                )
                for change in preview.changes
            ),
            tuple(warnings),
        )

    def save_configuration(
        self, *, changes: dict[str, object], expected_revision: str | None
    ) -> SaveResult:
        editor = self._editor
        if editor is None:
            return SaveResult("error", "Configuration editor is not loaded")
        if expected_revision != editor.revision:
            return SaveResult("conflict", "Configuration was reloaded before this save")

        try:
            candidate = SafeConfigEditor(
                self.config_path,
                allowed_roots=[self.project_root / "config"],
            )
        except (ConfigEditError, configuration.ConfigError, OSError) as error:
            return SaveResult("error", str(error))
        if candidate.revision != expected_revision:
            return SaveResult("conflict", "Configuration changed on disk before save")

        allowed_fields = {
            field.key: field
            for key in candidate.values
            if (field := _field_for(key)) is not None
        }
        try:
            for key, value in changes.items():
                field = allowed_fields.get(key)
                if field is None:
                    raise configuration.ConfigError(f"Setting is not editable: {key}")
                normalized = _normalize_field_value(field, value)
                candidate.set(key, normalized)
            preview = candidate.save()
        except StaleConfigError as error:
            return SaveResult("conflict", str(error))
        except (ConfigEditError, configuration.ConfigError, OSError, ValueError) as error:
            return SaveResult("error", str(error))
        self._editor = None
        return SaveResult("saved", f"Saved {len(preview.changes)} configuration change(s)")


def _field_for(key: str) -> ConfigField | None:
    label = key.replace("_", " ").title()
    if key in configuration.BOOLEAN_KEYS or key.startswith(("MODULE_", "FEATURE_")):
        return ConfigField(key, label, "boolean", "Validated true/false setting")
    if key == "BACKUP_RETENTION_DAYS":
        return ConfigField(key, label, "integer", "Days to retain backups", minimum=1, maximum=3650)
    if key in _CHOICES:
        return ConfigField(key, label, "choice", "Choose an allowlisted value", _CHOICES[key])
    return None


def _typed_value(field: ConfigField, value: str) -> object:
    if field.kind == "boolean":
        return value == "true"
    if field.kind == "integer":
        return int(value)
    return value


def _typed_for_key(key: str, value: str | None) -> object:
    if value is None:
        return "(unset)"
    field = _field_for(key)
    return _typed_value(field, value) if field else value


def _normalize_field_value(field: ConfigField, value: object) -> object:
    if field.kind == "boolean":
        if not isinstance(value, bool):
            raise configuration.ConfigError(f"{field.key} requires a boolean")
        return value
    if field.kind == "integer":
        if isinstance(value, bool) or not isinstance(value, int):
            raise configuration.ConfigError(f"{field.key} requires an integer")
        if not field.minimum <= value <= field.maximum:
            raise configuration.ConfigError(
                f"{field.key} must be between {field.minimum} and {field.maximum}"
            )
        return value
    if field.kind == "choice":
        if not isinstance(value, str) or value not in field.choices:
            raise configuration.ConfigError(f"{field.key} requires an allowlisted choice")
        return value
    raise configuration.ConfigError(f"Unsupported editor field: {field.key}")
