"""Read-only discovery and preview support for LSMF configuration profiles."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
import re

from lsmf.configuration import ConfigError, parse_config


PROFILE_METADATA_KEYS = frozenset({"PROFILE_NAME", "PROFILE_DESCRIPTION"})
PROFILE_ID_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_-]*$")


@dataclass(frozen=True)
class Profile:
    """A profile parsed as inert configuration data."""

    profile_id: str
    name: str
    description: str
    settings: dict[str, str]
    unknown_keys: tuple[str, ...] = ()
    validation_errors: tuple[str, ...] = ()

    @property
    def valid(self) -> bool:
        return not self.validation_errors


@dataclass(frozen=True)
class ProfileError:
    """A discovery error tied to an entry when one is available."""

    entry: str | None
    message: str


@dataclass(frozen=True)
class ProfileDiscovery:
    profiles: tuple[Profile, ...]
    errors: tuple[ProfileError, ...]


@dataclass(frozen=True)
class SettingChange:
    key: str
    before: str | None
    after: str


@dataclass(frozen=True)
class ProfilePreview:
    profile_id: str
    changes: tuple[SettingChange, ...]
    unknown_keys: tuple[str, ...]
    validation_errors: tuple[str, ...]

    @property
    def valid(self) -> bool:
        return not self.validation_errors


def discover_profiles(
    profiles_root: Path | str,
    canonical_base: dict[str, str],
) -> ProfileDiscovery:
    """Discover direct ``*.conf`` children without following unsafe entries."""
    root = Path(profiles_root)
    if not root.exists():
        return ProfileDiscovery((), (ProfileError(None, f"profiles directory is missing: {root}"),))
    if root.is_symlink() or not root.is_dir():
        return ProfileDiscovery(
            (), (ProfileError(root.name, f"profiles root is not a regular directory: {root}"),)
        )

    profiles: list[Profile] = []
    errors: list[ProfileError] = []
    seen_ids: dict[str, str] = {}
    for entry in sorted(root.iterdir(), key=lambda path: path.name.casefold()):
        if entry.suffix != ".conf":
            continue
        profile_id = entry.stem
        if entry.is_symlink():
            errors.append(ProfileError(entry.name, "profile symlinks are not allowed"))
            continue
        if not entry.is_file():
            errors.append(ProfileError(entry.name, "profile entry is not a regular file"))
            continue
        if not PROFILE_ID_PATTERN.fullmatch(profile_id):
            errors.append(ProfileError(entry.name, f"invalid profile ID: {profile_id}"))
            continue
        normalized_id = profile_id.casefold()
        if normalized_id in seen_ids:
            errors.append(
                ProfileError(
                    entry.name,
                    f"duplicate profile ID {profile_id}; conflicts with {seen_ids[normalized_id]}",
                )
            )
            continue
        seen_ids[normalized_id] = entry.name

        try:
            values = parse_config(entry)
        except (ConfigError, OSError, UnicodeError) as error:
            errors.append(ProfileError(entry.name, str(error)))
            continue

        validation_errors: list[str] = []
        name = values.get("PROFILE_NAME", "").strip()
        description = values.get("PROFILE_DESCRIPTION", "").strip()
        if not name:
            validation_errors.append("PROFILE_NAME is required")
        if not description:
            validation_errors.append("PROFILE_DESCRIPTION is required")
        settings = {
            key: value for key, value in values.items() if key not in PROFILE_METADATA_KEYS
        }
        unknown_keys = tuple(sorted(set(settings) - set(canonical_base)))
        profiles.append(
            Profile(
                profile_id=profile_id,
                name=name or profile_id,
                description=description,
                settings=settings,
                unknown_keys=unknown_keys,
                validation_errors=tuple(validation_errors),
            )
        )

    return ProfileDiscovery(tuple(profiles), tuple(errors))


def preview_profile(profile: Profile, canonical_base: dict[str, str]) -> ProfilePreview:
    """Return only settings whose resulting value differs from the base."""
    changes = tuple(
        SettingChange(key, canonical_base.get(key), value)
        for key, value in sorted(profile.settings.items())
        if canonical_base.get(key) != value
    )
    return ProfilePreview(
        profile_id=profile.profile_id,
        changes=changes,
        unknown_keys=profile.unknown_keys,
        validation_errors=profile.validation_errors,
    )
