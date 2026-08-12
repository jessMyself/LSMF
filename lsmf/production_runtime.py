"""Explicit composition root for the inactive synthetic production helper."""

from __future__ import annotations

from dataclasses import dataclass
import asyncio
from pathlib import Path
import sys
from typing import Callable

from .privileged_protocol import Action
from .production_dispatcher import ProductionAuthorizer, ProductionDispatcher
from .protected_audit import ProtectedProductionAuditSink
from .read_only_process import ReadOnlyProcessExecutor
from .synthetic_process import SyntheticProcessExecutor
from .sysctl_manifest import SysctlManifestPolicy, load_sysctl_manifest
from .sysctl_process import SysctlProcessExecutor
from .system_authorization import AsyncPkcheckAuthorizer
from .system_bus_service import (
    CredentialResolver,
    SystemBusServiceBoundary,
    run_system_bus_service,
)
from .system_session import SystemdLoginSessionAdapter
from .trusted_manifest import TrustedManifestPolicy, load_trusted_manifest


class ProductionRuntimeError(RuntimeError):
    """Raised when helper-owned runtime configuration is incomplete."""


@dataclass(frozen=True, slots=True)
class Section2RuntimeConfig:
    runner_path: Path
    audit_path: Path
    pkcheck_executable: Path = Path("/usr/bin/pkcheck")
    expected_uid: int = 0

    def __post_init__(self) -> None:
        paths = (self.runner_path, self.audit_path, self.pkcheck_executable)
        if (
            any(not isinstance(path, Path) or not path.is_absolute() or "\x00" in str(path) for path in paths)
            or isinstance(self.expected_uid, bool)
            or not isinstance(self.expected_uid, int)
            or self.expected_uid < 0
        ):
            raise ProductionRuntimeError("Section 2 runtime configuration is invalid")
        for name, path in zip(("runner_path", "audit_path", "pkcheck_executable"), paths, strict=True):
            object.__setattr__(self, name, path.resolve(strict=False))


@dataclass(frozen=True, slots=True)
class Section3RuntimeConfig:
    runner_path: Path
    manifest_path: Path
    target_root: Path
    sysctl_root: Path
    backup_root: Path
    audit_path: Path
    worker_executable: Path = Path(sys.executable)
    pkcheck_executable: Path = Path("/usr/bin/pkcheck")
    expected_uid: int = 0
    worker_executable_uid: int = 0

    def __post_init__(self) -> None:
        names = (
            "runner_path", "manifest_path", "target_root", "sysctl_root", "backup_root", "audit_path",
            "worker_executable", "pkcheck_executable",
        )
        paths = tuple(getattr(self, name) for name in names)
        if (
            any(not isinstance(path, Path) or not path.is_absolute() or "\x00" in str(path) for path in paths)
            or any(isinstance(value, bool) or not isinstance(value, int) or value < 0 for value in (
                self.expected_uid, self.worker_executable_uid
            ))
        ):
            raise ProductionRuntimeError("Section 3 runtime configuration is invalid")
        for name, path in zip(names, paths, strict=True):
            object.__setattr__(self, name, path.resolve(strict=False))
        if self.expected_uid == 0 and (self.target_root != Path("/") or self.sysctl_root != Path("/proc/sys")):
            raise ProductionRuntimeError("installed Section 3 roots must be fixed")
        if self.backup_root == self.audit_path.parent or self.manifest_path.parent == self.backup_root:
            raise ProductionRuntimeError("Section 3 security stores must be disjoint")


@dataclass(frozen=True, slots=True)
class ProductionRuntimeConfig:
    manifest_path: Path
    target_root: Path
    backup_root: Path
    audit_path: Path
    worker_executable: Path = Path(sys.executable)
    pkcheck_executable: Path = Path("/usr/bin/pkcheck")
    expected_uid: int = 0
    worker_executable_uid: int = 0

    def __post_init__(self) -> None:
        names = (
            "manifest_path", "target_root", "backup_root", "audit_path",
            "worker_executable", "pkcheck_executable",
        )
        paths = tuple(getattr(self, name) for name in names)
        if (
            any(not isinstance(path, Path) or not path.is_absolute() or "\x00" in str(path) for path in paths)
            or isinstance(self.expected_uid, bool)
            or not isinstance(self.expected_uid, int)
            or self.expected_uid < 0
            or isinstance(self.worker_executable_uid, bool)
            or not isinstance(self.worker_executable_uid, int)
            or self.worker_executable_uid < 0
        ):
            raise ProductionRuntimeError("helper runtime configuration is invalid")
        for name, path in zip(names, paths, strict=True):
            object.__setattr__(self, name, path.resolve(strict=False))
        protected = (
            (self.manifest_path, False),
            (self.target_root, True),
            (self.backup_root, True),
            (self.audit_path, False),
        )
        for index, (left, left_directory) in enumerate(protected):
            for right, right_directory in protected[index + 1:]:
                if (
                    left == right
                    or (left_directory and right.is_relative_to(left))
                    or (right_directory and left.is_relative_to(right))
                ):
                    raise ProductionRuntimeError("helper security stores must be disjoint")


INSTALLED_RUNTIME_CONFIG = ProductionRuntimeConfig(
    manifest_path=Path("/etc/lsmf/helper/synthetic-manifest.json"),
    target_root=Path("/var/lib/lsmf/synthetic-targets"),
    backup_root=Path("/var/backups/lsmf/synthetic"),
    audit_path=Path("/var/log/lsmf/helper.jsonl"),
    worker_executable=Path("/usr/bin/python3"),
    pkcheck_executable=Path("/usr/bin/pkcheck"),
)

INSTALLED_SECTION2_CONFIG = Section2RuntimeConfig(
    runner_path=Path("/usr/libexec/lsmf-read-only-runner"),
    audit_path=Path("/var/log/lsmf/helper.jsonl"),
)

INSTALLED_SECTION3_CONFIG = Section3RuntimeConfig(
    runner_path=Path("/usr/libexec/lsmf-read-only-runner"),
    manifest_path=Path("/etc/lsmf/helper/sysctl-manifest.json"),
    target_root=Path("/"),
    sysctl_root=Path("/proc/sys"),
    backup_root=Path("/var/backups/lsmf/sysctl"),
    audit_path=Path("/var/log/lsmf/helper.jsonl"),
    worker_executable=Path("/usr/bin/python3"),
    pkcheck_executable=Path("/usr/bin/pkcheck"),
)


def build_section2_dispatcher(
    config: Section2RuntimeConfig,
    *,
    authorizer: ProductionAuthorizer | None = None,
    process_factory: Callable[..., object] | None = None,
) -> ProductionDispatcher:
    """Compose the Section 2 helper with only audit and one verify command."""
    if not isinstance(config, Section2RuntimeConfig):
        raise ProductionRuntimeError("typed Section 2 runtime configuration is required")
    process_options = {}
    if process_factory is not None:
        process_options["process_factory"] = process_factory
    executor = ReadOnlyProcessExecutor(
        audit_command=(str(config.runner_path), "audit"),
        verification_commands={
            "kernel_hardening": (str(config.runner_path), "verify", "kernel_hardening")
        },
        expected_executable_uid=config.expected_uid,
        **process_options,
    )
    selected_authorizer = authorizer or AsyncPkcheckAuthorizer(
        executable=config.pkcheck_executable,
        expected_executable_uid=config.expected_uid,
    )
    return ProductionDispatcher(
        policy=executor,
        authorizer=selected_authorizer,
        executor=executor,
        audit_sink=ProtectedProductionAuditSink(config.audit_path, expected_uid=config.expected_uid),
    )


def build_section2_boundary(
    config: Section2RuntimeConfig,
    *,
    credentials: CredentialResolver,
    sessions: SystemdLoginSessionAdapter,
    authorizer: ProductionAuthorizer | None = None,
    process_factory: Callable[..., object] | None = None,
) -> SystemBusServiceBoundary:
    dispatcher = build_section2_dispatcher(
        config, authorizer=authorizer, process_factory=process_factory
    )
    return SystemBusServiceBoundary(credentials, sessions, dispatcher)


def build_section3_dispatcher(
    config: Section3RuntimeConfig,
    *,
    authorizer: ProductionAuthorizer | None = None,
    process_factory: Callable[..., object] | None = None,
) -> ProductionDispatcher:
    """Compose only the approved manifest-backed Section 3 mutation actions."""
    if not isinstance(config, Section3RuntimeConfig):
        raise ProductionRuntimeError("typed Section 3 runtime configuration is required")
    manifest = load_sysctl_manifest(config.manifest_path, expected_uid=config.expected_uid)
    options = {}
    if process_factory is not None:
        options["process_factory"] = process_factory
    mutation_executor = SysctlProcessExecutor(
        manifest_path=config.manifest_path,
        target_root=config.target_root,
        sysctl_root=config.sysctl_root,
        backup_root=config.backup_root,
        expected_uid=config.expected_uid,
        expected_executable_uid=config.worker_executable_uid,
        executable=config.worker_executable,
        **options,
    )
    selected_authorizer = authorizer or AsyncPkcheckAuthorizer(
        executable=config.pkcheck_executable,
        expected_executable_uid=config.expected_uid,
    )
    read_executor = ReadOnlyProcessExecutor(
        audit_command=(str(config.runner_path), "audit"),
        verification_commands={
            "kernel_hardening": (str(config.runner_path), "verify", "kernel_hardening")
        },
        expected_executable_uid=config.expected_uid,
    )
    mutation_policy = SysctlManifestPolicy(
        manifest, backup_eligible=mutation_executor.backup_eligible
    )

    class CombinedPolicy:
        def validate(self, request):
            if request.action in {Action.AUDIT, Action.VERIFY_MODULE}:
                return read_executor.validate(request)
            return mutation_policy.validate(request)

    class CombinedExecutor:
        async def execute(self, request, cancellation):
            if request.action in {Action.AUDIT, Action.VERIFY_MODULE}:
                return await read_executor.execute(request, cancellation)
            return await mutation_executor.execute(request, cancellation)

    return ProductionDispatcher(
        policy=CombinedPolicy(),
        authorizer=selected_authorizer,
        executor=CombinedExecutor(),
        audit_sink=ProtectedProductionAuditSink(config.audit_path, expected_uid=config.expected_uid),
    )


def build_section3_boundary(
    config: Section3RuntimeConfig,
    *,
    credentials: CredentialResolver,
    sessions: SystemdLoginSessionAdapter,
    authorizer: ProductionAuthorizer | None = None,
    process_factory: Callable[..., object] | None = None,
) -> SystemBusServiceBoundary:
    return SystemBusServiceBoundary(
        credentials,
        sessions,
        build_section3_dispatcher(
            config, authorizer=authorizer, process_factory=process_factory
        ),
    )


def build_production_dispatcher(
    config: ProductionRuntimeConfig,
    *,
    authorizer: ProductionAuthorizer | None = None,
    process_factory: Callable[..., object] | None = None,
) -> ProductionDispatcher:
    """Join trusted policy, Polkit, process execution, audit, and lifecycle."""
    if not isinstance(config, ProductionRuntimeConfig):
        raise ProductionRuntimeError("typed helper runtime configuration is required")
    manifest = load_trusted_manifest(config.manifest_path, expected_uid=config.expected_uid)
    process_options = {}
    if process_factory is not None:
        process_options["process_factory"] = process_factory
    executor = SyntheticProcessExecutor(
        manifest_path=config.manifest_path,
        target_root=config.target_root,
        backup_root=config.backup_root,
        expected_uid=config.expected_uid,
        expected_executable_uid=config.worker_executable_uid,
        executable=config.worker_executable,
        **process_options,
    )
    selected_authorizer = authorizer
    if selected_authorizer is None:
        selected_authorizer = AsyncPkcheckAuthorizer(
            executable=config.pkcheck_executable,
            expected_executable_uid=config.expected_uid,
        )
    return ProductionDispatcher(
        policy=TrustedManifestPolicy(manifest, backup_eligible=executor.backup_eligible),
        authorizer=selected_authorizer,
        executor=executor,
        audit_sink=ProtectedProductionAuditSink(config.audit_path, expected_uid=config.expected_uid),
    )


def build_production_boundary(
    config: ProductionRuntimeConfig,
    *,
    credentials: CredentialResolver,
    sessions: SystemdLoginSessionAdapter,
    authorizer: ProductionAuthorizer | None = None,
    process_factory: Callable[..., object] | None = None,
) -> SystemBusServiceBoundary:
    """Connect the composed dispatcher to the credential-bound transport."""
    dispatcher = build_production_dispatcher(
        config,
        authorizer=authorizer,
        process_factory=process_factory,
    )
    return SystemBusServiceBoundary(credentials, sessions, dispatcher)


async def run_installed_production_service(
    config: ProductionRuntimeConfig = INSTALLED_RUNTIME_CONFIG,
) -> None:
    """Construct every trusted dependency before acquiring the system-bus name."""
    dispatcher = build_production_dispatcher(config)
    await run_system_bus_service(dispatcher)


async def run_installed_section2_service(
    config: Section2RuntimeConfig = INSTALLED_SECTION2_CONFIG,
) -> None:
    """Run the installed read-only Section 2 composition."""
    dispatcher = build_section2_dispatcher(config)
    await run_system_bus_service(dispatcher)


async def run_installed_section3_service(
    config: Section3RuntimeConfig = INSTALLED_SECTION3_CONFIG,
) -> None:
    dispatcher = build_section3_dispatcher(config)
    await run_system_bus_service(dispatcher)


def main() -> int:
    asyncio.run(run_installed_production_service())
    return 0


def section2_main() -> int:
    asyncio.run(run_installed_section2_service())
    return 0


def section3_main() -> int:
    asyncio.run(run_installed_section3_service())
    return 0
