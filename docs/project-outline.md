# LSMF Project Outline

## Purpose

The Linux Security Management Framework (LSMF) is intended to provide modular,
repeatable Linux security auditing, hardening, verification, reporting, backup,
and rollback. The project combines a Bash system engine with an unprivileged
PySide6/Qt desktop interface.

This document is the canonical product outline. A capability is not considered
implemented merely because it appears in configuration, an interface, or a
historical design document.

## Product principles

- Keep modules independent, idempotent, testable, and reversible.
- Detect the host before choosing platform-specific behavior.
- Create and validate durable backups before mutation.
- Report partial or uncertain outcomes instead of claiming success.
- Keep the desktop process unprivileged.
- Permit privileged operations only through typed, allowlisted actions with
  per-action authorization and protected audit records.
- Test mutation and rollback in disposable VMs, never on the development host.
- Maintain one canonical module inventory and one non-executable configuration
  schema.

## Implemented foundation

### Bash engine

- Entry point: `src/lsmf`.
- Libraries for common operations, detection, backup/restore, and reporting.
- Four module scripts: SSH, firewall, network, and kernel hardening.
- Desktop, server, and maximum-lockdown configuration profiles.
- A test harness and Python unit tests for the newer shared services.

The modules require further isolated idempotency, verification, and rollback
proof before production use.

### Qt desktop interface

The desktop application provides unprivileged inspection,
project-configuration, and typed helper-client workflows:

- Host and platform evidence.
- Discovery of actual module scripts and their declared capabilities.
- Validated configuration display and typed editing of the user-owned project
  configuration.
- Profile discovery and exact change previews.
- Report, backup, readiness, and bounded log views.

It can request separately authorized audit, one-module verification, the fixed
single and ordered-pair sysctl applies, and rollback of one exact eligible
backup. Mutable cancellation remains disabled pending the documented live
terminal-ordering defect.

### Privileged-helper preparation

The repository contains the typed protocol, credential-bound system-bus
service, per-action Polkit authorization, fixed executors, protected audit,
durable recovery, tests, service inputs, and a Debian-family package builder.
A source checkout installs nothing. The release-candidate package passed its
bounded offline Ubuntu 24.04 VM row, but is not approved for workstation use
or another distribution before release closure.

## Feature configuration direction

Granular feature controls remain a product goal, but historical claims of more
than 80 implemented features across nine modules were inaccurate. A feature
toggle may be exposed only when:

1. an implemented module consumes it;
2. its type, default, and risk are defined in the canonical schema;
3. apply, verification, idempotency, and rollback behavior are tested; and
4. the Qt interface reports its state truthfully.

Filesystem, PAM/password, container, web-server, and database hardening are
planned module families, not current implementations.

## Platform targets

The intended Linux targets include current Debian, Ubuntu, Linux Mint, Fedora,
Rocky Linux, AlmaLinux, KDE Neon, and best-effort Kali releases. Package-manager,
init-system, firewall, mandatory-access-control, boot, virtualization, desktop,
container, and cloud detection are architectural goals.

These are target platforms, not a compatibility guarantee. Support must be
claimed per tested image after the VM verification matrix records the version,
checksum, scenarios, and results.

## Interfaces

- **Qt desktop:** the sole graphical interface.
- **Bash CLI:** the system engine and development entry point.
- **Terminal menu:** retained but must hide or label placeholder actions.
- **Browser UI:** retired by user decision; no HTTP service or Flask dependency
  belongs in the product.

## Remaining program

The program contains exactly four user-gated sections:

1. **Disposable-VM helper integration:** completed.
2. **Qt audit and verification:** completed with cancellation limitation.
3. **Qt apply and rollback:** completed with durable recovery proof.
4. **Release verification:** active; source reconciliation and package
   preparation do not substitute for the separately approved VM matrix.

Detailed scope and acceptance criteria are maintained in
`project-review/consolidated-qt-roadmap.md`.

## Completion standard

LSMF is release-ready only when retained actions have automated coverage,
privileged actions pass their approved disposable-VM scenarios, documentation
matches implemented behavior, and failed or unavailable checks are reported as
such. Mock tests do not substitute for VM evidence.
