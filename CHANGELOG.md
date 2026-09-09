# Changelog

All notable changes to the Linux Security Management Framework (LSMF) will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- Unprivileged PySide6/Qt desktop interface and shared read services
- Canonical validated configuration and typed project-file editor
- Typed mock and Gate-2 privileged-helper protocols, request/peer binding,
  trusted-manifest policy, protected audit sink, system-bus credential boundary,
  libsystemd session resolver, fixed-argv Polkit adapter, specifications, and
  inactive-by-default package inputs
- Low-level `dbus-next` service transport for only `Submit` and `Cancel`, with
  unique-sender credential lookup, replay/ownership checks, trusted disconnect
  invalidation, and the fixed Section 3 dispatcher composition
- Manifest-only synthetic filesystem executor with read-only audit/verification,
  backup-first atomic apply, exact rollback, recovery backups, and durable
  mutation lockout when restoration cannot be verified
- Mock-tested production dispatcher with exact policy and authorization order,
  full-operation serialization, typed cancellation acknowledgement, fixed
  timeouts, cooperative disconnect handling, and protected lifecycle auditing
- Nonblocking fixed-argument Polkit adapter with exact five-action allowlisting,
  clean process environment, PID-reuse checks, bounded timeout, and child
  termination on cancellation
- Canonical project outline and four-section Qt roadmap
- Deterministic CI covering Bash, Python, headless Qt, protocol/security,
  temporary-root integration, and offline Debian-package inspection
- Debian-family Qt/helper release-candidate builder with a pinned offline
  PySide6 runtime; the recorded Gate 4.5 artifact passed its bounded Ubuntu
  24.04 VM row. Publication metadata subsequently changed the archive, so a
  newly built artifact requires replacement VM verification

### Changed

- Qt is now the sole graphical interface
- Product documentation distinguishes implemented behavior from planned or
  unverified capabilities
- Remaining milestones are numbered Sections 1 through 4
- Qt now exposes the verified Section 2 audit/verification and bounded Section
  3 apply/exact-rollback actions, and mutable Cancel is enabled for any running
  request with cancellation delivered on the helper's own connection

### Removed

- Flask server, browser assets, web launch/dependency scripts, and web-specific
  documentation
- Duplicate source copies, generated transcripts, and unrelated installer
  binaries

### Planned
- CIS compliance detailed scanner
- Additional hardening modules
  - PAM hardening
  - Audit system (auditd)
  - File integrity monitoring (AIDE)
  - Malware detection (rkhunter, chkrootkit, ClamAV)
  - Fail2Ban integration
  - AppArmor/SELinux profile management
- Broader package distribution
  - .rpm packages for RHEL/Fedora
  - Snap package
- Additional compliance frameworks
  - PCI-DSS
  - HIPAA
  - NIST CSF
- Remote management capabilities
- Ansible integration
- Container-based testing
- Module marketplace
- API for programmatic access

---

## Version History

No production release has been issued. The current package version is a release
candidate and is not production-ready.
