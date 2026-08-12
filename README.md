# Linux Security Management Framework (LSMF)

LSMF is an experimental Linux security-hardening framework with a Bash engine
and an unprivileged PySide6/Qt desktop interface. It emphasizes bounded
privilege, exact rollback, durable recovery, explicit authorization, and
evidence-backed release claims.

> **Safety notice:** LSMF is not production-ready. Test hardening and rollback
> only in disposable systems. Do not install the release candidate or run its
> mutation paths on a workstation or production machine.

## Current status

- Four Bash modules exist: SSH, firewall, network, and kernel hardening.
- Qt is the only graphical interface; the former browser interface is retired.
- The desktop runs without root privileges and uses a fixed, default-deny
  system-bus helper for approved privileged operations.
- Qt mutation is intentionally limited to kernel hardening or the exact ordered
  kernel-plus-network transaction, with eligible backup IDs and exact rollback.
- Mutable Qt Cancel remains disabled because its same-connection terminal-order
  defect is unresolved.
- A recorded amd64 Debian-family candidate passed one bounded, offline Ubuntu
  24.04 VM row. Publication-closure metadata changed the package archive after
  that row; a newly built archive requires replacement VM verification.
  Other distributions remain unverified targets.

Passing that VM row does not approve workstation installation, establish broad
distribution support, or make the project production-ready.

## Architecture and security model

The desktop is unprivileged. Privileged requests use a typed protocol, fixed
D-Bus interface, distinct Polkit actions, caller/session binding, protected
audit records, fixed subprocess entry points, bounded output, serialization,
and durable recovery lockout after uncertain mutation.

Source checkout alone does not install, register, enable, or start the helper.
The release package does not enable or start it during installation.

See:

- [Architecture](docs/architecture.md)
- [Privileged-helper design](docs/privileged-helper.md)
- [Security policy](SECURITY.md)
- [Verified claims and limitations](project-review/SECTION4_CLAIM_MATRIX.md)
- [VM evidence index](project-review/README.md)

## Desktop development

Run the interface as an ordinary user, never with `sudo`:

```bash
./scripts/install_desktop_deps.sh
./start-desktop.sh
```

See the [desktop guide](docs/desktop-interface.md) for dependencies and current
capabilities.

## Safe local verification

These checks do not apply live hardening:

```bash
bash tests/run_tests.sh
python3 -m unittest discover -s tests -p 'test_*.py'
python3 -m compileall -q desktop lsmf tests
make validate
bash scripts/check_release_claims.sh
```

ShellCheck is mandatory in CI. VM-only behavior cannot be proven by local unit
tests or mocks.

## Release-candidate package

`packaging/debian/build-package.sh` builds the deterministic amd64 package from
an explicit absolute output directory and version. Package construction does
not install it. The current builder includes third-party notices added after
the recorded Gate 4.5 artifact, so its output must complete a replacement VM
row before any binary release. It is not a general installation recommendation.

## Documentation

- [Project outline](docs/project-outline.md)
- [Desktop interface](docs/desktop-interface.md)
- [Configuration schema](docs/configuration.md)
- [Module development](docs/module-development.md)
- [Contributing](CONTRIBUTING.md)
- [Changelog](CHANGELOG.md)
- [Release-verification roadmap](project-review/consolidated-qt-roadmap.md)

## AI development disclosure

This project was developed with substantial assistance from AI coding tools.
Architecture, generated code, tests, documentation, and security-sensitive
changes were reviewed through automated checks and isolated virtual-machine
verification. AI assistance does not imply that the software is free of
defects; review the code and use it only in appropriate test environments.

## License

LSMF's own source is MIT-licensed; see [LICENSE](LICENSE). The release-candidate
package also redistributes pinned PySide6, Qt, and Shiboken components under
their applicable open-source terms. See [third-party notices](THIRD_PARTY_NOTICES.md).
