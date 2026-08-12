# LSMF Architecture Map

## Product surfaces

- `desktop/`: unprivileged PySide6/Qt widgets and controller.
- `lsmf/`: shared Python configuration, module/profile, protocol, IPC-security,
  and mock helper services.
- `src/lsmf`: Bash CLI entry point and dispatcher.
- `src/lib/`: common operations, detection, backup/restore, and reporting.
- `src/modules/`: four implemented hardening modules: SSH, firewall, network,
  and kernel.
- `src/ui/menu.sh`: legacy terminal menu; unimplemented entries are visibly
  labelled as planned and are not release claims.
- `config/`: canonical configuration and profiles.
- `packaging/privileged-helper/`: installed-runtime inputs and safe staging.
- `packaging/debian/`: deterministic Debian-family release-candidate builder.

There is no browser or HTTP product surface.

## Runtime relationships

1. `start-desktop.sh` starts `desktop.main` as a normal user.
2. The Qt controller consumes unprivileged services from `desktop/` and `lsmf/`.
3. Configuration is parsed as data and is never sourced by Python.
4. `src/lsmf` sources core Bash libraries and dispatches CLI operations.
5. Modules use shared libraries for detection, backup, mutation, verification,
   and reporting.
6. Privileged Qt actions cross the typed allowlisted helper boundary; Qt never
   becomes root.

## Trust boundaries

- Live Bash hardening and rollback can alter the host and belong only in an
  approved disposable VM until release verification is complete.
- A source checkout installs no helper. The recorded Gate 4.5 package passed a
  bounded offline Ubuntu 24.04 install/removal row. Publication metadata then
  changed the archive, so current builder output needs a replacement VM row and
  remains unapproved for workstation or production use.
- The production helper must derive peer identity from IPC credentials, obtain
  per-action authorization, accept no arbitrary commands or paths, and write a
  protected audit record.
- Unsupported and untested distributions are targets, not compatibility claims.
