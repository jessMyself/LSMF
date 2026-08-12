# LSMF Qt Desktop Interface

The PySide6 desktop application is LSMF's sole graphical interface. It is
intentionally unprivileged and must run as a normal user.

## Current capabilities

- Shows host and platform information.
- Shows the current user, architecture, backup-set count, and last-run timestamp evidence.
- Discovers implemented modules from `src/modules` rather than trusting documentation or a second registry.
- Displays truthful module metadata, configured enabled state, configuration key, and run/verify/rollback capabilities.
- Reads and validates the canonical flat configuration without executing it.
- Shows a clear valid, invalid, or unavailable configuration state without hiding unrelated dashboard data.
- Lists recent reports and backups from development and installed locations.
- Displays a read-only tail of the newest real LSMF log, bounded to 100 lines and 128 KiB, with its source and explicit unavailable/read-error states.
- Reports interface-readiness issues such as invalid configuration or malformed module metadata.
- Edits a predefined set of typed settings in the user-owned project configuration with confirmation, atomic replacement, stale-file detection, and unknown-key preservation.
- Discovers canonical profiles and previews their exact changes and warnings without applying them.
- Submits typed, separately authorized audit and `kernel_hardening`
  verification requests to an installed helper.
- Submits only the manifest-fixed `kernel_hardening` apply, ordered
  `kernel_hardening` plus `network_hardening` apply, and exact eligible-backup
  rollback requests after explicit confirmation.

It cannot edit installed `/etc/lsmf` configuration, apply arbitrary profiles or
modules, or select paths and commands for the helper. Mutable Cancel remains
disabled because the deferred same-connection cancellation case has not
returned its required typed terminal result in live testing.

The Gate-1 helper threat model, typed protocol, and default-deny mock core are
documented in [privileged-helper.md](privileged-helper.md). The completed helper
foundation now includes peer/session binding, fixed Polkit actions, D-Bus and
systemd artifacts, protected auditing, process isolation, durable recovery, and
Qt action controls. A source checkout does not install or activate the helper.
The release-candidate package passed the bounded offline Ubuntu 24.04 Section 4
VM row specified in
[privileged-helper-vm-verification.md](privileged-helper-vm-verification.md).
That evidence does not approve workstation installation or another
distribution.

## Install and run

```bash
./scripts/install_desktop_deps.sh
./start-desktop.sh
```

The installer reuses a virtual environment created directly at the project root when `pyvenv.cfg` and `bin/python` are present. Otherwise it creates `.venv-desktop`. The launcher refuses to run as root.

On Ubuntu, Qt also needs native X11 libraries. The launcher checks the `xcb` platform plugin before startup and reports unresolved libraries. For example, install a missing cursor library with:

```bash
sudo apt-get install libxcb-cursor0
```

## Development verification

The reusable service layer does not depend on Qt:

```bash
python3 -m unittest tests.test_desktop_services tests.test_module_catalog
python3 -m unittest tests.test_config_editor tests.test_profiles tests.test_desktop_controller
python3 -m py_compile desktop/services.py desktop/main.py
QT_QPA_PLATFORM=offscreen ./bin/python -m unittest tests.test_desktop_qt
```

## Consolidated remaining migration plan

The read-only dashboard, canonical configuration, safe project-file editor,
helper integration, audit/verification, and bounded apply/rollback sections are
complete. The program sections are:

1. **Section 1:** completed synthetic helper integration.
2. **Section 2:** completed Qt audit and one-module verification, with its
   same-connection cancellation limitation deferred and visible.
3. **Section 3:** completed bounded Qt apply, exact rollback, and durable
   recovery proof.
4. **Section 4:** the bounded Ubuntu 24.04 package row passed; documentation,
   privacy, clean-history publication, and CI closure remain release work.

See [the consolidated Qt roadmap](../project-review/consolidated-qt-roadmap.md) for scope, exclusions, dependencies, acceptance criteria, and verification requirements.

## Security model

- The desktop UI never runs as root.
- Display operations use ordinary file reads and Python platform APIs.
- No shell configuration is sourced or evaluated.
- No command strings are accepted from the UI.
- Privileged requests use typed, allowlisted parameters and produce protected
  audit records; Qt never receives generic command or path authority.
