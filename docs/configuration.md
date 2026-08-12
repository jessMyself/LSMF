# LSMF Configuration Schema

LSMF uses one non-executable, flat assignment format for the CLI and Qt desktop interface:

```text
# Comments and blank lines are allowed.
DISABLE_IPV6="true"
MODULE_SSH_ENABLED="true"
FEATURE_SSH_ROOT_LOGIN="true"
```

Keys must match `[A-Z][A-Z0-9_]*`. Values must be double-quoted and cannot contain quotes, backslashes, or newlines. Configuration files are parsed as data and must never be sourced or evaluated by a shell or Python process. Duplicate keys, sections, malformed assignments, and invalid known values are errors.

Unknown syntactically valid keys are accepted and preserved so a newer configuration can be handled by an older interface. Boolean settings accept only `true` or `false`. `BACKUP_RETENTION_DAYS` is a positive integer. `LOGGING_LEVEL` accepts `DEBUG`, `INFO`, `WARNING`, or `ERROR`; `MAC_SYSTEM` accepts `auto`, `apparmor`, `selinux`, or `none`; and `SYSTEM_ROLE` accepts `auto`, `desktop`, or `server`.

## Key inventory and defaults

The shipped `config/lsmf.conf` is the source of defaults. Its global keys are:

- Runtime: `LSMF_VERSION`, `INTERACTIVE_MODE`, `DRY_RUN`, `SYSTEM_ROLE`
- Selection: `ENABLED_MODULES`, `MAC_SYSTEM`
- Hardening: `DISABLE_IPV6`, `FIREWALL_ENABLED`, `SSH_HARDENING`, `SSH_PERMIT_ROOT_LOGIN`, `SSH_PASSWORD_AUTH`, `NETWORK_HARDENING`, `KERNEL_HARDENING`, `AUTOMATIC_UPDATES`, `CIS_COMPLIANCE_CHECK`
- Safety and output: `BACKUP_ENABLED`, `BACKUP_RETENTION_DAYS`, `ROLLBACK_ENABLED`, `LOGGING_LEVEL`, `LOGGING_VERBOSE`, `REPORT_FORMATS`

Profiles use the same grammar and may also define `PROFILE_NAME`, `PROFILE_DESCRIPTION`, `COMPILER_RESTRICTIONS`, and `USB_RESTRICTIONS`. The installer copies the main file and profiles without parsing them. The CLI `--config` option selects an alternate file; the network module currently consumes `DISABLE_IPV6` through the shared Bash reader. Profile-driven module selection is tracked separately in `LSMF-005`.

Module and feature state is namespaced as `MODULE_<MODULE_ID>_ENABLED` and `FEATURE_<MODULE_ID>_<FEATURE_ID>`. Missing module or feature keys use the default declared by the consuming interface; the Qt interface remains read-only during this migration section.

Readers and writers are `read_config_value`, `validate_config_file`, and `set_config_value` in `src/lib/common.sh`; the interface-neutral `ConfigStore` in `lsmf/configuration.py`; and the read-only desktop service. Bash writes preserve comments and ordering where possible. Python writes preserve key order and unknown keys but intentionally normalize the header and remove comments. Both writers replace the target atomically with a temporary file in the same directory.

The Qt editor exposes only predefined boolean, integer, and allowlisted-choice fields through `desktop/controller.py`. `lsmf/config_editor.py` limits saves to explicit user/project roots, rejects installed `/etc/lsmf`, root- or other-user-owned targets, symlink paths, unsafe parents, stale revisions, and invalid values. Unknown canonical keys remain in the file but are not automatically exposed as editable fields. Profile selection is preview-only in this stage.

## Migrating the legacy mixed file

Validate and migrate an old assignment/INI file without executing it:

```bash
python3 scripts/migrate_config.py --check /etc/lsmf/lsmf.conf
python3 scripts/migrate_config.py /etc/lsmf/lsmf.conf
```

Migration maps `[ssh_hardening] module_enabled` to `MODULE_SSH_ENABLED` and feature entries to `FEATURE_SSH_<FEATURE>`. It normalizes ordering/comments and creates `/etc/lsmf/lsmf.conf.legacy.bak` before atomically replacing the original.
