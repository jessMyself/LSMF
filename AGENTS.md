# AGENTS.md - Development Guidelines for AI Assistants

## Project Overview

This is the **Linux Security Management Framework (LSMF)**, a Bash and Qt
application under active development for hardening and securing Linux systems.
The framework aims to be modular, idempotent, and safe for interactive and
automated use; production readiness requires the remaining VM gates.

## Architecture

### Core Components

1. **Main Launcher** (`src/lsmf`)
   - Entry point for all operations
   - Parses CLI arguments
   - Orchestrates module execution
   - Handles interactive UI

2. **Library Directory** (`src/lib/`)
   - `common.sh` - Shared utilities, logging, validation
   - `backup.sh` - Backup and restore operations
   - `detection.sh` - System detection and classification
   - `reporting.sh` - Report generation in multiple formats

3. **Modules Directory** (`src/modules/`)
   - Independent security hardening modules
   - Each module is self-contained
   - Must implement: `run_*`, `rollback_*`, `verify_*` functions

4. **UI Directory** (`src/ui/`)
   - Dialog-based interactive menus
   - Progress indicators
   - User prompts and confirmations

## Development Guidelines

### Coding Standards

1. **Bash Best Practices**
   - Use `set -Eeuo pipefail` in all scripts
   - Quote all variables: `"${variable}"`
   - Use `[[ ]]` instead of `[ ]`
   - Prefer `$(command)` over backticks

2. **ShellCheck Compliance**
   - All scripts must pass ShellCheck without warnings
   - Run: `shellcheck src/**/*.sh`
   - Disable specific warnings with justification: `# shellcheck disable=SC2034 # Used in sourced script`

3. **Error Handling**
   - Use error traps: `trap 'error_handler' ERR`
   - Always check return codes
   - Provide meaningful error messages
   - Log errors before exiting

4. **Function Naming**
   - Use snake_case: `check_firewall_status()`
   - Prefix module functions: `ssh_configure_setting()`
   - Export library functions: `export -f function_name`

5. **Comments**
   - Add comments explaining WHY, not WHAT
   - Document complex logic
   - Include usage examples for functions
   - Module description at top of file

### Module Development

#### Module Template

```bash
#!/usr/bin/env bash

set -Eeuo pipefail

# Description: Brief description of what this module does
# Version: 1.0.0
# Author: Your Name

MODULE_NAME="module_name"
MODULE_VERSION="1.0.0"
MODULE_ENABLED="${MODULE_ENABLED:-true}"

run_module_name() {
    log_info "=== Module Name Hardening ==="
    
    # Create rollback point
    local rollback_id
    rollback_id=$(create_rollback_point "module_name" "Description")
    
    # Backup files before modification
    backup_file "/path/to/config"
    
    # Apply hardening
    # ... your logic here ...
    
    # Add to report
    add_report_data "Module Name" "What was done"
    
    log_success "Module completed"
    return 0
}

rollback_module_name() {
    local backup_id="$1"
    log_info "Rolling back module..."
    
    restore_file "/path/to/config" "${backup_id}"
    
    log_success "Rollback completed"
    return 0
}

verify_module_name() {
    log_info "Verifying module..."
    local issues=0
    
    # Check if hardening is applied
    # ... verification logic ...
    
    if [[ ${issues} -eq 0 ]]; then
        log_success "Verification passed"
        return 0
    else
        log_warn "Verification found ${issues} issues"
        return 1
    fi
}

# Run if executed directly
if [[ "${MODULE_ENABLED}" == "true" ]] && [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    run_module_name
fi
```

#### Module Requirements

1. **Idempotency**
   - Running multiple times should be safe
   - Check current state before modifying
   - Skip if already configured

2. **Backup**
   - Always backup files before modification
   - Use `backup_file()` function
   - Store rollback information

3. **Validation**
   - Validate configuration before applying
   - Test service restart/reload
   - Rollback on failure

4. **Logging**
   - Use logging functions: `log_info`, `log_error`, `log_success`
   - Log all significant actions
   - Include debug logging for troubleshooting

5. **Error Handling**
   - Return non-zero on failure
   - Cleanup on error
   - Restore previous state if possible

### Library Function Usage

Common functions available in all modules:

**Logging:**
```bash
log_info "Message"
log_success "Success message"
log_warn "Warning message"
log_error "Error message"
log_debug "Debug message"
```

**Backup/Restore:**
```bash
backup_file "/path/to/file"
restore_file "/path/to/file" "${backup_id}"
create_rollback_point "name" "description"
```

**System Detection:**
```bash
detect_os
is_supported_os
command_exists "command_name"
package_installed "package_name"
is_service_active "service_name"
```

**Execution:**
```bash
execute_command "command to run"
confirm "Prompt message" "y/n"
```

**Reporting:**
```bash
add_report_data "Key" "Value"
add_warning "Warning message"
add_recommendation "Recommendation"
```

### Testing

1. **Before Committing**
   - Test on a clean VM
   - Run ShellCheck
   - Test dry-run mode: `lsmf -d harden`
   - Test rollback functionality
   - Verify reports are generated

2. **Test Different Scenarios**
   - Fresh installation
   - Re-running hardening
   - Rollback and re-apply
   - Different OS distributions

3. **Test Script Template**
```bash
#!/usr/bin/env bash
# Test script for module_name

set -Eeuo pipefail

test_module() {
    echo "Testing module_name..."
    
    # Test dry run
    LSMF_DRY_RUN=true bash src/modules/module_name.sh
    
    # Test actual run
    bash src/modules/module_name.sh
    
    # Test verification
    verify_module_name
    
    # Test rollback
    rollback_module_name "${LSMF_RUN_ID}"
    
    echo "All tests passed!"
}

test_module
```

### Configuration

- Main config: `/etc/lsmf/lsmf.conf`
- Use `read_config_value "KEY"` to read
- Use `set_config_value "KEY" "VALUE"` to write
- Default values in code: `${CONFIG_VALUE:-default}`

### File Paths

**Development Mode:**
- Scripts run from source directory
- Uses relative paths

**Installed Mode:**
- Installed to `/opt/lsmf/`
- Config in `/etc/lsmf/`
- Logs in `/var/log/lsmf/`
- Backups in `/var/backups/lsmf/`

Handle both modes:
```bash
if [[ -d "${SCRIPT_DIR}/src/lib" ]]; then
    LIB_DIR="${SCRIPT_DIR}/src/lib"
else
    LIB_DIR="/opt/lsmf/lib"
fi
```

## Common Patterns

### Modifying Configuration Files

```bash
configure_setting() {
    local config_file="$1"
    local key="$2"
    local value="$3"
    
    # Backup first
    backup_file "${config_file}"
    
    # Update or append
    if grep -qE "^#?${key}" "${config_file}"; then
        sed -i "s|^#\?${key}.*|${key} ${value}|" "${config_file}"
    else
        echo "${key} ${value}" >> "${config_file}"
    fi
}
```

### Installing Packages

```bash
install_package() {
    local package="$1"
    
    if package_installed "${package}"; then
        log_info "${package} already installed"
        return 0
    fi
    
    local pkg_mgr
    pkg_mgr=$(detect_package_manager)
    
    case "${pkg_mgr}" in
        apt)
            execute_command "apt-get update"
            execute_command "apt-get install -y ${package}"
            ;;
        dnf|yum)
            execute_command "${pkg_mgr} install -y ${package}"
            ;;
    esac
}
```

### Service Management

```bash
configure_service() {
    local service="$1"
    
    if is_service_active "${service}"; then
        systemctl reload "${service}"
    else
        systemctl enable --now "${service}"
    fi
}
```

## Debugging

### Enable Verbose Mode

```bash
lsmf --verbose harden
```

### Check Logs

```bash
tail -f /var/log/lsmf/[RUN_ID]/lsmf.log
```

### Dry Run

```bash
lsmf -d harden
```

### Debug Specific Module

```bash
LSMF_VERBOSE=true bash src/modules/module_name.sh
```

## Git Workflow

1. Create feature branch: `git checkout -b feature/module-name`
2. Make changes
3. Test thoroughly
4. Commit with descriptive message
5. Push and create pull request

## Performance Considerations

- Avoid unnecessary command execution
- Use built-in Bash features when possible
- Cache detection results
- Minimize file I/O
- Consider parallel execution for independent modules

## Security Considerations

- Never store passwords in code
- Validate all inputs
- Use secure defaults
- Minimal privilege principle
- Sanitize file paths
- Check for command injection vectors

## Documentation

Update documentation when:
- Adding new modules
- Changing CLI options
- Modifying configuration options
- Adding new profiles
- Changing default behavior

Files to update:
- `README.md` - User documentation
- `CHANGELOG.md` - Version history
- Module comments - Inline documentation
- `AGENTS.md` - This file

## Need Help?

- Check existing modules for examples
- Review library functions in `src/lib/`
- Test in a VM before production
- Use ShellCheck for validation
- Read CIS Benchmarks for security guidance

## Module Priority

When adding new modules, consider:
1. **High Priority**: SSH, Firewall, Kernel hardening
2. **Medium Priority**: PAM, Audit, File integrity
3. **Low Priority**: Nice-to-have features

---

**Happy Coding! Build secure systems! 🔒**
