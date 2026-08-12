# Module Development Guide

## Quick Start

### Create a New Module

1. Copy the template:
```bash
cp src/modules/ssh_hardening.sh src/modules/mymodule.sh
```

2. Edit the module name and implement functions

3. Test the module:
```bash
sudo bash src/modules/mymodule.sh
```

## Module Structure

```bash
#!/usr/bin/env bash

set -Eeuo pipefail

# Module metadata
MODULE_NAME="mymodule"
MODULE_VERSION="1.0.0"
MODULE_ENABLED="${MODULE_ENABLED:-true}"

# Main execution function
run_mymodule() {
    log_info "=== My Module Hardening ==="
    
    # Your implementation here
    
    log_success "Module completed"
}

# Rollback function
rollback_mymodule() {
    local backup_id="$1"
    log_info "Rolling back..."
    
    # Restore changes
    
    log_success "Rollback completed"
}

# Verification function
verify_mymodule() {
    log_info "Verifying..."
    
    # Check if hardening is applied
    
    return 0
}

# Auto-run if executed directly
if [[ "${MODULE_ENABLED}" == "true" ]] && [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    run_mymodule
fi
```

## Available Library Functions

### Logging
```bash
log_info "Information message"
log_success "Success message"
log_warn "Warning message"
log_error "Error message"
log_debug "Debug message"
```

### Backup Operations
```bash
backup_file "/path/to/file"
restore_file "/path/to/file" "${backup_id}"
backup_directory "/path/to/dir"
create_rollback_point "name" "description"
```

### System Detection
```bash
detect_package_manager    # Returns: apt, dnf, yum, zypper
command_exists "command"  # Check if command exists
package_installed "pkg"   # Check if package installed
is_service_active "svc"   # Check if service running
```

### Execution
```bash
execute_command "command to run"
confirm "Question?" "y/n"
```

### Reporting
```bash
add_report_data "Key" "Value"
add_warning "Warning message"
add_recommendation "Recommendation"
```

## Best Practices

### 1. Always Backup First
```bash
run_mymodule() {
    local config_file="/etc/my.conf"
    backup_file "${config_file}"
    
    # Now safe to modify
    echo "setting=value" >> "${config_file}"
}
```

### 2. Validate Before Applying
```bash
run_mymodule() {
    local new_config="/tmp/my.conf"
    
    # Create new config
    generate_config > "${new_config}"
    
    # Validate
    if validate_config "${new_config}"; then
        backup_file "/etc/my.conf"
        cp "${new_config}" "/etc/my.conf"
    else
        log_error "Invalid configuration"
        return 1
    fi
}
```

### 3. Be Idempotent
```bash
run_mymodule() {
    if grep -q "setting=secure" /etc/my.conf; then
        log_info "Already configured, skipping"
        return 0
    fi
    
    # Apply changes
}
```

### 4. Handle Errors
```bash
run_mymodule() {
    if ! execute_command "critical-command"; then
        log_error "Critical command failed"
        return 1
    fi
    
    # Continue only if successful
}
```

### 5. Test Service Restart
```bash
run_mymodule() {
    backup_file "/etc/service.conf"
    
    # Modify config
    echo "option=value" >> "/etc/service.conf"
    
    # Test reload
    if systemctl reload myservice; then
        log_success "Service reloaded"
    else
        log_error "Service reload failed, restoring"
        restore_file "/etc/service.conf"
        systemctl reload myservice
        return 1
    fi
}
```

## Testing Your Module

### Manual Testing

```bash
# Test in dry-run mode
LSMF_DRY_RUN=true bash src/modules/mymodule.sh

# Test actual execution
sudo bash src/modules/mymodule.sh

# Test verification
verify_mymodule

# Test rollback
rollback_mymodule "${LSMF_RUN_ID}"
```

### Integration Testing

```bash
# Test through main launcher
sudo ./src/lsmf -m mymodule

# Test with profile
sudo ./src/lsmf -p custom harden
```

## Common Patterns

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
            execute_command "apt-get install -y ${package}"
            ;;
        dnf|yum)
            execute_command "${pkg_mgr} install -y ${package}"
            ;;
    esac
}
```

### Configuring Services

```bash
configure_service() {
    local service="$1"
    
    # Enable service
    systemctl enable "${service}"
    
    # Start or reload
    if is_service_active "${service}"; then
        systemctl reload "${service}"
    else
        systemctl start "${service}"
    fi
}
```

### Modifying Configuration

```bash
set_config_value() {
    local file="$1"
    local key="$2"
    local value="$3"
    
    backup_file "${file}"
    
    if grep -qE "^#?${key}" "${file}"; then
        sed -i "s|^#\?${key}.*|${key} ${value}|" "${file}"
    else
        echo "${key} ${value}" >> "${file}"
    fi
}
```

## Troubleshooting

### Enable Debug Logging

```bash
LSMF_VERBOSE=true bash src/modules/mymodule.sh
```

### Check Module Syntax

```bash
bash -n src/modules/mymodule.sh
shellcheck src/modules/mymodule.sh
```

### Test in Container

```bash
docker run -it -v $(pwd):/lsmf ubuntu:24.04 bash
cd /lsmf
bash src/modules/mymodule.sh
```
