#!/usr/bin/env bash

set -Eeuo pipefail

MODULE_NAME="ssh_hardening"
MODULE_VERSION="1.0.0"
MODULE_ENABLED="${MODULE_ENABLED:-true}"

run_ssh_hardening() {
    log_info "=== SSH Hardening Module ==="
    
    if ! package_installed openssh-server; then
        log_info "SSH server not installed, skipping module"
        return 0
    fi
    
    local ssh_config="/etc/ssh/sshd_config"
    
    if [[ ! -f "${ssh_config}" ]]; then
        log_error "SSH config not found: ${ssh_config}"
        return 1
    fi
    
    backup_file "${ssh_config}"
    
    local rollback_id
    rollback_id=$(create_rollback_point "ssh_hardening" "SSH configuration hardening")
    
    log_info "Hardening SSH configuration..."
    
    configure_ssh_setting "${ssh_config}" "PermitRootLogin" "no"
    configure_ssh_setting "${ssh_config}" "PasswordAuthentication" "no"
    configure_ssh_setting "${ssh_config}" "PubkeyAuthentication" "yes"
    configure_ssh_setting "${ssh_config}" "PermitEmptyPasswords" "no"
    configure_ssh_setting "${ssh_config}" "X11Forwarding" "no"
    configure_ssh_setting "${ssh_config}" "MaxAuthTries" "3"
    configure_ssh_setting "${ssh_config}" "MaxSessions" "2"
    configure_ssh_setting "${ssh_config}" "ClientAliveInterval" "300"
    configure_ssh_setting "${ssh_config}" "ClientAliveCountMax" "2"
    configure_ssh_setting "${ssh_config}" "LoginGraceTime" "60"
    configure_ssh_setting "${ssh_config}" "Protocol" "2"
    
    configure_ssh_setting "${ssh_config}" "Ciphers" "chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-ctr"
    
    configure_ssh_setting "${ssh_config}" "MACs" "hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com,hmac-sha2-512,hmac-sha2-256"
    
    configure_ssh_setting "${ssh_config}" "KexAlgorithms" "curve25519-sha256,curve25519-sha256@libssh.org,diffie-hellman-group-exchange-sha256"
    
    configure_ssh_setting "${ssh_config}" "HostKeyAlgorithms" "ssh-ed25519,rsa-sha2-512,rsa-sha2-256"
    
    configure_ssh_setting "${ssh_config}" "PubkeyAcceptedKeyTypes" "ssh-ed25519,rsa-sha2-512,rsa-sha2-256"
    
    if validate_sshd_config "${ssh_config}"; then
        log_success "SSH configuration validated"
        
        if is_service_active sshd || is_service_active ssh; then
            local ssh_service="sshd"
            is_service_active ssh && ssh_service="ssh"
            
            if systemctl reload "${ssh_service}"; then
                log_success "SSH service reloaded successfully"
            else
                log_error "Failed to reload SSH service, restoring backup"
                restore_file "${ssh_config}"
                systemctl reload "${ssh_service}" || true
                return 1
            fi
        fi
        
        add_report_data "SSH Hardening" "Applied strong ciphers, disabled root login, enforced key auth"
        log_success "SSH hardening completed successfully"
        return 0
    else
        log_error "SSH configuration validation failed, restoring backup"
        restore_file "${ssh_config}"
        return 1
    fi
}

configure_ssh_setting() {
    local config_file="$1"
    local key="$2"
    local value="$3"
    
    if grep -qE "^#?${key}" "${config_file}"; then
        sed -i "s|^#\?${key}.*|${key} ${value}|" "${config_file}"
    else
        echo "${key} ${value}" >> "${config_file}"
    fi
    
    log_debug "Set ${key} = ${value}"
}

validate_sshd_config() {
    local config_file="$1"
    
    if command_exists sshd; then
        sshd -t -f "${config_file}" 2>&1
        return $?
    else
        log_warn "sshd command not found, skipping validation"
        return 0
    fi
}

rollback_ssh_hardening() {
    local backup_id="$1"
    log_info "Rolling back SSH hardening..."
    
    if restore_file "/etc/ssh/sshd_config" "${backup_id}"; then
        local ssh_service="sshd"
        is_service_active ssh && ssh_service="ssh"
        systemctl reload "${ssh_service}" || true
        log_success "SSH configuration restored"
        return 0
    else
        return 1
    fi
}

verify_ssh_hardening() {
    local ssh_config="/etc/ssh/sshd_config"
    local issues=0
    
    log_info "Verifying SSH hardening..."
    
    verify_ssh_setting "${ssh_config}" "PermitRootLogin" "no" || ((issues++))
    verify_ssh_setting "${ssh_config}" "PasswordAuthentication" "no" || ((issues++))
    verify_ssh_setting "${ssh_config}" "PermitEmptyPasswords" "no" || ((issues++))
    
    if [[ ${issues} -eq 0 ]]; then
        log_success "SSH hardening verified"
        return 0
    else
        log_warn "SSH hardening verification found ${issues} issues"
        return 1
    fi
}

verify_ssh_setting() {
    local config_file="$1"
    local key="$2"
    local expected="$3"
    
    if grep -qE "^${key}\s+${expected}" "${config_file}"; then
        return 0
    else
        log_warn "SSH setting mismatch: ${key} (expected: ${expected})"
        return 1
    fi
}

if [[ "${MODULE_ENABLED}" == "true" ]] && [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    run_ssh_hardening
fi
