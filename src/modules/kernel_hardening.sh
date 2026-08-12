#!/usr/bin/env bash

set -Eeuo pipefail

# shellcheck disable=SC2034 # Module metadata is consumed by discovery tooling.
MODULE_NAME="kernel_hardening"
# shellcheck disable=SC2034 # Module metadata is consumed by discovery tooling.
MODULE_VERSION="1.0.0"
MODULE_ENABLED="${MODULE_ENABLED:-true}"

run_kernel_hardening() {
    log_info "=== Kernel Hardening Module ==="
    
    local sysctl_conf="/etc/sysctl.d/99-lsmf-kernel.conf"
    
    backup_file "/etc/sysctl.conf"
    
    local _rollback_id
    _rollback_id=$(create_rollback_point "kernel_hardening" "Kernel security hardening")
    
    log_info "Configuring kernel security parameters..."
    
    cat > "${sysctl_conf}" << 'EOF'
kernel.randomize_va_space = 2

kernel.yama.ptrace_scope = 1

fs.protected_symlinks = 1

fs.protected_hardlinks = 1

fs.protected_fifos = 2

fs.protected_regular = 2

kernel.kptr_restrict = 2

kernel.dmesg_restrict = 1

kernel.printk = 3 3 3 3

kernel.unprivileged_bpf_disabled = 1

net.core.bpf_jit_harden = 2

kernel.kexec_load_disabled = 1

kernel.sysrq = 0

fs.suid_dumpable = 0

kernel.core_uses_pid = 1

kernel.modules_disabled = 0

kernel.perf_event_paranoid = 3

vm.mmap_min_addr = 65536

dev.tty.ldisc_autoload = 0
EOF
    
    configure_core_dumps
    
    if sysctl -p "${sysctl_conf}" >/dev/null 2>&1; then
        log_success "Kernel hardening applied successfully"
        add_report_data "Kernel Hardening" "Applied ASLR, ptrace restrictions, kernel pointer protection"
        return 0
    else
        log_error "Failed to apply kernel sysctl settings"
        rm -f "${sysctl_conf}"
        return 1
    fi
}

configure_core_dumps() {
    log_info "Disabling core dumps..."
    
    local limits_conf="/etc/security/limits.d/99-lsmf-coredump.conf"
    backup_file "${limits_conf}" 2>/dev/null || true
    
    cat > "${limits_conf}" << 'EOF'
* hard core 0
* soft core 0
EOF
    
    if command_exists systemctl; then
        local coredump_conf="/etc/systemd/coredump.conf.d/99-lsmf.conf"
        mkdir -p "$(dirname "${coredump_conf}")"
        
        cat > "${coredump_conf}" << 'EOF'
[Coredump]
Storage=none
ProcessSizeMax=0
EOF
        
        systemctl daemon-reload 2>/dev/null || true
    fi
    
    echo "ulimit -S -c 0 > /dev/null 2>&1" >> /etc/profile
    
    log_success "Core dumps disabled"
}

restrict_compiler_access() {
    log_info "Restricting compiler access to administrators..."
    
    local compilers=("/usr/bin/gcc" "/usr/bin/g++" "/usr/bin/cc" "/usr/bin/c++" "/usr/bin/clang" "/usr/bin/as")
    
    for compiler in "${compilers[@]}"; do
        if [[ -f "${compiler}" ]]; then
            chmod 750 "${compiler}"
            log_debug "Restricted access to ${compiler}"
        fi
    done
    
    add_report_data "Compiler Access" "Restricted to administrators only"
}

harden_modules() {
    log_info "Configuring kernel module restrictions..."
    
    local modprobe_conf="/etc/modprobe.d/99-lsmf-hardening.conf"
    backup_file "${modprobe_conf}" 2>/dev/null || true
    
    cat > "${modprobe_conf}" << 'EOF'
install cramfs /bin/true
install freevxfs /bin/true
install jffs2 /bin/true
install hfs /bin/true
install hfsplus /bin/true
install udf /bin/true

install usb-storage /bin/true

install dccp /bin/true
install sctp /bin/true
install rds /bin/true
install tipc /bin/true

install bluetooth /bin/true

install firewire-core /bin/true
EOF
    
    log_success "Kernel module restrictions configured"
}

rollback_kernel_hardening() {
    local backup_id="$1"
    log_info "Rolling back kernel hardening..."
    
    rm -f "/etc/sysctl.d/99-lsmf-kernel.conf"
    rm -f "/etc/security/limits.d/99-lsmf-coredump.conf"
    rm -f "/etc/systemd/coredump.conf.d/99-lsmf.conf"
    rm -f "/etc/modprobe.d/99-lsmf-hardening.conf"
    
    if restore_file "/etc/sysctl.conf" "${backup_id}"; then
        sysctl -p /etc/sysctl.conf >/dev/null 2>&1 || true
        log_success "Kernel configuration restored"
        return 0
    else
        return 1
    fi
}

verify_kernel_hardening() {
    log_info "Verifying kernel hardening..."
    local issues=0
    
    verify_sysctl "kernel.randomize_va_space" "2" || ((issues++))
    verify_sysctl "kernel.yama.ptrace_scope" "1" || ((issues++))
    verify_sysctl "fs.protected_symlinks" "1" || ((issues++))
    verify_sysctl "fs.protected_hardlinks" "1" || ((issues++))
    verify_sysctl "kernel.kptr_restrict" "2" || ((issues++))
    verify_sysctl "kernel.dmesg_restrict" "1" || ((issues++))
    
    if [[ ${issues} -eq 0 ]]; then
        log_success "Kernel hardening verified"
        return 0
    else
        log_warn "Kernel hardening verification found ${issues} issues"
        return 1
    fi
}

if [[ "${MODULE_ENABLED}" == "true" ]] && [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    run_kernel_hardening
    restrict_compiler_access
    harden_modules
fi
