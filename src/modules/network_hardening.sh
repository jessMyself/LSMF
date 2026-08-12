#!/usr/bin/env bash

set -Eeuo pipefail

# shellcheck disable=SC2034 # Module metadata is consumed by discovery tooling.
MODULE_NAME="network_hardening"
# shellcheck disable=SC2034 # Module metadata is consumed by discovery tooling.
MODULE_VERSION="1.0.0"
MODULE_ENABLED="${MODULE_ENABLED:-true}"

run_network_hardening() {
    log_info "=== Network Hardening Module ==="
    
    local sysctl_conf="/etc/sysctl.d/99-lsmf-network.conf"
    
    backup_file "/etc/sysctl.conf"
    
    local _rollback_id
    _rollback_id=$(create_rollback_point "network_hardening" "Network sysctl hardening")
    
    log_info "Configuring network security parameters..."
    
    cat > "${sysctl_conf}" << 'EOF'
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0

net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv6.conf.all.accept_redirects = 0
net.ipv6.conf.default.accept_redirects = 0

net.ipv4.conf.all.secure_redirects = 0
net.ipv4.conf.default.secure_redirects = 0

net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0
net.ipv6.conf.all.accept_source_route = 0
net.ipv6.conf.default.accept_source_route = 0

net.ipv4.conf.all.log_martians = 1
net.ipv4.conf.default.log_martians = 1

net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1

net.ipv4.icmp_echo_ignore_broadcasts = 1

net.ipv4.icmp_ignore_bogus_error_responses = 1

net.ipv4.tcp_syncookies = 1

net.ipv4.tcp_timestamps = 0

net.ipv6.conf.all.accept_ra = 0
net.ipv6.conf.default.accept_ra = 0

net.ipv4.conf.all.proxy_arp = 0

net.ipv4.tcp_max_syn_backlog = 2048
net.ipv4.tcp_synack_retries = 2
net.ipv4.tcp_syn_retries = 5

net.core.netdev_max_backlog = 5000

net.ipv4.ip_forward = 0
net.ipv6.conf.all.forwarding = 0
EOF
    
    local ipv6_disabled
    ipv6_disabled=$(read_config_value "DISABLE_IPV6" 2>/dev/null || echo "true")
    
    if [[ "${ipv6_disabled}" == "true" ]]; then
        log_info "Disabling IPv6..."
        cat >> "${sysctl_conf}" << 'EOF'

net.ipv6.conf.all.disable_ipv6 = 1
net.ipv6.conf.default.disable_ipv6 = 1
net.ipv6.conf.lo.disable_ipv6 = 1
EOF
        add_report_data "IPv6" "Disabled"
    else
        log_info "IPv6 will remain enabled (per configuration)"
        add_report_data "IPv6" "Enabled (hardened)"
    fi
    
    if sysctl -p "${sysctl_conf}" >/dev/null 2>&1; then
        log_success "Network hardening applied successfully"
        add_report_data "Network Hardening" "Applied secure sysctl settings"
        return 0
    else
        log_error "Failed to apply sysctl settings"
        rm -f "${sysctl_conf}"
        return 1
    fi
}

rollback_network_hardening() {
    local backup_id="$1"
    log_info "Rolling back network hardening..."
    
    rm -f "/etc/sysctl.d/99-lsmf-network.conf"
    
    if restore_file "/etc/sysctl.conf" "${backup_id}"; then
        sysctl -p /etc/sysctl.conf >/dev/null 2>&1 || true
        log_success "Network configuration restored"
        return 0
    else
        return 1
    fi
}

verify_network_hardening() {
    log_info "Verifying network hardening..."
    local issues=0
    
    verify_sysctl "net.ipv4.conf.all.send_redirects" "0" || ((issues++))
    verify_sysctl "net.ipv4.conf.all.accept_source_route" "0" || ((issues++))
    verify_sysctl "net.ipv4.tcp_syncookies" "1" || ((issues++))
    verify_sysctl "net.ipv4.conf.all.rp_filter" "1" || ((issues++))
    
    if [[ ${issues} -eq 0 ]]; then
        log_success "Network hardening verified"
        return 0
    else
        log_warn "Network hardening verification found ${issues} issues"
        return 1
    fi
}

if [[ "${MODULE_ENABLED}" == "true" ]] && [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    run_network_hardening
fi
