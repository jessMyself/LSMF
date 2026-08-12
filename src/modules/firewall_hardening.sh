#!/usr/bin/env bash

set -Eeuo pipefail

# shellcheck disable=SC2034 # Module metadata is consumed by discovery tooling.
MODULE_NAME="firewall_hardening"
# shellcheck disable=SC2034 # Module metadata is consumed by discovery tooling.
MODULE_VERSION="1.0.0"
MODULE_ENABLED="${MODULE_ENABLED:-true}"

run_firewall_hardening() {
    log_info "=== Firewall Hardening Module ==="
    
    local firewall_type="${FIREWALL_TYPE}"
    
    if [[ "${firewall_type}" == "none" ]]; then
        log_info "No firewall detected, installing and configuring..."
        install_firewall
        firewall_type="${FIREWALL_TYPE}"
    fi
    
    case "${firewall_type}" in
        ufw)
            harden_ufw
            ;;
        firewalld)
            harden_firewalld
            ;;
        iptables)
            harden_iptables
            ;;
        nftables)
            harden_nftables
            ;;
        *)
            log_error "Unsupported firewall type: ${firewall_type}"
            return 1
            ;;
    esac
}

install_firewall() {
    local pkg_mgr
    pkg_mgr=$(detect_package_manager)
    
    case "${pkg_mgr}" in
        apt)
            execute_command "apt-get update"
            execute_command "apt-get install -y ufw"
            FIREWALL_TYPE="ufw"
            ;;
        dnf|yum)
            execute_command "${pkg_mgr} install -y firewalld"
            FIREWALL_TYPE="firewalld"
            ;;
        *)
            log_error "Unable to install firewall for package manager: ${pkg_mgr}"
            return 1
            ;;
    esac
    
    log_success "Firewall installed: ${FIREWALL_TYPE}"
}

harden_ufw() {
    log_info "Configuring UFW firewall..."
    
    local _rollback_id
    _rollback_id=$(create_rollback_point "firewall_ufw" "UFW firewall configuration")
    
    execute_command "ufw --force reset"
    
    execute_command "ufw default deny incoming"
    execute_command "ufw default allow outgoing"
    execute_command "ufw default deny routed"
    
    if [[ "${SYSTEM_ROLE}" == "desktop" ]] || [[ "${SYSTEM_ROLE}" == "laptop" ]] || [[ "${SYSTEM_ROLE}" == "workstation" ]]; then
        log_info "Desktop/laptop detected, allowing common services..."
    fi
    
    if package_installed openssh-server; then
        execute_command "ufw limit 22/tcp comment 'SSH'"
        log_success "Allowed SSH (rate limited)"
    fi
    
    execute_command "ufw logging on"
    execute_command "ufw logging medium"
    
    execute_command "ufw --force enable"
    
    if systemctl enable ufw && systemctl start ufw; then
        log_success "UFW firewall enabled and started"
        add_report_data "Firewall (UFW)" "Configured with default deny, SSH rate limiting"
        return 0
    else
        log_error "Failed to enable UFW"
        return 1
    fi
}

harden_firewalld() {
    log_info "Configuring firewalld..."
    
    local _rollback_id
    _rollback_id=$(create_rollback_point "firewall_firewalld" "Firewalld configuration")
    
    execute_command "systemctl enable --now firewalld"
    
    execute_command "firewall-cmd --set-default-zone=drop"
    
    local active_zone="public"
    execute_command "firewall-cmd --zone=${active_zone} --set-target=DROP --permanent"
    
    if package_installed openssh-server; then
        execute_command "firewall-cmd --zone=${active_zone} --add-service=ssh --permanent"
        log_success "Allowed SSH in ${active_zone} zone"
    fi
    
    execute_command "firewall-cmd --zone=${active_zone} --add-icmp-block-inversion --permanent"
    
    execute_command "firewall-cmd --set-log-denied=all --permanent"
    
    execute_command "firewall-cmd --reload"
    
    log_success "Firewalld configured and reloaded"
    add_report_data "Firewall (firewalld)" "Configured with drop default, logging enabled"
    return 0
}

harden_iptables() {
    log_info "Configuring iptables..."
    
    local _rollback_id
    _rollback_id=$(create_rollback_point "firewall_iptables" "Iptables configuration")
    
    backup_file "/etc/iptables/rules.v4" 2>/dev/null || true
    backup_file "/etc/iptables/rules.v6" 2>/dev/null || true
    
    iptables -F
    iptables -X
    iptables -Z
    
    iptables -P INPUT DROP
    iptables -P FORWARD DROP
    iptables -P OUTPUT ACCEPT
    
    iptables -A INPUT -i lo -j ACCEPT
    iptables -A OUTPUT -o lo -j ACCEPT
    
    iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
    
    iptables -A INPUT -p tcp --dport 22 -m conntrack --ctstate NEW -m recent --set
    iptables -A INPUT -p tcp --dport 22 -m conntrack --ctstate NEW -m recent --update --seconds 60 --hitcount 4 -j DROP
    iptables -A INPUT -p tcp --dport 22 -j ACCEPT
    
    iptables -A INPUT -p icmp --icmp-type echo-request -m limit --limit 1/s -j ACCEPT
    
    iptables -A INPUT -m conntrack --ctstate INVALID -j DROP
    
    if command_exists iptables-save && command_exists netfilter-persistent; then
        iptables-save > /etc/iptables/rules.v4
        log_success "Iptables rules saved"
    fi
    
    log_success "Iptables configured"
    add_report_data "Firewall (iptables)" "Configured with default drop, SSH rate limiting"
    return 0
}

harden_nftables() {
    log_info "Configuring nftables..."
    
    local _rollback_id
    _rollback_id=$(create_rollback_point "firewall_nftables" "Nftables configuration")
    
    local nft_config="/etc/nftables.conf"
    backup_file "${nft_config}" 2>/dev/null || true
    
    cat > "${nft_config}" << 'EOF'
#!/usr/sbin/nft -f

flush ruleset

table inet filter {
    chain input {
        type filter hook input priority 0; policy drop;
        
        iif lo accept
        
        ct state established,related accept
        ct state invalid drop
        
        tcp dport 22 ct state new limit rate 4/minute accept
        
        icmp type echo-request limit rate 1/second accept
    }
    
    chain forward {
        type filter hook forward priority 0; policy drop;
    }
    
    chain output {
        type filter hook output priority 0; policy accept;
    }
}
EOF
    
    if nft -f "${nft_config}"; then
        systemctl enable nftables
        systemctl restart nftables
        log_success "Nftables configured and enabled"
        add_report_data "Firewall (nftables)" "Configured with default drop, rate limiting"
        return 0
    else
        log_error "Failed to load nftables configuration"
        restore_file "${nft_config}"
        return 1
    fi
}

rollback_firewall_hardening() {
    local backup_id="$1"
    log_info "Rolling back firewall configuration..."
    
    case "${FIREWALL_TYPE}" in
        ufw)
            ufw --force disable
            ;;
        firewalld)
            systemctl stop firewalld
            systemctl disable firewalld
            ;;
        iptables)
            restore_file "/etc/iptables/rules.v4" "${backup_id}" || true
            restore_file "/etc/iptables/rules.v6" "${backup_id}" || true
            ;;
        nftables)
            restore_file "/etc/nftables.conf" "${backup_id}" || true
            systemctl restart nftables || true
            ;;
    esac
    
    log_success "Firewall configuration restored"
}

verify_firewall_hardening() {
    log_info "Verifying firewall configuration..."
    
    case "${FIREWALL_TYPE}" in
        ufw)
            if ufw status | grep -q "Status: active"; then
                log_success "UFW is active"
                return 0
            fi
            ;;
        firewalld)
            if systemctl is-active --quiet firewalld; then
                log_success "Firewalld is active"
                return 0
            fi
            ;;
        iptables)
            if iptables -L -n | grep -q "Chain INPUT (policy DROP)"; then
                log_success "Iptables default DROP policy verified"
                return 0
            fi
            ;;
        nftables)
            if systemctl is-active --quiet nftables; then
                log_success "Nftables is active"
                return 0
            fi
            ;;
    esac
    
    log_error "Firewall verification failed"
    return 1
}

if [[ "${MODULE_ENABLED}" == "true" ]] && [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    run_firewall_hardening
fi
