#!/usr/bin/env bash

set -Eeuo pipefail

declare -g OS_NAME=""
declare -g OS_VERSION=""
declare -g OS_ID=""
declare -g OS_ID_LIKE=""
declare -g OS_CODENAME=""
declare -g KERNEL_VERSION=""
declare -g DESKTOP_ENV=""
declare -g SYSTEM_ROLE=""
declare -g IS_VIRTUAL=""
declare -g IS_CONTAINER=""
declare -g CLOUD_PROVIDER=""
declare -g INIT_SYSTEM=""
declare -g FIREWALL_TYPE=""
declare -g MAC_SYSTEM=""
declare -g PACKAGE_MANAGER=""
declare -g CPU_ARCH=""
declare -g BOOT_MODE=""
declare -g SECURE_BOOT=""

detect_os() {
    if [[ -f /etc/os-release ]]; then
        source /etc/os-release
        OS_NAME="${NAME:-Unknown}"
        OS_VERSION="${VERSION_ID:-Unknown}"
        OS_ID="${ID:-unknown}"
        OS_ID_LIKE="${ID_LIKE:-}"
        OS_CODENAME="${VERSION_CODENAME:-}"
    elif [[ -f /etc/lsb-release ]]; then
        source /etc/lsb-release
        OS_NAME="${DISTRIB_ID:-Unknown}"
        OS_VERSION="${DISTRIB_RELEASE:-Unknown}"
        OS_ID=$(echo "${DISTRIB_ID}" | tr '[:upper:]' '[:lower:]')
    else
        OS_NAME="Unknown"
        OS_VERSION="Unknown"
        OS_ID="unknown"
    fi
    
    KERNEL_VERSION=$(uname -r)
    CPU_ARCH=$(uname -m)
    
    log_info "Detected OS: ${OS_NAME} ${OS_VERSION} (${OS_ID})"
    log_debug "Kernel: ${KERNEL_VERSION}, Architecture: ${CPU_ARCH}"
}

detect_desktop_environment() {
    if [[ -n "${XDG_CURRENT_DESKTOP:-}" ]]; then
        DESKTOP_ENV="${XDG_CURRENT_DESKTOP}"
    elif [[ -n "${DESKTOP_SESSION:-}" ]]; then
        DESKTOP_ENV="${DESKTOP_SESSION}"
    elif command_exists gnome-shell; then
        DESKTOP_ENV="GNOME"
    elif command_exists plasmashell; then
        DESKTOP_ENV="KDE"
    elif command_exists xfce4-session; then
        DESKTOP_ENV="XFCE"
    elif command_exists mate-session; then
        DESKTOP_ENV="MATE"
    elif command_exists cinnamon-session; then
        DESKTOP_ENV="Cinnamon"
    else
        DESKTOP_ENV="None"
    fi
    
    log_debug "Desktop Environment: ${DESKTOP_ENV}"
}

detect_virtualization() {
    IS_VIRTUAL="false"
    
    if command_exists systemd-detect-virt; then
        local virt_type
        virt_type=$(systemd-detect-virt 2>/dev/null || echo "none")
        
        if [[ "${virt_type}" != "none" ]]; then
            IS_VIRTUAL="${virt_type}"
            log_debug "Virtualization detected: ${virt_type}"
        fi
    elif [[ -f /sys/class/dmi/id/product_name ]]; then
        local product_name
        product_name=$(cat /sys/class/dmi/id/product_name 2>/dev/null || echo "")
        
        case "${product_name}" in
            *VirtualBox*) IS_VIRTUAL="virtualbox" ;;
            *VMware*) IS_VIRTUAL="vmware" ;;
            *KVM*) IS_VIRTUAL="kvm" ;;
            *QEMU*) IS_VIRTUAL="qemu" ;;
        esac
    fi
}

detect_container() {
    IS_CONTAINER="false"
    
    if [[ -f /.dockerenv ]]; then
        IS_CONTAINER="docker"
    elif [[ -f /run/.containerenv ]]; then
        IS_CONTAINER="podman"
    elif grep -q "lxc\|docker\|kubepods" /proc/1/cgroup 2>/dev/null; then
        IS_CONTAINER="true"
    fi
    
    if [[ "${IS_CONTAINER}" != "false" ]]; then
        log_debug "Container detected: ${IS_CONTAINER}"
    fi
}

detect_cloud_provider() {
    CLOUD_PROVIDER="none"
    
    if command_exists dmidecode; then
        local sys_vendor
        sys_vendor=$(dmidecode -s system-manufacturer 2>/dev/null || echo "")
        
        case "${sys_vendor}" in
            *Amazon*|*AWS*) CLOUD_PROVIDER="aws" ;;
            *Microsoft*) CLOUD_PROVIDER="azure" ;;
            *Google*) CLOUD_PROVIDER="gcp" ;;
            *DigitalOcean*) CLOUD_PROVIDER="digitalocean" ;;
        esac
    fi
    
    if [[ "${CLOUD_PROVIDER}" == "none" ]] && command_exists curl; then
        if curl -s -m 1 http://169.254.169.254/latest/meta-data/ >/dev/null 2>&1; then
            CLOUD_PROVIDER="aws"
        elif curl -s -m 1 -H "Metadata:true" http://169.254.169.254/metadata/instance?api-version=2021-02-01 >/dev/null 2>&1; then
            CLOUD_PROVIDER="azure"
        elif curl -s -m 1 -H "Metadata-Flavor: Google" http://metadata.google.internal/computeMetadata/v1/ >/dev/null 2>&1; then
            CLOUD_PROVIDER="gcp"
        fi
    fi
    
    if [[ "${CLOUD_PROVIDER}" != "none" ]]; then
        log_debug "Cloud provider: ${CLOUD_PROVIDER}"
    fi
}

detect_init_system() {
    if [[ -d /run/systemd/system ]]; then
        INIT_SYSTEM="systemd"
    elif command_exists initctl && initctl version 2>/dev/null | grep -q upstart; then
        INIT_SYSTEM="upstart"
    elif [[ -f /sbin/init ]] && file /sbin/init | grep -q "SysV"; then
        INIT_SYSTEM="sysvinit"
    else
        INIT_SYSTEM="unknown"
    fi
    
    log_debug "Init system: ${INIT_SYSTEM}"
}

detect_firewall() {
    FIREWALL_TYPE="none"
    
    if command_exists ufw && ufw status 2>/dev/null | grep -q "Status: active"; then
        FIREWALL_TYPE="ufw"
    elif command_exists firewall-cmd && systemctl is-active --quiet firewalld; then
        FIREWALL_TYPE="firewalld"
    elif command_exists iptables && iptables -L -n 2>/dev/null | grep -q "Chain"; then
        FIREWALL_TYPE="iptables"
    elif command_exists nft && nft list tables 2>/dev/null | grep -q "table"; then
        FIREWALL_TYPE="nftables"
    fi
    
    log_debug "Firewall: ${FIREWALL_TYPE}"
}

detect_mac_system() {
    MAC_SYSTEM="none"
    
    if command_exists aa-status && systemctl is-active --quiet apparmor 2>/dev/null; then
        MAC_SYSTEM="apparmor"
    elif command_exists getenforce && [[ "$(getenforce 2>/dev/null)" != "Disabled" ]]; then
        MAC_SYSTEM="selinux"
    fi
    
    log_debug "MAC system: ${MAC_SYSTEM}"
}

detect_boot_mode() {
    if [[ -d /sys/firmware/efi ]]; then
        BOOT_MODE="UEFI"
    else
        BOOT_MODE="BIOS"
    fi
    
    log_debug "Boot mode: ${BOOT_MODE}"
}

detect_secure_boot() {
    SECURE_BOOT="disabled"
    
    if [[ -f /sys/firmware/efi/efivars/SecureBoot-* ]]; then
        local sb_value
        sb_value=$(od -An -t u1 /sys/firmware/efi/efivars/SecureBoot-* 2>/dev/null | awk '{print $NF}')
        [[ "${sb_value}" == "1" ]] && SECURE_BOOT="enabled"
    fi
    
    log_debug "Secure Boot: ${SECURE_BOOT}"
}

classify_system_role() {
    local role="unknown"
    
    if [[ "${IS_CONTAINER}" != "false" ]]; then
        role="container"
    elif [[ "${IS_VIRTUAL}" != "false" ]]; then
        role="vm"
    elif [[ "${DESKTOP_ENV}" != "None" ]]; then
        if laptop-detect 2>/dev/null; then
            role="laptop"
        else
            role="desktop"
        fi
    elif systemctl list-unit-files | grep -qE "(httpd|nginx|apache2)\.service"; then
        role="webserver"
    elif systemctl list-unit-files | grep -qE "(mysql|mariadb|postgresql)\.service"; then
        role="database"
    elif systemctl list-unit-files | grep -qE "(samba|nfs)\.service"; then
        role="fileserver"
    elif [[ "${CLOUD_PROVIDER}" != "none" ]]; then
        role="cloud"
    else
        role="server"
    fi
    
    SYSTEM_ROLE="${role}"
    log_info "System role classified as: ${SYSTEM_ROLE}"
}

confirm_system_role() {
    if [[ "${LSMF_INTERACTIVE}" != "true" ]]; then
        return 0
    fi
    
    cat << EOF

Detected system role: ${SYSTEM_ROLE}

Available roles:
  1) Desktop
  2) Laptop
  3) Server
  4) Workstation
  5) Web Server
  6) Database Server
  7) File Server
  8) Virtual Machine
  9) Container
 10) Cloud Instance
EOF
    
    local choice
    read -r -p "Is this correct? (y/n or enter number to change): " choice
    
    case "${choice}" in
        y|Y|"") return 0 ;;
        n|N) ;;
        1) SYSTEM_ROLE="desktop" ;;
        2) SYSTEM_ROLE="laptop" ;;
        3) SYSTEM_ROLE="server" ;;
        4) SYSTEM_ROLE="workstation" ;;
        5) SYSTEM_ROLE="webserver" ;;
        6) SYSTEM_ROLE="database" ;;
        7) SYSTEM_ROLE="fileserver" ;;
        8) SYSTEM_ROLE="vm" ;;
        9) SYSTEM_ROLE="container" ;;
        10) SYSTEM_ROLE="cloud" ;;
    esac
    
    log_info "System role set to: ${SYSTEM_ROLE}"
}

run_system_detection() {
    log_info "Running system detection..."
    
    detect_os
    detect_desktop_environment
    detect_virtualization
    detect_container
    detect_cloud_provider
    detect_init_system
    detect_firewall
    detect_mac_system
    detect_boot_mode
    detect_secure_boot
    
    PACKAGE_MANAGER=$(detect_package_manager)
    
    classify_system_role
    confirm_system_role
    
    save_detection_results
    
    log_success "System detection complete"
}

save_detection_results() {
    local output_file="${LSMF_LOG_DIR}/${LSMF_RUN_ID}/detection.json"
    
    cat > "${output_file}" << EOF
{
  "os_name": "${OS_NAME}",
  "os_version": "${OS_VERSION}",
  "os_id": "${OS_ID}",
  "os_id_like": "${OS_ID_LIKE}",
  "os_codename": "${OS_CODENAME}",
  "kernel_version": "${KERNEL_VERSION}",
  "cpu_arch": "${CPU_ARCH}",
  "desktop_env": "${DESKTOP_ENV}",
  "system_role": "${SYSTEM_ROLE}",
  "is_virtual": "${IS_VIRTUAL}",
  "is_container": "${IS_CONTAINER}",
  "cloud_provider": "${CLOUD_PROVIDER}",
  "init_system": "${INIT_SYSTEM}",
  "firewall_type": "${FIREWALL_TYPE}",
  "mac_system": "${MAC_SYSTEM}",
  "package_manager": "${PACKAGE_MANAGER}",
  "boot_mode": "${BOOT_MODE}",
  "secure_boot": "${SECURE_BOOT}",
  "timestamp": "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
}
EOF
    
    log_debug "Detection results saved to: ${output_file}"
}

print_system_info() {
    cat << EOF

╔════════════════════════════════════════════════════════════════╗
║                    SYSTEM INFORMATION                          ║
╠════════════════════════════════════════════════════════════════╣
║ OS:              ${OS_NAME} ${OS_VERSION}
║ Distribution:    ${OS_ID}
║ Kernel:          ${KERNEL_VERSION}
║ Architecture:    ${CPU_ARCH}
║ Desktop:         ${DESKTOP_ENV}
║ System Role:     ${SYSTEM_ROLE}
║ Virtualization:  ${IS_VIRTUAL}
║ Container:       ${IS_CONTAINER}
║ Cloud:           ${CLOUD_PROVIDER}
║ Init:            ${INIT_SYSTEM}
║ Firewall:        ${FIREWALL_TYPE}
║ MAC:             ${MAC_SYSTEM}
║ Package Mgr:     ${PACKAGE_MANAGER}
║ Boot Mode:       ${BOOT_MODE}
║ Secure Boot:     ${SECURE_BOOT}
╚════════════════════════════════════════════════════════════════╝

EOF
}

is_supported_os() {
    case "${OS_ID}" in
        debian|ubuntu|linuxmint|neon|kali|rocky|almalinux|fedora|rhel|centos)
            return 0
            ;;
        *)
            if [[ "${OS_ID_LIKE}" =~ (debian|ubuntu|rhel|fedora) ]]; then
                log_warn "OS derivative detected, support is best-effort"
                return 0
            fi
            log_error "Unsupported OS: ${OS_ID}"
            return 1
            ;;
    esac
}

export -f detect_os detect_desktop_environment detect_virtualization
export -f detect_container detect_cloud_provider detect_init_system
export -f detect_firewall detect_mac_system detect_boot_mode detect_secure_boot
export -f classify_system_role confirm_system_role run_system_detection
export -f save_detection_results print_system_info is_supported_os
