#!/usr/bin/env bash

set -Eeuo pipefail

readonly LSMF_VERSION="1.0.0"
readonly LSMF_ROOT="${LSMF_ROOT:-/opt/lsmf}"
LSMF_CONFIG="${LSMF_CONFIG:-/etc/lsmf/lsmf.conf}"
readonly LSMF_LOG_DIR="${LSMF_LOG_DIR:-/var/log/lsmf}"
readonly LSMF_BACKUP_DIR="${LSMF_BACKUP_DIR:-/var/backups/lsmf}"
readonly LSMF_ROLLBACK_DIR="${LSMF_ROLLBACK_DIR:-/var/lib/lsmf/rollback}"
readonly LSMF_REPORT_DIR="${LSMF_REPORT_DIR:-/var/lib/lsmf/reports}"

LSMF_RUN_ID=""
LSMF_START_TIME=""
LSMF_DRY_RUN="${LSMF_DRY_RUN:-false}"
LSMF_INTERACTIVE="${LSMF_INTERACTIVE:-true}"
LSMF_VERBOSE="${LSMF_VERBOSE:-false}"

declare -A LSMF_COLORS=(
    [RED]='\033[0;31m'
    [GREEN]='\033[0;32m'
    [YELLOW]='\033[1;33m'
    [BLUE]='\033[0;34m'
    [MAGENTA]='\033[0;35m'
    [CYAN]='\033[0;36m'
    [WHITE]='\033[1;37m'
    [NC]='\033[0m'
)

error_handler() {
    local line_no=$1
    local _bash_lineno=$2
    local last_command=$3
    log_error "Error on line ${line_no}: command '${last_command}' exited with status $?"
    cleanup_on_error
    exit 1
}

trap 'error_handler ${LINENO} ${BASH_LINENO} "$BASH_COMMAND"' ERR

cleanup_on_error() {
    log_warn "Cleaning up after error..."
}

init_lsmf() {
    LSMF_RUN_ID="$(date +%Y%m%d_%H%M%S)_$$"
    LSMF_START_TIME="$(date +%s)"
    
    mkdir -p "${LSMF_LOG_DIR}/${LSMF_RUN_ID}"
    mkdir -p "${LSMF_BACKUP_DIR}"
    mkdir -p "${LSMF_ROLLBACK_DIR}"
    mkdir -p "${LSMF_REPORT_DIR}"
    
    log_info "LSMF v${LSMF_VERSION} initialized - Run ID: ${LSMF_RUN_ID}"
}

check_root() {
    if [[ $EUID -ne 0 ]]; then
        log_error "This script must be run as root"
        return 1
    fi
    return 0
}

print_color() {
    local color=$1
    shift
    echo -e "${LSMF_COLORS[$color]}$*${LSMF_COLORS[NC]}"
}

log_message() {
    local level=$1
    shift
    local message="$*"
    local timestamp
    timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    
    local log_file="${LSMF_LOG_DIR}/${LSMF_RUN_ID}/lsmf.log"
    echo "[${timestamp}] [${level}] ${message}" >> "${log_file}"
    
    if [[ "${LSMF_VERBOSE}" == "true" ]] || [[ "${level}" != "DEBUG" ]]; then
        case "${level}" in
            ERROR)   print_color RED "[ERROR] ${message}" >&2 ;;
            WARN)    print_color YELLOW "[WARN] ${message}" ;;
            SUCCESS) print_color GREEN "[SUCCESS] ${message}" ;;
            INFO)    print_color CYAN "[INFO] ${message}" ;;
            DEBUG)   [[ "${LSMF_VERBOSE}" == "true" ]] && print_color MAGENTA "[DEBUG] ${message}" ;;
        esac
    fi
}

log_error() {
    log_message "ERROR" "$@"
}

log_warn() {
    log_message "WARN" "$@"
}

log_success() {
    log_message "SUCCESS" "$@"
}

log_info() {
    log_message "INFO" "$@"
}

log_debug() {
    log_message "DEBUG" "$@"
}

log_command() {
    local cmd="$*"
    local cmd_log="${LSMF_LOG_DIR}/${LSMF_RUN_ID}/commands.log"
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] ${cmd}" >> "${cmd_log}"
    log_debug "Executing: ${cmd}"
}

execute_command() {
    local cmd="$*"
    log_command "${cmd}"
    
    if [[ "${LSMF_DRY_RUN}" == "true" ]]; then
        log_info "[DRY-RUN] Would execute: ${cmd}"
        return 0
    fi
    
    local output
    local exit_code
    
    output=$(eval "${cmd}" 2>&1) || exit_code=$?
    exit_code=${exit_code:-0}
    
    if [[ ${exit_code} -ne 0 ]]; then
        log_error "Command failed with exit code ${exit_code}: ${cmd}"
        log_debug "Output: ${output}"
        return "${exit_code}"
    fi
    
    [[ -n "${output}" ]] && log_debug "Output: ${output}"
    return 0
}

confirm() {
    local prompt="$1"
    local default="${2:-n}"
    
    if [[ "${LSMF_INTERACTIVE}" != "true" ]]; then
        [[ "${default}" == "y" ]] && return 0 || return 1
    fi
    
    local response
    if [[ "${default}" == "y" ]]; then
        read -r -p "${prompt} [Y/n] " response
        response=${response:-y}
    else
        read -r -p "${prompt} [y/N] " response
        response=${response:-n}
    fi
    
    [[ "${response}" =~ ^[Yy] ]] && return 0 || return 1
}

get_runtime() {
    local end_time
    end_time=$(date +%s)
    local runtime=$((end_time - LSMF_START_TIME))
    echo "${runtime}"
}

format_duration() {
    local seconds=$1
    local hours=$((seconds / 3600))
    local minutes=$(( (seconds % 3600) / 60 ))
    local secs=$((seconds % 60))
    
    if [[ ${hours} -gt 0 ]]; then
        printf "%dh %dm %ds" ${hours} ${minutes} ${secs}
    elif [[ ${minutes} -gt 0 ]]; then
        printf "%dm %ds" ${minutes} ${secs}
    else
        printf "%ds" ${secs}
    fi
}

validate_file() {
    local file="$1"
    [[ -f "${file}" ]] && return 0
    log_error "File not found: ${file}"
    return 1
}

validate_directory() {
    local dir="$1"
    [[ -d "${dir}" ]] && return 0
    log_error "Directory not found: ${dir}"
    return 1
}

is_service_active() {
    local service="$1"
    systemctl is-active --quiet "${service}" 2>/dev/null
}

is_service_enabled() {
    local service="$1"
    systemctl is-enabled --quiet "${service}" 2>/dev/null
}

command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Verification helpers are shared because individual modules are sourced in
# isolation by the read-only CLI and privileged helper paths.
verify_sysctl() {
    local key="$1"
    local expected="$2"
    local actual

    actual=$(sysctl -n "${key}" 2>/dev/null || echo "")
    if [[ "${actual}" == "${expected}" ]]; then
        return 0
    fi
    log_warn "Sysctl mismatch: ${key} (expected: ${expected}, actual: ${actual})"
    return 1
}

package_installed() {
    local package="$1"
    local pkg_manager
    pkg_manager=$(detect_package_manager)
    
    case "${pkg_manager}" in
        apt)
            dpkg -l "${package}" 2>/dev/null | grep -q '^ii' ;;
        dnf|yum)
            rpm -q "${package}" >/dev/null 2>&1 ;;
        zypper)
            zypper se -i "${package}" | grep -q "^i" ;;
        *)
            log_error "Unknown package manager: ${pkg_manager}"
            return 1
            ;;
    esac
}

detect_package_manager() {
    if command_exists apt-get; then
        echo "apt"
    elif command_exists dnf; then
        echo "dnf"
    elif command_exists yum; then
        echo "yum"
    elif command_exists zypper; then
        echo "zypper"
    else
        log_error "No supported package manager found"
        return 1
    fi
}

generate_checksum() {
    local file="$1"
    sha256sum "${file}" | awk '{print $1}'
}

verify_checksum() {
    local file="$1"
    local expected_checksum="$2"
    local actual_checksum
    actual_checksum=$(generate_checksum "${file}")
    
    if [[ "${actual_checksum}" == "${expected_checksum}" ]]; then
        return 0
    else
        log_error "Checksum mismatch for ${file}"
        log_debug "Expected: ${expected_checksum}"
        log_debug "Actual: ${actual_checksum}"
        return 1
    fi
}

create_temp_file() {
    mktemp -t lsmf.XXXXXXXXXX
}

create_temp_dir() {
    mktemp -d -t lsmf.XXXXXXXXXX
}

write_json() {
    local output_file="$1"
    shift
    local json_content="$*"
    echo "${json_content}" > "${output_file}"
}

validate_config_value() {
    local key="$1"
    local value="$2"

    case "${key}" in
        AUTOMATIC_UPDATES|BACKUP_ENABLED|CIS_COMPLIANCE_CHECK|DISABLE_IPV6|DRY_RUN|\
        FIREWALL_ENABLED|INTERACTIVE_MODE|KERNEL_HARDENING|LOGGING_VERBOSE|\
        NETWORK_HARDENING|ROLLBACK_ENABLED|SSH_HARDENING|MODULE_*|FEATURE_*)
            [[ "${value}" == "true" || "${value}" == "false" ]] || {
                echo "${key} must be true or false" >&2
                return 1
            }
            ;;
        BACKUP_RETENTION_DAYS)
            [[ "${value}" =~ ^[0-9]+$ && "${value}" -ge 1 ]] || {
                echo "BACKUP_RETENTION_DAYS must be a positive integer" >&2
                return 1
            }
            ;;
        LOGGING_LEVEL)
            [[ "${value}" =~ ^(DEBUG|INFO|WARNING|ERROR)$ ]] || return 1
            ;;
        MAC_SYSTEM)
            [[ "${value}" =~ ^(auto|apparmor|selinux|none)$ ]] || return 1
            ;;
        SYSTEM_ROLE)
            [[ "${value}" =~ ^(auto|desktop|server)$ ]] || return 1
            ;;
    esac
}

validate_config_file() {
    local config_file="$1"
    local line
    local assignment_pattern='^([A-Z][A-Z0-9_]*)="([^"\\]*)"$'
    declare -A seen=()

    if [[ ! -f "${config_file}" ]]; then
        echo "Config file not found: ${config_file}" >&2
        return 1
    fi

    while IFS= read -r line || [[ -n "${line}" ]]; do
        [[ -z "${line}" || "${line}" == \#* ]] && continue
        if [[ ! "${line}" =~ ${assignment_pattern} ]]; then
            echo "Invalid configuration line in ${config_file}: ${line}" >&2
            return 1
        fi
        if [[ -n "${seen[${BASH_REMATCH[1]}]:-}" ]]; then
            echo "Duplicate configuration key in ${config_file}: ${BASH_REMATCH[1]}" >&2
            return 1
        fi
        seen[${BASH_REMATCH[1]}]=1
        validate_config_value "${BASH_REMATCH[1]}" "${BASH_REMATCH[2]}" || return 1
    done < "${config_file}"
}

read_config_value() {
    local key="$1"
    local config_file="${2:-$LSMF_CONFIG}"
    local line
    local assignment_pattern='^([A-Z][A-Z0-9_]*)="([^"\\]*)"$'

    if [[ ! "${key}" =~ ^[A-Z][A-Z0-9_]*$ ]]; then
        echo "Invalid configuration key: ${key}" >&2
        return 1
    fi
    validate_config_file "${config_file}" || return 1

    while IFS= read -r line || [[ -n "${line}" ]]; do
        if [[ "${line}" =~ ${assignment_pattern} ]] && [[ "${BASH_REMATCH[1]}" == "${key}" ]]; then
            echo "${BASH_REMATCH[2]}"
            return 0
        fi
    done < "${config_file}"
    return 1
}

set_config_value() {
    local key="$1"
    local value="$2"
    local config_file="${3:-$LSMF_CONFIG}"
    local config_dir
    local temp_file

    if [[ ! "${key}" =~ ^[A-Z][A-Z0-9_]*$ ]]; then
        echo "Invalid configuration key: ${key}" >&2
        return 1
    fi
    if [[ "${value}" == *'"'* || "${value}" == *\\* || "${value}" == *$'\n'* || "${value}" == *$'\r'* ]]; then
        echo "Invalid characters in value for ${key}" >&2
        return 1
    fi
    validate_config_value "${key}" "${value}" || return 1

    config_dir=$(dirname "${config_file}")
    mkdir -p "${config_dir}"
    if [[ -f "${config_file}" ]]; then
        validate_config_file "${config_file}" || return 1
    fi
    temp_file=$(mktemp "${config_dir}/.$(basename "${config_file}").XXXXXX")

    if [[ -f "${config_file}" ]]; then
        if ! awk -v key="${key}" -v value="${value}" '
            BEGIN { found = 0 }
            $0 ~ "^" key "=" {
                if (found) { exit 2 }
                print key "=\"" value "\""
                found = 1
                next
            }
            { print }
            END { if (!found) print key "=\"" value "\"" }
        ' "${config_file}" > "${temp_file}"; then
            rm -f "${temp_file}"
            echo "Failed to update configuration key: ${key}" >&2
            return 1
        fi
        chmod --reference="${config_file}" "${temp_file}"
    else
        printf '# LSMF configuration. Parsed as data; never source this file.\n%s="%s"\n' \
            "${key}" "${value}" > "${temp_file}"
        chmod 600 "${temp_file}"
    fi
    mv -f "${temp_file}" "${config_file}"
}

array_contains() {
    local needle="$1"
    shift
    local item
    for item in "$@"; do
        [[ "${item}" == "${needle}" ]] && return 0
    done
    return 1
}

print_banner() {
    cat << 'EOF'
╔════════════════════════════════════════════════════════════════╗
║                                                                ║
║   Linux Security Management Framework (LSMF)                  ║
║   Version: 1.0.0                                              ║
║                                                                ║
║   Comprehensive System Hardening & Security Management        ║
║                                                                ║
╚════════════════════════════════════════════════════════════════╝
EOF
}

export -f error_handler cleanup_on_error init_lsmf check_root
export -f print_color log_message log_error log_warn log_success log_info log_debug
export -f log_command execute_command confirm get_runtime format_duration
export -f validate_file validate_directory is_service_active is_service_enabled
export -f command_exists verify_sysctl package_installed detect_package_manager
export -f generate_checksum verify_checksum create_temp_file create_temp_dir
export -f write_json validate_config_value validate_config_file read_config_value set_config_value
export -f array_contains print_banner
