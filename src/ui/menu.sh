#!/usr/bin/env bash

set -Eeuo pipefail

check_dialog() {
    if ! command_exists dialog; then
        log_error "dialog is not installed. Installing..."
        local pkg_mgr
        pkg_mgr=$(detect_package_manager)
        
        case "${pkg_mgr}" in
            apt) apt-get update && apt-get install -y dialog ;;
            dnf|yum) ${pkg_mgr} install -y dialog ;;
            zypper) zypper install -y dialog ;;
        esac
    fi
}

show_main_menu() {
    local choice
    choice=$(dialog --clear --backtitle "LSMF v${LSMF_VERSION}" \
        --title "Linux Security Management Framework" \
        --menu "Choose an option:" 20 70 12 \
        1 "System Audit" \
        2 "Apply Hardening" \
        3 "Restore Previous Configuration" \
        4 "View Reports" \
        5 "View Logs" \
        6 "Configure Settings (planned)" \
        7 "Update Framework (planned)" \
        8 "Run Individual Modules" \
        9 "CIS Compliance Scan (planned)" \
        10 "Security Score (informational)" \
        11 "System Information" \
        12 "Exit" \
        2>&1 >/dev/tty)
    
    echo "${choice}"
}

show_hardening_menu() {
    local choice
    choice=$(dialog --clear --backtitle "LSMF v${LSMF_VERSION}" \
        --title "Hardening Options" \
        --menu "Choose hardening mode:" 15 70 4 \
        1 "Simple Mode (planned)" \
        2 "Advanced Mode (Select Individual Modules)" \
        3 "Profile-Based (planned)" \
        4 "Back to Main Menu" \
        2>&1 >/dev/tty)
    
    echo "${choice}"
}

show_module_selection() {
    local modules_dir="$1"
    local selected_modules
    
    local menu_items=()
    local i=1
    
    for module in "${modules_dir}"/*.sh; do
        if [[ -f "${module}" ]]; then
            local module_name
            module_name=$(basename "${module}" .sh)
            menu_items+=("${i}" "${module_name}" "off")
            ((i++))
        fi
    done
    
    selected_modules=$(dialog --clear --backtitle "LSMF v${LSMF_VERSION}" \
        --title "Select Modules" \
        --checklist "Choose modules to run:" 20 70 12 \
        "${menu_items[@]}" \
        2>&1 >/dev/tty)
    
    echo "${selected_modules}"
}

show_profile_menu() {
    local choice
    choice=$(dialog --clear --backtitle "LSMF v${LSMF_VERSION}" \
        --title "Security Profiles" \
        --menu "Choose a security profile:" 18 70 10 \
        1 "Desktop - Standard desktop workstation" \
        2 "Laptop (planned)" \
        3 "Server - General purpose server" \
        4 "Web Server (planned)" \
        5 "Database Server (planned)" \
        6 "File Server (planned)" \
        7 "Workstation (planned)" \
        8 "Maximum Lockdown - Highest security" \
        9 "Custom profile (planned)" \
        10 "Back" \
        2>&1 >/dev/tty)
    
    echo "${choice}"
}

show_backup_menu() {
    local backup_items=()
    local backup_number
    local backup_label
    while IFS=$'\t' read -r backup_number backup_label; do
        [[ -n "${backup_number}" ]] && backup_items+=("${backup_number}" "${backup_label}")
    done < <(list_backups_for_menu)

    if [[ ${#backup_items[@]} -eq 0 ]]; then
        dialog --backtitle "LSMF v${LSMF_VERSION}" \
            --title "Backups" \
            --msgbox "No backups found." 8 50
        return 1
    fi
    
    local choice
    choice=$(dialog --clear --backtitle "LSMF v${LSMF_VERSION}" \
        --title "Restore Backup" \
        --menu "Choose a backup to restore:" 20 70 12 \
        "${backup_items[@]}" \
        2>&1 >/dev/tty)
    
    echo "${choice}"
}

list_backups_for_menu() {
    if [[ ! -d "${LSMF_BACKUP_DIR}" ]]; then
        return 1
    fi
    
    local i=1
    for backup in "${LSMF_BACKUP_DIR}"/*; do
        if [[ -d "${backup}" ]]; then
            local backup_id
            backup_id=$(basename "${backup}")
            local manifest="${backup}/manifest.txt"
            local file_count=0
            
            if [[ -f "${manifest}" ]]; then
                file_count=$(wc -l < "${manifest}")
            fi
            
            printf '%s\t%s\n' "${i}" "${backup_id} (${file_count} files)"
            ((i++))
        fi
    done
}

show_progress() {
    local title="$1"
    local message="$2"
    local percent="${3:-0}"
    
    echo "${percent}" | dialog --backtitle "LSMF v${LSMF_VERSION}" \
        --title "${title}" \
        --gauge "${message}" 10 70 0
}

show_message() {
    local title="$1"
    local message="$2"
    
    dialog --backtitle "LSMF v${LSMF_VERSION}" \
        --title "${title}" \
        --msgbox "${message}" 12 70
}

show_info() {
    local title="$1"
    local message="$2"
    
    dialog --backtitle "LSMF v${LSMF_VERSION}" \
        --title "${title}" \
        --infobox "${message}" 8 50
    sleep 2
}

show_yes_no() {
    local title="$1"
    local message="$2"
    
    dialog --backtitle "LSMF v${LSMF_VERSION}" \
        --title "${title}" \
        --yesno "${message}" 10 70
    
    return $?
}

show_input() {
    local title="$1"
    local prompt="$2"
    local default="${3:-}"
    
    local input
    input=$(dialog --backtitle "LSMF v${LSMF_VERSION}" \
        --title "${title}" \
        --inputbox "${prompt}" 10 70 "${default}" \
        2>&1 >/dev/tty)
    
    echo "${input}"
}

show_text_file() {
    local title="$1"
    local file="$2"
    
    if [[ ! -f "${file}" ]]; then
        show_message "Error" "File not found: ${file}"
        return 1
    fi
    
    dialog --backtitle "LSMF v${LSMF_VERSION}" \
        --title "${title}" \
        --textbox "${file}" 30 100
}

show_system_info_ui() {
    local info_file
    info_file=$(create_temp_file)
    
    cat > "${info_file}" << EOF
╔════════════════════════════════════════════════════════════════╗
║                    SYSTEM INFORMATION                          ║
╠════════════════════════════════════════════════════════════════╣
║
║ Operating System:    ${OS_NAME} ${OS_VERSION}
║ Distribution:        ${OS_ID}
║ Kernel:              ${KERNEL_VERSION}
║ Architecture:        ${CPU_ARCH}
║ Desktop:             ${DESKTOP_ENV}
║ System Role:         ${SYSTEM_ROLE}
║
║ Virtualization:      ${IS_VIRTUAL}
║ Container:           ${IS_CONTAINER}
║ Cloud Provider:      ${CLOUD_PROVIDER}
║
║ Init System:         ${INIT_SYSTEM}
║ Firewall:            ${FIREWALL_TYPE}
║ MAC System:          ${MAC_SYSTEM}
║ Package Manager:     ${PACKAGE_MANAGER}
║
║ Boot Mode:           ${BOOT_MODE}
║ Secure Boot:         ${SECURE_BOOT}
║
╚════════════════════════════════════════════════════════════════╝
EOF
    
    show_text_file "System Information" "${info_file}"
    rm -f "${info_file}"
}

show_security_score_ui() {
    calculate_security_score
    
    local score_file
    score_file=$(create_temp_file)
    
    local rating
    if [[ ${SECURITY_SCORE} -ge 90 ]]; then
        rating="Excellent"
    elif [[ ${SECURITY_SCORE} -ge 75 ]]; then
        rating="Good"
    elif [[ ${SECURITY_SCORE} -ge 60 ]]; then
        rating="Fair"
    elif [[ ${SECURITY_SCORE} -ge 40 ]]; then
        rating="Poor"
    else
        rating="Critical"
    fi
    
    cat > "${score_file}" << EOF
╔════════════════════════════════════════════════════════════════╗
║                    SECURITY SCORE                              ║
╠════════════════════════════════════════════════════════════════╣
║
║                    Score: ${SECURITY_SCORE}/100
║                    Rating: ${rating}
║
╠════════════════════════════════════════════════════════════════╣
║ Score Breakdown:
║
║ Base Score:                   50
║ Firewall Active:              +5
║ MAC System Active:            +10
║ Secure Boot Enabled:          +5
║ Hardening Applied:            +${#REPORT_DATA[@]}
║
╠════════════════════════════════════════════════════════════════╣
║ Recommendations to Improve Score:
║
EOF
    
    [[ "${FIREWALL_TYPE}" == "none" ]] && echo "║ - Enable and configure firewall" >> "${score_file}"
    [[ "${MAC_SYSTEM}" == "none" ]] && echo "║ - Enable AppArmor or SELinux" >> "${score_file}"
    [[ "${SECURE_BOOT}" == "disabled" ]] && echo "║ - Enable Secure Boot" >> "${score_file}"
    [[ ${#REPORT_DATA[@]} -lt 10 ]] && echo "║ - Apply more hardening modules" >> "${score_file}"
    
    cat >> "${score_file}" << EOF
║
╚════════════════════════════════════════════════════════════════╝
EOF
    
    show_text_file "Security Score" "${score_file}"
    rm -f "${score_file}"
}

show_log_viewer() {
    local log_dir="${LSMF_LOG_DIR}/${LSMF_RUN_ID}"
    
    if [[ ! -d "${log_dir}" ]]; then
        show_message "Error" "No logs found for current run"
        return 1
    fi
    
    local log_files=()
    local i=1
    
    for log_file in "${log_dir}"/*.log; do
        if [[ -f "${log_file}" ]]; then
            local log_name
            log_name=$(basename "${log_file}")
            log_files+=("${i}" "${log_name}")
            ((i++))
        fi
    done
    
    if [[ ${#log_files[@]} -eq 0 ]]; then
        show_message "Error" "No log files found"
        return 1
    fi
    
    local choice
    choice=$(dialog --clear --backtitle "LSMF v${LSMF_VERSION}" \
        --title "View Logs" \
        --menu "Choose a log file:" 20 70 12 \
        "${log_files[@]}" \
        2>&1 >/dev/tty)
    
    if [[ -n "${choice}" ]]; then
        local selected_log="${log_files[$((choice * 2 - 1))]}"
        show_text_file "Log: ${selected_log}" "${log_dir}/${selected_log}"
    fi
}

cleanup_dialog() {
    clear
}

export -f check_dialog show_main_menu show_hardening_menu show_module_selection
export -f show_profile_menu show_backup_menu list_backups_for_menu
export -f show_progress show_message show_info show_yes_no show_input show_text_file
export -f show_system_info_ui show_security_score_ui show_log_viewer cleanup_dialog
