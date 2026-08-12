#!/usr/bin/env bash

set -Eeuo pipefail

backup_file() {
    local file="$1"
    local backup_id="${2:-$LSMF_RUN_ID}"
    
    if [[ ! -f "${file}" ]]; then
        log_warn "File does not exist, skipping backup: ${file}"
        return 0
    fi
    
    local backup_dir="${LSMF_BACKUP_DIR}/${backup_id}"
    mkdir -p "${backup_dir}"
    
    local file_dir
    file_dir=$(dirname "${file}")
    local backup_subdir="${backup_dir}${file_dir}"
    mkdir -p "${backup_subdir}"
    
    local backup_path="${backup_dir}${file}"
    
    if [[ -f "${backup_path}" ]]; then
        log_debug "Backup already exists: ${backup_path}"
        return 0
    fi
    
    cp -a "${file}" "${backup_path}"
    
    local checksum
    checksum=$(generate_checksum "${file}")
    
    local metadata="${backup_path}.meta"
    cat > "${metadata}" << EOF
original_path=${file}
backup_path=${backup_path}
checksum=${checksum}
timestamp=$(date -u +%Y-%m-%dT%H:%M:%SZ)
permissions=$(stat -c %a "${file}")
owner=$(stat -c %u "${file}")
group=$(stat -c %g "${file}")
size=$(stat -c %s "${file}")
EOF
    
    log_success "Backed up: ${file} -> ${backup_path}"
    
    local manifest="${LSMF_BACKUP_DIR}/${backup_id}/manifest.txt"
    echo "${file}" >> "${manifest}"
    
    return 0
}

backup_directory() {
    local dir="$1"
    local backup_id="${2:-$LSMF_RUN_ID}"
    
    if [[ ! -d "${dir}" ]]; then
        log_warn "Directory does not exist, skipping backup: ${dir}"
        return 0
    fi
    
    local backup_dir="${LSMF_BACKUP_DIR}/${backup_id}"
    mkdir -p "${backup_dir}"
    
    local backup_path="${backup_dir}${dir}"
    mkdir -p "$(dirname "${backup_path}")"
    
    cp -a "${dir}" "${backup_path}"
    
    log_success "Backed up directory: ${dir} -> ${backup_path}"
    return 0
}

restore_file() {
    local file="$1"
    local backup_id="${2:-$LSMF_RUN_ID}"
    
    local backup_path="${LSMF_BACKUP_DIR}/${backup_id}${file}"
    local metadata="${backup_path}.meta"
    
    if [[ ! -f "${backup_path}" ]]; then
        log_error "Backup not found: ${backup_path}"
        return 1
    fi
    
    if [[ ! -f "${metadata}" ]]; then
        log_warn "Metadata not found for backup: ${metadata}"
    fi
    
    if [[ -f "${file}" ]]; then
        local temp_backup
        temp_backup=$(create_temp_file)
        cp "${file}" "${temp_backup}"
        log_debug "Created temporary backup: ${temp_backup}"
    fi
    
    cp -a "${backup_path}" "${file}"
    
    if [[ -f "${metadata}" ]]; then
        local perms owner group
        perms=$(grep "^permissions=" "${metadata}" | cut -d= -f2)
        owner=$(grep "^owner=" "${metadata}" | cut -d= -f2)
        group=$(grep "^group=" "${metadata}" | cut -d= -f2)
        
        [[ -n "${perms}" ]] && chmod "${perms}" "${file}"
        [[ -n "${owner}" ]] && [[ -n "${group}" ]] && chown "${owner}:${group}" "${file}"
    fi
    
    log_success "Restored: ${backup_path} -> ${file}"
    return 0
}

restore_all() {
    local backup_id="${1:-$LSMF_RUN_ID}"
    local backup_dir="${LSMF_BACKUP_DIR}/${backup_id}"
    local manifest="${backup_dir}/manifest.txt"
    
    if [[ ! -f "${manifest}" ]]; then
        log_error "Manifest not found: ${manifest}"
        return 1
    fi
    
    log_info "Restoring all files from backup: ${backup_id}"
    
    local file
    local count=0
    local failed=0
    
    while IFS= read -r file; do
        if restore_file "${file}" "${backup_id}"; then
            ((count++))
        else
            ((failed++))
        fi
    done < "${manifest}"
    
    log_info "Restored ${count} files, ${failed} failed"
    
    [[ ${failed} -eq 0 ]] && return 0 || return 1
}

list_backups() {
    if [[ ! -d "${LSMF_BACKUP_DIR}" ]]; then
        log_info "No backups found"
        return 0
    fi
    
    log_info "Available backups:"
    local backup
    for backup in "${LSMF_BACKUP_DIR}"/*; do
        if [[ -d "${backup}" ]]; then
            local backup_id
            backup_id=$(basename "${backup}")
            local manifest="${backup}/manifest.txt"
            local file_count=0
            
            if [[ -f "${manifest}" ]]; then
                file_count=$(wc -l < "${manifest}")
            fi
            
            echo "  ${backup_id} (${file_count} files)"
        fi
    done
}

delete_backup() {
    local backup_id="$1"
    local backup_dir="${LSMF_BACKUP_DIR}/${backup_id}"
    
    if [[ ! -d "${backup_dir}" ]]; then
        log_error "Backup not found: ${backup_id}"
        return 1
    fi
    
    rm -rf "${backup_dir}"
    log_success "Deleted backup: ${backup_id}"
    return 0
}

verify_backup() {
    local file="$1"
    local backup_id="${2:-$LSMF_RUN_ID}"
    
    local backup_path="${LSMF_BACKUP_DIR}/${backup_id}${file}"
    local metadata="${backup_path}.meta"
    
    if [[ ! -f "${backup_path}" ]]; then
        log_error "Backup not found: ${backup_path}"
        return 1
    fi
    
    if [[ ! -f "${metadata}" ]]; then
        log_warn "Cannot verify backup, metadata missing: ${metadata}"
        return 1
    fi
    
    local stored_checksum
    stored_checksum=$(grep "^checksum=" "${metadata}" | cut -d= -f2)
    
    local actual_checksum
    actual_checksum=$(generate_checksum "${backup_path}")
    
    if [[ "${stored_checksum}" == "${actual_checksum}" ]]; then
        log_success "Backup verified: ${backup_path}"
        return 0
    else
        log_error "Backup verification failed: ${backup_path}"
        return 1
    fi
}

get_backup_info() {
    local backup_id="$1"
    local backup_dir="${LSMF_BACKUP_DIR}/${backup_id}"
    local manifest="${backup_dir}/manifest.txt"
    
    if [[ ! -d "${backup_dir}" ]]; then
        log_error "Backup not found: ${backup_id}"
        return 1
    fi
    
    echo "Backup ID: ${backup_id}"
    echo "Location: ${backup_dir}"
    
    if [[ -f "${manifest}" ]]; then
        local file_count
        file_count=$(wc -l < "${manifest}")
        echo "Files: ${file_count}"
    else
        echo "Files: Unknown (manifest missing)"
    fi
    
    if [[ -d "${backup_dir}" ]]; then
        local size
        size=$(du -sh "${backup_dir}" | cut -f1)
        echo "Size: ${size}"
    fi
}

create_rollback_point() {
    local name="$1"
    local description="${2:-}"
    
    local rollback_id="${LSMF_RUN_ID}_${name}"
    local rollback_dir="${LSMF_ROLLBACK_DIR}/${rollback_id}"
    mkdir -p "${rollback_dir}"
    
    cat > "${rollback_dir}/info.txt" << EOF
name=${name}
description=${description}
timestamp=$(date -u +%Y-%m-%dT%H:%M:%SZ)
run_id=${LSMF_RUN_ID}
EOF
    
    log_success "Created rollback point: ${rollback_id}"
    echo "${rollback_id}"
}

save_rollback_state() {
    local rollback_id="$1"
    local state_type="$2"
    local state_data="$3"
    
    local rollback_dir="${LSMF_ROLLBACK_DIR}/${rollback_id}"
    mkdir -p "${rollback_dir}"
    
    echo "${state_data}" >> "${rollback_dir}/${state_type}.state"
    log_debug "Saved ${state_type} state to rollback point: ${rollback_id}"
}

list_rollback_points() {
    if [[ ! -d "${LSMF_ROLLBACK_DIR}" ]]; then
        log_info "No rollback points found"
        return 0
    fi
    
    log_info "Available rollback points:"
    local rollback
    for rollback in "${LSMF_ROLLBACK_DIR}"/*; do
        if [[ -d "${rollback}" ]]; then
            local rollback_id
            rollback_id=$(basename "${rollback}")
            local info="${rollback}/info.txt"
            
            if [[ -f "${info}" ]]; then
                local name timestamp
                name=$(grep "^name=" "${info}" | cut -d= -f2)
                timestamp=$(grep "^timestamp=" "${info}" | cut -d= -f2)
                echo "  ${rollback_id} - ${name} (${timestamp})"
            else
                echo "  ${rollback_id}"
            fi
        fi
    done
}

export -f backup_file backup_directory restore_file restore_all
export -f list_backups delete_backup verify_backup get_backup_info
export -f create_rollback_point save_rollback_state list_rollback_points
