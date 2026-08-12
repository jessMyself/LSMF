#!/usr/bin/env bash

set -Eeuo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "${SCRIPT_DIR}")"
FIXTURES="${SCRIPT_DIR}/fixtures/config"
TEST_ROOT="$(mktemp -d)"
trap 'rm -rf "${TEST_ROOT}"' EXIT

LSMF_CONFIG="${FIXTURES}/canonical.conf"
LSMF_LOG_DIR="${TEST_ROOT}/logs"
LSMF_BACKUP_DIR="${TEST_ROOT}/backups"
LSMF_ROLLBACK_DIR="${TEST_ROOT}/rollback"
LSMF_REPORT_DIR="${TEST_ROOT}/reports"
source "${PROJECT_ROOT}/src/lib/common.sh"

echo "[TEST] Validating shared configuration fixtures with Bash..."

validate_config_file "${FIXTURES}/canonical.conf"
validate_config_file "${PROJECT_ROOT}/config/lsmf.conf"
for profile in "${PROJECT_ROOT}"/config/profiles/*.conf; do
    validate_config_file "${profile}"
done
[[ "$(read_config_value DISABLE_IPV6 "${FIXTURES}/canonical.conf")" == "false" ]]
[[ "$(read_config_value MODULE_SSH_ENABLED "${FIXTURES}/canonical.conf")" == "true" ]]
[[ "$(read_config_value FUTURE_SETTING "${FIXTURES}/canonical.conf")" == "preserved" ]]

if validate_config_file "${FIXTURES}/malformed.conf" >/dev/null 2>&1; then
    echo "  ✗ Malformed fixture unexpectedly passed"
    exit 1
fi

config_copy="${TEST_ROOT}/written.conf"
cp "${FIXTURES}/canonical.conf" "${config_copy}"
set_config_value DISABLE_IPV6 true "${config_copy}"
[[ "$(read_config_value DISABLE_IPV6 "${config_copy}")" == "true" ]]
[[ "$(read_config_value FUTURE_SETTING "${config_copy}")" == "preserved" ]]
if find "${TEST_ROOT}" -maxdepth 1 -name '.written.conf.*' | grep -q .; then
    echo "  ✗ Atomic writer left a temporary file"
    exit 1
fi

echo "  ✓ Bash parser and atomic writer passed"
