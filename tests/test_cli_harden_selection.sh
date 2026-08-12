#!/usr/bin/env bash

set -Eeuo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "${SCRIPT_DIR}")"
FIXTURE_ROOT="$(mktemp -d)"
trap 'rm -rf "${FIXTURE_ROOT}"' EXIT

mkdir -p "${FIXTURE_ROOT}/modules" "${FIXTURE_ROOT}/config/profiles"

for module_id in alpha_module beta_module fail_module; do
    module_path="${FIXTURE_ROOT}/modules/${module_id}.sh"
    printf '%s\n' '#!/usr/bin/env bash' \
        'printf '\''%s\n'\'' "$(basename "$0" .sh)" >> "${EXECUTION_SENTINEL}"' \
        '[[ "$(basename "$0" .sh)" != "fail_module" ]]' > "${module_path}"
    chmod 0755 "${module_path}"
done

printf '%s\n' 'PROFILE_NAME="Ordered"' 'PROFILE_DESCRIPTION="Selection fixture"' \
    'ENABLED_MODULES="beta_module alpha_module"' > "${FIXTURE_ROOT}/config/profiles/ordered.conf"
printf '%s\n' 'PROFILE_NAME="All"' 'PROFILE_DESCRIPTION="All fixture"' \
    'ENABLED_MODULES="all"' > "${FIXTURE_ROOT}/config/profiles/all.conf"
printf '%s\n' 'PROFILE_NAME="Duplicate"' 'PROFILE_DESCRIPTION="Duplicate fixture"' \
    'ENABLED_MODULES="alpha_module alpha_module"' > "${FIXTURE_ROOT}/config/profiles/duplicate.conf"
printf '%s\n' 'PROFILE_NAME="Empty"' 'PROFILE_DESCRIPTION="Empty fixture"' \
    'ENABLED_MODULES=""' > "${FIXTURE_ROOT}/config/profiles/empty.conf"
printf '%s\n' 'PROFILE_NAME="Mixed all"' 'PROFILE_DESCRIPTION="Invalid all fixture"' \
    'ENABLED_MODULES="all alpha_module"' > "${FIXTURE_ROOT}/config/profiles/mixed-all.conf"

source "${PROJECT_ROOT}/src/lsmf"
MODULES_DIR="${FIXTURE_ROOT}/modules"
CONFIG_DIR="${FIXTURE_ROOT}/config"
export EXECUTION_SENTINEL="${FIXTURE_ROOT}/executed"
log_info() { :; }
log_success() { :; }
log_error() { :; }
add_warning() { :; }
run_system_detection() { :; }
is_supported_os() { return 0; }
calculate_security_score() { SECURITY_SCORE=0; }
generate_report() { :; }

unset RUN_MODULE PROFILE
parse_arguments --module alpha_module harden
[[ "${LSMF_COMMAND}" == "harden" && "${RUN_MODULE}" == "alpha_module" ]]
unset RUN_MODULE PROFILE
parse_arguments --profile ordered --dry-run harden
[[ "${LSMF_COMMAND}" == "harden" && "${PROFILE}" == "ordered" && "${LSMF_DRY_RUN}" == "true" ]]
LSMF_DRY_RUN=false
if (trap - ERR; parse_arguments --module); then
    echo "Missing module value unexpectedly parsed" >&2
    exit 1
fi
if (trap - ERR; parse_arguments --profile ""); then
    echo "Empty profile value unexpectedly parsed" >&2
    exit 1
fi
unset RUN_MODULE PROFILE

selection=()
RUN_MODULE=beta_module
select_hardening_modules selection
[[ "${selection[*]}" == "${MODULES_DIR}/beta_module.sh" ]]

RUN_MODULE=""
if select_hardening_modules selection; then
    echo "Empty module ID unexpectedly passed" >&2
    exit 1
fi
RUN_MODULE="invalid/module"
if select_hardening_modules selection; then
    echo "Invalid module ID unexpectedly passed" >&2
    exit 1
fi
RUN_MODULE=missing_module
if select_hardening_modules selection; then
    echo "Unknown module unexpectedly passed" >&2
    exit 1
fi

unset RUN_MODULE
PROFILE=ordered
select_hardening_modules selection
[[ "${selection[*]}" == "${MODULES_DIR}/beta_module.sh ${MODULES_DIR}/alpha_module.sh" ]]

PROFILE=all
select_hardening_modules selection
[[ "${selection[*]}" == "${MODULES_DIR}/alpha_module.sh ${MODULES_DIR}/beta_module.sh ${MODULES_DIR}/fail_module.sh" ]]

for invalid_profile in duplicate empty mixed-all missing 'invalid/profile'; do
    PROFILE="${invalid_profile}"
    if select_hardening_modules selection; then
        echo "Invalid profile ${invalid_profile} unexpectedly passed" >&2
        exit 1
    fi
done

RUN_MODULE=alpha_module
PROFILE=ordered
if select_hardening_modules selection; then
    echo "Combined module and profile selection unexpectedly passed" >&2
    exit 1
fi

unset RUN_MODULE PROFILE
LSMF_INTERACTIVE=false
LSMF_DRY_RUN=true
run_hardening
[[ ! -e "${EXECUTION_SENTINEL}" ]]

LSMF_DRY_RUN=false
RUN_MODULE=alpha_module
run_hardening
[[ "$(cat "${EXECUTION_SENTINEL}")" == "alpha_module" ]]

: > "${EXECUTION_SENTINEL}"
PROFILE=all
unset RUN_MODULE
if run_hardening; then
    echo "Hardening unexpectedly ignored a module failure" >&2
    exit 1
fi
[[ "$(cat "${EXECUTION_SENTINEL}")" == $'alpha_module\nbeta_module\nfail_module' ]]

echo "CLI hardening selection, dry-run, and aggregation passed"
