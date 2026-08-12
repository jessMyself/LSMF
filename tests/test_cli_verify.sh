#!/usr/bin/env bash

set -Eeuo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "${SCRIPT_DIR}")"
FIXTURE_ROOT="$(mktemp -d)"
trap 'rm -rf "${FIXTURE_ROOT}"' EXIT

mkdir -p "${FIXTURE_ROOT}/modules"

cat > "${FIXTURE_ROOT}/modules/pass_module.sh" <<'EOF'
#!/usr/bin/env bash
run_pass_module() { echo apply-ran >> "${MUTATION_SENTINEL}"; }
verify_pass_module() { return 0; }
if [[ "${MODULE_ENABLED:-true}" == "true" ]] && [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    run_pass_module
fi
EOF

cat > "${FIXTURE_ROOT}/modules/fail_module.sh" <<'EOF'
#!/usr/bin/env bash
verify_fail_module() { return 1; }
EOF

cat > "${FIXTURE_ROOT}/modules/incomplete_module.sh" <<'EOF'
#!/usr/bin/env bash
run_incomplete_module() { return 0; }
EOF

export MUTATION_SENTINEL="${FIXTURE_ROOT}/mutation-ran"
source "${PROJECT_ROOT}/src/lsmf"
declare -F verify_sysctl >/dev/null
[[ ${#REPORT_DATA[@]} -eq 0 ]]
[[ ${#REPORT_WARNINGS[@]} -eq 0 ]]
[[ ${#REPORT_RECOMMENDATIONS[@]} -eq 0 ]]
MODULES_DIR="${FIXTURE_ROOT}/modules"
log_info() { :; }
log_success() { :; }
log_error() { :; }

RUN_MODULE=pass_module
run_verification
[[ ! -e "${MUTATION_SENTINEL}" ]]

RUN_MODULE=missing_module
if run_verification; then
    echo "Unknown module unexpectedly passed verification" >&2
    exit 1
fi

RUN_MODULE="invalid/module"
if run_verification; then
    echo "Invalid module ID unexpectedly passed verification" >&2
    exit 1
fi

unset RUN_MODULE
if run_verification; then
    echo "Aggregate verification unexpectedly ignored failures" >&2
    exit 1
fi

rm "${FIXTURE_ROOT}/modules/fail_module.sh" "${FIXTURE_ROOT}/modules/incomplete_module.sh"
run_verification
[[ ! -e "${MUTATION_SENTINEL}" ]]

echo "CLI verification selection and aggregation passed"
