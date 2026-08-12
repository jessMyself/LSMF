#!/usr/bin/env bash

set -Eeuo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
FIXTURE_ROOT="$(mktemp -d)"
trap 'rm -rf "${FIXTURE_ROOT}"' EXIT

assert_contains() {
    local output="$1"
    local expected="$2"

    if [[ "${output}" != *"${expected}"* ]]; then
        echo "  ✗ Missing expected output: ${expected}"
        return 1
    fi
}

echo "[TEST] Verifying test harness aggregation..."

success_output="$(LSMF_SKIP_HARNESS_REGRESSION=true bash "${SCRIPT_DIR}/run_tests.sh")"
assert_contains "${success_output}" "Test Results"
assert_contains "${success_output}" "Failed: 0"

mkdir -p "${FIXTURE_ROOT}/src/lib" "${FIXTURE_ROOT}/src/modules" \
    "${FIXTURE_ROOT}/src/ui" "${FIXTURE_ROOT}/scripts" \
    "${FIXTURE_ROOT}/config/profiles"
printf '%s\n' '#!/usr/bin/env bash' 'if then' > "${FIXTURE_ROOT}/src/broken.sh"
printf '%s\n' '#!/usr/bin/env bash' > "${FIXTURE_ROOT}/src/lsmf"
printf '%s\n' 'invalid=(' > "${FIXTURE_ROOT}/config/lsmf.conf"
printf '%s\n' '#!/usr/bin/env bash' > "${FIXTURE_ROOT}/scripts/install.sh"
printf '%s\n' '#!/usr/bin/env bash' > "${FIXTURE_ROOT}/scripts/uninstall.sh"

set +e
failure_output="$(LSMF_TEST_PROJECT_ROOT="${FIXTURE_ROOT}" \
    LSMF_SKIP_HARNESS_REGRESSION=true bash "${SCRIPT_DIR}/run_tests.sh" 2>&1)"
failure_status=$?
set -e

if [[ ${failure_status} -eq 0 ]]; then
    echo "  ✗ Intentionally broken fixture unexpectedly passed"
    exit 1
fi

assert_contains "${failure_output}" "[TEST] Checking project structure..."
assert_contains "${failure_output}" "[TEST] Checking Bash syntax..."
assert_contains "${failure_output}" "[TEST] Validating configuration files..."
assert_contains "${failure_output}" "[TEST] Checking executable permissions..."
assert_contains "${failure_output}" "[TEST] Running ShellCheck..."
assert_contains "${failure_output}" "Test Results"
assert_contains "${failure_output}" "✗ Some tests failed"

echo "  ✓ Test harness reaches its summary and aggregates failures"
