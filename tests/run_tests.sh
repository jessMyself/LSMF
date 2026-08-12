#!/usr/bin/env bash

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="${LSMF_TEST_PROJECT_ROOT:-$(dirname "${SCRIPT_DIR}")}"

echo "╔════════════════════════════════════════════════════════════════╗"
echo "║   LSMF Test Suite                                             ║"
echo "╚════════════════════════════════════════════════════════════════╝"
echo ""

TESTS_PASSED=0
TESTS_FAILED=0
TESTS_SKIPPED=0

list_product_scripts() {
    find "${PROJECT_ROOT}/src" "${PROJECT_ROOT}/scripts" -type f -name "*.sh" -print 2>/dev/null

    if [[ -f "${PROJECT_ROOT}/src/lsmf" ]]; then
        echo "${PROJECT_ROOT}/src/lsmf"
    fi

    find "${PROJECT_ROOT}" -maxdepth 1 -type f -name "start-*.sh" -print 2>/dev/null
}

test_shellcheck() {
    echo "[TEST] Running ShellCheck..."
    
    if ! command -v shellcheck >/dev/null 2>&1; then
        echo "  ⚠ ShellCheck not installed, skipping..."
        TESTS_SKIPPED=$((TESTS_SKIPPED + 1))
        return 0
    fi
    
    local failed=0
    
    while IFS= read -r file; do
        if ! shellcheck -x "${file}" >/dev/null 2>&1; then
            echo "  ✗ Failed: ${file}"
            failed=1
        fi
    done < <(list_product_scripts)
    
    if [[ ${failed} -eq 0 ]]; then
        echo "  ✓ ShellCheck passed"
        TESTS_PASSED=$((TESTS_PASSED + 1))
        return 0
    else
        echo "  ✗ ShellCheck failed"
        TESTS_FAILED=$((TESTS_FAILED + 1))
        return 1
    fi
}

test_syntax() {
    echo "[TEST] Checking Bash syntax..."
    
    local failed=0
    
    while IFS= read -r file; do
        if ! bash -n "${file}" 2>/dev/null; then
            echo "  ✗ Syntax error: ${file}"
            failed=1
        fi
    done < <(list_product_scripts)
    
    if [[ ${failed} -eq 0 ]]; then
        echo "  ✓ Syntax check passed"
        TESTS_PASSED=$((TESTS_PASSED + 1))
        return 0
    else
        echo "  ✗ Syntax check failed"
        TESTS_FAILED=$((TESTS_FAILED + 1))
        return 1
    fi
}

test_config_files() {
    echo "[TEST] Validating configuration files..."
    
    local failed=0
    
    if ! bash -n "${PROJECT_ROOT}/config/lsmf.conf" 2>/dev/null; then
        echo "  ✗ Invalid: config/lsmf.conf"
        failed=1
    fi
    
    while IFS= read -r file; do
        if ! bash -n "${file}" 2>/dev/null; then
            echo "  ✗ Invalid: ${file}"
            failed=1
        fi
    done < <(find "${PROJECT_ROOT}/config/profiles" -name "*.conf" -type f)
    
    if [[ ${failed} -eq 0 ]]; then
        echo "  ✓ Configuration files valid"
        TESTS_PASSED=$((TESTS_PASSED + 1))
        return 0
    else
        echo "  ✗ Configuration validation failed"
        TESTS_FAILED=$((TESTS_FAILED + 1))
        return 1
    fi
}

test_file_structure() {
    echo "[TEST] Checking project structure..."
    
    local failed=0
    local required_dirs=(
        "src/lib"
        "src/modules"
        "src/ui"
        "config"
        "config/profiles"
        "scripts"
        "docs"
        "tests"
    )
    
    for dir in "${required_dirs[@]}"; do
        if [[ ! -d "${PROJECT_ROOT}/${dir}" ]]; then
            echo "  ✗ Missing directory: ${dir}"
            failed=1
        fi
    done
    
    local required_files=(
        "src/lsmf"
        "src/lib/common.sh"
        "src/lib/backup.sh"
        "src/lib/detection.sh"
        "src/lib/reporting.sh"
        "config/lsmf.conf"
        "README.md"
        "AGENTS.md"
        "LICENSE"
    )
    
    for file in "${required_files[@]}"; do
        if [[ ! -f "${PROJECT_ROOT}/${file}" ]]; then
            echo "  ✗ Missing file: ${file}"
            failed=1
        fi
    done
    
    if [[ ${failed} -eq 0 ]]; then
        echo "  ✓ Project structure valid"
        TESTS_PASSED=$((TESTS_PASSED + 1))
        return 0
    else
        echo "  ✗ Project structure incomplete"
        TESTS_FAILED=$((TESTS_FAILED + 1))
        return 1
    fi
}

test_executable_permissions() {
    echo "[TEST] Checking executable permissions..."
    
    local failed=0
    
    if [[ ! -x "${PROJECT_ROOT}/src/lsmf" ]]; then
        echo "  ✗ Not executable: src/lsmf"
        failed=1
    fi
    
    if [[ ! -x "${PROJECT_ROOT}/scripts/install.sh" ]]; then
        echo "  ✗ Not executable: scripts/install.sh"
        failed=1
    fi
    
    if [[ ! -x "${PROJECT_ROOT}/scripts/uninstall.sh" ]]; then
        echo "  ✗ Not executable: scripts/uninstall.sh"
        failed=1
    fi
    
    if [[ ${failed} -eq 0 ]]; then
        echo "  ✓ Executable permissions correct"
        TESTS_PASSED=$((TESTS_PASSED + 1))
        return 0
    else
        echo "  ✗ Executable permissions incorrect"
        TESTS_FAILED=$((TESTS_FAILED + 1))
        return 1
    fi
}

test_config_schema() {
    echo "[TEST] Checking shared configuration schema..."

    if bash "${SCRIPT_DIR}/test_config_schema.sh"; then
        echo "  ✓ Shared configuration schema passed"
        TESTS_PASSED=$((TESTS_PASSED + 1))
        return 0
    else
        echo "  ✗ Shared configuration schema failed"
        TESTS_FAILED=$((TESTS_FAILED + 1))
        return 1
    fi
}

test_cli_verify() {
    echo "[TEST] Checking CLI module verification..."
    if bash "${SCRIPT_DIR}/test_cli_verify.sh"; then
        echo "  ✓ CLI module verification passed"
        TESTS_PASSED=$((TESTS_PASSED + 1))
        return 0
    fi
    echo "  ✗ CLI module verification failed"
    TESTS_FAILED=$((TESTS_FAILED + 1))
    return 1
}

test_cli_hardening_selection() {
    echo "[TEST] Checking CLI hardening selection..."
    if bash "${SCRIPT_DIR}/test_cli_harden_selection.sh"; then
        echo "  ✓ CLI hardening selection passed"
        TESTS_PASSED=$((TESTS_PASSED + 1))
        return 0
    fi
    echo "  ✗ CLI hardening selection failed"
    TESTS_FAILED=$((TESTS_FAILED + 1))
    return 1
}

run_tests() {
    test_file_structure || true
    test_syntax || true
    test_config_files || true
    test_executable_permissions || true
    test_shellcheck || true
    test_config_schema || true
    test_cli_verify || true
    test_cli_hardening_selection || true

    if [[ "${LSMF_SKIP_HARNESS_REGRESSION:-false}" != "true" ]]; then
        if bash "${SCRIPT_DIR}/test_run_tests.sh"; then
            TESTS_PASSED=$((TESTS_PASSED + 1))
        else
            TESTS_FAILED=$((TESTS_FAILED + 1))
        fi
    fi
}

run_tests

echo ""
echo "════════════════════════════════════════════════════════════════"
echo " Test Results"
echo "════════════════════════════════════════════════════════════════"
echo " Passed: ${TESTS_PASSED}"
echo " Failed: ${TESTS_FAILED}"
echo " Skipped: ${TESTS_SKIPPED}"
echo "════════════════════════════════════════════════════════════════"
echo ""

if [[ ${TESTS_FAILED} -eq 0 ]]; then
    echo "✓ All tests passed!"
    exit 0
else
    echo "✗ Some tests failed"
    exit 1
fi
