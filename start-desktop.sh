#!/usr/bin/env bash

set -Eeuo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

if [[ -f "${SCRIPT_DIR}/pyvenv.cfg" && -x "${SCRIPT_DIR}/bin/python" ]]; then
    PYTHON_BIN="${SCRIPT_DIR}/bin/python"
else
    PYTHON_BIN="${SCRIPT_DIR}/.venv-desktop/bin/python"
fi

if [[ "${EUID}" -eq 0 ]]; then
    echo "Do not run the LSMF desktop interface as root." >&2
    exit 1
fi

if [[ ! -x "${PYTHON_BIN}" ]]; then
    echo "Desktop environment not found." >&2
    echo "Run ./scripts/install_desktop_deps.sh first." >&2
    exit 1
fi

if ! "${PYTHON_BIN}" -c 'import PySide6' >/dev/null 2>&1; then
    echo "PySide6 is not installed in ${PYTHON_BIN}." >&2
    echo "Run ./scripts/install_desktop_deps.sh first." >&2
    exit 1
fi

QT_PLUGIN_DIR="$("${PYTHON_BIN}" -c 'from PySide6.QtCore import QLibraryInfo; print(QLibraryInfo.path(QLibraryInfo.LibraryPath.PluginsPath))')"
XCB_PLUGIN="${QT_PLUGIN_DIR}/platforms/libqxcb.so"
if [[ -f "${XCB_PLUGIN}" ]] && command -v ldd >/dev/null 2>&1; then
    MISSING_LIBRARIES="$(ldd "${XCB_PLUGIN}" 2>/dev/null | awk '/not found/ && !seen[$1]++ {print $1}')"
    if [[ -n "${MISSING_LIBRARIES}" ]]; then
        echo "Qt cannot start because these native libraries are missing:" >&2
        echo "${MISSING_LIBRARIES}" >&2
        if grep -qx 'libxcb-cursor.so.0' <<< "${MISSING_LIBRARIES}"; then
            echo "Install the Ubuntu package with:" >&2
            echo "  sudo apt-get install libxcb-cursor0" >&2
        fi
        exit 1
    fi
fi

exec "${PYTHON_BIN}" -m desktop.main
