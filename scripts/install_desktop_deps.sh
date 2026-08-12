#!/usr/bin/env bash

set -Eeuo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

if [[ -f "${PROJECT_ROOT}/pyvenv.cfg" && -x "${PROJECT_ROOT}/bin/python" ]]; then
    VENV_DIR="${PROJECT_ROOT}"
else
    VENV_DIR="${PROJECT_ROOT}/.venv-desktop"
fi

if ! command -v python3 >/dev/null 2>&1; then
    echo "Python 3 is required" >&2
    exit 1
fi

if [[ ! -x "${VENV_DIR}/bin/python" ]]; then
    python3 -m venv "${VENV_DIR}"
fi

"${VENV_DIR}/bin/python" -m pip install --upgrade pip
"${VENV_DIR}/bin/python" -m pip install -r "${PROJECT_ROOT}/desktop/requirements.txt"

echo "Desktop dependencies installed in ${VENV_DIR}"
echo "Run: ${PROJECT_ROOT}/start-desktop.sh"
