#!/usr/bin/env bash

set -Eeuo pipefail

INSTALL_DIR="/opt/lsmf"
CONFIG_DIR="/etc/lsmf"
BIN_LINK="/usr/local/bin/lsmf"

echo "╔════════════════════════════════════════════════════════════════╗"
echo "║   Linux Security Management Framework (LSMF) Installer       ║"
echo "╚════════════════════════════════════════════════════════════════╝"
echo ""

if [[ $EUID -ne 0 ]]; then
    echo "Error: This installer must be run as root"
    exit 1
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

echo "[1/6] Creating directories..."
mkdir -p "${INSTALL_DIR}"/{lib,modules,ui,templates}
mkdir -p "${CONFIG_DIR}/profiles"
mkdir -p /var/log/lsmf
mkdir -p /var/backups/lsmf
mkdir -p /var/lib/lsmf/{rollback,reports}

echo "[2/6] Installing library files..."
cp -r "${PROJECT_ROOT}"/src/lib/* "${INSTALL_DIR}/lib/"

echo "[3/6] Installing modules..."
cp -r "${PROJECT_ROOT}"/src/modules/* "${INSTALL_DIR}/modules/"

echo "[4/6] Installing UI components..."
cp -r "${PROJECT_ROOT}"/src/ui/* "${INSTALL_DIR}/ui/"

echo "[5/6] Installing configuration..."
if [[ ! -f "${CONFIG_DIR}/lsmf.conf" ]]; then
    cp "${PROJECT_ROOT}"/config/lsmf.conf "${CONFIG_DIR}/"
else
    echo "   Configuration already exists, skipping..."
fi

cp -r "${PROJECT_ROOT}"/config/profiles/* "${CONFIG_DIR}/profiles/"

echo "[6/6] Installing main launcher..."
cp "${PROJECT_ROOT}/src/lsmf" "${INSTALL_DIR}/"
chmod +x "${INSTALL_DIR}/lsmf"

if [[ -L "${BIN_LINK}" ]]; then
    rm -f "${BIN_LINK}"
fi
ln -s "${INSTALL_DIR}/lsmf" "${BIN_LINK}"

echo ""
echo "╔════════════════════════════════════════════════════════════════╗"
echo "║   Installation Complete!                                      ║"
echo "╠════════════════════════════════════════════════════════════════╣"
echo "║   Installation directory: ${INSTALL_DIR}"
echo "║   Configuration: ${CONFIG_DIR}/lsmf.conf"
echo "║   Logs: /var/log/lsmf"
echo "║   Backups: /var/backups/lsmf"
echo "╠════════════════════════════════════════════════════════════════╣"
echo "║   Run 'lsmf' to start the framework                           ║"
echo "║   Run 'lsmf --help' for usage information                     ║"
echo "╚════════════════════════════════════════════════════════════════╝"
echo ""
