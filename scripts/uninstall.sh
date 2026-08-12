#!/usr/bin/env bash

set -Eeuo pipefail

INSTALL_DIR="/opt/lsmf"
CONFIG_DIR="/etc/lsmf"
BIN_LINK="/usr/local/bin/lsmf"
LOG_DIR="/var/log/lsmf"
BACKUP_DIR="/var/backups/lsmf"
LIB_DIR="/var/lib/lsmf"

echo "╔════════════════════════════════════════════════════════════════╗"
echo "║   Linux Security Management Framework (LSMF) Uninstaller     ║"
echo "╚════════════════════════════════════════════════════════════════╝"
echo ""

if [[ $EUID -ne 0 ]]; then
    echo "Error: This uninstaller must be run as root"
    exit 1
fi

read -r -p "Remove LSMF? This will NOT remove backups or logs. [y/N] " response
if [[ ! "${response}" =~ ^[Yy]$ ]]; then
    echo "Uninstall cancelled"
    exit 0
fi

echo "[1/5] Removing binary link..."
rm -f "${BIN_LINK}"

echo "[2/5] Removing installation directory..."
rm -rf "${INSTALL_DIR}"

echo "[3/5] Removing configuration..."
read -r -p "Remove configuration files? [y/N] " response
if [[ "${response}" =~ ^[Yy]$ ]]; then
    rm -rf "${CONFIG_DIR}"
else
    echo "   Keeping configuration files..."
fi

echo "[4/5] Cleaning up data directories..."
read -r -p "Remove logs? [y/N] " response
if [[ "${response}" =~ ^[Yy]$ ]]; then
    rm -rf "${LOG_DIR}"
else
    echo "   Keeping logs in ${LOG_DIR}"
fi

read -r -p "Remove backups? [y/N] " response
if [[ "${response}" =~ ^[Yy]$ ]]; then
    rm -rf "${BACKUP_DIR}"
else
    echo "   Keeping backups in ${BACKUP_DIR}"
fi

echo "[5/5] Removing library data..."
read -r -p "Remove rollback and report data? [y/N] " response
if [[ "${response}" =~ ^[Yy]$ ]]; then
    rm -rf "${LIB_DIR}"
else
    echo "   Keeping data in ${LIB_DIR}"
fi

echo ""
echo "╔════════════════════════════════════════════════════════════════╗"
echo "║   Uninstallation Complete!                                    ║"
echo "╚════════════════════════════════════════════════════════════════╝"
echo ""
