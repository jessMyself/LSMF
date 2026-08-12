#!/usr/bin/env bash

set -Eeuo pipefail

if [[ $# -ne 1 ]]; then
    echo "Usage: $0 STAGING_ROOT" >&2
    exit 64
fi

staging_root="$1"
if [[ -z "${staging_root}" || "${staging_root}" == "/" || "${staging_root}" != /* ]]; then
    echo "STAGING_ROOT must be an absolute non-root directory" >&2
    exit 64
fi
if [[ ! -d "${staging_root}" || -L "${staging_root}" ]]; then
    echo "STAGING_ROOT must already exist and must not be a symlink" >&2
    exit 64
fi
if [[ -n "$(find "${staging_root}" -type l -print -quit)" ]]; then
    echo "STAGING_ROOT must not contain symlinks" >&2
    exit 64
fi

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
repository_root="$(cd -- "${script_dir}/../.." && pwd -P)"

rm -f -- "${staging_root}/usr/libexec/lsmf-privileged-helper"
rm -f -- "${staging_root}/usr/libexec/lsmf-read-only-runner"
rm -f -- "${staging_root}/usr/lib/systemd/system/lsmf-privileged-helper.service"
rm -f -- "${staging_root}/usr/share/dbus-1/system-services/org.lsmf.Helper1.service"
rm -f -- "${staging_root}/usr/share/dbus-1/system.d/org.lsmf.Helper1.conf"
rm -f -- "${staging_root}/usr/share/polkit-1/actions/org.lsmf.helper.policy"
rm -f -- "${staging_root}/etc/lsmf/helper/synthetic-manifest.json"
rm -f -- "${staging_root}/etc/lsmf/helper/sysctl-manifest.json"
rm -f -- "${staging_root}/var/lib/lsmf/synthetic-targets/toggle.conf"
rm -f -- "${staging_root}/usr/lib/lsmf/lsmf"
rm -f -- "${staging_root}/usr/lib/lsmf/modules/kernel_hardening.sh"
while IFS= read -r source; do
    rm -f -- "${staging_root}/usr/lib/lsmf/lib/$(basename -- "${source}")"
done < <(find "${repository_root}/src/lib" -maxdepth 1 -type f -name '*.sh' -print | sort)
while IFS= read -r source; do
    rm -f -- "${staging_root}/usr/lib/lsmf/ui/$(basename -- "${source}")"
done < <(find "${repository_root}/src/ui" -maxdepth 1 -type f -name '*.sh' -print | sort)
while IFS= read -r source; do
    rm -f -- "${staging_root}/usr/lib/python3/dist-packages/lsmf/$(basename -- "${source}")"
done < <(find "${repository_root}/lsmf" -maxdepth 1 -type f -name '*.py' -print | sort)

for directory in \
    "${staging_root}/usr/lib/python3/dist-packages/lsmf" \
    "${staging_root}/etc/lsmf/helper" \
    "${staging_root}/var/lib/lsmf/synthetic-targets" \
    "${staging_root}/var/backups/lsmf/synthetic" \
    "${staging_root}/var/backups/lsmf/sysctl"; do
    rmdir --ignore-fail-on-non-empty -- "${directory}"
done

for directory in \
    "${staging_root}/usr/lib/lsmf/modules" \
    "${staging_root}/usr/lib/lsmf/lib" \
    "${staging_root}/usr/lib/lsmf/ui" \
    "${staging_root}/usr/lib/lsmf"; do
    rmdir --ignore-fail-on-non-empty -- "${directory}"
done
