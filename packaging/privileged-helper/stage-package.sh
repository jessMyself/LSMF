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

install -d -m 0755 "${staging_root}/usr/libexec"
install -d -m 0755 "${staging_root}/usr/lib/lsmf/lib"
install -d -m 0755 "${staging_root}/usr/lib/lsmf/modules"
install -d -m 0755 "${staging_root}/usr/lib/lsmf/ui"
install -d -m 0755 "${staging_root}/usr/lib/python3/dist-packages/lsmf"
install -d -m 0755 "${staging_root}/usr/share/dbus-1/system-services"
install -d -m 0755 "${staging_root}/usr/share/dbus-1/system.d"
install -d -m 0755 "${staging_root}/usr/share/polkit-1/actions"
install -d -m 0755 "${staging_root}/usr/lib/systemd/system"
install -d -m 0755 "${staging_root}/etc/lsmf/helper"
install -d -m 0700 "${staging_root}/var/lib/lsmf/synthetic-targets"
install -d -m 0700 "${staging_root}/var/backups/lsmf/synthetic"
install -d -m 0700 "${staging_root}/var/backups/lsmf/sysctl"
install -d -m 0700 "${staging_root}/var/log/lsmf"
install -d -m 0700 "${staging_root}/var/lib/lsmf/reports"

install -m 0755 "${script_dir}/lsmf-privileged-helper" "${staging_root}/usr/libexec/lsmf-privileged-helper"
install -m 0755 "${script_dir}/lsmf-read-only-runner" "${staging_root}/usr/libexec/lsmf-read-only-runner"
install -m 0644 "${script_dir}/lsmf-privileged-helper.service" "${staging_root}/usr/lib/systemd/system/lsmf-privileged-helper.service"
install -m 0644 "${script_dir}/org.lsmf.Helper1.service" "${staging_root}/usr/share/dbus-1/system-services/org.lsmf.Helper1.service"
install -m 0644 "${script_dir}/org.lsmf.Helper1.conf" "${staging_root}/usr/share/dbus-1/system.d/org.lsmf.Helper1.conf"
install -m 0644 "${script_dir}/org.lsmf.helper.policy" "${staging_root}/usr/share/polkit-1/actions/org.lsmf.helper.policy"
install -m 0644 "${script_dir}/synthetic-manifest.json" "${staging_root}/etc/lsmf/helper/synthetic-manifest.json"
install -m 0644 "${script_dir}/sysctl-manifest.json" "${staging_root}/etc/lsmf/helper/sysctl-manifest.json"
install -m 0600 "${script_dir}/synthetic-toggle.conf" "${staging_root}/var/lib/lsmf/synthetic-targets/toggle.conf"
install -m 0755 "${repository_root}/src/lsmf" "${staging_root}/usr/lib/lsmf/lsmf"
install -m 0644 "${repository_root}/src/modules/kernel_hardening.sh" "${staging_root}/usr/lib/lsmf/modules/kernel_hardening.sh"
while IFS= read -r source; do
    install -m 0644 "${source}" "${staging_root}/usr/lib/lsmf/lib/$(basename -- "${source}")"
done < <(find "${repository_root}/src/lib" -maxdepth 1 -type f -name '*.sh' -print | sort)
while IFS= read -r source; do
    install -m 0644 "${source}" "${staging_root}/usr/lib/lsmf/ui/$(basename -- "${source}")"
done < <(find "${repository_root}/src/ui" -maxdepth 1 -type f -name '*.sh' -print | sort)

while IFS= read -r source; do
    install -m 0644 "${source}" "${staging_root}/usr/lib/python3/dist-packages/lsmf/$(basename -- "${source}")"
done < <(find "${repository_root}/lsmf" -maxdepth 1 -type f -name '*.py' -print | sort)
