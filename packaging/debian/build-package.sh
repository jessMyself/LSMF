#!/usr/bin/env bash

set -Eeuo pipefail

usage() {
    echo "Usage: $0 --output ABSOLUTE_DIRECTORY [--version VERSION] [--wheel-dir ABSOLUTE_DIRECTORY]" >&2
}

output_directory=""
version="0.4.0~rc1"
wheel_directory=""
while [[ $# -gt 0 ]]; do
    case "$1" in
        --output)
            [[ $# -ge 2 ]] || { usage; exit 64; }
            output_directory="$2"
            shift 2
            ;;
        --version)
            [[ $# -ge 2 ]] || { usage; exit 64; }
            version="$2"
            shift 2
            ;;
        --wheel-dir)
            [[ $# -ge 2 ]] || { usage; exit 64; }
            wheel_directory="$2"
            shift 2
            ;;
        *)
            usage
            exit 64
            ;;
    esac
done

if [[ -z "${output_directory}" || "${output_directory}" != /* || "${output_directory}" == "/" ]]; then
    echo "--output must name an absolute non-root directory" >&2
    exit 64
fi
if [[ ! "${version}" =~ ^[0-9][0-9A-Za-z.+:~-]*$ ]]; then
    echo "Invalid Debian package version" >&2
    exit 64
fi
if ! command -v dpkg-deb >/dev/null 2>&1; then
    echo "dpkg-deb is required" >&2
    exit 69
fi

script_directory="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
repository_root="$(cd -- "${script_directory}/../.." && pwd -P)"
if [[ -z "${wheel_directory}" ]]; then
    wheel_directory="${script_directory}/.wheels"
fi
if [[ "${wheel_directory}" != /* || ! -d "${wheel_directory}" || -L "${wheel_directory}" ]]; then
    echo "--wheel-dir must name an existing absolute non-symlink directory" >&2
    exit 66
fi
(cd "${wheel_directory}" && sha256sum -c "${script_directory}/pyside6-wheels.sha256")
mkdir -p -- "${output_directory}"
build_root="$(mktemp -d -p "${output_directory}" .lsmf-build.XXXXXX)"
trap 'rm -rf -- "${build_root}"' EXIT
package_root="${build_root}/lsmf-privileged-helper"
build_epoch="${SOURCE_DATE_EPOCH:-0}"
if [[ ! "${build_epoch}" =~ ^[0-9]+$ ]]; then
    echo "SOURCE_DATE_EPOCH must be a non-negative integer" >&2
    exit 64
fi
mkdir -m 0755 -- "${package_root}"

"${repository_root}/packaging/privileged-helper/stage-package.sh" "${package_root}"

# Synthetic targets belong to the earlier disposable-VM gate, not the release payload.
rm -f -- \
    "${package_root}/etc/lsmf/helper/synthetic-manifest.json" \
    "${package_root}/var/lib/lsmf/synthetic-targets/toggle.conf"
rmdir --ignore-fail-on-non-empty -- "${package_root}/var/lib/lsmf/synthetic-targets"
rmdir --ignore-fail-on-non-empty -- "${package_root}/var/backups/lsmf/synthetic"

install -d -m 0755 "${package_root}/DEBIAN" "${package_root}/usr/share/doc/lsmf-privileged-helper"
install -d -m 0755 \
    "${package_root}/opt/lsmf/app/desktop" \
    "${package_root}/opt/lsmf/app/config/profiles" \
    "${package_root}/opt/lsmf/app/src/modules" \
    "${package_root}/opt/lsmf/qt" \
    "${package_root}/usr/bin"
for source in "${repository_root}"/desktop/*.py; do
    install -m 0644 "${source}" "${package_root}/opt/lsmf/app/desktop/$(basename -- "${source}")"
done
install -m 0644 "${repository_root}/config/lsmf.conf" "${package_root}/opt/lsmf/app/config/lsmf.conf"
for source in "${repository_root}"/config/profiles/*.conf; do
    install -m 0644 "${source}" "${package_root}/opt/lsmf/app/config/profiles/$(basename -- "${source}")"
done
for source in "${repository_root}"/src/modules/*.sh; do
    install -m 0644 "${source}" "${package_root}/opt/lsmf/app/src/modules/$(basename -- "${source}")"
done
install -m 0755 "${script_directory}/lsmf-desktop" "${package_root}/usr/bin/lsmf-desktop"
while IFS= read -r wheel; do
    /usr/bin/python3 -m zipfile -e "${wheel_directory}/${wheel}" "${package_root}/opt/lsmf/qt"
done < <(awk '{print $2}' "${script_directory}/pyside6-wheels.sha256")
find "${package_root}/opt/lsmf/qt" -type d -exec chmod 0755 {} +
find "${package_root}/opt/lsmf/qt" -type f -exec chmod 0644 {} +
sed "s/@VERSION@/${version}/g" "${script_directory}/control.in" > "${package_root}/DEBIAN/control"
chmod 0644 "${package_root}/DEBIAN/control"
install -m 0755 "${script_directory}/postinst" "${package_root}/DEBIAN/postinst"
install -m 0755 "${script_directory}/prerm" "${package_root}/DEBIAN/prerm"
install -m 0755 "${script_directory}/postrm" "${package_root}/DEBIAN/postrm"
install -m 0644 "${repository_root}/docs/privileged-helper.md" \
    "${package_root}/usr/share/doc/lsmf-privileged-helper/privileged-helper.md"
install -m 0644 "${repository_root}/LICENSE" \
    "${package_root}/usr/share/doc/lsmf-privileged-helper/copyright"

if find "${package_root}" -type l -print -quit | grep -q .; then
    echo "Package payload must not contain symlinks" >&2
    exit 1
fi
if find "${package_root}" -xdev -type f -perm /6000 -print -quit | grep -q .; then
    echo "Package payload must not contain setuid or setgid files" >&2
    exit 1
fi
if find "${package_root}" -xdev -perm /022 -print -quit | grep -q .; then
    echo "Package payload must not contain group- or world-writable objects" >&2
    exit 1
fi

while IFS= read -r -d '' payload_path; do
    touch -h -d "@${build_epoch}" -- "${payload_path}"
done < <(find "${package_root}" -xdev -print0)

artifact="${output_directory}/lsmf_${version}_amd64.deb"
SOURCE_DATE_EPOCH="${build_epoch}" dpkg-deb --root-owner-group -Zgzip --build "${package_root}" "${artifact}"
sha256sum "${artifact}"
