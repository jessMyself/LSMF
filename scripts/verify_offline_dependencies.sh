#!/usr/bin/env bash

set -Eeuo pipefail

if [[ $# -ne 1 ]]; then
    echo "Usage: $0 ABSOLUTE_DEPENDENCY_DIRECTORY" >&2
    exit 64
fi

dependency_directory="$1"
if [[ "${dependency_directory}" != /* || ! -d "${dependency_directory}" || -L "${dependency_directory}" ]]; then
    echo "dependency directory must be an absolute non-symlink directory" >&2
    exit 64
fi

repository_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)"
manifest="${repository_root}/packaging/debian/ubuntu-noble-offline-deps.sha256"
(cd "${dependency_directory}" && sha256sum -c "${manifest}")

package="${dependency_directory}/libxcb-cursor0_0.1.4-1build1_amd64.deb"
[[ "$(dpkg-deb --field "${package}" Package)" == "libxcb-cursor0" ]]
[[ "$(dpkg-deb --field "${package}" Version)" == "0.1.4-1build1" ]]
[[ "$(dpkg-deb --field "${package}" Architecture)" == "amd64" ]]
dpkg-deb --field "${package}" Depends | grep -Fq 'libxcb-image0'
dpkg-deb --field "${package}" Depends | grep -Fq 'libxcb-render-util0'

echo "Ubuntu Noble offline dependency closure verified"
