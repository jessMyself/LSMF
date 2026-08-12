#!/usr/bin/env bash

set -Eeuo pipefail

repository_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)"
cd "${repository_root}"

failures=0

if [[ -f Agent.MD ]]; then
    echo "Internal release-excluded path remains: Agent.MD" >&2
    failures=$((failures + 1))
fi

for forbidden_directory in skills/lsmf-project-orchestrator project-review/prompts; do
    if [[ -d "${forbidden_directory}" ]] && \
        find "${forbidden_directory}" -type f -print -quit | grep -q .; then
        echo "Internal release-excluded path remains: ${forbidden_directory}" >&2
        failures=$((failures + 1))
    fi
done

if find project-review -maxdepth 1 -type f \
    \( -name 'HANDOFF_*' -o -name 'AGENT_TASK_*' -o -name '*WORKFLOW*' \) \
    -print -quit | grep -q .; then
    echo "Internal handoff, task, or workflow remains in project-review." >&2
    failures=$((failures + 1))
fi

if rg -n -i --hidden \
    --glob '!.git/**' \
    --glob '!packaging/debian/.wheels/**' \
    --glob '!packaging/debian/.test-tmp/**' \
    --glob '!packaging/debian/.build-test/**' \
    --glob '!packaging/debian/.release-test/**' \
    --glob '!packaging/debian/.ubuntu-deps/**' \
    '(\/home\/[[:alnum:]_.-]+\/|\/Users\/[[:alnum:]_.-]+\/|[A-Z]:\\Users\\|@protonmail\.com|@gmail\.com|@outlook\.com|BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY)' .; then
    echo "Personal path, personal email, or private-key material found." >&2
    failures=$((failures + 1))
fi

if [[ ${failures} -ne 0 ]]; then
    exit 1
fi

echo "Public-tree privacy and internal-record checks passed"
