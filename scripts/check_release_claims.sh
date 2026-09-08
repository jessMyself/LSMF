#!/usr/bin/env bash

set -Eeuo pipefail

repository_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)"
cd "${repository_root}"

if ! command -v rg >/dev/null 2>&1; then
    echo "ripgrep (rg) is required to run release claim checks; install it first." >&2
    exit 1
fi

failures=0

if rg -n -i \
    --glob '!docs/**' \
    --glob '!project-review/**' \
    --glob '!CHANGELOG.md' \
    --glob '!scripts/check_release_claims.sh' \
    --glob '!website-outline.txt' \
    '(from|import)[[:space:]]+flask|werkzeug|flask-cors|start-web|web[-_]ui' .; then
    echo "Retired browser runtime references remain in active product files." >&2
    failures=$((failures + 1))
fi

if git ls-files | rg '(^|/)(__pycache__|\.pytest_cache)(/|$)|\.py[co]$'; then
    echo "Generated Python cache files are tracked." >&2
    failures=$((failures + 1))
fi

if [[ -d .github/workflows ]]; then
    if rg -n 'continue-on-error:[[:space:]]*true|\|\|[[:space:]]*true' .github/workflows; then
        echo "CI contains a fail-open check." >&2
        failures=$((failures + 1))
    fi
fi

if [[ ${failures} -ne 0 ]]; then
    exit 1
fi

echo "Release claim and repository hygiene checks passed"
