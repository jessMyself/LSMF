# Contributing to LSMF

Contributions are welcome, but security claims must remain narrower than the
evidence supporting them.

## Workflow

1. Fork and clone the repository.
2. Create a focused branch.
3. Add or update regression coverage.
4. Run the safe local checks below.
5. Update documentation when behavior or claims change.
6. Open a pull request describing scope, risk, and verification.

Never run live hardening or rollback on a development workstation. Use mocks,
fixtures, or an explicitly disposable VM.

## Safe checks

```bash
bash tests/run_tests.sh
python3 -m unittest discover -s tests -p 'test_*.py'
python3 -m compileall -q desktop lsmf tests
make validate
make shellcheck
bash scripts/check_release_claims.sh
git diff --check
```

If a mandatory check is unavailable, report it as unavailable rather than
passing. Mocks and package inspection do not replace VM evidence for D-Bus,
Polkit, sessions, reboot, installation, hardening, or rollback.

## Code expectations

- Bash scripts use `set -Eeuo pipefail`, quoted variables, `[[ ]]`, meaningful
  errors, and ShellCheck-clean syntax.
- Qt stays unprivileged.
- Privileged behavior uses the existing typed, allowlisted helper boundary.
- Inputs are validated and fixed command boundaries are preserved.
- Mutations are idempotent, backup-first, verified, and exactly recoverable.
- Tests and comments explain security invariants and failure behavior.
- Documentation distinguishes implemented, VM-verified, planned, and
  unsupported capabilities.

See [AGENTS.md](AGENTS.md) and [module development](docs/module-development.md)
for repository-specific conventions.

## Pull requests

Describe:

- the problem and intended behavior;
- files and trust boundaries affected;
- tests added or changed;
- exact commands run and their outcomes;
- unavailable or skipped checks;
- VM image and isolation details when live behavior was exercised;
- documentation and release-claim impact.

Do not attach unsanitized logs, credentials, private keys, personal paths,
hostnames, addresses, VM images, or production configuration.

Security reports belong in the private process described in
[SECURITY.md](SECURITY.md), not a public issue.

Contributions are licensed under the [MIT License](LICENSE).
