# Security Policy

## Project status

LSMF is an experimental release candidate, not production-ready software. The
only package-specific VM evidence is a bounded offline Ubuntu 24.04 amd64 row
for the recorded Gate 4.5 artifact. Publication metadata changed the package
after that row, so a newly built archive is not VM-verified. Other
distributions and real workstation installation remain unsupported.

## Reporting a vulnerability

Do not publish suspected vulnerabilities, credentials, exploit details, or
sensitive logs in a public issue.

Use GitHub's private vulnerability-reporting feature for this repository. If
that feature is unavailable, do not disclose technical details in an issue;
wait for the private reporting channel to be restored.

Include, when safe:

- affected commit or package version;
- component and entry point;
- reproducible steps using a disposable system;
- expected and observed security boundary;
- whether credentials, privilege escalation, persistent mutation, or data
  exposure may be involved;
- sanitized logs with usernames, paths, hostnames, addresses, tokens, and
  machine identifiers removed.

Reports will be acknowledged when maintainers are available. No response-time
or remediation SLA is currently offered.

## Supported security scope

Security-sensitive behavior must preserve these boundaries:

- Qt remains unprivileged and refuses root launch.
- Privileged operations remain typed, allowlisted, bounded, and separately
  authorized.
- Mutation requires a durable eligible backup before changes begin.
- Uncertain mutation fails closed and permits only exact marked recovery.
- Source checkout does not install or activate privileged components.
- Live hardening and rollback belong only in explicitly disposable systems.

Mutable interactive cancellation is not a supported capability; the Qt Cancel
control remains disabled pending correction and live proof.
