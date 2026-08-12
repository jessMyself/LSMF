# LSMF Project Audit

## Current assessment

LSMF has a tested Qt/configuration foundation and a bounded Ubuntu 24.04
release-candidate package row, but it is not production ready. The graphical
browser surface and its unauthenticated privileged mutation path have been
removed. The Qt application remains unprivileged.

## Confirmed gaps

- Mutable Qt Cancel remains disabled because same-connection terminal ordering
  is unresolved.
- Only SSH, firewall, network, and kernel module scripts exist; additional
  module families remain plans.
- Only Ubuntu 24.04 has package-specific VM evidence; supported-distribution
  claims require separate applicable artifacts and recorded image rows.
- Production use, workstation installation, and public release remain outside
  the verified boundary.

## Security boundary

Do not run live hardening or rollback on the workstation. Keep Qt unprivileged.
Use mocks first and an explicitly approved disposable VM for helper and mutation
testing. No HTTP control surface is part of the architecture.

## Authoritative release status

Follow the four sections and current completion state in
`project-review/consolidated-qt-roadmap.md`. The bounded Ubuntu 24.04 package
row is recorded separately; unsupported distributions remain unverified.
