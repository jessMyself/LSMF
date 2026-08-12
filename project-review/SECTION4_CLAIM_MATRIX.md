# Section 4 product-claim matrix

| Surface or claim | Status | Release statement |
|---|---|---|
| Graphical interface | Implemented | PySide6/Qt Widgets is the only graphical interface. |
| Browser/HTTP interface | Removed | No Flask, browser launcher, or HTTP product surface is retained. |
| CLI modules | Implemented, not release-verified | SSH, firewall, network, and kernel scripts exist; broad live behavior still requires disposable-system evidence. |
| Qt audit | Implemented and previously VM-tested | Typed read-only audit through the helper. |
| Qt verification | Implemented and previously VM-tested | Exactly `kernel_hardening` verification. |
| Qt apply | Implemented and previously VM-tested | Exactly kernel apply or ordered kernel-plus-network apply. |
| Qt rollback | Implemented and previously VM-tested | One exact eligible backup ID with durable recovery enforcement. |
| Mutable Qt Cancel | Limited/disabled | Deferred same-connection terminal ordering is unresolved; do not claim interactive cancellation. |
| Configuration editor | Implemented | Only typed user/project files; installed `/etc/lsmf` remains read-only to Qt. |
| Profiles | Preview plus explicit CLI selection | Three repository profiles; Qt does not apply a profile automatically. |
| Terminal menu | Legacy/limited | Planned entries are labelled; it is not the primary release interface. |
| CIS scanner | Planned | No detailed CIS scanner is implemented. |
| Filesystem/PAM/auditd/AIDE/malware modules | Planned | Not part of the implemented module inventory. |
| Helper source checkout | Inactive | Checkout does not install, register, enable, or start the helper. |
| Recorded Gate 4.5 Debian package | Ubuntu-tested historical candidate | The exact recorded amd64 archive contains Qt, pinned PySide6, and the helper; offline installation, packaged Qt/helper scenarios, and removal passed the bounded Ubuntu 24.04 row. |
| Current package builder output | Replacement VM row required | Publication metadata and third-party notices changed the archive after Gate 4.5. Source checks and package inspection do not transfer the recorded artifact's VM result. |
| Ubuntu 24.04 | Evidence-bearing target for recorded artifact | The recorded package passed its isolated offline Gate 4.5 row; a newly built archive requires replacement verification, and no result transfers to another distribution. |
| Debian, Fedora, Rocky/Alma, Mint, Neon, Kali | Unverified targets | No support claim until an applicable artifact and mandatory image matrix pass. |
| Production readiness | Not achieved | The recorded Ubuntu package row passed, but current-package verification, public-release closure, broader compatibility, and production validation remain. |

## Configuration reconciliation

The canonical configuration retains implemented engine and interface settings.
Unimplemented filesystem feature flags and the unimplemented CIS scan default
were removed. Some retained generic settings are consumed only by the legacy
Bash engine; their presence does not grant Qt or helper capabilities.

## Known release blockers

1. The same-connection mutable-cancellation defect remains unresolved and Qt
   Cancel stays disabled.
2. Publication metadata changed the package after the recorded Gate 4.5 row;
   current builder output needs a replacement Ubuntu 24.04 VM row.
3. No other distribution has package-specific evidence.
