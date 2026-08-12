# Section 1 isolated VM evidence — 2026-08-07

## Outcome

The LSMF-012 synthetic privileged-helper integration gate passed on the approved disposable Ubuntu clone. Every accepted request targeted only the root-owned synthetic fixture. The workstation was never installed or hardened.

This closes the technical acceptance criteria for Section 1. Beginning Section 2 still requires the user's separate approval.

## Environment and retained evidence

- Clone label: `lsmf-helper-gate-20260807` (private host path omitted)
- Vendor-clean baseline: unchanged.
- Retained serial transcript: `evidence/serial.log`
- Final serial SHA-256 before cleanup: `83efad81d426befe48a89df0cf9106b641c7e4199a3151b3a73b2ba5fa6bba4a`
- Retained exact QEMU invocations: `evidence/qemu-*.args.txt`
- Every acceptance boot used `-nodefaults -nic none`; TCP 2222 had no listener.
- Final state: helper uninstalled, clone powered off, QEMU PID file absent, and `qemu-img check` reported no errors.

## Passed scenario matrix

| Scenario | Evidence-backed result |
|---|---|
| Installation and activation | Root-owned fixed package tree installed; system D-Bus activated the hardened systemd service. |
| Credential/session binding | Graphical UID 1000 resolved to session 1/seat0; direct SSH/headless caller failed `identity_unavailable`. |
| Rejection before authorization | Unknown module returned typed `request_rejected` with `authorization_outcome=not_requested`. |
| Live authorization | Allowed verify/apply/rollback reached live Polkit with distinct action IDs. |
| Live denial | VM-only verify policy set `allow_active=no`; live `pkcheck` returned typed `authorization_denied`; no started/executor record. Production policy hash was restored. |
| Replay | First valid unknown-module request was rejected; identical request ID replay failed registration. |
| Same-peer cancellation | Same D-Bus connection received `accepted:true`; Submit returned typed `cancelled`; no mutation or recovery marker. |
| Disconnect cancellation | Client connection closed with EOF; helper recorded typed cancelled lifecycle; no mutation or recovery marker. |
| Serialization | Two concurrent verify requests completed as non-overlapping started/terminal audit pairs in request order. |
| Audit failure | Temporarily unsafe audit-file mode caused `Internal service error` before execution; mode restored to root-owned 0600. |
| Backup-first apply | Apply produced `backup-16a71dab-c0cc-40cb-8405-91e1898c6213` before changing `off\n` to `on\n`. |
| Exact rollback | Exact backup rollback restored `off\n`; post-rollback verify truthfully reported mismatch. |
| Timeout and forced kill | Fixed-UUID VM-only worker stopped after durable backup and before mutation; timeout plus bounded grace failed closed and marked the exact eligible backup. |
| Abrupt worker crash | Separate fixed UUID exited after durable backup and before mutation; parent failed closed and marked exact recovery. |
| Recovery lockout | New apply returned `recovery_required` with the marked backup ID. |
| Exact recovery | Only rollback of the marked eligible ID succeeded and durably cleared the marker. |
| Reboot | Helper remained inactive until D-Bus activation after reboot; rejection and allowed verify behavior remained correct. |
| Uninstall | Installed helper artifacts disappeared; D-Bus returned `ServiceUnknown`; backup and audit hashes were preserved. |

## Fault-injection and diagnostic disclosures

- Timeout and crash used one VM-only `synthetic_executor.py` variant selected by two fixed UUIDs. It stopped or exited only after the real backup was durable and before mutation. It was never added to repository packaging.
- After each injected test, installed production source SHA-256 matched the staged production source before further testing or uninstall.
- Deterministic denial used one VM-only Polkit policy changing only `verify-module` active authorization from `auth_admin` to `no`. Production policy hash matched after restoration.
- Two interactive denial attempts were authorized rather than denied and are unsuccessful test attempts, not denial evidence.
- One initial cancellation fixture used the wrong single-module field and was rejected before registration. The corrected retry passed.
- A temporary approved diagnostic phase used restricted QEMU user networking and loopback-only `127.0.0.1:2222`. Guest key/config were removed, SSH service/socket disabled, and all later/final boots used `-nic none`. Host-side temporary credentials are deleted during closure cleanup.
- An ad-hoc optical copy initially changed only top-level `/etc`, `/usr`, and `/var` owner metadata. They were repaired to `root:root 0755` and repeatedly verified. Package staging itself was not the cause.

## Final source verification

- Repository virtual-environment Python suite: **178 passed, 0 skipped**.
- Bash project suite: **6 passed, 0 failed, 1 skipped**.
- The one unavailable check was ShellCheck because it is not installed.
- Python compilation and `git diff --check`: passed.

## Completion boundary

This evidence verifies only the synthetic Section 1 helper boundary. It does not authorize real hardening modules, privileged Qt controls, workstation execution, or release-readiness claims.
