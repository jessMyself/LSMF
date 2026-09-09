# Consolidated Qt Roadmap

## Established foundation

LSMF has a repaired test harness, canonical non-executable configuration,
truthful Qt read services, typed project-file editing, module/profile discovery,
Gate-1 mock models, a strict Gate-2 production envelope, trusted-manifest and
protected-audit primitives, system-bus credential and libsystemd session
adapters, synchronous and nonblocking fixed-argv Polkit adapters, an uninstalled
deny-all D-Bus service, a
manifest-only synthetic filesystem executor with backup/recovery primitives,
mock-tested serialized dispatcher with cancellation/timeout/audit lifecycle,
an isolated bounded synthetic worker adapter, a source-level production
composition root, inactive package-tree staging/removal artifacts, and a
disposable-VM verification specification. Partial live VM evidence now covers
packaged D-Bus activation, graphical-session identity, per-action Polkit,
rejection before authorization, synthetic apply/verify/exact rollback,
same-peer and disconnect cancellation, timeout/forced kill, abrupt crash,
durable exact recovery, protected audit, reboot activation, uninstall
preservation, and strict `-nic none` isolation. Live denial, replay,
audit-sink failure, and serialization also passed; the technical Section 1
acceptance matrix is complete. A native distribution package remains future
release work. The browser interface was retired by user decision before
privileged Qt parity; it is not a compatibility target and must not be restored.

The remaining program contains exactly four user-gated sections. Security gates
inside a section remain sequential. A section is complete only when its
acceptance criteria pass and the user approves continuation.

## Section 1 — Disposable-VM helper integration

**ID and priority:** LSMF-012, P0

**Objective:** Build and verify production IPC, credential/session, Polkit,
trusted-policy, protected-audit, and synthetic-executor adapters exclusively in
an approved disposable Linux VM.

**Scope:**

- Select and checksum one initial VM image.
- Prove the target is disposable and is not the workstation.
- Install helper artifacts only inside the clone.
- Implement system-bus credential binding and session resolution.
- Implement exact per-action authorization and protected audit recording.
- Use only a root-owned trusted manifest and synthetic targets.
- Exercise rejection, replay, disconnect, denial, audit failure, serialization,
  cancellation, timeout, crash recovery, installation, and removal cases.
- Export bounded evidence and restore or delete the clone.

**Exclusions:** Real LSMF modules or targets, workstation installation, Qt
privileged controls, production deployment, and claims beyond the tested image.

**Dependencies:** Existing Gate-1 models and specifications; QEMU/KVM or another
explicitly selected hypervisor; fresh authorization before VM mutation.

**Acceptance criteria:** Every mandatory Gate-2 row passes on synthetic targets;
rejected requests produce no executor call; no network listener exists;
ownership and modes are correct; evidence is exported; the VM is restored; Qt
actions remain unavailable.

**Status:** Technical acceptance criteria passed on 2026-08-07. Evidence is in
`project-review/SECTION1_VM_EVIDENCE_2026-08-07.md`. Section 2 was explicitly
approved and started on 2026-08-07.

## Section 2 — Qt audit and verification

**ID and priority:** LSMF-013, P0

**Objective:** Add truthful Qt audit and exactly one implemented-module
verification action through the verified helper boundary.

**Scope:**

- Make CLI/module verification functional and aggregate failures correctly.
- Add typed helper actions for audit and one-module verification.
- Test with mocks and synthetic VM targets before connecting Qt.
- Add exact confirmation, progress, cancellation, bounded output, denial/error
  states, terminal results, and report refresh.

**Exclusions:** Apply, installed-configuration mutation, rollback, bulk module
execution, workstation audit, or broad authorization caching.

**Dependencies:** Section 1 and functional module verification.

**Acceptance criteria:** Audit and one-module verification pass mock and approved
VM tests; denial, cancellation, timeout, and error states are truthful; target
hashes prove verification is non-mutating; Qt remains unprivileged.

**Status:** Complete as of 2026-08-07. Source-mode CLI verification now
selects and aggregates module verification without running apply entry points.
A fixed-command read-only process adapter has mock coverage for typed audit,
one allowlisted `kernel_hardening` verification, failure, cancellation, and the
production dispatcher authorization/audit lifecycle. The Qt workflow has mock
coverage for exact confirmation, running/cancellation state, bounded terminal
output, denial details, and report refresh. A strict unprivileged D-Bus client
validates the fixed `Submit`/`Cancel` endpoint and matching typed replies. A
Qt-safe background bridge now wires that client into the default desktop while
keeping cancellation on the same bus connection and delivering terminal state
back on the GUI thread. The inactive package tree now selects a fixed
Section 2 composition and stages only one real-module runner entry point:
`audit` or `verify kernel_hardening`. The hardened service grants write access
only to its runtime, log, and report paths. Live isolated-VM tests passed
unknown/apply rejection, Polkit denial, successful and failing verification,
successful typed audit/report generation, bounded timeout, reset/relaunch, and
uninstall. The final six sysctl values matched baseline and the powered-off
QCOW2 passed `qemu-img check`. A checksum-verified cancellation follow-up fixed
worker process-group termination and live-proved descendant removal, but the
same-connection terminal result still becomes `timed_out` after Cancel returns
`accepted:true`. Mutable Qt Cancel therefore remains disabled and is not a
release capability.

## Section 3 — Qt apply and rollback

**ID and priority:** LSMF-014, P0

**Objective:** Add verified Qt single-module apply, explicitly bounded
multi-module apply, and exact backup rollback.

**Scope:**

- Repair CLI profile/module selection used by explicit apply requests.
- Use installed trusted manifests to define allowed actions and ordering.
- Require a durable validated rollback point before mutation.
- Implement exact backup-ID rollback with integrity and eligibility checks.
- Test idempotency, partial failure, cancellation, timeout, concurrency,
  crash/reboot recovery, and rollback on synthetic VM targets.
- Show exact modules or backup IDs, confirmation, progress, terminal evidence,
  and recovery-required states in Qt.

**Exclusions:** Caller-supplied paths, commands, packages, services, or
unmanifested modules; workstation hardening; unsupported systems; silent
recovery claims.

**Dependencies:** Sections 1 and 2; working CLI selection; approved manifests
and disposable snapshots.

**Acceptance criteria:** Repeat apply is idempotent; backup failure prevents
mutation; exact rollback restores verified hashes; uncertain states block
further mutation; each action has distinct authorization and audit evidence;
every VM scenario restores cleanly.

**Status:** Source Gates 3.3 through 3.7 complete as of 2026-08-09. A separate
version-2 command-free manifest fixes the single action to `kernel_hardening`
and the only multi action to exact order `kernel_hardening`, then
`network_hardening`. The transaction snapshots exact managed-file
existence/content/metadata plus 46 runtime sysctl values, validates the durable
backup before mutation, restores exactly or enters a one-backup recovery
lockout, and runs behind a fixed subprocess boundary. The combined helper
retains Section 2 audit/verification and distinct per-action Polkit/audit
lifecycle. Qt exposes exact confirmations and backup IDs while mutable Cancel
remains disabled. Source, temporary-root, subprocess, packaging, and Qt tests
pass. Gate 3.8 installation, strict rejection, and authorization preflight ran
in the isolated VM without mutation. It exposed that `PrivateNetwork=yes` hid
required network sysctls and could not target the guest network namespace; the
unit now uses `PrivateNetwork=no` while retaining
`RestrictAddressFamilies=AF_UNIX`. The corrected retry passed single/repeat and
ordered multi apply plus several rollbacks, but exact first-baseline rollback
failed because `kernel.unprivileged_bpf_disabled=1` is also irreversible. The
helper/drop-ins are uninstalled and the guest is powered off, but that runtime
value remains divergent. The approved 46-key correction passes two complete
source aggregates and excludes both confirmed irreversible keys. A fresh
vendor-clean clone used an approved one-time offline recovery rule with exact
script-only sudo access; unrelated sudo remained denied. Strict rejection,
single/repeat apply and rollback, ordered multi apply and rollback, exact
46-value/file baseline restoration, backup-first failure, uninstall, and rule
removal passed. The VM is powered off and image-clean. A boot-attached
checksum-recorded harness proved exact restoration
after a mid-write exception, recovery lockout after an abrupt worker exit, and
exact marked rollback to the full baseline; it was then byte-restored,
uninstalled, and powered off with an image-clean result. Post-backup timeout
and external forced kill now pass in valid isolated runs. The forced-kill
result preserved its exact recovery ID, the helper stayed available, wrong-ID
rollback was rejected, exact rollback restored baseline, and powered-off
closure was image-clean. Earlier v4/v5 disconnects were excluded harness
failures caused by a literal worker `pgrep` mismatch. A final fresh isolated
clone then passed client disconnect, single-worker serialization, typed
audit-sink failure with exact recovery, persisted reboot lockout, wrong-ID
rejection, exact reboot recovery, uninstall, authorization removal, and
powered-off image integrity. Gate 3.8 is complete. Gate 3.9 then passed two
220-test source aggregates, Bash/static validation, truthful documentation
review, and whole-worktree commit planning. LSMF-014 was committed as
`0da0527`, `c616ba9`, and `291cc07`; consolidated VM evidence is retained in
`SECTION3_VM_EVIDENCE_2026-08-09.md`.

## Section 4 — Release verification

**ID and priority:** LSMF-015, P1

**Objective:** Reconcile product claims and establish release-quality build,
test, packaging, and compatibility evidence for the Qt-only product.

**Scope:**

- Confirm no browser runtime, dependency, launcher, or HTTP listener remains.
- Reconcile module inventory, profiles, feature toggles, terminal placeholders,
  and supported-platform statements.
- Add CI gates for Bash, Python, headless Qt, protocol/security, packaging, and
  non-destructive integration tests.
- Test installers and the supported VM compatibility matrix.
- Produce migration and release notes.

**Exclusions:** New product features, unsupported-platform engines, unverified
module claims, and destructive tests outside disposable VMs.

**Dependencies:** Sections 2 and 3; module-claim reconciliation and CI work may
be prepared earlier when independent.

**Acceptance criteria:** The repository remains Qt-only; every retained outcome
is implemented and documented truthfully; CI passes; approved VM checks pass;
installation and startup documentation is current; the final diff contains no
unrelated user work.

**Status (2026-08-11):** Gates 4.0 through 4.4 completed their approved source
work. The corrected Debian-family Qt/helper Gate 4.5 candidate then passed the
bounded isolated Ubuntu 24.04 Gate 4.5 row: offline install/reinstall, packaged
Qt smoke, remaining helper stateful scenarios, reboot-persistent exact
recovery, uninstall, clean shutdown, and powered-off image integrity. Other
distributions and Gate 4.6 source-publication closure remain open. Publication
metadata later changed the archive, so current builder output needs a
replacement Ubuntu VM row before binary release.

**Update (2026-09-09):** the replacement Ubuntu VM row is complete. The Gate
4.5 Option 1 fault-injection/crash-recovery evidence (s0–s5) is recorded in
`SECTION4_GATE45_VM_EVIDENCE_OPTION1_FAULT_RECOVERY_2026-09-09.md` and the
Polkit prompt matrix (s6) in
`SECTION4_GATE45_VM_EVIDENCE_OPTION1_POLKIT_MATRIX_2026-09-09.md`, both passing
on the Ubuntu 24.04 test-ready clone. Mutable Qt Cancel is re-enabled
(commit `b056b8b`) now that same-connection cancellation has live evidence;
Cancel enablement is derived from whether an action is running and mutation
actions return the same cancellable handle as read-only actions.

**Update (2026-09-09, later):** Gate 4.6 source-publication closure is
complete. The public GitHub repository carries the sanitized history of this
snapshot (internal handoffs and operator host paths excluded), with CI green
on the published commit, CodeQL passing with no open findings, secret
scanning and push protection enabled, private vulnerability reporting
enabled, and `main` protected (pull requests with a required passing
`source-and-security` check and review, no force pushes or deletions). The
repository publishes source only; no binary is published as VM-verified, and
the recorded-package/replacement-VM-row statements above remain unchanged.

## Program completion rule

Passing mocks never substitutes for VM evidence. A skipped mandatory check is
`NOT TESTED`. The program is complete only when all four sections meet their
acceptance criteria.
