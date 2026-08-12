# Privileged Helper Disposable-VM Verification

## Status and authorization boundary

This is a future integration-test specification, not an executable runbook and
not authorization to install or invoke the LSMF helper. Every command below is
an illustrative **future/manual command** that may be used only after the
helper, packaging, test image, and exact test run receive separate approval.

Never run this procedure on a workstation, production host, persistent user
environment, or VM containing useful data. Do not adapt it to containers: the
tests require a real init system, system D-Bus, Polkit, login sessions, process
credentials, filesystems, and reboot/crash behavior. Qt privileged controls
remain disabled until the applicable action passes this gate.

## Supported image matrix

Use clean, locally controlled, full-system virtual machines from verified
vendor installation media. The initial required images follow the project's
documented platform families:

| Image | Required test role | Snapshot baseline |
| --- | --- | --- |
| Debian 12, current supported point release | Debian packaging and Polkit baseline | Fresh install, updates pinned and recorded |
| Ubuntu 24.04 LTS, current supported point release | Primary desktop/active-seat case | Fresh desktop install, updates pinned and recorded |
| Fedora, one explicitly selected supported release | RPM/systemd/SELinux variation | Fresh desktop install, updates pinned and recorded |
| Rocky or AlmaLinux, one explicitly selected supported release | Enterprise-RPM variation | Fresh install plus a minimal graphical local seat |

Record ISO URL, vendor checksum, image checksum, package versions, kernel,
virtualization engine/version, firmware mode, filesystem, SELinux/AppArmor
state, locale, and update timestamp. A result applies only to that exact image.
Adding or replacing an image requires a reviewed matrix update.

Create two immutable snapshots per image: `vendor-clean` before adding test
dependencies and `lsmf-test-ready` after dependencies and synthetic fixtures,
but before helper installation. Fork a new disposable clone from
`lsmf-test-ready` for every destructive or fault-injection scenario.

## Isolation and synthetic targets

The VM must use a dedicated virtual disk, private virtual network with no
inbound forwarding, no shared folders, no host clipboard, no USB passthrough,
no host SSH agent, and no mounted user data. Disable outbound networking after
approved packages and artifacts are staged. Transfer artifacts through a
one-time read-only ISO whose checksum is recorded.

All apply, verify, and rollback tests target a test-only helper manifest and
synthetic module executables. Synthetic targets live on the disposable disk
under a fixed test root, model regular files, modes, ownership, service-like
state, failure points, and deterministic output, and never name real SSH,
firewall, PAM, kernel, audit, package-manager, bootloader, or account files.
The helper's production manifest and real LSMF modules are out of scope for
this gate. Fixtures must support: no-op apply, one deterministic mutation,
multi-module dependency order, deliberate failure before/after commit,
bounded long output, timeout, cancellation, and rollback verification.

## Mandatory preflight identity proof

Before any installation, an operator must prove from both the virtualization
control plane and inside the guest that the target is the disposable clone.
The proof is reviewed by a second person and attached to the evidence bundle.
Required evidence includes:

- VM name and unique VM UUID matching the approved test record;
- current snapshot/clone ancestry and dedicated virtual-disk identifiers;
- hypervisor detection, guest machine ID, boot ID, hostname, OS release, and
  root-filesystem device/UUID;
- absence of shared folders, host mounts, forwarded devices, and useful data;
- private network topology and outbound-network-disabled state;
- a clone-specific nonce placed in the image before boot and matching the
  control-plane record.

Any missing, ambiguous, stale, or mismatched value is an immediate stop. The
operator must not override the check by editing the guest identity.

Illustrative commands, **future/manual and guest-only after approval**:

```text
systemd-detect-virt
cat /etc/machine-id
cat /proc/sys/kernel/random/boot_id
findmnt -no SOURCE,UUID,TARGET /
cat /etc/os-release
hostnamectl
```

Hypervisor snapshot and device inspection commands are deliberately omitted
because they are platform-specific; the approved run plan must supply exact,
read-only commands and expected identifiers.

## Future installation and removal sequence

Only an approved packaging artifact may install the helper. Do not copy loose
development files into system locations. The approved future/manual sequence
is: verify artifact checksums and signatures; inspect package contents offline;
install into a fresh clone; verify package ownership; validate static policy,
D-Bus, and systemd definitions; reload service-manager state; then start only
through an authorized IPC request. Do not enable persistent startup unless the
packaging contract requires it.

The future removal sequence is: collect bounded evidence; stop and disable the
test service; remove the package through its package manager; reload service
manager state; prove its bus name, policy, executable, manifests, runtime
state, and test backup state are absent; then restore the snapshot. Uninstall
success never replaces mandatory snapshot restoration.

## Deployment and service checks

Before the first request, verify and record:

- helper, manifest, module entry points, policy, service definitions, and all
  parents are `root:root` and not group/other writable;
- executables are `0755` or stricter, non-secret policy/manifests `0644` or
  stricter, secret/backup state `0600`, state directories `0700`;
- every relevant object is a regular file with no symlink, unexpected hard
  link, unexpected mount, or writable ancestor; no executable has setuid;
- installed hashes match the package manifest and intentional tampering makes
  the helper refuse startup or execution;
- systemd uses the declared absolute executable, minimal fixed environment,
  fixed working directory/umask, closed unnecessary descriptors, bounded
  resources, and the strongest compatible hardening options;
- exactly the expected system-bus name/interface is exposed, with no session-
  bus service, TCP/UDP listener, outbound connection, or network dependency;
- unsafe logging, lock storage, manifest, policy, ownership, or mode causes a
  fail-closed refusal with a bounded audit record where logging is available.

## Peer identity, session, and replay cases

For every case, correlate kernel/system-bus credentials, login session data,
Polkit subject, request ID, parameter digest, audit records, and executor-call
count. The executor count must remain zero for rejected or denied requests.

| Case | Expected result |
| --- | --- |
| Local active graphical user owns the live bus connection | Eligible to reach the action-specific Polkit decision |
| Caller-supplied PID/UID/session fields | Rejected as unknown protocol fields; derived identity unchanged |
| Different UID, PID, or session than the credential-bearing peer | Rejected before execution |
| Inactive local graphical session | Denied/fail closed |
| Remote, SSH, headless, lingering, or no-seat session | Denied/fail closed |
| Ambiguous, unavailable, stale, or transitioning session | Denied/fail closed |
| Bus owner disconnect or unique-name replacement before/during authorization | Authorization invalidated; no new execution |
| Same request ID repeated by same or different peer | Replay rejected, including after denial, completion, and reboot retention window |
| Same ID with changed action or parameters | Rejected; prior authorization is not reusable |
| Cancellation from a different peer/session | Rejected; owner request continues truthfully |
| Qt launched as root | Unsupported; grants no bypass and must not weaken checks |

## Exact Polkit cases

Run each action separately with no helper-side authorization cache:

| Protocol action | Required Polkit action | Prompt/denial proof |
| --- | --- | --- |
| `audit` | `org.lsmf.helper.audit` | Its own prompt; denial/dismissal produces `denied`, zero executor calls |
| `verify_module` | `org.lsmf.helper.verify-module` | Its own prompt for the exact module digest; no apply grant reuse |
| `apply_module` | `org.lsmf.helper.apply-module` | Its own prompt naming only validated display-safe detail |
| `apply_modules` | `org.lsmf.helper.apply-modules` | Its own prompt for the exact bounded list digest; single-apply grant is insufficient |
| `rollback_backup` | `org.lsmf.helper.rollback-backup` | Its own prompt for an exact manifest-resolved backup ID |

For all five, test explicit allow, explicit deny, user dismissal, prompt timeout,
authority unavailable, malformed/indeterminate reply, peer disconnect during
the prompt, and session deactivation between allow and execution. Confirm that
unknown actions, invalid identifiers, extra fields, duplicate IDs, and invalid
backup IDs are rejected without prompting. A grant for any one action must not
authorize any other action or a request with changed parameters.

## Lifecycle, failure, and recovery scenarios

### Audit sink and protocol failures

Make the protected audit sink unavailable before request acceptance, before
the required start event, and at terminal-event write. Pre-start failure must
prevent all execution, including `audit` and `verify_module`. Terminal audit
failure must be reported explicitly and must not rewrite an executor success
as an unqualified success. Verify bounded records for reject, deny, start,
cancel, timeout, failure, and success without secrets or unbounded output.

Send oversized, truncated, non-UTF-8, duplicate-key, wrong-version, wrong-type,
unknown-field, and action-schema-invalid envelopes. Expect a bounded rejection,
no prompt, no executor call, and no service crash.

### Concurrency, cancellation, and timeout

Submit overlapping read and mutating requests from the same and different
eligible peers. Initially all operations must serialize; at most one executor
may run. Confirm fair bounded queue behavior, unique terminal responses, lock
recovery, and no authorization reuse.

Cancel before start, during execution, after the documented commit point, from
the wrong peer, and concurrently with disconnect. Confirm staged process-group
termination, descendant reaping, post-state checks, and exactly one truthful
terminal state. Exercise each fixed action timeout plus the global hard limit;
no caller may choose a timeout. A timed-out or cancelled mutation that cannot
prove consistency must enter recovery-required state and block further writes.

### Crash and reboot recovery

Force service-process termination before executor start, during backup commit,
during mutation, after mutation/before verification, and during rollback.
Power off the disposable VM at the same checkpoints. After service restart or
guest reboot, verify stale-lock handling, incomplete transaction detection,
audit correlation, manifest durability, no automatic claim of rollback, and
continued mutation denial until recovery state is resolved by the approved
procedure. Repeat with corrupted runtime state and a changed boot ID.

### Backup integrity, apply, verify, and rollback

Before mutation, prove backup creation, manifest/file fsync, completeness,
ownership, modes, hashes, target identities, helper/protocol version, module
set, and completion state. Mutation must not start when any proof fails.

For `apply_module` and `apply_modules`, capture target hashes before and after.
Run each apply twice: the second run must be a verified no-op or produce the
same declared state without a duplicate unsafe change. Verify trusted dependency
order, partial failure reporting, the returned backup ID, and automatic rollback
claims against actual restored hashes.

For `verify_module`, prove it does not mutate target, backup, or service state
and reports both compliant and deliberately non-compliant fixtures accurately.
For `rollback_backup`, test exact restoration and post-restore verification,
plus unknown, partial, already-invalidated, incompatible, tampered, symlinked,
hard-linked, mode/owner-invalid, and manifest-changed backup sets. No caller path
may be accepted. A partial or unverified restore is failure and leaves explicit
recovery-required state.

## Evidence bundle

Store evidence outside the disposable guest before restoration, in an approved
test-results location containing no secrets. Each scenario bundle includes:

- immutable scenario ID, image/snapshot identity, artifact hashes, package and
  dependency versions, kernel, policy/service hashes, and test timestamps;
- preflight proof and reviewer sign-off;
- exact future/manual commands actually approved and run, with exit status;
- sanitized request/terminal-response pairs and parameter digests;
- credential/session/Polkit correlation and executor-call counts;
- bounded journal/audit excerpts, service status and hardening output;
- file metadata, package-integrity results, listening-socket/process evidence;
- before/after target and backup hashes, manifests, lock/recovery state;
- cancellation/timeout/crash timeline and descendant-process proof;
- pass/fail decision, deviations, issue links, and restoration evidence.

Redact authentication material and never collect full user configuration,
environment contents, private keys, or unrelated logs. Hashes are evidence,
not substitutes for retaining the approved synthetic fixtures and manifests.

## Pass/fail matrix

| Gate | Pass condition | Automatic fail condition |
| --- | --- | --- |
| Isolation/preflight | Clone, snapshot, devices, network, and guest nonce match reviewed record | Any ambiguity, host sharing, useful data, or workstation identity |
| Packaging/integrity | Exact approved files, ownership, modes, hashes, and clean uninstall | Loose install, writable/symlinked object, setuid, residue |
| Service exposure | Exact system-bus API, hardened service, no network listener/request | Extra API/bus, unsafe environment, listener, network activity |
| Peer/session binding | Only credential-derived active local peer can proceed | Caller identity trusted, stale/remote/inactive subject proceeds |
| Polkit separation | Exact per-action prompt and binding on every request | Umbrella/cached/reused grant or denial executes |
| Validation/replay | Invalid input/replay rejected before prompt/execution | Crash, prompt, execution, or ID reuse accepted |
| Audit | Required bounded records; pre-start sink failure blocks execution | Missing start gate, secrets/unbounded data, hidden terminal failure |
| Serialization | At most one allowed executor; locks recover safely | Mutation race, orphan, deadlock, or unsafe stale-lock clearing |
| Cancel/timeout | Process tree stopped and state truthfully verified | Orphan, false cancellation/rollback, inconsistent state unblocked |
| Crash/reboot | Durable incomplete-state detection and fail-closed recovery | Silent continuation, lost transaction, mutation allowed while unsafe |
| Backup/rollback | Complete durable backup and hash-verified exact restoration | Mutation without backup, path lookup, tamper accepted, partial success |
| Idempotency/verify | Repeat apply stable; verify accurate and non-mutating | Duplicate unsafe change, false compliance, verify mutation |
| Restoration | Evidence exported and clone reverted/deleted after each scenario | Snapshot not restored, guest reused, cleanup merely claimed |

One failed mandatory row fails that action/image combination. A skipped check is
`NOT TESTED`, never a pass. Qt may expose an action only after that action passes
on every currently supported image selected for release and all unresolved
security findings are reviewed.

## Mandatory restoration and stop conditions

After **every** scenario, successful or not: stop the clone, export the bounded
evidence, revert to the named immutable snapshot or delete the clone, prove the
next boot has the baseline disk/snapshot identity and a new boot ID, and record
the restoration in the matrix. Never continue from a mutated guest.

Immediately stop the entire run on suspected workstation targeting, unexpected
mount/device/network access, loss of snapshot provenance, real-system target in
a manifest, audit evidence leakage, helper escape from its allowlist, or an
unexplained privileged process. Preserve only safe evidence, isolate the VM,
and require a new reviewed plan before resuming.
