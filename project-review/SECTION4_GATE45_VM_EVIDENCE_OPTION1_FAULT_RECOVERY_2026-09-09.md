# Section 4 Gate 4.5 Option 1 evidence — Fault injection and crash recovery (s0–s5)

## Purpose and scope

This row records the **Option 1 fault-injection / crash-recovery evidence** for
Gate 4.5: real VM fault-injection testing of the privileged helper against the
actual production `SysctlTransactionExecutor`, driven through a
fault-injecting worker wrapper (`gate45-fault-worker.py`) that calls the real,
unmodified executor and only intercepts I/O at defined transaction
checkpoints. Every client request runs through the packaged production path
(D-Bus service, `production_protocol`, `production_dispatcher`,
`ipc_security`, `system_authorization`, protected audit sink) exactly as a
production caller would invoke it.

This satisfies the lifecycle/failure/recovery scenarios in
`docs/privileged-helper-vm-verification.md` (audit-sink and protocol
failures; concurrency, cancellation and timeout; crash and reboot recovery;
backup integrity, apply, verify, and rollback) for the Ubuntu 24.04
test-ready clone. It records scenarios **s0_sanity through s5_after_reboot**
only. The Polkit prompt matrix (**s6_polkit**) is covered by the separate
existing row
`SECTION4_GATE45_VM_EVIDENCE_OPTION1_POLKIT_MATRIX_2026-09-09.md`
(committed as `0c09388`) and is **NOT re-documented here**; its harness-fix
disclosures are referenced, not repeated.

The Option 3 row (`SECTION4_GATE45_VM_EVIDENCE_V3_2026-09-08.md`) explicitly
deferred "fault-injection/crash-recovery scenarios" and "the Polkit prompt
matrix" to a following Option 1 run. This row (s0–s5) plus the s6 row close
that deferral.

## Outcome

All scenarios pass on the final clean runs, with per-sub-case verdicts and
evidence-log line pointers given below:

| Scenario | Final-run verdict | Clean-baseline evidence |
| --- | --- | --- |
| s0_sanity | Pass (one disclosed harness artifact, see s0 row) | serial-s0_sanity.log:881–883 (recorded harness artifact instance), clean condition re-proven by every later BASELINE-OK |
| s1_disconnect | Pass (2/2 sub-cases) | serial-s1_disconnect.log:907, :920 |
| s2_concurrent | Pass | serial-s2_concurrent.log:903 |
| s3_audit | Pass (3/3 failure points behave as specified) | serial-s3_audit.log:901 |
| s4_crash | Pass (5/5 checkpoints) | serial-s4_crash.log:891, :907, :923, :939, :961 |
| s5_reboot + s5_after_reboot | Pass | serial-s5_after_reboot.log:37, :57 |

## Verified inputs, isolation, and base image identity

All hashes below were freshly computed with `sha256sum` on 2026-09-09 at
write time (not carried from any earlier record).

- VM working directory: `vm-gate45/` (external drive,
  private host path). Scenario execution: `bash run-scenario.sh <name>`,
  which forks a **fresh disposable overlay** of the golden test-ready base
  (`disks/ovl-<name>.qcow2` plus a cloned `OVMF_VARS.fd`), boots it with
  `-nic none` and a serial console only, runs the guest-side scenario over
  that serial console, powers the guest off, and deletes the overlay on exit.
- Golden base used by every scenario overlay:
  `disks/lsmf-gate45-testready.qcow2`, SHA-256
  `f0e63809964f928bac538d68ba385342547fcfd12c02513f039164274b828ab3`.
  This matches `evidence/option1-testready-base.sha256` and is the same hash
  the s6 row recorded (unchanged before/after its run). The documented
  sync-gap rebuild from Handoff 1 is already complete and baked into this
  file.
- Vendor-clean provenance disk (original Ubuntu 24.04.4 autoinstall state):
  `disks/lsmf-gate45-vendor-clean-backup.qcow2`, SHA-256
  `b21ee81072ee5becf9d8b168483a0fe2cd2e06724d89fde486d68d7a53dd3a0b`
  (same value recorded in the Option 3 row).
- LSMF package manifest under test:
  `packaging/privileged-helper/sysctl-manifest.json`, SHA-256
  `b5cc1b945808ad1532357fa8f02c7f51e894459cb932835beec0ce2f719e6498`.
  The s0 sanity transcript records the installed guest manifest hash as the
  same value (serial-s0_sanity.log:878).
- Guest identity recorded per boot in the transcripts: s0 boot
  `aca28aa6-d0bf-4eb9-9849-117e16d532fe` (serial-s0_sanity.log:880); the s5
  post-reboot boot id changed to `d14ea8a7-879b-4d6d-8339-edda8827c02e`
  (serial-s5_after_reboot.log:29), proving the guest genuinely rebooted.
- Scenario run windows (UTC, 2026-09-08; host-local UTC-7 same date):
  s0 19:22Z, s1 final run 20:01–20:02Z (earlier harness attempts 19:55–19:58Z,
  see disclosures), s2 final run 21:14Z (earlier attempts 20:04Z and 20:52Z),
  s3 21:15–21:16Z, s4 21:17–21:18Z, s5 21:27Z (pre-reboot) and
  21:31–21:32Z (post-reboot).

## Test-harness-only deviations from a real production install (disclosure)

These are deliberate, disclosed, and none of them alter the helper's own
authorization or execution path:

- **lightdm + a graphical autologin session** running a custom driver script
  (`harness/gate45-driver.sh`) was added SOLELY so the automated tests could
  establish a genuine local+graphical systemd-logind session — the helper
  hard-requires exactly one such session (`lsmf/ipc_security.py`). It is not
  needed by the helper in production (provision.sh installs it and autologs
  in `gatetest` on `tty7/seat0`; serial-s0_sanity.log:884 shows the active
  graphical session).
- **Passwordless sudo for the `gatetest` account**
  (`/etc/sudoers.d/99-gate45-test`) is TEST-ONLY and is used only to drive
  setup/teardown of fault injection from the test scripts. It never bypasses
  the helper's own authorization path; every helper client call is made as
  the unprivileged `gatetest` user through the real Polkit/D-Bus boundary
  (for s0–s5 under the disclosed auto-approve rule below, for s6 with no
  rule at all).
- **Polkit auto-approve rule** `/etc/polkit-1/rules.d/49-gate45-stateful.rules`
  returns YES for `org.lsmf.helper.*` actions requested by `gatetest`, so the
  stateful scenarios (s0–s5) can run unattended. It is explicitly REMOVED
  before s6 (the prompt matrix tests real prompt/deny/timeout behavior with
  the rule absent; the removal is visible in serial-s6_polkit.log:879).
  Production installs never carry this rule.
- **The fault-injecting worker replaces only adapter-level interception
  points.** `swap-worker.sh` temporarily installs `gate45-fault-worker.py` in
  place of the packaged `lsmf.sysctl_worker`, but that wrapper imports and
  runs the real, unmodified `SysctlTransactionExecutor` transaction code and
  only pauses/crashes at the defined checkpoint boundaries (inside-backup,
  after-backup, after-first-write, after-mutation, rollback-mid). The real
  `production_protocol`, `production_dispatcher`, `ipc_security`, and
  `system_authorization` code runs completely unmodified. After every
  scenario the original worker is restored and `dpkg --verify lsmf` proves
  package integrity (`WORKER-RESTORE-VERIFIED`, e.g.
  serial-s1_disconnect.log:922).
- **Mutations target the disposable guest's own managed sysctl state.**
  Applies write `/etc/sysctl.d/99-lsmf-{kernel,network}.conf` and live
  `/proc/sys` values per the packaged manifest inside the disposable clone
  only; every scenario ends by restoring that state and proving it with the
  phase-0 baseline (`BASELINE-OK` lines quoted below).
- **Single-operator run, no independent second reviewer.** The
  privileged-helper verification doc calls for independent second-person
  review; no second operator was available. Same disclosure carried forward
  from the Option 3 row.

## Per-scenario results

Line numbers refer to the evidence logs in
`vm-gate45/evidence/option1/`. For s3, s4, and s5 the
`serial-` and `live-` files are byte-identical (same SHA-256, see artifact
table); for s1 and s2 the `serial-` file is the final clean run while the
`live-` file additionally retains earlier harness-attempt output (see
"Known harness defects").

### s0_sanity — environment and deployment sanity

Purpose: prove the disposable guest is in the expected pre-fault state —
packaged helper installed intact, manifest in place, an active local
graphical session exists, and a first client call works end to end through
that session. (`serial-s0_sanity.log`, run 2026-09-08T19:22Z.)

- Unit state: `unit: inactive / static` — D-Bus-activated unit, not enabled
  at boot (line 876), matching the packaging contract.
- Package integrity: `dpkg --verify lsmf` rc=0 (`dpkg-verify-ok`, line 877).
- Manifest: installed `/etc/lsmf/helper/sysctl-manifest.json` SHA-256
  `b5cc1b94…` == repo `packaging/privileged-helper/sysctl-manifest.json`
  (line 878); modules `['kernel_hardening', 'network_hardening']` (line 879).
- Boot identity recorded: `boot_id` line 880.
- **Baseline check — recorded harness artifact, NOT a product finding:**
  the check emitted `BASELINE-DIFF` for exactly one key,
  `sysctls:kernel.printk: '4 4 1 7' -> '1 4 1 7'` (lines 881–883). The serial
  login helper of the harness at that time ran `sudo dmesg -n 1` to quiet the
  console (lines 872–874), which rewrote `kernel.printk` (a
  manifest-managed key) after the phase-0 baseline capture. This is the
  recorded instance of the disclosed harness defect ("dmesg perturbing
  kernel.printk"); the scenario continued and every subsequent s0 check
  passed. The pristine-baseline condition of this base is demonstrated by the
  `BASELINE-OK` lines of every later scenario (s1–s5 below).
- Graphical session present: `gatetest` active on `seat0`/`tty7` (line 884).
- Client call via the graphical session: one `audit` request through the
  driver FIFO returned
  `{"action":"audit","error":null,"exit_code":0,…,request_id 28fb6d78…,"status":"succeeded","result":{"finding_count":2}}`
  with `CLIENT-RC-0` (lines 885–891).

### s1_disconnect — client disconnect mid-apply (2/2 sub-cases pass)

Purpose (gate spec: peer disconnect during/after authorization must not
execute or must enter a truthful recovery state; recovery-required blocks
further writes until exact rollback). Fault worker sleeps after the durable
backup commit while the client disconnects. (`serial-s1_disconnect.log`,
final run 2026-09-08T20:01–20:02Z.)

- **(a) Hard disconnect (pass):** fault `after-backup` sleep 8s; client
  `apply_module --disconnect-after 4`. Helper reported
  `disconnected-without-reply` (lines 889–890); one worker was live at
  disconnect+grace (line 888), then gone. The follow-up apply was blocked:
  `error.code: "recovery_required"`, `exit_code:1`, `"Exact rollback is
  required"` naming the exact backup (`backup-6fd10cb9-…`, lines 897–899).
  Exact rollback of that marker succeeded: `error:null`, `exit_code:0`,
  `"Exact rollback complete"` (lines 900–901). End state
  `BASELINE-OK` (line 907).
- **(b) Graceful disconnect (pass):** fault `after-backup` sleep 1.5s; client
  disconnect after 1s, within the helper's grace window. Worker received
  SIGTERM within the grace period and stopped cleanly
  (`disconnected-without-reply`, line 914; `worker-gone`); no recovery marker
  was left. End state `BASELINE-OK` (line 920).
- Original worker restored and verified (line 922); scenario end line 923.

### s2_concurrent — overlapping applies serialize (pass)

Purpose (gate spec serialization row: at most one executor during overlap,
unique terminal responses, distinct backups, exact rollback of both).
(`serial-s2_concurrent.log`, final run 2026-09-08T21:14:05–25Z.)

- Overlapping `apply_module` (A, kernel_hardening) and `apply_modules` (B,
  kernel+network) under an `after-backup` sleep fault: worker count during
  overlap was **1** and later **0** (lines 886–887) — at most one executor.
- Both completed with distinct terminal responses and distinct backups:
  A `error:null`, `exit_code:0`, `backup-b8b5f03c-…` (line 890); B
  `error:null`, `exit_code:0`, `backup-34ceb27d-…` (line 891).
- Audit lifecycle tail recorded for the window (lines 892–893) shows bounded
  per-request lifecycle events (`started`/`failed`/`succeeded`/`cancelled`).
- Exact rollback of B then A both succeeded `error:null`, `"Exact rollback
  complete"` (lines 894–897). End state `BASELINE-OK` (line 903).

### s3_audit — protected audit-sink failures (pass, all three failure points)

Purpose (gate spec audit row: pre-start sink failure must prevent ALL
execution including `audit` and `verify_module`; terminal-event write failure
must be reported explicitly and never rewrite an executor success as
unqualified success; bounded records, no secrets). (`serial-s3_audit.log`,
run 2026-09-08T21:15–21:16Z; identical to `live-s3_audit.log`.)

- **Pre-start sink failure (pass):** with the sink path
  `/var/log/lsmf/helper.jsonl` replaced by a directory, `audit` and
  `verify_module` both failed closed before execution with D-Bus
  `org.lsmf.Helper1.Error.internal_error` ("Internal service error") —
  neither action executed (lines 877–879). Sink restored to mode 600
  `root:root` (line 884).
- **Terminal-event write failure (pass):** with the sink mode broken to 644
  mid-flight (line 889), the mutation itself completed but the terminal audit
  write failed; the response reports it explicitly:
  `error.code:"audit_failed"`, `"Terminal audit recording failed"`,
  `status:"failed"`, `exit_code:null` — never rewritten as success
  (line 892, request `a15a60d4-…`). Sink mode restored to 600 (line 893).
- The apply's own backup remained exact and was rolled back cleanly
  `error:null`, `exit_code:0` (lines 894–895). End state
  `BASELINE-OK` (line 901).

### s4_crash — service-process termination at five checkpoints (5/5 pass)

Purpose (gate spec crash row: force termination before executor start /
during backup commit / during mutation / after mutation before verification /
during rollback; each crash must leave either no durable state or an
explicit recovery marker, and further writes stay blocked until exact
rollback of the marker). (`serial-s4_crash.log`, run
2026-09-08T21:17:48–56Z; identical to `live-s4_crash.log`.) Each checkpoint
crashed the worker via `os._exit(137)` at the named adapter boundary.

| Checkpoint | Result | Evidence lines |
| --- | --- | --- |
| inside-backup | Crash before any durable backup: apply failed closed (`executor_failed`), no marker existed, so the follow-up apply ran and its own backup was rolled back exactly. `BASELINE-OK` | 876–891 |
| after-backup | Durable backup + recovery marker existed; apply failed closed, next apply blocked `recovery_required`, exact rollback of the marker succeeded, marker cleared. `BASELINE-OK` | 893–907 |
| after-first-write | Same recovery pattern after the first managed-file write; blocked until exact rollback of the marker. `BASELINE-OK` | 909–923 |
| after-mutation | Same recovery pattern after all mutation writes, before verification. `BASELINE-OK` | 925–939 |
| rollback-mid | Clean apply, then crash mid-rollback: partial restore left a `recovery-…` marker; rolling back that recovery snapshot undid the partial restore, then the original apply backup was rolled back again exactly. `BASELINE-OK` | 941–961 |

Representative responses: crashed applies returned
`error.code:"executor_failed"` with `exit_code:null` (e.g. lines 878, 895,
911, 927, 944); blocked follow-ups returned `recovery_required` with the
exact marker id (e.g. lines 899, 915, 931); every marker rollback returned
`error:null`, `exit_code:0`, `"Exact rollback complete"`.

### s5_reboot + s5_after_reboot — crash, reboot, and recovery (pass)

Purpose (gate spec crash/reboot row: after a guest reboot verify stale-lock
handling, incomplete-transaction detection, audit correlation, manifest
durability, NO automatic rollback claim, continued mutation denial until the
recovery marker is cleared by the approved procedure — plus the spec's
corrupted-runtime-state repeat). (`serial-s5_reboot.log` pre-reboot run
2026-09-08T21:27Z; `serial-s5_after_reboot.log` post-reboot run 21:31Z; both
identical to their `live-` twins.)

- Pre-reboot: crash at `after-backup` → apply failed closed
  (`executor_failed`, line 878); durable recovery marker written
  (`backup-17c1ce4c-…`, line 879); `REBOOT-REQUESTED` (line 881).
- Post-reboot (new `boot_id`, line 29): the marker **persists** across the
  reboot (line 30) — stale-lock/incomplete-transaction detection held.
  `apply_module` was still blocked with `recovery_required`,
  `exit_code:1` — **no automatic rollback claim** (line 33). Exact rollback
  of the persisted marker then succeeded (line 35). `BASELINE-OK` (line 37).
- Corrupted-runtime-state repeat (lines 38–57): a second crash produced
  marker `backup-ccdac285-…` (line 42); the recovery snapshot payload was
  tampered with, breaking the integrity envelope (lines 43–44); rollback of
  the corrupted backup **failed closed** —
  `error.code:"request_rejected"`, `"Request is not eligible"` (line 46);
  apply remained blocked (line 48); after the marker was removed per the
  approved admin procedure (line 49), apply succeeded (line 50) and its
  cleanup rollback succeeded (line 51). Final `BASELINE-OK` (line 57).

## Known harness defects encountered and fixed during testing

These are harness-engineering issues, NOT product findings; the packaged
helper code was not modified for any of them. Earlier-attempt output is
retained inside the `live-s1_disconnect.log` / `live-s2_concurrent.log`
files ahead of each scenario's final clean run.

1. **`backup_id` JSON extraction bug in `scenarios.sh`** (read
   `['backup_id']` instead of `['result']['backup_id']`): rollback steps in
   the two earlier s2 attempts did not execute, leaving the hardened state in
   place, so their baseline checks reported diffs
   (`live-s2_concurrent.log:905`, `:1843`). Already fixed in Handoff 1; the
   final s2 transcript shows correct `result.backup_id` handling with both
   rollbacks succeeding (serial-s2_concurrent.log:894–897).
2. **FIFO EOF / lightdm teardown issue and the PTY/FIFO driver fix**: an
   earlier s1 attempt died at the driver handshake immediately after launch
   (early segment of `live-s1_disconnect.log`); the fix is baked into the
   test-ready base via `harness/gate45-driver.sh`, and all final runs show
   `driver-ready` before any client call.
3. **Absolute-path backing-file bug in the overlay mechanism**: overlay
   creation previously risked a relative backing-file reference; the scenario
   runner now passes the absolute base path
   (`qemu-img create -b "$(pwd)/disks/lsmf-gate45-testready.qcow2" -F qcow2`).
4. **`dmesg` perturbing `kernel.printk` during tests**: the serial login
   helper ran `sudo dmesg -n 1` to quiet the console, mutating a
   manifest-managed sysctl after the phase-0 baseline capture. Recorded
   instance: serial-s0_sanity.log:872–874 causing the single-key
   `BASELINE-DIFF` at lines 881–883 (also visible in an earlier s1 attempt in
   the live log). Once the login helper stopped perturbing printk, every
   final run's baseline check passed (s1–s5 `BASELINE-OK` lines above).
5. **s6-specific harness fixes** (per-command authentication-agent
   registration, `poll_result` echo-noise, `invalid-payload` sentinel,
   `authority-down` masking) are already disclosed in the s6 evidence row and
   are referenced there rather than repeated.

## Overall verdict

Gate 4.5 **Option 1 fault/recovery evidence (s0–s5) passes** on the Ubuntu
24.04 test-ready clone, and the separately recorded **Polkit prompt matrix
(s6) passes** in its own row. Together they close the deferrals the Option 3
row recorded ("Fault-injection / crash-recovery scenarios" and "Polkit
prompt matrix"), satisfying the Section 4 Gate 4.5 row language of
`project-review/consolidated-qt-roadmap.md` (stateful helper scenarios,
reboot-persistent exact recovery, cancellation/disconnect handling) under the
program completion rule — passing mocks never substitutes for VM evidence,
and no mandatory check is silently omitted: the single s0 baseline artifact
is disclosed above with its root cause, and every other sub-case is backed
by the quoted `BASELINE-OK` / expected-block / expected-error evidence lines.

Scope boundaries (unchanged from the s6 and Option 3 rows): this covers
Ubuntu 24.04 only; no Debian, Fedora, Rocky/Alma, Mint, Neon, or Kali
compatibility claim is made; single-operator evidence with no second-person
review; and this document does not itself authorize publication or a
workstation install.

## Evidence artifacts (local, retained on the host)

All files in `vm-gate45/evidence/option1/`, SHA-256 computed
2026-09-09:

| File | SHA-256 |
| --- | --- |
| serial-s0_sanity.log | `1bfdbe8d28919bc29cd9b0801fa786954938ba81d8c59e22dacda0380aee8c4d` |
| serial-s1_disconnect.log | `e8b97bdba8eaab514930dbe61e74055d013992680bffed1599dfe231bd61edee` |
| live-s1_disconnect.log (also retains two earlier harness attempts) | `615b88bc07e933a3b0fd7d62c6d5cdf4954c92f74fb414a70818d81603c74c73` |
| serial-s2_concurrent.log | `5b91f2f3c482b7153736c4f876b4d83fcec535aee4a0e4647523a9a4005121ab` |
| live-s2_concurrent.log (also retains two earlier harness attempts) | `8952d03e756bc0facfd9d9acf3491e4a000153bb3e9c77b3fa0a4f32740e5d45` |
| serial-s3_audit.log / live-s3_audit.log (identical) | `6dd76a035c09babf16f699895120f5817442c01543335b86decae2d3f012ddff` |
| serial-s4_crash.log / live-s4_crash.log (identical) | `40530e5b6c7adbc0768c630a8f89c6893932b4bdcdeb8072c4a2b543637c496e` |
| serial-s5_reboot.log / live-s5_reboot.log (identical) | `a70532f56adcad4fa8deca6858fb3cb5488ee5326ab71675e09e5420c0ac777a` |
| serial-s5_after_reboot.log / live-s5_after_reboot.log (identical) | `c483c97ad0d652dcac2eb7e6c4bb49020410ee49ba2914e330ac7c722d26a290` |

Base/sentinel identity records: `evidence/option1-testready-base.sha256`
records the golden base hash
`f0e63809964f928bac538d68ba385342547fcfd12c02513f039164274b828ab3`, which
matches the fresh `sha256sum` of the test-ready base taken at write time. The
vendor-clean provenance backup
(`disks/lsmf-gate45-vendor-clean-backup.qcow2`) was also freshly hashed and
matches the value the Option 3 row recorded
(`b21ee81072ee5becf9d8b168483a0fe2cd2e06724d89fde486d68d7a53dd3a0b`).
