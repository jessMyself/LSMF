# Section 4 Gate 4.5 Option 1 evidence — Polkit prompt matrix (s6_polkit)

## Outcome

The Gate 4.5 **Polkit prompt matrix** (`s6_polkit` scenario, Option 1 scope)
**passes fully** against the real `auth_admin` policy on the same
test-ready base clone that produced the V3 Option 3 row. All 15 matrix cases
behaved correctly in the final clean run:

- **no-seat (4/4)**: serial (seat-less) subjects are rejected before any
  prompt with `org.lsmf.Helper1.Error.identity_unavailable`.
- **active-seat allow (5/5)**: the correct password at the prompt grants
  authorization; `audit`, `apply_module`, `apply_modules` (grant not reused),
  and `rollback_backup` all completed with `"error":null, exit_code:0`.
  `verify_module` passed the authorization gate and then reported its own
  app-level read-only verification result (`verification_failed`,
  exit_code 1) — deterministic across every run on this hardened guest and
  not an authorization failure.
- **active-seat deny (4/4)**: wrong password, agent dismissed mid-prompt,
  no agent registered, and authority unavailable all correctly deny with
  `authorization_denied` (fail closed).
- **peer disconnect while prompt pending**: helper reports
  `disconnected-without-reply`, apply never executes.
- **invalid payload**: `busctl ... Submit s "not-json"` is rejected with
  `Call failed: Request validation failed` before any prompt is raised.

The V3 row explicitly deferred this matrix to "a following Option 1 run";
this document records that run.

## Harness defect fixed (root cause of the earlier failures)

On polkitd 124 (Ubuntu 24.04), a registered authentication agent
(`pkttyagent`) is matched **only against the exact checked subject
(pid+starttime)** — polkitd never falls back to the subject's login session.
The harness's single long-lived driver-scoped agent (registered once at
login for the driver shell's pid) therefore could never authorize the
short-lived client processes the driver spawns for each check: polkitd
returned `authorization_denied` without ever contacting an agent, so every
active-seat allow case failed even with correct credentials.

Fix (host-side harness only, `vm-gate45/run-s6-polkit.py`):
each backgrounded client command now kills any prior agent and registers a
fresh `pkttyagent --process <client-pid> --fallback` scoped to the exact pid
of the D-Bus-calling process (a `timeout` wrapper is stripped first so the
registered pid is the real client, not the wrapper). Three further harness
defects found while closing out the matrix were fixed in the same file:

1. `active-noagent` (no agent registered) had been defeated by the
   unconditional agent spawn — `drv_submit`/`drv_bg` gained a
   `spawn_agent=False` option used by that negative case.
2. `poll_result` mistook the serial terminal's echo of its own poll command
   for real result content, returning garbage on the first poll whenever the
   result file was not yet written — it now reads only between explicit
   start/end markers.
3. `invalid-payload` captured the driver's `GATE45-DRV-RC: 0` echo line
   instead of the real `busctl` output — it now splits on the same explicit
   sentinel convention used elsewhere in the harness.
4. The authority-down case used `systemctl stop polkit`, but
   `org.freedesktop.PolicyKit1` is D-Bus-activatable
   (`SystemdService=polkit.service`) and silently restarted on the next
   call, making the case racy — it now uses `systemctl mask --now polkit`
   (unmasked and restarted immediately after).

**Product code was not modified.** The packaged LSMF code inside the guest
(`/usr/lib/python3/dist-packages/lsmf/...`) and the harness driver script
(`harness/gate45-driver.sh`, whose PTY/FIFO fix is baked into the test-ready
base) were untouched; only the host-side scenario runner
(`run-s6-polkit.py`, which lives outside this repository) changed.

## Verified inputs and isolation

- VM working directory: `vm-gate45/` (external drive,
  private host path); scenario run via `bash run-scenario.sh s6_polkit`.
- Base disk: `disks/lsmf-gate45-testready.qcow2`, SHA-256
  `f0e63809964f928bac538d68ba385342547fcfd12c02513f039164274b828ab3`
  (unchanged; matches `evidence/option1-testready-base.sha256` before and
  after the run — the golden base was not contaminated).
- Fresh disposable overlay per run (`disks/ovl-s6_polkit.qcow2`,
  `disks/ovl-s6_polkit-VARS.fd`), deleted by `run-scenario.sh` cleanup on
  exit; guest booted with `-nic none` and a serial console only.
- Guest shut down cleanly (`sudo systemctl poweroff --no-wall`); scenario
  runner reported `SCENARIO s6_polkit COMPLETE (guest powered off)`.
- Run window (UTC): 2026-09-09T00:16–00:27Z (host-local equivalent
  2026-09-08 17:16–17:27, UTC-7).

## Evidence artifacts (local, retained on the host)

- `evidence/option1/host-s6_polkit.log` — host-side run log with every
  `CASE` line and the full MATRIX SUMMARY (15/15 cases).
  SHA-256: `d5ab9850041fa14d694c3714db4014f24d1b2b85431d427a34a9ea31edfe3feb`
- `evidence/option1/serial-s6_polkit.log` — guest serial transcript for the
  same run (rule removal/restore, polkitd journal, helper audit lifecycle).
  SHA-256: `b340c6bf1d838f89e0427813dbc286cc3a4e24f006ff3784b7e50fbab250538d`

## Matrix summary (final clean run, 2026-09-09T00:25–00:26Z)

| Case | Observed outcome |
| --- | --- |
| no-seat:audit | dbus-error `identity_unavailable` (denied pre-prompt) |
| no-seat:verify_module | dbus-error `identity_unavailable` (denied pre-prompt) |
| no-seat:apply_module | dbus-error `identity_unavailable` (denied pre-prompt) |
| no-seat:rollback_backup | dbus-error `identity_unavailable` (denied pre-prompt) |
| active-allow:audit | `error:null`, `exit_code:0` |
| active-allow:verify_module | auth succeeded; app-level `verification_failed`, `exit_code:1` |
| active-allow:apply_module | `error:null`, `exit_code:0` |
| active-allow:apply_modules | `error:null`, `exit_code:0` (own prompt, grant not reused) |
| active-allow:rollback_backup | `error:null`, `exit_code:0` |
| active-wrongpw:verify_module | `authorization_denied` (wrong password x3) |
| active-dismiss:audit | `authorization_denied` (agent killed mid-prompt) |
| active-noagent:audit | `authorization_denied` (no agent registered) |
| active-disconnect:apply_module | `disconnected-without-reply` (apply never ran) |
| authority-down:audit | `authorization_denied` (fail closed, authority masked) |
| invalid-payload:submit | `Call failed: Request validation failed` (pre-prompt) |

## Scope boundaries and disclosures

- This row covers the **Polkit prompt matrix only** (scenario `s6_polkit`).
  Fault-injection/crash-recovery scenarios s1–s5 were executed separately on
  2026-09-08 against the same base; their serial/live transcripts are
  retained in the same evidence directory and their outcomes are recorded in
  the working handoffs, not re-verified in this document.
- Single-operator run; no independent second-person review performed
  (same disclosure as V3).
- This does not broaden the supported-platform statement: no Debian,
  Fedora, Rocky/Alma, Mint, Neon, or Kali claims are made, and this document
  does not itself authorize publication or a workstation install.
- The `identity_unavailable` and `unix-group:admin is not valid` journal
  messages are pre-existing, harmless (the `admin` group does not exist on
  this Ubuntu build) and unrelated to the results above.
