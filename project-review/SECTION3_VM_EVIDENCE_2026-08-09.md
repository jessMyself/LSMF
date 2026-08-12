# Section 3 Gate 3.8 VM evidence — complete fault/recovery proof

## Outcome

Gate 3.8 ran only in the retained disposable Ubuntu guest under KVM,
`-nodefaults`, and exact `-nic none`. Installation, ownership/mode checks,
strict request rejection, per-action authorization/audit, backup-first failure,
recovery lockout, reboot recovery, exact marked rollback, uninstall, and final
offline closure were exercised. The guest was restored to the complete captured
runtime/file baseline before uninstall and poweroff.

Gate 3.8 is **COMPLETE**. The corrected 46-key manifest passed the clean-guest
happy path and every approved fault/recovery case. Historical partial and
excluded attempts remain below for provenance; the final replacement-clone
result is authoritative.

## Isolation and closure evidence

- QEMU had no network device, forwarding, host share, SPICE, or USB
  redirection. Guest `ip -brief link` showed loopback only.
- Preflight disk SHA-256:
  `e7c6efb99fde3cf1a79e49ed04f81a68ebd35b240d737ba09e3b0cd9a12132e4`.
- Preflight OVMF SHA-256:
  `d878585ed274c4d8e52b69bbf6b3f8e7a9f528fa99afce30bd27305ab293754e`.
- The older Section 2 closure hashes did not match these fresh preflight
  hashes, so they were treated as historical rather than current evidence.
- Final `qemu-img check`: no errors.
- Final disk SHA-256:
  `37e54e00cc98ea507b40cb260affdce4a4060e2e856fd3109daf9e463fa832e8`.
- Final OVMF SHA-256:
  `53d5785deedda25f85e82b3f93a404409ad77a767f950047370fcbf1b62d4237`.

## Passed live behavior

- All 48 manifest keys existed before mutation; complete values and both
  managed-file states were captured. Baseline evidence SHA-256 was
  `91051f1633925d2ea12896e81ce1cfd4088c3845daa51d635cc36a28c47264bc`.
- Installed files were root-owned with expected modes; helper activation was
  on demand and initially inactive.
- Unknown, reversed-order, duplicate, caller-path, command-like, wrong-backup,
  and malformed requests were rejected. Eligible requests reached their exact
  Polkit action IDs and protected audit lifecycle.
- Backup failure under the original sandbox occurred before mutation and left
  the full baseline exact with no recovery marker.
- Recovery lockout blocked subsequent mutation after uncertain restoration.
- After reboot restored runtime state, exact D-Bus rollback of
  `backup-bcbdde3b-d74d-4f18-ba8b-ed0424f72bfe` succeeded and cleared the
  marker.
- Uninstall left the unit `not-found`, D-Bus returned `ServiceUnknown`, no
  helper/worker process remained, and protected audit plus 12 backup evidence
  files were retained with root-only modes.

## Confirmed defects

### 1. Wrong network namespace

`PrivateNetwork=yes` hid `/proc/sys/net/core/bpf_jit_harden` and could not
target the guest's real network sysctls. The source unit was corrected to
`PrivateNetwork=no` while retaining `RestrictAddressFamilies=AF_UNIX`. Source
verification passed after this correction.

### 2. Exact rollback contract is incompatible with the current manifest

The corrected sandbox reached mutation, but `kernel.printk` is exposed by procfs
with normalized whitespace that does not compare byte-for-byte with the
space-separated manifest value. Apply therefore entered restoration after
other keys had changed.

Restoration then encountered `kernel.kexec_load_disabled`, which changed from
baseline `0` to desired `1`. That transition is one-way for the current boot,
so immediate exact rollback cannot be guaranteed. The recovery marker correctly
remained set. Before reboot the divergent values were:

- `fs.suid_dumpable`: `2` to `0`
- `kernel.core_uses_pid`: `0` to `1`
- `kernel.kexec_load_disabled`: `0` to `1`
- `kernel.perf_event_paranoid`: `4` to `3`
- `kernel.sysrq`: `176` to `0`
- `kernel.unprivileged_bpf_disabled`: `2` to `1`
- `net.core.bpf_jit_harden`: `0` to `2`

Reboot with absent managed drop-ins restored every value to baseline. The exact
marked rollback then succeeded without rewriting already-equal immutable keys.

## Source corrections completed during the gate

- `PrivateNetwork=no` with `RestrictAddressFamilies=AF_UNIX` retained.
- Apply and restore skip writes when the observed value is already exact,
  retaining full final verification. This fixed immutable-but-already-correct
  values without broadening capabilities.
- Regression coverage increased the Python suite to 217 tests; Python, Bash,
  syntax/configuration validation, and `git diff --check` passed. ShellCheck
  remains unavailable.

## Approved correction and retry outcome

The approved correction was implemented:

1. Canonicalize whitespace-only numeric sysctl reads before exact comparison.
2. Remove `kernel.kexec_load_disabled` from the rollback-capable manifest,
   reducing it from 48 to 47 settings.
3. Add regression tests for procfs whitespace normalization and rejection of
   irreversible settings in rollback-capable manifests.
4. Run two source aggregate passes. Both passed 219/219 Python tests; the Bash
   suite passed 8, failed 0, and skipped ShellCheck because it is unavailable.

The retry used the same KVM, `-nodefaults`, exact `-nic none` isolation. Strict
request rejection, single apply, repeat apply, repeat rollback, ordered
kernel-plus-network apply, and multi rollback succeeded. Rolling back the first
kernel backup failed, however, and the final runtime baseline comparison was
false. The retry therefore stopped before the remaining fault matrix.

The newly confirmed cause is `kernel.unprivileged_bpf_disabled=1`. The guest
baseline was `2`; after apply it was `1`, and that value could not be restored
by exact rollback. After helper/drop-in uninstall and reboot it was still `1`.
The guest-side unprivileged post-reboot check then stopped at the expected
permission boundary for `net.core.bpf_jit_harden`, so no broader complete
baseline claim is made.

Closure state after the retry:

- helper and managed drop-ins uninstalled;
- D-Bus activation returned `ServiceUnknown`, unit was `not-found`, no helper
  process remained, and the recovery marker was absent;
- guest powered off cleanly;
- final `qemu-img check` found no errors;
- final disk SHA-256:
  `5df59e5fadb93ae9256618ce838707308cf9c2a6e2395043f5167e09ad1db979`;
- final OVMF SHA-256:
  `64378457f25da6a4fc88815c4ed149c62bfde8a1e9402142aeb96d873d7dfc0c`.

The approved 47-to-46 source correction removed the newly confirmed
irreversible setting and extended the loader regression to reject both known
irreversible keys. Two fresh source aggregates passed 219/219 Python tests;
each Bash run passed 8, failed 0, and skipped ShellCheck because it is
unavailable.

A new working clone was created from the read-only vendor-clean snapshot. The
source snapshot, untouched test-ready copy, and isolated image were byte
identical before cloning (disk SHA-256
`32db4b84bd615bd9fd5902e110cd7c4d0f2bc6ccb6484350309a53aa2ef2d3b7`;
OVMF SHA-256
`e03c868a8070d7aae8af74a39e5b5c5d92d175c627a09a2eca71cc742dd83b52`).
The clone booted under KVM, `-nodefaults`, exact `-nic none`, and the
checksum-recorded 46-key ISO. Before installation, `sudo -n true` returned
`a password is required`. Under the no-password constraint, no credential was
entered and no package, helper, managed file, or sysctl mutation occurred.

The clean clone was powered off. Final `qemu-img check` found no errors. Its
post-boot disk SHA-256 is
`26a7c94d48b9ec5d7a51859a9624d0ef123f8b6488fa723b47a5c2dc3a969ffd`
and OVMF SHA-256 is
`54808e745fad553cbb047952b976e77b60b2ec4bbebd68e5f3c8a51b88abf045`.
The user approved a one-time recovery provisioning workflow. A local Ubuntu
24.04.4 live ISO (SHA-256
`0479e02d64f6d85563d9bee59928fe3ab2bc84258e4a22df173b4d44e4cee43f`)
booted with exact `-nic none`. It mounted only the disposable clone and copied
a narrow sudoers rule from a read-only data ISO. The rule parsed successfully,
was root-owned mode `0440`, and had SHA-256
`babd585bd420f5268caf06464bef81ff7716e660b93a1863f2ba9070f493068a`.
Unrelated `sudo -n true` remained denied.

## Clean-clone 46-key live result

The normal guest boot installed the helper from the checksum-recorded ISO and
captured all 46 runtime keys with no missing key. Baseline evidence SHA-256 was
`528ea716aa587080bbdf61fce5d517821070bcfa6ced7e71d29879878b821045`.
The following passed:

- strict rejection for unknown, reversed, duplicate, caller-path,
  command-like, wrong-backup, and malformed requests;
- distinct authorization/audit for allowed actions;
- single kernel apply, repeat apply, repeat rollback, and first-baseline
  rollback;
- ordered kernel-plus-network apply and exact rollback;
- exact final comparison of all 46 runtime values and both managed files;
- absent recovery marker;
- backup-root failure reported `backup_failed` before mutation, with runtime
  and files still exactly at baseline and no recovery marker.

A data-ISO hot swap while the old ISO remained mounted produced mixed stale
file contents. The affected diagnostic was cancelled without entering a
password. Its backup-failure operations failed before mutation and its cleanup
restored the backup directory. Subsequent unintended happy-path requests still
completed exact rollbacks. No result from the mixed mount is used as evidence
except the independently printed exact baseline and absent-marker checks. The
guest was rebooted with the final ISO mounted from startup before uninstall.

Final uninstall proved the unit `not-found`, D-Bus `ServiceUnknown`, no helper
process, absent recovery marker, and retained root-protected audit/backups. The
temporary sudoers rule was removed; retrying its formerly allowed exact command
returned `a password is required`. The offline guest is powered off and
`qemu-img check` found no errors. Final clone hashes:

- disk:
  `832ea36483ae609be29bb8b8dba591c46697ecb2817797c1b7414e24f7a6ebbf`;
- OVMF:
  `2f42ddf8bbf590001aa3372dc8ed3434f2a38f374fa15863cc79cac62aa8fbe6`.

The offline-installed `python3-dbus-next` dependency remains in this disposable
clone. Gate 3.8 is still **PARTIAL**, not complete. No hot-swapped mounted ISO
may be used for remaining scenarios; every harness must be present from boot
and independently checksum-verified.

## Boot-attached fault-harness result

A second vendor-clean disposable clone ran a checksum-recorded fault harness
from boot-attached read-only media. The ISO SHA-256 was
`926270be103dcbf4492f2e17cec78db943b72ad2bcf93af8d8bd0e40ea080635`.
The guest retained the exact KVM, `-nodefaults`, and `-nic none` isolation. The
temporary sudo rule remained limited to named gate scripts on that read-only
medium; no password was entered.

The harness replaced only the installed guest worker, after preserving its
bytes and SHA-256. The following foundational fault cases passed against the
real 46-key transaction and helper boundary:

- A forced mid-write exception returned `failed` with `apply_failed`, restored
  every runtime value and managed file exactly, and left no recovery marker.
- An abrupt worker exit immediately after durable backup returned `failed`
  with `executor_failed` and created the exact expected recovery marker
  `backup-8431abc8-45d6-4d65-a183-40d14076b242`.
- Exact D-Bus rollback of that marked backup succeeded, restored every runtime
  value and managed file to baseline, and cleared the recovery marker.

Before removal, the production worker was restored byte-for-byte to SHA-256
`d48b6f5b3000efba05715cf83dbd7aa2605093ad3c527455ae126199856ac3eb`.
Uninstall then proved unit `not-found`, D-Bus `ServiceUnknown`, no helper or
worker process, absent recovery marker, and retained root-protected evidence.
The temporary sudo rule was removed. The guest powered off cleanly and final
`qemu-img check` found no errors. Closure hashes are:

- disk:
  `3c5b180254747af70d2db248e4494be474d433c86b4257de547fc1a651eabbf6`;
- OVMF:
  `d68bf04644e2990bf6476e9a61357308a2b86ace85aad03b78042f1106aca2f8`.

Gate 3.8 remains partial. Post-backup timeout, external forced kill,
disconnect, concurrent serialization, audit-sink failure, reboot recovery, and
wrong recovery-ID rejection remain untested against the 46-key manifest.

## Host power-loss transition

The laptop later powered off because its battery was depleted while the
remaining Gate 3.8 matrix was being prepared. The previously active working
clone was not treated as safely suspended or clean. It was preserved for
diagnosis under:

`lsmf-helper-gate-20260809-remaining-interrupted-powerloss` (private host path omitted)

Before preservation, the interrupted clone had no observed running QEMU
process and an offline `qemu-img check` reported no errors. Its diagnostic
hashes were disk
`c10671708270d172f6e5d77fb0eb4a04ec9d6d98299c44c94193994353bf633d`
and OVMF
`9d64f048f8e6b73ab5b11214c6a979b4041c08e7085ac247e8c04713f9248b0d`.
These facts do not make it an approved baseline, and it must not be booted for
the remaining matrix.

A fresh working directory was then initiated from the vendor-clean snapshot at
`lsmf-helper-gate-20260809-remaining` (private host path omitted).
The creation command's final output was lost across context compaction. A
subsequent read-only command intended to verify both directories, fresh hashes,
and `qemu-img check` was aborted after 23.2 seconds. No output from that command
was retained. Fresh-clone existence, completeness, hashes, and image integrity
for that interrupted attempt are therefore **NOT VERIFIED**. Later valid rows
below supersede it; the interrupted attempt remains excluded.

The reboot also removed the temporary staging directory, data ISO, and QEMU
typing helper. They must be regenerated from current checksum-recorded inputs;
no missing `/tmp` artifact is evidence. No additional VM matrix case is claimed
from the interrupted session.

No Section 4 work, workstation mutation, networking, new modules, mutation
Cancel, commits, or sub-agents were authorized or performed.

## Powered-off resume integrity checkpoint

The previously aborted verification command is treated as having no result.
On resume, a new powered-off inspection established the following before any
staging, boot, mount, or mutation:

- no QEMU process referenced either the preserved interrupted directory or the
  fresh `remaining` directory (inspection-command text matches were excluded);
- the interrupted directory remained present and untouched as diagnostic
  evidence;
- the fresh disk SHA-256 was
  `32db4b84bd615bd9fd5902e110cd7c4d0f2bc6ccb6484350309a53aa2ef2d3b7`,
  exactly matching the vendor-clean disk;
- the fresh OVMF variables SHA-256 was
  `e03c868a8070d7aae8af74a39e5b5c5d92d175c627a09a2eca71cc742dd83b52`,
  exactly matching the vendor-clean OVMF variables;
- offline `qemu-img check` reported `No errors were found on the image`
  (`107583/655360`, 16.42% allocated; image end offset `7056195584`).

This establishes the fresh `remaining` directory as the clean powered-off
input for the resumed matrix. It is not evidence for any unrun live case.

## Resumed boot-attached harness

The remaining-matrix harness was rebuilt from current repository bytes in a
fresh temporary staging tree. Bash syntax checks and Python byte-compilation
passed. The staged sudoers rule parsed successfully and was tightened to seven
explicit `/usr/bin/bash` commands on the read-only
`LSMF_SECTION3_CLEAN` medium; it contains no wildcard command or caller path.
The host sandbox emitted an ownership warning for its sandbox-projected
`/etc/sudo.conf`, separately from reporting that the staged rule parsed OK.

The checker now exits nonzero for any 46-key runtime mismatch, managed-file
mismatch, unexpected recovery marker, surviving worker, or concurrent worker
count other than one. The forced-kill and reboot-arm cases also require the
recovery marker to equal the exact backup ID printed by the instrumented worker
after durable backup.

Current input and harness SHA-256 values:

- vendor-clean disk:
  `32db4b84bd615bd9fd5902e110cd7c4d0f2bc6ccb6484350309a53aa2ef2d3b7`;
- vendor-clean OVMF variables:
  `e03c868a8070d7aae8af74a39e5b5c5d92d175c627a09a2eca71cc742dd83b52`;
- Ubuntu recovery ISO:
  `0479e02d64f6d85563d9bee59928fe3ab2bc84258e4a22df173b4d44e4cee43f`;
- `python3-dbus-next_0.2.3-3_all.deb`:
  `52ec9a0f167e9683577c475e8aedd37c18f1db74f3a1ca8b2df2b024f2f4ef31`;
- boot-attached `LSMF_SECTION3_CLEAN` ISO:
  `849f5083063474cf28d96926ec27c71e9c00762221c9ca447ee50a68a715ba7a`;
- explicit sudoers rule:
  `91448ceb2bc5e9e25ddacf81cbf209b4b040bc468af3efa338cd6a68e4810f7c`;
- strict baseline checker:
  `db459dbfbb1c330bba2488e2447da26d60dd60bf369ca4019a498a4b80653308`;
- remaining matrix:
  `d893ce6097a8c7c92b1ae0da8ced2e92786a339dff3893ecb852cf702c4002f3`;
- reboot arm:
  `f9f1bc47df4baf5fb3e29b58a5d986dcb614f4603ea0012df9b15ca393727178`;
- reboot recovery:
  `6fb1ce724d6564a733b08f02f4239f0cf5699534eb859203ebc6a4ef81297639`;
- instrumented worker:
  `6e81547a0609c8c0ba7afe54586588e517dcbcc546ed5802bfecc6d713dea132`;
- worker restore:
  `661c18380b96f18244c3c8b951269a6bea90854473def9a34f9c71dc3a0dc3ff`;
- uninstall checker:
  `ba0b6d9c4aeddf16fc24850eab65d90dde4bc1900841aabab1342137f48b59a6`.

These are staging and static-validation results only. No remaining live case is
claimed by this subsection.

### First resumed harness attempt excluded

The first resumed live attempt proved only the post-backup timeout case. It
returned typed `timed_out` after 60 seconds with its backup ID, zero surviving
workers, all 46 runtime values and both managed files exactly at baseline, and
no recovery marker.

The following external-kill attempt is excluded. Its client received a D-Bus
recipient-disconnected error rather than the required typed `failed` /
`executor_failed` result, so the matrix stopped before later cases. The helper
journal showed an explicit clean service stop, not a helper crash. Review found
that the harness `EXIT` cleanup trap could run in background client subshells
and stop the helper while the parent shell still awaited the result. Offline
inspection confirmed that this invalid attempt left no recovery marker; the
worker was paused immediately after durable backup and had not begun mutation.

The invalid clone was powered off, found image-clean, and preserved as
`lsmf-helper-gate-20260809-remaining-harness-invalid-20260810` with closure
hashes:

- disk:
  `4415dd21d7e6f6dc8af5336600ded85fa901e21c621f4151d3d441e1bb29f1ab`;
- OVMF variables:
  `49dcbf5dde510add92c5f2855d8016ccda47f5d508cd8470abe1ce6a9997543e`.

No external-kill, disconnect, serialization, audit-failure, or reboot result is
claimed from that attempt. The harness cleanup now checks `BASHPID` and runs
only in the main harness shell. Corrected hashes are:

- `LSMF_SECTION3_CLEAN` ISO:
  `7deeb1d18c40154cb80065e77cc866af91cf870d3da634b53fea8c0a15f0cbda`;
- remaining matrix:
  `414eb245681f0e8a5bb2f68d86073e0703125dc455e12619dfbcc28eef748155`.

A second resumed clone was created from the vendor-clean inputs. Before boot,
its disk and OVMF hashes again exactly matched the authoritative clean hashes,
and offline `qemu-img check` found no errors.

## Second host shutdown transition

The laptop shut down unexpectedly a second time while the second resumed clone
was booted from recovery media for offline sudoers provisioning. The command
that was in progress and the attempted post-command screenshot produced no
retained terminal result. They are treated as having **NO RESULT**: the
sudoers rule is not claimed installed, and no live Gate 3.8 case is claimed.

After the host restarted, a new powered-off inspection established:

- no running QEMU process was observed;
- the second clone's disk SHA-256 remained
  `32db4b84bd615bd9fd5902e110cd7c4d0f2bc6ccb6484350309a53aa2ef2d3b7`,
  exactly matching the vendor-clean disk;
- offline `qemu-img check` reported `No errors were found on the image`
  (`107583/655360`, 16.42% allocated; image end offset `7056195584`);
- its writable OVMF variables SHA-256 was
  `e86d6f9a4af052a3659921ade30206b621f9a7fc9375656297ce02b2c6c91901`,
  which does **not** match the vendor-clean OVMF SHA-256
  `e03c868a8070d7aae8af74a39e5b5c5d92d175c627a09a2eca71cc742dd83b52`;
- `/tmp/lsmf-section3-stage-20260810-resume` and
  `/tmp/lsmf-section3-remaining-resume-v2.iso` were absent after restart.

The unchanged disk and clean image check show that no disk mutation landed,
but the changed OVMF file means this directory is not an approved clean
baseline. Preserve it as second-shutdown diagnostic state before replacement.
Create a new working clone from both authoritative vendor-clean inputs, repeat
the full powered-off hash and image checkpoint, and rebuild the corrected
temporary harness from current repository bytes before another boot.

The previous host boot's retained journal ended at `2026-08-10 04:29:24 PDT`
with `systemd-logind: Power key pressed short`; no later clean-shutdown sequence
was present in the inspected final 120 entries. At `04:16:40`, the kernel had
also logged a page-allocation failure with zero configured swap. These are
diagnostic observations, not proof that either an intentional power-button
action or memory pressure caused the shutdown. A sandboxed `upower` query could
not connect to `upowerd`, so battery state was unavailable.

The cause of this second shutdown is therefore unresolved. It must not be
described as a clean guest shutdown or attributed to battery depletion without
additional host evidence.

## Recovery after second shutdown

With AC online and the battery charging at 95%, the second-shutdown directory
was preserved as:

`lsmf-helper-gate-20260809-remaining-second-shutdown-20260810` (private host path omitted)

Its diagnostic hashes remained disk
`32db4b84bd615bd9fd5902e110cd7c4d0f2bc6ccb6484350309a53aa2ef2d3b7`
and OVMF
`e86d6f9a4af052a3659921ade30206b621f9a7fc9375656297ce02b2c6c91901`.
A replacement `remaining` directory was created from both authoritative
vendor-clean inputs. Before boot, its disk and OVMF hashes exactly matched the
authoritative values, and offline `qemu-img check` again reported no errors
(`107583/655360`, 16.42% allocated; image end offset `7056195584`).

The corrected harness was rebuilt from current repository bytes. Bash syntax,
Python byte-compilation, and the explicit seven-command sudoers parse passed.
The sandbox-projected `/etc/sudo.conf` ownership warning remained separate from
the staged rule's `parsed OK` result. All previously recorded material hashes
matched, including corrected remaining-matrix SHA-256
`414eb245681f0e8a5bb2f68d86073e0703125dc455e12619dfbcc28eef748155`.
The newly built boot-attached ISO SHA-256 is
`b82e62681e2c5415abfdf8851236adac455aada9c524cc0cbce17ac77bc978d2`.
This is a pre-boot integrity checkpoint, not a live-case result.

### Resume-only v4 attempt excluded

To avoid rerunning the already-passed timeout case, the guest was cleanly
powered off before any new fault and the temporary matrix was rebuilt without
that first block. The v4 resume-only matrix SHA-256 was
`aec9a9f1047f7632d69eddbfd7b1873a6c58b1a42dc0d9ed429feaf56e44ff0a`;
the boot-attached ISO SHA-256 was
`45c714a95096dd28b7a86c719ebc5372c1232fcdaf8846b1fd0ebb068aecb4e2`.
It was attached read-only from startup under verified `-nodefaults -nic none`
isolation.

The external-kill case again returned a D-Bus recipient-disconnected error
before a typed result. No worker PID, exact recovery ID, or later case was
claimed. Bounded service evidence showed `Result=success`,
`ExecMainStatus=0`, `ActiveState=inactive`, and `SubState=dead`; journal entries
showed an explicit `Stopping` followed by successful deactivation in the same
second as startup. This proves the helper did not crash. The installed fault
worker source SHA-256 remained the expected
`6e81547a0609c8c0ba7afe54586588e517dcbcc546ed5802bfecc6d713dea132`.

The attempt was powered off, and offline `qemu-img check` found no errors. A
subsequent isolated recovery boot exited before terminal inspection, so the
presence and value of any recovery marker remain **UNKNOWN**. That inspection
has no result. The clone was preserved rather than reused as:

`lsmf-helper-gate-20260809-remaining-harness-invalid-v4-20260811` (private host path omitted)

Closure hashes were disk
`91543ececbab3c3d032470ced6b69d0902488175a354a75e7a6d4f5daeb26168`
and OVMF
`f084fd62d0859e80b99629459381f9fd8c0a2959feb17510ae046accd1ec7fd2`.

Review strengthened the harness again: every background submit now explicitly
clears its inherited `EXIT` trap before invoking the D-Bus client, including
the reboot-arm client. Corrected v5 hashes are:

- resume-only remaining matrix:
  `ea6a0e581a1e3cd9463f61b92e1d86de9b220eaefc3f196c43cfca325ea00d5b`;
- reboot arm:
  `5f66d6e1a53f633db559d4ba43b7d20a14b4bf0a4f586af6a1cab8196639b92f`;
- boot-attached v5 ISO:
  `cf414f1ac94a1223cd61c77f6a857e3ba3b34a1b5b9b36f12088ce23f5d0f565`.

A new `remaining` clone again exactly matched both vendor-clean hashes and
passed offline `qemu-img check`. It has not been booted. Live retry was paused
because a host AIDE integrity update was actively using about 4 GiB RAM with
zero swap, leaving about 1.9 GiB available. The AIDE task was not interrupted
or modified. Resume only after it completes and host memory returns to a safe
level.

### v5 background-trap correction falsified

After the host AIDE task was stopped, available memory recovered above 5 GiB.
The powered-off clone, ISO, AC power, and image integrity checkpoints passed.
The v5 ISO was provisioned offline with the exact sudoers hash and clean
unmounts, then booted under verified `-nodefaults -nic none` isolation with a
3 GiB guest allocation. Installation again captured 46 keys with zero missing
runtime keys and baseline SHA-256
`66dc49cee83b5bc9aff580849689bd07f5e2a0818ced2719c13bf600944aca0c`.
Production and fault-worker hashes matched their expected values.

The first v5 forced-kill request nevertheless produced the same D-Bus
recipient-disconnected error before a worker PID, typed result, or exact
recovery ID was printed. The matrix stopped; disconnect, serialization,
audit-failure, and reboot cases did not run. Explicitly clearing `EXIT` in every
background submit therefore did **not** correct the failure and falsifies the
background-trap explanation as a sufficient root cause. No further speculative
harness correction is approved by this evidence.

The guest was powered off, and offline `qemu-img check` reported no errors
(`108096/655360`, 16.49% allocated; image end offset `7089815552`). The clone
was preserved as:

`lsmf-helper-gate-20260809-remaining-harness-invalid-v5-20260811` (private host path omitted)

Closure hashes were disk
`da8d6d2ac49e81db56ad23acfdac60d43b1780e6742ee9d433d5b966423f8660`
and OVMF
`5bd46b9fee5d08808bb198a558c2f54d59703e70bf9b707f18581c5b9bdcc5fa`.
The standard `remaining` path is intentionally absent. This v5 result remains
excluded; the later focused diagnosis and valid forced-kill retry are recorded
below.

## Focused source diagnosis and valid forced-kill-only retry

Independent source review established that v4/v5 did not prove a production
lifecycle defect. Production launched the worker through resolved executable
`/usr/bin/python3.12`, but the harness searched for literal `python3 -m
lsmf.sysctl_worker`. Under `set -e`, the failed `pgrep` terminated the main
harness, whose `EXIT` cleanup explicitly stopped the helper. A bounded local
argv proof confirmed that the literal pattern failed and the resolved pattern
matched.

A deterministic router-boundary regression using a real external `/usr/bin/sleep`
subprocess stayed connected and returned a D-Bus method reply. Before the
minimal source fix it exposed a distinct defect: the exact durable recovery ID
was present in the marker but absent from the typed dispatcher result. The fix
propagates `SyntheticProcessError.backup_id` through `ProductionDispatcher`.
Focused tests passed 33; full Python discovery passed 220; Bash tests passed 8
with 0 failures and one unavailable-ShellCheck skip. Byte compilation, Bash
syntax, `make validate`, and `git diff --check` passed.

The subsequent user-approved retry was restricted to forced-kill only. A fresh
clone was created from the vendor-clean disk and OVMF variables after exact
hash and clean `qemu-img` checks. Every boot used KVM, `-nodefaults`, exact
`-nic none`, private writable disk/OVMF files, and boot-attached read-only ISO
SHA-256
`4275a58cb4530068f809ec4a6ffd685c4af51d21267285e11f00637c730219ba`.
The valid clone is:

`lsmf-helper-gate-20260811-forced-retry` (private host path omitted)

The guest verified 46 baseline keys with none missing. Its instrumented worker
reported exact PID 2291; the harness verified that PID's `/proc` argv and
membership in `lsmf-privileged-helper.service` before sending SIGKILL. Request
`6327f2d1-4023-45d0-9988-f336c3a4dc6d` returned typed `failed` /
`executor_failed` with exact backup ID
`backup-6327f2d1-4023-45d0-9988-f336c3a4dc6d`. The recovery marker matched.
The helper remained available: follow-up mutation failed closed as
`recovery_required` with the same ID, wrong-ID rollback was rejected, and
exact-ID rollback succeeded. Worker count was zero; runtime and file baselines
matched; the marker was absent. The serial log records
`LSMF-SECTION3-FORCED-KILL-RETRY-PASSED`.

The production worker was restored byte-for-byte before uninstall. Uninstall
left the unit not found, D-Bus activation `ServiceUnknown`, no helper process,
and no recovery marker. Retained backups/logs kept root-only permissions. The
formerly authorized uninstall command was then denied with `sudo: a password
is required`, confirming sudoers removal. ACPI shutdown completed and no
scoped QEMU process remained. Final `qemu-img check` reported no errors
(108925/655360 clusters, 16.62%; image end offset 7144144896). Closure SHA-256
values are disk
`4143d310e4cb0e40df0f1299b9236688ccca3bf940e9f52963c6fa56232f6d4a`
and OVMF
`a7f0b61947ee726023ce73c7192a9b8a0d31b59a61c1c64c70757a3c37bff700`.

External forced kill is therefore **PASSED**. Gate 3.8 remains **PARTIAL**:
client disconnect, concurrent serialization, audit-sink failure, and reboot
recovery remain unrun. They require a separate approved proposal; this result
does not authorize them.

## First remaining-cases clone excluded

The user approved one fresh clone for the four still-unrun cases. Vendor-clean
disk and OVMF hashes matched, the source and fresh clone passed `qemu-img
check`, and every boot used KVM, `-nodefaults`, exact `-nic none`, private
disk/OVMF files, and boot-attached read-only ISO SHA-256
`71be0d497bde15e175d2882dc951728a3a9ddf4c9e147954d51e3a2fb8f2d760`.
Offline sudoers provisioning parsed successfully and installed exact hash
`91448ceb2bc5e9e25ddacf81cbf209b4b040bc468af3efa338cd6a68e4810f7c`.

Installation captured all 46 keys with baseline SHA-256
`66dc49cee83b5bc9aff580849689bd07f5e2a0818ced2719c13bf600944aca0c`.
Instrumentation preserved the production worker at SHA-256
`d48b6f5b3000efba05715cf83dbd7aa2605093ad3c527455ae126199856ac3eb`.
The client-disconnect harness then stopped: its unprivileged client attempted
to stat `/run/lsmf/fault-ready`, and the private helper runtime directory
correctly returned `PermissionError`. Although the resulting process exit
disconnected the D-Bus owner, post-backup timing was not proven by the intended
root boundary. Client disconnect is therefore **NOT PASSED**; serialization,
audit failure, and reboot recovery did not run.

The worker was byte-restored and uninstall proved unit `not-found`, D-Bus
`ServiceUnknown`, no helper process, no recovery marker, zero backup files,
root-only retained directories/log, and denial of the former passwordless
command. ACPI shutdown completed. Powered-off `qemu-img check` reported no
errors (108513/655360 clusters, 16.56%; image end offset 7117144064). Closure
hashes are disk
`57ecd805c3113064665f66c3e30ff94da6cef283666d5c3feeb39453e3d1e9a4`
and OVMF
`45afedc95b521c784ebe6d8d00be13909216a0e092c5cdc3e7908890cf25be94`.
The excluded powered-off clone and serial log are at:

`lsmf-helper-gate-20260811-final-matrix` (private host path omitted)

The corrected client no longer reads protected helper state. It publishes its
own PID, and the root harness validates that exact unprivileged process and
sends `SIGUSR1` only after root observes the durable backup. Corrected ISO
SHA-256 is
`b6fb802357bfdf15a251e13ad7d7eaa51d4fbeaf3a2d8c313ea62026889ef407`.
A replacement fresh clone requires new explicit approval.

## Final replacement clone — Gate 3.8 complete

The user approved one replacement fresh clone using corrected boot ISO
SHA-256
`b6fb802357bfdf15a251e13ad7d7eaa51d4fbeaf3a2d8c313ea62026889ef407`.
The vendor-clean disk and OVMF hashes matched their authorities, both source
and replacement images passed powered-off `qemu-img check`, and every boot
used KVM, `-nodefaults`, exact `-nic none`, private writable disk/OVMF files,
and the boot-attached read-only ISO. Offline sudoers provisioning installed and
parsed exact hash
`91448ceb2bc5e9e25ddacf81cbf209b4b040bc468af3efa338cd6a68e4810f7c`.

Installation found all 46 runtime keys and reproduced baseline SHA-256
`66dc49cee83b5bc9aff580849689bd07f5e2a0818ced2719c13bf600944aca0c`.
Only loopback was present. The production worker was preserved at SHA-256
`d48b6f5b3000efba05715cf83dbd7aa2605093ad3c527455ae126199856ac3eb`.

The remaining cases passed:

- **Client disconnect:** root observed durable-backup readiness, validated
  exact unprivileged client PID 2468, and signalled that client to disconnect.
  Worker count returned to zero, runtime/files matched baseline, no marker
  remained, and a bounded follow-up apply plus exact rollback succeeded.
- **Concurrent serialization:** worker count remained exactly one while the
  first request was held. Both requests succeeded with distinct backup IDs;
  reverse-order rollback restored the original baseline with zero workers and
  no marker.
- **Audit-sink failure:** the terminal result was typed `failed` /
  `audit_failed` and preserved exact backup ID
  `backup-b939219c-575c-4bc0-b98a-e6b430e09d9b`. Restoring safe audit mode and
  rolling back that exact ID restored baseline.
- **Reboot recovery:** worker PID 2786 exited after durable backup. The typed
  `executor_failed` result and persisted marker both carried
  `backup-88ee4d00-6d77-4e0c-a026-a5e522139f94`. After reboot, new mutation
  failed as `recovery_required` with that ID; a structurally valid wrong ID was
  rejected without changing the marker; exact rollback restored all runtime
  and file state and then cleared the marker.

The production worker was restored to its original hash before uninstall.
Closure proved unit `not-found`, D-Bus `ServiceUnknown`, no helper/worker
process, no recovery marker, 11 retained backup files, root-only backup/log
directories, and audit log mode 0600. Repeating the formerly authorized
command produced `sudo: a password is required`. The guest stopped by ACPI and
no scoped QEMU remained. Powered-off `qemu-img check` reported no errors
(108474/655360 clusters, 16.55%; image end offset 7114588160). Final SHA-256
values are disk
`dddec7eb172e11a51ccf20b3e5757cb84c705fb90cb8de29ff96b77ca0366f40`
and OVMF
`da9063486a1b399e2b6ed8ada1c2cef234018611abf1112c6c000a312ab57ba6`.
The powered-off clone and exact serial evidence are at:

`lsmf-helper-gate-20260811-final-v2` (private host path omitted)

Gate 3.8 is complete. Gate 3.9 subsequently passed, and the later bounded
Ubuntu 24.04 package row is recorded in the retained Section 4 evidence.
