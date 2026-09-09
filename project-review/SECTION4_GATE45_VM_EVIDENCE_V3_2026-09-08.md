# Section 4 Gate 4.5 Ubuntu package evidence — replacement row (Option 3 scope)

## Outcome and scope

This is a **replacement Gate 4.5 evidence row**, re-run because the publication
metadata change altered the released archive since the prior V2 evidence
(`SECTION4_GATE45_VM_EVIDENCE_V2_2026-08-11.md`).

This run covers **Option 3 only**: fully automatable install, package-integrity,
and uninstall/reinstall checks. It does **not** cover fault-injection/crash-recovery
scenarios or the Polkit prompt matrix — those are explicitly marked NOT TESTED
below and deferred to a following Option 1 run, per the project's own gate rule
that untested scenarios must be labeled rather than silently omitted.

This does not establish Debian, Fedora, Rocky/Alma, Mint, Neon, or Kali
compatibility and does not authorize publication or a workstation install.

## Deviations from the V2 methodology (disclosed)

- **Single-operator run, no second-person review.** The privileged-helper
  verification doc calls for independent second-person review; no second
  operator was available for this run. This is a deviation from written
  policy and is disclosed here rather than claimed as compliant.
- **Network-enabled dependency resolution, not fully air-gapped.** V2 used
  `-nic none` for a fully offline install. This run used QEMU user-mode
  networking (SLIRP) so `apt` could resolve non-pinned transitive runtime
  dependencies (`python3-dbus-next`, `policykit-1`, `libgl1`, `libegl1`,
  `libfontconfig1`, `libxkbcommon0`, and their own transitive deps) directly
  from the Ubuntu archive over the internet, rather than building a full
  offline closure for all of them. The one dependency the repository's own
  offline-dependency test pins and verifies, `libxcb-cursor0`, was still
  pre-staged and installed offline from the checksum-recorded package, matching
  `packaging/debian/ubuntu-noble-offline-deps.sha256`.
- Guest automation was done over an SSH port-forward (added for this run) once
  a netplan/interface-naming issue was found and fixed on the fresh install,
  rather than via QEMU monitor `sendkey` console typing for every step.

## Verified inputs and isolation

- VM working directory: private operator host path (excluded from this snapshot)
- Ubuntu ISO: `ubuntu-24.04.4-live-server-amd64.iso`
  SHA-256: `e907d92eeec9df64163a7e454cbc8d7755e8ddc7ed42f99dbc80c40f1a138433`
  (verified against the official Ubuntu `SHA256SUMS` file before use)
- Vendor-clean disk SHA-256 (post-autoinstall, pre-any-test):
  `b21ee81072ee5becf9d8b168483a0fe2cd2e06724d89fde486d68d7a53dd3a0b`
- Vendor-clean disk backup kept byte-identical at
  `disks/lsmf-gate45-vendor-clean-backup.qcow2` (same hash, confirmed by
  re-hash: `b21ee81072ee5becf9d8b168483a0fe2cd2e06724d89fde486d68d7a53dd3a0b`)
- OVMF_VARS.fd SHA-256 before first boot:
  `4c5226b0edd402876f2cc7678acb9b3db198e64c8f4f36c0495e6df06e2f6711`
  (this file's hash legitimately changes after boot because UEFI stores boot
  variables in it; post-test hash recorded separately below, not treated as a
  tamper signal)
- Package under test SHA-256 (`lsmf_0.4.0~rc1_amd64.deb`, built via
  `packaging/debian/build-package.sh`):
  `bbe5274d9c443f3f958c7386d89f85064f8b35b751e664ef3855601e14df6bb5`
- Pinned offline dependency SHA-256 (`libxcb-cursor0_0.1.4-1build1_amd64.deb`):
  `137cf52479b5a9d8c5926d70d311af04be41941a32ee777340d704cc458c06d8`
  (matches `packaging/debian/ubuntu-noble-offline-deps.sha256`; independently
  re-hashed inside the guest after transfer via the attached `extras.iso` and
  confirmed identical)

## Install and package-integrity results (both proved)

- `dpkg --verify lsmf` returned rc=0 (no discrepancies) after install.
- No packaged file had a setuid/setgid bit or unsafe mode; all installed
  objects were owned `root:root` with mode 644 (data/libs) or 755 (the three
  executables: `/usr/bin/lsmf-desktop`, `/usr/libexec/lsmf-privileged-helper`,
  `/usr/libexec/lsmf-read-only-runner`).
- The `lsmf-privileged-helper.service` unit was `loaded`/`inactive`, and
  `UnitFileState=static` (D-Bus-activated only, not enabled at boot).
- Root desktop launch was rejected: `sudo /usr/bin/lsmf-desktop --help`
  returned exit code 1 with `Do not run the LSMF desktop interface as root.`
  before any Qt import occurred (per the launcher's own EUID check, ahead of
  `exec /usr/bin/python3`).
- The packaged ordinary-user offscreen Qt smoke test passed: running
  `from PySide6.QtWidgets import QApplication; import desktop.main` with
  `QT_QPA_PLATFORM=offscreen` and `PYTHONPATH` pointed at the packaged
  `/opt/lsmf/qt` and `/opt/lsmf/app` trees printed `packaged-qt-import-ok`
  with no errors.
- The production sysctl manifest (`/etc/lsmf/helper/sysctl-manifest.json`)
  contained **46** distinct keys across all modules, and all 46 keys existed
  under `/proc/sys` on this kernel (`6.8.0-100-generic`) — matching the count
  reported in the V2 evidence for the prior kernel/build.
- The D-Bus service descriptor (`org.lsmf.Helper1.service`) and the Polkit
  action policy (`org.lsmf.helper.policy`, actions `audit`, `verify-module`,
  `apply-module`, etc., all `allow_active=auth_admin`) were present and
  well-formed. **The Polkit prompt matrix itself was NOT TESTED** in this run.

## Uninstall / reinstall results

- `sudo apt-get purge -y lsmf` completed cleanly.
- After purge, verified fully absent: `dpkg -l lsmf` (no package),
  `/usr/bin/lsmf-desktop`, `/usr/libexec/lsmf-privileged-helper`, `/opt/lsmf`,
  `/etc/lsmf`, the systemd unit file, the D-Bus service file, and the Polkit
  policy file — all reported "No such file or directory".
- `systemctl status lsmf-privileged-helper.service` reported
  "Unit ... could not be found" (unit fully unloaded).
- `busctl call ... GetNameOwner ... org.lsmf.Helper1` failed with
  "no such name" (exit code 1) — confirming the D-Bus name was unowned.
- Reinstalling the identical package succeeded cleanly a second time
  (idempotency), with `dpkg --verify lsmf` again returning rc=0 and the
  helper unit again `inactive`/`static` afterward.

## NOT TESTED in this run (explicitly deferred to Option 1)

- **Fault-injection / crash-recovery scenarios**: real D-Bus client
  disconnect mid-apply, concurrent-apply serialization, protected audit-sink
  failure, crash-after-durable-backup + reboot recovery, and rollback
  clearing the recovery marker. None of these were exercised in this run.
- **Polkit prompt matrix**: interactive authorization behavior across the
  helper's actions was not exercised; only the static policy file's presence
  and structure were checked.
- **Second-person review** of this evidence bundle: not performed (single
  operator).

## Shutdown and final image state

- The guest was shut down cleanly via `sudo shutdown -h now`; the QEMU
  process exited with code 0.
- `qemu-img check` on the post-test disk reported "No errors were found on
  the image."
- Post-test disk SHA-256 (after install → verify → purge → reinstall →
  shutdown, i.e. reflecting the final installed state, not vendor-clean):
  `50f8331c5e52922faa10d34f287e2a7652b5f13b556e6b57041d917f4e1454c4`

## Next step

Per the project owner's direction, an Option 1 run (full fault-injection and
crash-recovery scenarios plus the Polkit prompt matrix) is approved to follow
this Option 3 evidence directly, without requiring a further confirmation
round, reusing this same vendor-clean disk/OVMF baseline as the starting
point.
