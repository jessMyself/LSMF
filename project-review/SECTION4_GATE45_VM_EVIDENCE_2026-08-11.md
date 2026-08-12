# Section 4 Gate 4.5 Ubuntu package evidence — excluded attempt

## Outcome

Gate 4.5 did **not pass**. The one approved Ubuntu 24.04 clone produced a valid
release-blocking package dependency failure and is excluded. No Qt/helper,
mutation, recovery, or compatibility row is claimed from this clone.

## Approved inputs

- Clone label: `lsmf-section4-gate45-ubuntu-20260811` (private host path omitted)
- Evidence label: `section4-gate45-ubuntu-20260811` (private host path omitted)
- Vendor-clean disk SHA-256:
  `32db4b84bd615bd9fd5902e110cd7c4d0f2bc6ccb6484350309a53aa2ef2d3b7`
- Vendor-clean OVMF SHA-256:
  `e03c868a8070d7aae8af74a39e5b5c5d92d175c627a09a2eca71cc742dd83b52`
- Ubuntu ISO SHA-256:
  `0479e02d64f6d85563d9bee59928fe3ab2bc84258e4a22df173b4d44e4cee43f`
- Corrected Qt/helper package SHA-256:
  `94e2b74d0ef31e4aa93af41179d20abfd8641c4648e7cb77dd6d64c60669870d`
- Gate 4.5 boot ISO SHA-256:
  `d989d25b009e345d3230996ae5b62659ee44d6cb5981f4e799908a59ade8d6e9`

Every boot used KVM, `-nodefaults`, exact `-nic none`, the private approved
disk/OVMF files, and only checksum-recorded read-only ISO media.

## Valid result

The first normal `sudo -n` install attempt failed closed because the recovery
source ISO had not been automounted; no package was installed. Recovery media
then explicitly mounted `/dev/sr1` read-only and the disposable system volume,
installed the exact narrow sudoers rule, and reported its target `parsed OK`.

The next normal boot invoked only the allowlisted install script. It verified
the exact package hash and confirmed the helper unit was absent before install.
The offline `python3-dbus-next` dependency installed. `dpkg` unpacked the LSMF
archive but refused configuration:

```text
lsmf depends on libxcb-cursor0; however:
  Package libxcb-cursor0 is not installed.
dpkg: error processing package lsmf (--install):
 dependency problems - leaving unconfigured
```

This is a package/release failure. Installing the declared dependency ad hoc or
continuing into the matrix would have invalidated the predeclared offline
artifact boundary. Packaged Qt smoke, authorization, mutation, recovery, and
uninstall acceptance therefore remain **NOT TESTED**.

## Removal and closure

`dpkg -r lsmf` removed the unpacked package. The helper unit was `not-found`,
D-Bus returned `ServiceUnknown`, no helper process existed, and no recovery
marker existed. Because package configuration never created its state
directories, the cleanup script stopped before its final retained-directory
and sudoers-removal assertions.

A subsequent recovery cleanup was mistimed before the live desktop completed.
Premature recovery-ISO eject caused SquashFS read errors and a stuck shutdown.
The cleanup command has no result and temporary sudoers removal is **UNVERIFIED**.
The already-excluded QEMU instance was terminated through its exact private
monitor. This is forced closure, not a clean-poweroff pass.

Final powered-off `qemu-img check` found no errors. Closure hashes:

- disk: `07b12049713dbbdd734c1143289d20d1801f8562effb907ae6a7d4b5a1cc972e`;
- OVMF: `fc6508105af1df73b3c133c47fa708d8bcbe97b0a7d09bab5a785bef35314cda`.

Do not boot or reuse this excluded clone. Do not call Gate 4.5 complete.

## Next dependency

Build a complete offline dependency closure for the declared Ubuntu package,
at minimum including the exact vendor package for `libxcb-cursor0` and any
recursive dependencies not already present in the authoritative base image.
Validate package hashes and install ordering offline, update the boot ISO, and
return a new one-fresh-clone proposal. A new clone requires new explicit user
approval; the approved clone count has been consumed.

Source-level closure correction subsequently pinned the Ubuntu Noble archive
package `libxcb-cursor0_0.1.4-1build1_amd64.deb` at SHA-256
`137cf52479b5a9d8c5926d70d311af04be41941a32ee777340d704cc458c06d8`.
The failed guest's package manager reported only this declared dependency as
missing; the package's recursive dependencies were present. This correction
does not change the excluded outcome or authorize another clone.
