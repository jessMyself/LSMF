# Section 4 Gate 4.5 Ubuntu package evidence — passed replacement row

## Outcome

Gate 4.5 is **complete for the bounded Ubuntu 24.04 amd64 release-candidate
row**. The approved replacement clone installed and reinstalled the exact
package offline, exercised the packaged Qt/helper boundary and remaining
stateful scenarios, removed the package, shut down cleanly, and passed the
powered-off image check.

This does not establish Debian, Fedora, Rocky/Alma, Mint, Neon, or Kali
compatibility and does not authorize publication or a workstation install.

## Verified inputs and isolation

- Clone label: `lsmf-section4-gate45-ubuntu-v2-20260811` (private host path omitted)
- Evidence label: `section4-gate45-ubuntu-v2-20260811` (private host path omitted)
- Vendor-clean disk SHA-256:
  `32db4b84bd615bd9fd5902e110cd7c4d0f2bc6ccb6484350309a53aa2ef2d3b7`
- Vendor-clean OVMF SHA-256:
  `e03c868a8070d7aae8af74a39e5b5c5d92d175c627a09a2eca71cc742dd83b52`
- Ubuntu ISO SHA-256:
  `0479e02d64f6d85563d9bee59928fe3ab2bc84258e4a22df173b4d44e4cee43f`
- Corrected Gate 4.5 ISO SHA-256:
  `6ab716285129e6468484aa6216649824f2334a83b786d9233afff00093360fb3`
- Package SHA-256:
  `94e2b74d0ef31e4aa93af41179d20abfd8641c4648e7cb77dd6d64c60669870d`
- Noble dependency SHA-256:
  `137cf52479b5a9d8c5926d70d311af04be41941a32ee777340d704cc458c06d8`
- Narrow sudoers rule SHA-256:
  `cad56311202dc484126d518bf673b2c8a2405ec2c5d8f703a16f8a19f73688a4`

Every recorded test launch used KVM, `-nodefaults`, exact `-nic none`, the
private clone disk and OVMF files, and only the checksum-recorded read-only test
ISO. The reboot half restarted the same approved clone; no second clone was
created.

## Provisioning correction

The recovery-language wizard did not accept emulated navigation reliably. The
guest was first shut down with no disk change; its disk remained byte-identical
to the vendor-clean hash and passed `qemu-img check`. A reviewed, bounded,
one-time installed-GRUB `init=/bin/bash` transaction then mounted the test ISO
read-only, installed only the exact script-path sudoers rule, validated it with
`visudo`, emitted `LSMF-SECTION4-V2-PROVISIONED`, synced, remounted the root
filesystem read-only, and powered off. `recovery-serial.log` contains the rule
hash and parse-success evidence.

## Package and packaged-Qt results

`gate45-serial.log` records two successful runs of the install harness. The
first installed the pinned offline dependencies and `lsmf 0.4.0~rc1`; the
second reinstalled the same archive and demonstrated package idempotency.
Both runs proved:

- the helper unit was not active or enabled after installation;
- `dpkg --verify lsmf` passed and the selected installed objects had root
  ownership and safe modes;
- no writable or set-ID packaged code object was found;
- root desktop launch was rejected with status 1 before importing Qt;
- the packaged ordinary-user offscreen Qt smoke passed;
- the production manifest contained 46 available runtime keys;
- the baseline artifact hash was
  `f8ebc2a30bb624d7887c564ba1de705630dda779a36ecfc432207c1290a27bd1`;
- only guest loopback was present because the hypervisor supplied no NIC.

## Stateful helper results

The exact production worker was saved, hash checked, replaced temporarily by
the checksum-recorded VM fault worker, and restored afterward to SHA-256
`d48b6f5b3000efba05715cf83dbd7aa2605093ad3c527455ae126199856ac3eb`.

The serial records contain typed terminal results and exact backup identities
for every stateful case:

- real D-Bus client disconnect left no worker or recovery marker, restored the
  complete baseline, and allowed a successful follow-up apply and rollback;
- two concurrent apply clients produced exactly one worker, serialized, then
  both exact rollbacks restored the baseline;
- protected audit-sink failure returned `failed/audit_failed` with the exact
  eligible backup ID, followed by successful exact rollback;
- crash after durable backup returned `failed/executor_failed` with
  `backup-15283378-a2fd-41a7-b190-0ca1126273aa` and persisted that recovery
  requirement across reboot;
- after reboot, a new apply returned `failed/recovery_required` with the same
  ID, a wrong ID was rejected, and only exact rollback cleared the marker and
  restored all runtime and file baselines.

The earlier Section 3 evidence remains the applicable proof for strict
request/authorization rejection, read-only audit/verification, single/repeat
and ordered multi apply, timeout, external forced kill, exact rollback, and
the other already completed production-boundary rows. Gate 4.5 re-proved the
package-specific and remaining stateful rows rather than treating package
construction or process launch as acceptance.

## Uninstall and powered-off closure

Package-manager removal passed. The launcher, Qt payload, helper executable,
unit, D-Bus activation/configuration, Polkit policy, and manifest were absent;
the unit load state was `not-found`; D-Bus returned `ServiceUnknown`; no helper
or worker process remained; and the recovery marker was absent. The protected
backup and log directories were intentionally retained at mode 0700 and the
audit file at mode 0600. The temporary sudoers rule was removed.

The guest then shut down through ACPI and QEMU exited. Final powered-off
`qemu-img check` found no errors. Final hashes are:

- disk: `717c4316b7ed5b978c9827cf209075f0875cd92290999ba07e977f8b747842b8`
- OVMF variables:
  `1b301e3422daef61a3acab486c96626110025e46e1e414d2aa0474585ef61835`

The passed clone remains powered off and preserved. Do not reuse or delete it
without a separate cleanup decision.
