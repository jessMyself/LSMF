# Privileged-helper runtime inputs

These files are package inputs for disposable-VM validation. They are
not installed, registered, enabled, or started by the repository. The current entry
point starts a system-bus service that binds calls to bus-derived credentials
and the caller's active local graphical logind session. Its dispatcher now
selects the fixed Section 3 source runtime. That runtime preserves audit and
exactly one `kernel_hardening` verification command and adds only three typed
mutation shapes: `kernel_hardening`, the exact ordered pair
`kernel_hardening` then `network_hardening`, and rollback of one eligible exact
backup ID. Caller-selected paths, commands, services, packages, environment,
working directory, arbitrary modules, and other orderings fail closed. There
is still no approved workstation installer. The repository's async dispatcher, isolated
process adapters, and source-level composition roots are tested with mocks and
temporary fixture roots. The earlier synthetic composition remains covered as
Section 1 evidence. The packaged entry point now selects the combined Section
3 composition, but these files
remain inactive and the staging scripts refuse the real filesystem root. They
only assemble or remove an explicit non-root package tree; they do not invoke
systemd, D-Bus, Polkit, or a package manager. A nonblocking fixed-argument
Polkit adapter is implemented and has been exercised against live Polkit in the
approved isolated Ubuntu VM. Cancellation, disconnect, timeout/forced kill,
abrupt crash, exact recovery, and removal preservation also passed there. That
gate evidence does not make these artifacts production-ready or authorize real
hardening modules. The full Section 1 synthetic matrix, including denial,
replay, audit-sink failure, serialization, recovery, and uninstall, passed in
the approved isolated VM. The audit and `kernel_hardening` verification runner
has isolated-VM evidence from Section 2. The sysctl transaction, version-2
manifest, backup/recovery store, fixed worker, Qt mutation controls, and
expanded service sandbox have source, temporary-root, and completed Section 3
Ubuntu VM evidence. The new Debian release-candidate archive itself has not
been installed or exercised in a VM.
Mutable Cancel remains disabled in Qt pending correction and live proof of the
deferred same-connection terminal-ordering defect.

`packaging/debian/build-package.sh` creates a deterministic amd64 Debian-family
Qt/helper release-candidate package. The exact candidate passed its bounded
offline Ubuntu 24.04 Section 4 VM row. It installs the unprivileged desktop, launcher,
pinned hash-verified PySide6 runtime, and helper boundary in one archive. The
builder removes the earlier synthetic manifest and toggle fixture from the
final payload. Building a package does not install, register, start, or
authorize the helper.

Ubuntu 24.04/Noble supplies the selected runtime binding as
`python3-dbus-next` 0.2.3. Its low-level API retains the bus-assigned unique
sender. The service asks `org.freedesktop.DBus` for that sender's PID and UID;
neither identity value is accepted from the request body.

Any future package must install the helper, read-only runner, selected LSMF
sources, policy, D-Bus declarations, trusted manifests, and their parent
directories as `root:root`. The helper and runner executables may be mode
`0755` or stricter; non-executable policy and declarations must be
mode `0644` or stricter. Runtime and state directories must be `0700`, with
runtime files and secret-bearing or backup manifests `0600`. No parent may be
group- or other-writable. A setuid or setgid helper is forbidden.

The proposed service owns only the system-bus name `org.lsmf.Helper1`, uses
local `AF_UNIX` IPC, and has private networking. Its absolute `ExecStart` is
package-controlled and must never incorporate caller input. The five distinct
Polkit actions have fail-closed inactive/non-local defaults and require an
administrator authentication for an active local session. The helper must
still validate credential-derived identity and request ownership and request
the exact action on every operation; policy authentication alone is not trust.

The Section 3 unit grants only `CAP_SYS_ADMIN` and `CAP_NET_ADMIN`, makes only
`/etc/sysctl.d` and `/var/backups/lsmf/sysctl` additionally writable, and keeps
network access private. Those capabilities and the decision to set
`ProtectKernelTunables=no` and `PrivateNetwork=no` are mandatory VM verification targets; source tests
do not prove that every selected sysctl is writable or that the sandbox is
sufficient on Ubuntu.

Do not copy these files into `/usr`, `/etc`, or any system service/policy
directory on a workstation. Installation, activation, and behavior must first
be tested through the separately approved disposable-VM verification gate.
