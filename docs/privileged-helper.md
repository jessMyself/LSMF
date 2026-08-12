# Privileged Helper Security and Protocol Specification

## Status and scope

This document specifies the security boundary for a future Linux-only LSMF
privileged helper. It is a design and test contract, not authorization to
install a helper or Polkit policy, expose Qt action controls, or execute an
audit, verification, hardening, or rollback operation.

The PySide6 desktop process remains unprivileged. A separate, narrowly scoped
root helper may eventually perform only these operations:

1. `audit`
2. `verify_module` for exactly one implemented module
3. `apply_module` for exactly one implemented module
4. `apply_modules` for an explicit bounded list of implemented modules
5. `rollback_backup` for exactly one validated backup ID

Everything not explicitly described here is denied.

## Trust boundaries and principals

The unprivileged Qt application is an untrusted request origin. Its widgets,
configuration files, process environment, working directory, cached module
metadata, and serialized requests are not authority. Compromise of Qt must not
provide a generic root command channel.

The root helper is the enforcement boundary. It owns the action allowlist,
module-to-entry-point mapping, executable paths, clean environment, timeouts,
output limits, backup root, validation, authorization checks, execution, and
audit records. It must not import UI state as policy.

The Polkit authority decides whether the authenticated local subject may
perform one particular action. Authorization does not make request data
trusted, does not bypass helper validation, and is not reusable for a different
action or request.

Communication must use a local, credential-bearing IPC mechanism (for example,
a system D-Bus service). The helper must obtain the caller's PID, UID, and
session identity from kernel/service-manager credentials, never from request
fields. It must reject requests when credentials cannot be obtained or no
unique live local subject can be constructed.

The initial supported caller is a local, active, graphical seat session. The
helper must require that the authenticated subject corresponds to the IPC peer,
is in the same live login session that initiated the request, and is locally
active when Polkit policy requires an active session. Remote, lingering,
headless, replaced-owner, ambiguous-session, and unverifiable subjects fail
closed. Root invoking the Qt application is not a supported shortcut and does
not relax any rule.

## Forbidden request and execution surfaces

No request may contain or influence:

- filesystem paths, URLs, web or network requests;
- shell text, shell fragments, pipelines, redirections, or command strings;
- arbitrary `argv`, executable names, interpreter names, or subcommands;
- environment variables, working directories, file descriptors, or user/group
  selections;
- generic commands, package names, service names, configuration keys, or raw
  module function names;
- caller-selected log, report, backup, policy, or output destinations.

The helper must never invoke a shell with caller data, use `shell=True`, search
`PATH`, source Bash or configuration files, evaluate configuration as code,
inherit the caller's environment, or select an executable from caller input.
Every executable must be an absolute root-owned allowlisted path. The helper
must construct fixed argument vectors internally, use a minimal constant
environment, a fixed safe working directory, closed extra file descriptors,
and an explicit umask.

## Protocol envelopes

### Gate 1 mock-core envelope implemented in this repository

The completed helper-foundation milestone implements a deliberately minimal,
non-production JSON model for
validation and helper-core tests. Requests use exact flat fields:
`version`, `request_id`, `action`, and only the action-specific `module_id`,
`module_ids`, or `backup_id` field. Results use exactly `version`, `request_id`,
`action`, `status`, `message`, `output`, and `truncated`; Gate 1 statuses are
`success`, `error`, `denied`, `cancelled`, and `timeout`. Its request limit is
16 KiB, output is capped at 32 KiB, and lists contain at most 32 module IDs.

This mock envelope is not the installed IPC protocol. It contains no peer
credentials, transport, Polkit adapter, or executor. The repository includes a
strict versioned production envelope, system-bus credential lookup
boundary, libsystemd login-session resolver, fixed-argv per-action `pkcheck`
adapter, no-follow trusted-manifest loader/policy, and protected append-only
audit sink. `lsmf/system_bus_service.py` wires only `Submit` and `Cancel` to a
low-level `dbus-next` transport that retains the bus-assigned unique sender,
derives its PID/UID through the bus daemon, binds the live logind session, and
invalidates disconnected callers. Noble's selected dependency is
`python3-dbus-next` 0.2.3. A separate manifest-only synthetic filesystem engine
now implements fixture audit, verification, backup-first apply, exact rollback,
recovery backups, and recovery-required lockout. It accepts no request paths or
commands. A source checkout leaves the D-Bus service uninstalled.
`lsmf/production_dispatcher.py` provides the injected
async orchestration boundary connecting bus-bound requests to trusted policy,
per-action authorization, protected lifecycle auditing, full-operation
serialization, cooperative cancellation/disconnect handling, fixed timeouts,
and a typed executor. Mock integration through the D-Bus boundary passes.
`AsyncPkcheckAuthorizer` provides the nonblocking runtime authorization side
with the same fixed arguments, exact five-action allowlist, clean environment,
PID-reuse check, bounded timeout, and cancellation cleanup. Fixed external
process adapters, the packaged Section 3 composition, and bounded Qt actions are
implemented and have completed their Section 1–3 Ubuntu VM gates. Mutable Qt
Cancel remains disabled for the separately documented same-connection terminal
ordering defect.

### Production envelope

The transport encoding is UTF-8 JSON with duplicate object keys rejected. A
request must be a single object whose encoded size is at most 16 KiB. Integers
must be JSON integers, not strings or floating-point values. Boolean and null
substitution is invalid. Unknown, missing, or duplicate fields are rejected.

Every operation request has exactly these top-level fields:

```json
{
  "protocol_version": 1,
  "request_id": "018f4ec8-6c3a-7b2d-9ef1-7b9ba20d9374",
  "action": "verify_module",
  "parameters": {"module_id": "ssh_hardening"}
}
```

- `protocol_version` is exactly `1`.
- `request_id` is a canonical lowercase UUID string. It is a correlation token,
  not an authorization credential, and must be unique among live and recently
  completed requests. Reuse is rejected.
- `action` is one of the five literal values in this document.
- `parameters` must match the action schema exactly.

Identifiers use canonical ASCII only. A `module_id` must match
`[a-z][a-z0-9_]{0,63}` and must also occur in the helper's root-owned installed
module allowlist. Discovery is performed by the helper from its trusted
installation manifest; the caller cannot add a module by naming a file.

A `backup_id` is an opaque identifier, not a path. It must match
`[A-Za-z0-9][A-Za-z0-9._-]{0,127}`, must not equal `.` or `..`, must not contain
`..`, and must resolve by exact manifest lookup to one helper-managed backup.
Regex validation alone is insufficient.

### Exact action schemas

| Action | Exact `parameters` object | Additional rules |
| --- | --- | --- |
| `audit` | `{}` | Read/assessment action; it may not mutate host configuration. |
| `verify_module` | `{"module_id": STRING}` | Exactly one implemented, verify-capable module. |
| `apply_module` | `{"module_id": STRING}` | Exactly one implemented, apply-capable module. |
| `apply_modules` | `{"module_ids": [STRING, ...]}` | 1–32 unique implemented, apply-capable IDs; caller order is preserved only if the trusted helper declares it safe, otherwise trusted dependency order is used and reported. |
| `rollback_backup` | `{"backup_id": STRING}` | The trusted backup manifest must be valid, complete, and eligible for rollback. |

An empty module list, duplicate ID, unsupported capability, unknown ID, extra
parameter, or type mismatch is rejected before authorization or execution.

## Polkit authorization

Authorization is checked after structural and allowlist validation but before
any privileged side effect. This avoids prompting for impossible requests while
ensuring validation itself performs no host mutation.

Each operation has a distinct Polkit action ID:

| Protocol action | Polkit action ID |
| --- | --- |
| `audit` | `org.lsmf.helper.audit` |
| `verify_module` | `org.lsmf.helper.verify-module` |
| `apply_module` | `org.lsmf.helper.apply-module` |
| `apply_modules` | `org.lsmf.helper.apply-modules` |
| `rollback_backup` | `org.lsmf.helper.rollback-backup` |

The helper supplies only validated, display-safe identifiers as Polkit details.
The policy must not grant a broad umbrella action. Authorization is requested
for the credential-derived subject on every request, with no helper-side grant
cache. A successful authorization is bound to the request ID, exact action,
canonical parameter digest, peer identity, and live IPC ownership. Any change,
disconnect, owner replacement, session transition, or authorization error
invalidates it. Denial, dismissal, timeout, authority unavailability, malformed
reply, or indeterminate result fails closed and produces no executor call.

## Response schema and bounded output

The helper returns exactly one terminal response per accepted request:

```json
{
  "protocol_version": 1,
  "request_id": "018f4ec8-6c3a-7b2d-9ef1-7b9ba20d9374",
  "action": "verify_module",
  "status": "succeeded",
  "started_at": "2026-07-21T18:42:03Z",
  "finished_at": "2026-07-21T18:42:04Z",
  "exit_code": 0,
  "summary": "Verification completed",
  "output": "bounded diagnostic output",
  "output_truncated": false,
  "error": null,
  "result": {"module_ids": ["ssh_hardening"], "backup_id": null}
}
```

Fields are exact and always present. `status` is one of `succeeded`, `failed`,
`denied`, `cancelled`, `timed_out`, or `rejected`. `exit_code` is an integer in
0–255 only when an executor started, otherwise null. `summary` is plain text of
at most 512 UTF-8 bytes. `output` is sanitized plain text of at most 64 KiB;
excess is discarded and `output_truncated` is true. Binary/control content is
escaped or replaced. `error` is null or exactly
`{"code": STRING, "message": STRING}`, with an allowlisted stable error code
and a message of at most 512 UTF-8 bytes. It contains no traceback, secret,
policy internals, or untrusted path. `result` has one exact shape selected by
the request action:

| Action | Exact terminal `result` object |
| --- | --- |
| `audit` | `{"finding_count": INTEGER}` |
| `verify_module` | `{"module_ids": [STRING], "backup_id": null}` |
| `apply_module` | `{"module_ids": [STRING], "backup_id": STRING_OR_NULL}` |
| `apply_modules` | `{"module_ids": [STRING, ...], "backup_id": STRING_OR_NULL}` |
| `rollback_backup` | `{"module_ids": [STRING, ...], "backup_id": STRING}` |

`finding_count` is 0–10,000. Result module lists contain only the validated
targets actually processed, in the helper's execution order, with the same
1–32 bound (or an empty list if execution did not start). For apply responses,
`backup_id` is non-null once a valid rollback point was committed, even if the
operation later failed. It is null only if mutation never began. Unknown result
fields are forbidden.

Progress events, if later added, use the same request binding, are monotonically
sequenced, contain no unbounded executor stream, and cannot replace the terminal
response. The desktop must present failure, denial, cancellation, timeout, and
truncation truthfully; transport completion is not operation success.

## Timeouts and cancellation

Timeouts are fixed per action by the helper and are not caller parameters. A
global hard maximum is required in addition to action-specific limits. On a
timeout, the helper terminates the dedicated process group using a fixed staged
termination policy, waits for reaping, performs action-specific consistency
checks, writes an audit event, and returns `timed_out`. Failure to prove a safe
post-state is reported explicitly and must not be represented as rollback.

Cancellation is a transport control message containing only `protocol_version`
and `request_id`; it is not a sixth privileged host action. It is accepted only
from the same live peer/session that owns the request. Cancellation never starts
another executable. The helper requests termination, reaps the process tree,
performs the same consistency checks, and returns `cancelled` only after work has
stopped. If an operation has crossed a documented non-cancellable commit point,
the helper reports that cancellation was not accepted and continues to a
truthful terminal state. IPC disconnect triggers cancellation where safe, but
must not silently claim that a committed change was undone.

Concurrent mutating operations (`apply_module`, `apply_modules`, and
`rollback_backup`) are serialized with a helper-owned lock. Audit or verification
must not race a mutation unless the helper proves the relevant operation is
read-consistent; the initial implementation should serialize all operations.

## Rollback contract

Apply actions must create and validate a helper-managed rollback point before
the first mutation. A successful apply response reports its backup ID. If
backup creation, manifest fsync, or validation fails, mutation must not begin.
The manifest records the exact module set, trusted target identities, hashes or
other integrity metadata, creation time, helper/protocol version, and completion
state.

`rollback_backup` restores only objects listed in the exact trusted manifest.
It must reject partial, unknown, already-invalidated, incompatible, tampered,
symlinked, or ownership/mode-invalid backup sets. It may not accept a caller
path or discover additional targets during rollback. Rollback creates its own
pre-rollback recovery point when feasible, verifies the restored state, and
reports partial restoration as failure with precise bounded diagnostics.
Automatic rollback after a failed apply is action-specific and must be recorded
as attempted and verified, not merely claimed. A failed or unverified rollback
leaves an explicit recovery-required state that blocks further mutation until
handled in a disposable/tested recovery workflow.

## Filesystem and TOCTOU requirements

The helper must avoid check-then-open by using descriptor-relative operations
from pre-opened trusted directory descriptors, `O_NOFOLLOW`/equivalent
no-symlink resolution, and identity checks before and after relevant operations.
It must not canonicalize an untrusted path and later reopen it by name.

Installed manifests, module executables, helper configuration, Polkit policy,
backup manifests, and parent directories must be root-owned and not writable by
group or others. Before execution, the helper verifies regular-file type,
ownership, mode, expected installation root, and (where deployed) packaged
integrity metadata. Backup IDs are resolved beneath a fixed root through an
exact manifest index, never string concatenation. Atomic writes use same-filesystem
temporary files, restrictive creation modes, file and directory sync, and
descriptor-based replacement. Unexpected mounts, symlinks, hard-link identity
changes, or inode/metadata changes cause rejection.

## Audit records

The helper writes an append-only, root-owned audit event for every rejected,
denied, started, cancelled, timed-out, failed, and successful request. Records
must be structured, size-bounded, safely encoded, and sent to a local protected
system logging facility or an equivalently protected root-owned store. Logging
failure before execution fails closed for every action, including audit and
verification.

Each event includes:

- timestamp, protocol/helper version, request ID, and lifecycle event;
- credential-derived UID, PID, session, and available local seat identity;
- exact protocol action and canonical digest of validated parameters;
- validated module IDs or backup ID where safe to record;
- Polkit action ID and authorization outcome, without authentication secrets;
- executor start state, terminal status, exit code, duration, truncation flag;
- backup ID created/used and rollback attempt/verification outcome;
- stable error code and integrity/consistency-check outcome.

Records must never include shell text, environment contents, authentication
material, full configuration contents, or unbounded stdout/stderr. Request IDs
are correlation values, not proof that two records share an authenticated user.

## Deployment ownership and modes

The helper executable, trusted manifests, module entry points, configuration,
and Polkit policy are installed only by a trusted package/administrator and are
owned by `root:root`. Executables are mode `0755` or stricter; non-executable
policy/manifests are `0644` or stricter; secret-bearing state and backup
manifests are `0600` or stricter. All parent directories are root-owned and not
group/other writable. Runtime state directories use `0700`, runtime files use
`0600`, and no setuid executable is permitted. The service manager starts the
helper with a minimal environment and restrictive hardening appropriate to the
required host operations.

The helper refuses to start if ownership, modes, manifest integrity, IPC name,
required logging, lock storage, or policy integration is unsafe or ambiguous.
It must expose no TCP/UDP listener and make no network request.

## Fail-closed state machine

The required order is: decode and size-check; validate exact schema; derive peer
identity; validate identifiers against trusted manifests; acquire the operation
lock; verify deployment and target integrity; obtain the exact Polkit
authorization; create/validate a rollback point when mutating; execute one fixed
allowlisted operation; verify post-state; write audit outcome; return a bounded
terminal response.

Failure at any stage prevents later stages. In particular, validation and
authorization failure cannot reach an executor; backup failure cannot reach a
mutation; post-state uncertainty cannot produce `succeeded`; audit failure
cannot be hidden; and exceptions default to a stable failure response after
safe cleanup. There is no fallback to an HTTP service, sudo, a shell, a less-specific
Polkit action, or direct execution by Qt.

## Verification gates

### Gate 1: protocol and helper-core tests with mocks

Before any production executor or policy exists, automated tests must prove:

- exact schema acceptance and rejection, including duplicate/unknown fields,
  wrong JSON types, Unicode confusables, oversized input, and identifier limits;
- all unknown actions, modules, capabilities, backups, and request reuse fail
  before executor invocation;
- each action requests only its corresponding Polkit action for the
  credential-derived peer, and all denial/error/session-change cases fail closed;
- no caller value becomes a path, executable, argument vector, environment,
  working directory, file descriptor, network destination, or shell input;
- output, errors, progress, audit records, lists, concurrency, and time are
  bounded; truncation is explicit;
- timeout, cancellation, disconnect, process-tree cleanup, locking, and audit
  lifecycle behavior are deterministic;
- backup-before-mutation and manifest integrity gates hold; partial/failed
  rollback is never reported as success;
- filesystem race, symlink, hard-link, ownership, mode, and manifest-change
  simulations fail closed.

Tests use injected authorizer, executor, clock, credential provider, filesystem,
logger, and process controller fakes. They run without root and must not invoke
LSMF Bash modules or modify the host.

### Disposable Linux VM integration

Packaged artifacts may be tested only after a separate implementation/install
plan is approved for a disposable Linux VM snapshot. Verify real IPC peer
credentials, local/remote and active/inactive session behavior, Polkit denial and
per-action prompts, ownership/mode refusal, service hardening, clean environment,
no network listener, cancellation, timeout cleanup, crash recovery, reboot
recovery, concurrent requests, backup integrity, apply idempotency, verification,
and rollback restoration. Use synthetic fixture targets first, then supported
distribution images. Revert the VM snapshot after each destructive scenario.

No production workstation, user data, or live system configuration may be used
for these tests. Passing mocks is not evidence that host hardening or rollback
works; passing one VM image is not evidence of cross-distribution support.

## Qt integration status

Qt exposes audit, one-module verification, one-module apply, the exact bounded
module-pair apply, and exact backup rollback after their Section 1–3 gates.
Each action shows the target and privilege impact, requires confirmation,
reports authorization/error states, and returns bounded terminal output. Qt
remains unprivileged, generic paths and commands are unavailable, mutable
Cancel remains disabled, and no browser fallback exists.
