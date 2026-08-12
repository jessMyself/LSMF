"""Private fixed-configuration worker for Section 3 sysctl transactions."""

from __future__ import annotations

import argparse
import os
import signal
import sys

from .production_protocol import MAX_REQUEST_BYTES, decode_request, encode_result
from .synthetic_executor import CancellationToken
from .sysctl_manifest import load_sysctl_manifest
from .sysctl_transaction import (
    ProcSysctlValues,
    RootedManagedFiles,
    SysctlBackupStore,
    SysctlTransactionExecutor,
)


def _arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument("--manifest", required=True)
    parser.add_argument("--target-root", required=True)
    parser.add_argument("--sysctl-root", required=True)
    parser.add_argument("--backup-root", required=True)
    parser.add_argument("--expected-uid", required=True, type=int)
    return parser.parse_args()


def main() -> int:
    arguments = _arguments()
    token = CancellationToken()
    signal.signal(signal.SIGTERM, lambda _signum, _frame: token.cancel())
    signal.signal(signal.SIGUSR1, lambda _signum, _frame: token.cancel(timed_out=True))
    payload = sys.stdin.buffer.read(MAX_REQUEST_BYTES + 1)
    request = decode_request(payload)
    manifest = load_sysctl_manifest(arguments.manifest, expected_uid=arguments.expected_uid)
    executor = SysctlTransactionExecutor(
        manifest,
        RootedManagedFiles(arguments.target_root, expected_uid=arguments.expected_uid),
        ProcSysctlValues(arguments.sysctl_root),
        SysctlBackupStore(arguments.backup_root, expected_uid=arguments.expected_uid),
    )
    sys.stdout.buffer.write(encode_result(executor.execute(request, token)).encode("utf-8"))
    sys.stdout.buffer.flush()
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception:
        os._exit(1)
