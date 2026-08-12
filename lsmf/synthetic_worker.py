"""Private fixed-configuration worker for the synthetic filesystem engine."""

from __future__ import annotations

import argparse
import os
import signal
import sys

from lsmf.production_protocol import MAX_REQUEST_BYTES, decode_request, encode_result
from lsmf.synthetic_executor import CancellationToken, SyntheticExecutor
from lsmf.trusted_manifest import load_trusted_manifest


def _arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument("--manifest", required=True)
    parser.add_argument("--target-root", required=True)
    parser.add_argument("--backup-root", required=True)
    parser.add_argument("--expected-uid", required=True, type=int)
    return parser.parse_args()


def main() -> int:
    arguments = _arguments()
    token = CancellationToken()

    def cancel(_signum: int, _frame: object) -> None:
        token.cancel()

    def time_out(_signum: int, _frame: object) -> None:
        token.cancel(timed_out=True)

    signal.signal(signal.SIGTERM, cancel)
    signal.signal(signal.SIGUSR1, time_out)
    payload = sys.stdin.buffer.read(MAX_REQUEST_BYTES + 1)
    request = decode_request(payload)
    manifest = load_trusted_manifest(arguments.manifest, expected_uid=arguments.expected_uid)
    executor = SyntheticExecutor(
        manifest,
        arguments.target_root,
        arguments.backup_root,
        expected_uid=arguments.expected_uid,
    )
    result = executor.execute(request, token)
    encoded = encode_result(result).encode("utf-8")
    sys.stdout.buffer.write(encoded)
    sys.stdout.buffer.flush()
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception:
        # The parent treats every missing terminal result as uncertain and
        # persists recovery-required; worker details never cross the boundary.
        os._exit(1)
