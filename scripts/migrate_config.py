#!/usr/bin/env python3
"""Migrate the legacy mixed LSMF configuration to the canonical flat schema."""

from __future__ import annotations

import argparse
from pathlib import Path
import shutil
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from lsmf.configuration import ConfigError, parse_legacy_mixed, write_config_atomic


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("config", type=Path, help="configuration file to migrate in place")
    parser.add_argument("--check", action="store_true", help="validate migration without writing")
    args = parser.parse_args()

    try:
        values = parse_legacy_mixed(args.config)
        if args.check:
            print(f"Valid legacy configuration: {len(values)} settings")
            return 0
        backup = args.config.with_suffix(args.config.suffix + ".legacy.bak")
        if backup.exists():
            raise ConfigError(f"refusing to overwrite existing backup: {backup}")
        shutil.copy2(args.config, backup)
        write_config_atomic(args.config, values)
        print(f"Migrated {len(values)} settings; backup: {backup}")
        return 0
    except (ConfigError, OSError) as error:
        print(f"Migration failed: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
