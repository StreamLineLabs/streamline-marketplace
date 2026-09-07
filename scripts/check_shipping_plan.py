#!/usr/bin/env python3
"""Fail closed unless the current tag has an explicit future shipping plan."""

from __future__ import annotations

import argparse
import sys

import validate_registry as vr


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--tag", required=True)
    parser.add_argument("--selection", default="registry/shipping.json")
    args = parser.parse_args(argv)

    plan = vr.ReleasePlan.from_file(args.selection, args.tag)
    if plan.errors:
        for error in plan.errors:
            print(f"ERROR: {error}", file=sys.stderr)
        print(
            "ERROR: current source is not releasable under an existing historical tag; "
            "coordinate a workspace/CLI version bump and future shipping plan first",
            file=sys.stderr,
        )
        return 1
    print(f"{args.tag}: explicit future shipping plan contains {len(plan.by_key)} WASM item(s)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
