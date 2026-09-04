#!/usr/bin/env python3
"""Require a release tag to equal both the workspace and CLI package version."""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
import tomllib
from pathlib import Path

TAG_RE = re.compile(r"^v([0-9]+\.[0-9]+\.[0-9]+(?:[-+][0-9A-Za-z.-]+)?)$")
CLI_PACKAGE = "streamline-marketplace-cli"


def release_versions(tag, metadata, workspace_version):
    errors = []
    match = TAG_RE.match(tag)
    if not match:
        return [f"release tag '{tag}' is not a canonical vX.Y.Z tag"]
    tag_version = match.group(1)

    cli_versions = {
        package["version"]
        for package in metadata.get("packages", [])
        if package.get("name") == CLI_PACKAGE
    }
    if len(cli_versions) != 1:
        errors.append(
            f"cargo metadata must contain exactly one {CLI_PACKAGE} package; "
            f"found {sorted(cli_versions)}"
        )
        return errors
    cli_version = next(iter(cli_versions))

    if workspace_version != tag_version:
        errors.append(
            f"release tag {tag} does not match workspace version {workspace_version}"
        )
    if cli_version != tag_version:
        errors.append(f"release tag {tag} does not match CLI version {cli_version}")
    return errors


def check_release_version(tag, repo_root=Path(".")):
    repo_root = Path(repo_root)
    command = [
        "cargo",
        "metadata",
        "--locked",
        "--no-deps",
        "--format-version",
        "1",
    ]
    try:
        result = subprocess.run(
            command,
            cwd=repo_root,
            check=True,
            capture_output=True,
            text=True,
        )
        metadata = json.loads(result.stdout)
        root_manifest = tomllib.loads(
            (repo_root / "Cargo.toml").read_text(encoding="utf-8")
        )
        workspace_version = root_manifest["workspace"]["package"]["version"]
    except (OSError, KeyError, json.JSONDecodeError, subprocess.CalledProcessError) as exc:
        return [f"failed to resolve locked Cargo release metadata: {exc}"]
    return release_versions(tag, metadata, workspace_version)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--tag", required=True)
    args = parser.parse_args(argv)

    errors = check_release_version(args.tag)
    if errors:
        for error in errors:
            print(f"ERROR: {error}", file=sys.stderr)
        return 1
    print(f"{args.tag}: workspace and {CLI_PACKAGE} versions match")
    return 0


if __name__ == "__main__":
    sys.exit(main())
