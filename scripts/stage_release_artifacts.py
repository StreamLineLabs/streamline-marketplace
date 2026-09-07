#!/usr/bin/env python3
"""Stage only the catalog entries explicitly selected for one release tag."""

from __future__ import annotations

import argparse
import json
import shutil
import sys
from pathlib import Path

import validate_registry as vr


def load_catalog(path):
    try:
        data = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        return None, [f"{path}: cannot be read as JSON: {exc}"]
    if not isinstance(data, list):
        return None, [f"{path}: expected a JSON array"]
    return data, []


def stage_release(catalog_path, selection_path, tag, build_dir, output_dir):
    """Copy the exact selected assets, returning a list of validation errors."""
    plan = vr.ReleasePlan.from_file(selection_path, tag)
    errors = list(plan.errors)
    catalog, catalog_errors = load_catalog(catalog_path)
    errors.extend(catalog_errors)
    if errors:
        return errors, 0

    by_key = {}
    for entry in catalog:
        if not isinstance(entry, dict):
            continue
        key = (entry.get("name"), entry.get("version"))
        by_key.setdefault(key, []).append(entry)

    build_dir = Path(build_dir)
    output_dir = Path(output_dir)
    staged = 0

    for key, item in plan.by_key.items():
        matches = by_key.get(key, [])
        label = f"{item['name']}@{item['version']}"
        if len(matches) != 1:
            errors.append(
                f"{label}: expected exactly one matching catalog entry, found {len(matches)}"
            )
            continue

        entry = matches[0]
        release_tag, url_asset, identity_error = vr.release_coordinates(entry)
        if identity_error is not None:
            errors.append(f"{label}: {identity_error}")
            continue
        if release_tag != tag:
            errors.append(
                f"{label}: selected for {tag}, but wasm_url targets {release_tag}"
            )
        if url_asset != item["asset"]:
            errors.append(
                f"{label}: selection names '{item['asset']}', but wasm_url names "
                f"'{url_asset}'"
            )
        checksum_valid = bool(vr.SHA256_RE.match(entry.get("checksum", "")))
        if not checksum_valid:
            errors.append(
                f"{label}: selected shipping entry must carry a real sha256 digest"
            )

        source = build_dir / item["asset"]
        if not source.is_file():
            errors.append(f"{label}: built artifact '{source}' does not exist")
            continue
        if release_tag != tag or url_asset != item["asset"] or not checksum_valid:
            continue

        output_dir.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source, output_dir / item["asset"])
        staged += 1

    return errors, staged


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--tag", required=True)
    parser.add_argument("--build-dir", required=True)
    parser.add_argument("--output-dir", required=True)
    parser.add_argument("--catalog", default="registry/transforms.json")
    parser.add_argument("--selection", default="registry/shipping.json")
    args = parser.parse_args(argv)

    errors, staged = stage_release(
        args.catalog,
        args.selection,
        args.tag,
        args.build_dir,
        args.output_dir,
    )
    if errors:
        for error in errors:
            print(f"ERROR: {error}", file=sys.stderr)
        return 1

    print(f"{args.tag}: staged {staged} explicitly selected WASM artifact(s)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
