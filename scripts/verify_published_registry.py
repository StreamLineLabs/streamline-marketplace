#!/usr/bin/env python3
"""Verify the live catalog against artifacts actually published on GitHub."""

from __future__ import annotations

import argparse
import json
import shutil
import sys
import urllib.error
import urllib.request
from pathlib import Path

import validate_registry as vr


def load_json(path, description):
    path = Path(path)
    try:
        return json.loads(path.read_text(encoding="utf-8")), []
    except (OSError, json.JSONDecodeError) as exc:
        return None, [f"{path}: cannot be read as {description}: {exc}"]


def catalog_by_key(catalog):
    entries = {}
    for entry in catalog:
        if not isinstance(entry, dict):
            continue
        key = (entry.get("name"), entry.get("version"))
        entries.setdefault(key, []).append(entry)
    return entries


def published_manifest_errors(catalog, plan):
    """Require immutable manifest URL/checksum fields to equal the live catalog."""
    entries = catalog_by_key(catalog)
    errors = []
    for key, item in plan.by_key.items():
        label = f"{item['name']}@{item['version']}"
        manifest_url = item.get("url")
        manifest_checksum = item.get("checksum")
        if not isinstance(manifest_url, str) or not manifest_url:
            errors.append(f"{label}: published manifest is missing its immutable URL")
        if not isinstance(manifest_checksum, str) or not vr.SHA256_RE.match(
            manifest_checksum
        ):
            errors.append(f"{label}: published manifest is missing its immutable checksum")

        matches = entries.get(key, [])
        if len(matches) != 1:
            errors.append(
                f"{label}: expected exactly one matching live catalog entry, found "
                f"{len(matches)}"
            )
            continue
        entry = matches[0]
        if manifest_url != entry.get("wasm_url"):
            errors.append(f"{label}: live catalog URL differs from the published manifest")
        if manifest_checksum != entry.get("checksum"):
            errors.append(
                f"{label}: live catalog checksum differs from the published manifest"
            )
    return errors


def download_selected(catalog, plan, destination):
    """Download exactly one published artifact for every manifest record."""
    entries = catalog_by_key(catalog)
    destination = Path(destination)
    destination.mkdir(parents=True, exist_ok=True)
    errors = []

    for key, item in plan.by_key.items():
        matches = entries.get(key, [])
        label = f"{item['name']}@{item['version']}"
        if len(matches) != 1:
            errors.append(
                f"{label}: expected exactly one matching live catalog entry, found "
                f"{len(matches)}"
            )
            continue

        entry = matches[0]
        tag, asset, identity_error = vr.release_coordinates(entry)
        if identity_error is not None:
            errors.append(f"{label}: {identity_error}")
            continue
        if tag != plan.expected_tag or asset != item["asset"]:
            errors.append(
                f"{label}: published manifest expects {plan.expected_tag}/{item['asset']}, "
                f"but the live catalog URL targets {tag}/{asset}"
            )
            continue

        request = urllib.request.Request(
            entry["wasm_url"],
            headers={"User-Agent": "streamline-marketplace-release-verifier"},
        )
        target = destination / item["asset"]
        try:
            with urllib.request.urlopen(request, timeout=60) as response, target.open(
                "wb"
            ) as output:
                shutil.copyfileobj(response, output)
        except (OSError, urllib.error.URLError) as exc:
            errors.append(f"{label}: failed to download {entry['wasm_url']}: {exc}")
            target.unlink(missing_ok=True)
            continue
        if target.stat().st_size == 0:
            errors.append(f"{label}: downloaded artifact '{target}' is empty")

    return errors


def verify_published(catalog_path, manifest_path, artifacts=None, work_dir=None):
    """Verify all immutable published manifests, returning a list of errors."""
    catalog, errors = load_json(catalog_path, "a catalog")
    manifests, manifest_errors = load_json(manifest_path, "published release metadata")
    errors.extend(manifest_errors)
    if errors:
        return errors
    if not isinstance(catalog, list):
        return [f"{catalog_path}: expected a JSON array"]
    if not isinstance(manifests, dict) or not manifests:
        return [f"{manifest_path}: expected a non-empty JSON object keyed by release tag"]

    work_dir = Path(work_dir) if work_dir is not None else None
    artifacts = Path(artifacts) if artifacts is not None else None
    verified = 0

    if work_dir is not None:
        shutil.rmtree(work_dir, ignore_errors=True)
        work_dir.mkdir(parents=True)

    for tag in sorted(manifests):
        plan = vr.ReleasePlan.from_file(manifest_path, tag)
        errors.extend(plan.errors)
        if plan.errors:
            continue
        identity_errors = published_manifest_errors(catalog, plan)
        errors.extend(identity_errors)
        if identity_errors:
            continue

        if artifacts is not None:
            tag_dir = artifacts / tag
            artifact_dir = tag_dir if tag_dir.is_dir() else artifacts
        else:
            artifact_dir = work_dir / tag
            download_errors = download_selected(catalog, plan, artifact_dir)
            errors.extend(download_errors)
            if download_errors:
                continue

        index = vr.ArtifactIndex([artifact_dir])
        errors.extend(index.errors)
        validation_errors, _ = vr.validate(
            Path(catalog_path),
            vr.RELEASE,
            index,
            plan,
        )
        validation_errors.extend(plan.missing_errors())
        validation_errors.extend(index.unreferenced_errors())
        if validation_errors:
            errors.extend(validation_errors)
            continue

        print(
            f"{tag}: verified {index.bound_entries}/{len(plan.by_key)} live catalog "
            "entries against published artifact bytes"
        )
        verified += index.bound_entries

    if verified == 0:
        errors.append("no published WASM artifacts were verified")
    return errors


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--catalog", default="registry/transforms.json")
    parser.add_argument("--manifest", default="registry/published-releases.json")
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument("--artifacts", metavar="DIR")
    source.add_argument("--download", action="store_true")
    parser.add_argument("--work-dir", default="target/published-registry-verification")
    args = parser.parse_args(argv)

    errors = verify_published(
        args.catalog,
        args.manifest,
        artifacts=args.artifacts,
        work_dir=args.work_dir if args.download else None,
    )
    if errors:
        for error in errors:
            print(f"ERROR: {error}", file=sys.stderr)
        return 1
    print("Published registry verification passed.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
