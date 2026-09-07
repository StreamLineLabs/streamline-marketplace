#!/usr/bin/env python3
"""Validate the marketplace transform catalog.

Three modes, ordered from cheapest to most authoritative:

* ``--mode structural`` (default) — pre-artifact validation. Every entry must
  carry all required fields, and each checksum must be either a canonical
  ``sha256:<64 hex>`` digest or the explicit ``pending`` sentinel used for
  transforms whose release artifact does not exist yet. This mode is
  deterministic and never depends on built or published artifacts.

* ``--mode digests`` — advisory, artifact-free audit answering one question:
  "does every catalog entry already carry a real digest?" Any ``pending`` entry
  fails. It proves nothing about the bytes behind a digest, and a catalog that
  legitimately still lists unimplemented transforms fails it by construction,
  so it is never a release gate and no workflow blocks on it.

* ``--mode release`` — authoritative release gate. Requires ``--artifacts DIR``
  (repeatable), ``--expected-tag vX.Y.Z``, and an explicit shipping selection
  supplied by ``--selection FILE`` or repeatable ``--ship`` arguments. The
  binding is two-way:

  1. Every selected entry must exist at the selected catalog version, use the
     expected GitHub release tag and selected asset basename in ``wasm_url``,
     carry a real ``sha256:<64 hex>`` digest, and map unambiguously to exactly
     one staged artifact whose bytes hash to that digest.
  2. Entries not selected for this tag — including entries intentionally
     targeting older releases — are not republished and do not require an
     artifact in this release. A selected ``pending`` entry is always a hard
     failure.
  3. Every staged ``*.wasm`` artifact must be referenced by at least one catalog
     entry in the explicit selection, so a module cannot be signed and
     published accidentally or under an older release's metadata. Native
     release binaries (the CLI) are deliberately out of scope: they are
     published alongside the catalog and are covered by the release manifest,
     signatures, and provenance instead.

The shipping selection is keyed by catalog ``name`` + ``version`` and records
the exact release asset basename. Release URLs must use the canonical
``https://github.com/streamlinelabs/streamline-marketplace/releases/download/``
path. Binding therefore covers catalog identity, URL tag, basename, and bytes;
an entry for an older tag or an unrelated same-named file cannot satisfy the
current release.

Exit status is 0 on success and 1 when any entry fails validation.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from pathlib import Path
from urllib.parse import unquote, urlsplit

REQUIRED_FIELDS = (
    "name",
    "version",
    "description",
    "author",
    "wasm_url",
    "categories",
    "min_streamline_version",
    "checksum",
)

PENDING = "pending"
PENDING_VALUES = (PENDING, "sha256:pending")
SHA256_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
RELEASE_TAG_RE = re.compile(r"^v[0-9]+\.[0-9]+\.[0-9]+(?:[-+][0-9A-Za-z.-]+)?$")
RELEASE_URL_PREFIX = ("streamlinelabs", "streamline-marketplace", "releases", "download")

# Only WebAssembly modules are published *through* the catalog. Native release
# binaries (the `streamline-marketplace` CLI) ship alongside it and are covered
# by the release manifest, cosign signatures, and provenance, so they are
# exempt from the "every staged artifact must be in the catalog" rule.
CATALOG_ARTIFACT_SUFFIX = ".wasm"

STRUCTURAL = "structural"
DIGESTS = "digests"
RELEASE = "release"
MODES = (STRUCTURAL, DIGESTS, RELEASE)

# Read in chunks so a large native binary never has to be resident in memory.
_HASH_CHUNK = 1024 * 1024


def release_coordinates(entry):
    """Return ``(tag, asset, error)`` from a canonical GitHub release URL."""
    url = entry.get("wasm_url")
    if not isinstance(url, str) or not url:
        return None, None, "wasm_url is missing, so release identity cannot be verified"

    parsed = urlsplit(url)
    if parsed.scheme != "https" or parsed.netloc != "github.com":
        return None, None, (
            f"wasm_url '{url}' must use https://github.com/streamlinelabs/"
            "streamline-marketplace/releases/download/<tag>/<asset>"
        )
    if parsed.query or parsed.fragment:
        return None, None, f"wasm_url '{url}' must not contain a query or fragment"

    segments = tuple(unquote(segment) for segment in parsed.path.split("/") if segment)
    if len(segments) != 6 or segments[:4] != RELEASE_URL_PREFIX:
        return None, None, (
            f"wasm_url '{url}' is not a canonical Streamline Marketplace release URL"
        )

    tag, asset = segments[4], segments[5]
    if not RELEASE_TAG_RE.match(tag):
        return None, None, f"wasm_url release tag '{tag}' is not a canonical vX.Y.Z tag"
    if not asset or asset in (".", "..") or "/" in asset or "\\" in asset:
        return None, None, f"wasm_url '{url}' yields an unusable release asset '{asset}'"
    return tag, asset, None


def parse_shipping_spec(spec):
    """Parse ``name@version=asset.wasm`` into a selection record."""
    try:
        identity, asset = spec.rsplit("=", 1)
        name, version = identity.rsplit("@", 1)
    except ValueError:
        return None, (
            f"invalid --ship value '{spec}'; expected name@version=asset.wasm"
        )
    record = {"name": name.strip(), "version": version.strip(), "asset": asset.strip()}
    return record, None


class ReleasePlan:
    """Explicit catalog entries and asset names shipping under one release tag."""

    def __init__(self, expected_tag, records):
        self.expected_tag = expected_tag
        self.by_key = {}
        self.by_asset = {}
        self.found = set()
        self.errors = []

        if not isinstance(expected_tag, str) or not RELEASE_TAG_RE.match(expected_tag):
            self.errors.append(
                f"expected release tag '{expected_tag}' is not a canonical vX.Y.Z tag"
            )

        if not isinstance(records, list):
            self.errors.append("release selection must be a JSON array")
            return

        for position, record in enumerate(records):
            label = f"release selection item #{position}"
            if not isinstance(record, dict):
                self.errors.append(f"{label} is not a JSON object")
                continue

            name = record.get("name")
            version = record.get("version")
            asset = record.get("asset")
            if not all(isinstance(value, str) and value.strip() for value in (name, version, asset)):
                self.errors.append(f"{label} requires non-empty name, version, and asset strings")
                continue
            name, version, asset = name.strip(), version.strip(), asset.strip()
            if Path(asset).name != asset or not asset.endswith(CATALOG_ARTIFACT_SUFFIX):
                self.errors.append(
                    f"{label} asset '{asset}' must be a .wasm basename without directories"
                )
                continue

            key = (name, version)
            if key in self.by_key:
                self.errors.append(f"duplicate release selection for {name}@{version}")
                continue
            if asset in self.by_asset:
                other = self.by_asset[asset]
                self.errors.append(
                    f"release asset '{asset}' is selected by both "
                    f"{other['name']}@{other['version']} and {name}@{version}"
                )
                continue

            item = {"name": name, "version": version, "asset": asset}
            for optional in ("url", "checksum"):
                if optional in record:
                    item[optional] = record[optional]
            self.by_key[key] = item
            self.by_asset[asset] = item

    @classmethod
    def from_file(cls, path, expected_tag):
        path = Path(path)
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            plan = cls(expected_tag, [])
            plan.errors.append(f"{path}: cannot be read as a release selection: {exc}")
            return plan

        if not isinstance(data, dict):
            plan = cls(expected_tag, [])
            plan.errors.append(f"{path}: release selection must be a JSON object keyed by tag")
            return plan
        if expected_tag not in data:
            plan = cls(expected_tag, [])
            plan.errors.append(
                f"{path}: no explicit shipping selection exists for {expected_tag}"
            )
            return plan
        return cls(expected_tag, data[expected_tag])

    @classmethod
    def from_specs(cls, expected_tag, specs):
        records = []
        errors = []
        for spec in specs:
            record, error = parse_shipping_spec(spec)
            if error is not None:
                errors.append(error)
            else:
                records.append(record)
        plan = cls(expected_tag, records)
        plan.errors.extend(errors)
        return plan

    def item_for(self, entry):
        return self.by_key.get((entry.get("name"), entry.get("version")))

    def mark_found(self, item):
        self.found.add((item["name"], item["version"]))

    def missing_errors(self):
        return [
            (
                f"release selection requires {item['name']}@{item['version']} as "
                f"'{item['asset']}', but that catalog entry was not found"
            )
            for key, item in self.by_key.items()
            if key not in self.found
        ]


def sha256_of(path):
    """Return ``sha256:<hex>`` for the bytes of ``path``."""
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(_HASH_CHUNK), b""):
            digest.update(chunk)
    return f"sha256:{digest.hexdigest()}"


class ArtifactIndex:
    """Deterministic basename -> staged artifact mapping.

    Directories are walked recursively and sorted, so the same tree always
    produces the same index. A basename that resolves to more than one file is
    kept as a collision and reported as ambiguous rather than resolved by an
    arbitrary precedence rule.

    The index also records which staged asset names the catalog referenced, so
    release validation can close the loop in both directions: no catalog entry
    without an artifact, and no staged WASM artifact without a catalog entry.
    """

    def __init__(self, roots):
        self.roots = [Path(root) for root in roots]
        self.by_name = {}
        self.errors = []
        self.referenced = set()
        self.bound_entries = 0
        self._digests = {}

        for root in self.roots:
            if not root.exists():
                self.errors.append(f"artifact directory '{root}' does not exist")
                continue
            if not root.is_dir():
                self.errors.append(f"artifact path '{root}' is not a directory")
                continue
            for path in sorted(root.rglob("*")):
                if path.is_file():
                    self.by_name.setdefault(path.name, []).append(path)

    def describe_roots(self):
        return ", ".join(str(root) for root in self.roots)

    def mark_referenced(self, name):
        """Record that a catalog entry maps to the release asset ``name``."""
        self.referenced.add(name)

    def resolve(self, name):
        """Return ``(path, error)`` for a release-asset basename."""
        matches = self.by_name.get(name, [])
        if not matches:
            return None, (
                f"expected release artifact '{name}' was not found under "
                f"{self.describe_roots()}; an entry carrying a real sha256 digest must "
                f"map to an artifact staged in this release (use '{PENDING}' only for a "
                "transform this release does not ship)"
            )
        if len(matches) > 1:
            listed = ", ".join(str(match) for match in matches)
            return None, (
                f"release artifact '{name}' is ambiguous: {len(matches)} candidates "
                f"({listed})"
            )
        return matches[0], None

    def unreferenced_errors(self):
        """Errors for staged catalog artifacts that no catalog entry claims.

        A WASM module that is built, staged, signed, and published without a
        catalog entry is an unbound artifact: nothing pins its bytes, so it is
        rejected rather than shipped silently.
        """
        errors = []
        for name, paths in sorted(self.by_name.items()):
            if not name.lower().endswith(CATALOG_ARTIFACT_SUFFIX):
                continue
            if name in self.referenced:
                continue
            listed = ", ".join(str(path) for path in paths)
            errors.append(
                f"staged release artifact '{name}' ({listed}) is not referenced by any "
                "catalog entry; every staged WASM artifact must be published through "
                "the catalog"
            )
        return errors

    def digest(self, path):
        cached = self._digests.get(path)
        if cached is None:
            cached = sha256_of(path)
            self._digests[path] = cached
        return cached


def artifact_name_for(entry):
    """Return ``(basename, error)`` derived from an entry's ``wasm_url``."""
    url = entry.get("wasm_url")
    if not isinstance(url, str) or not url:
        return None, "wasm_url is missing, so no release artifact can be identified"

    path = urlsplit(url).path
    name = unquote(path).rsplit("/", 1)[-1].strip()
    if not name or name in (".", ".."):
        return None, f"wasm_url '{url}' does not end in a release asset name"
    if "/" in name or "\\" in name:
        return None, f"wasm_url '{url}' yields an unusable release asset name '{name}'"
    return name, None


def validate_entry(entry, label, mode, index, plan=None):
    """Validate one catalog entry, returning a list of error strings."""
    errors = []

    for field in REQUIRED_FIELDS:
        if field not in entry or entry[field] in ("", [], None):
            errors.append(f"{label}: missing required field '{field}'")

    checksum = entry.get("checksum", "")
    checksum_is_digest = False
    checksum_is_pending = False
    if not isinstance(checksum, str):
        errors.append(f"{label}: checksum must be a string")
    elif SHA256_RE.match(checksum):
        checksum_is_digest = True
    elif checksum in PENDING_VALUES:
        checksum_is_pending = True
        if mode == DIGESTS:
            errors.append(
                f"{label}: checksum is '{checksum}' — the digest audit requires the "
                "real sha256 digest of the published artifact"
            )
    else:
        errors.append(
            f"{label}: checksum '{checksum}' is neither 'sha256:<64 hex>' nor '{PENDING}'"
        )

    if mode != RELEASE:
        return errors

    item = plan.item_for(entry)
    if item is None:
        # This catalog entry belongs to another release or is not shipping. It
        # remains structurally checked above but must not require or claim any
        # artifact staged for the current tag.
        return errors

    plan.mark_found(item)
    index.mark_referenced(item["asset"])

    tag, url_asset, identity_error = release_coordinates(entry)
    if identity_error is not None:
        errors.append(f"{label}: {identity_error}")
    else:
        if tag != plan.expected_tag:
            errors.append(
                f"{label}: selected for {plan.expected_tag}, but wasm_url targets "
                f"older/different release tag {tag}"
            )
        if url_asset != item["asset"]:
            errors.append(
                f"{label}: release selection expects asset '{item['asset']}', but "
                f"wasm_url names '{url_asset}'"
            )

    if checksum_is_pending:
        errors.append(
            f"{label}: selected for {plan.expected_tag} as '{item['asset']}', but "
            f"checksum is '{checksum}'; every shipping artifact needs its real digest"
        )
        return errors
    if not checksum_is_digest:
        return errors

    path, resolve_error = index.resolve(item["asset"])
    if resolve_error is not None:
        errors.append(f"{label}: {resolve_error}")
        return errors

    actual = index.digest(path)
    if actual != checksum:
        errors.append(
            f"{label}: checksum {checksum} does not match staged release artifact "
            f"{path} ({actual})"
        )
        return errors

    index.bound_entries += 1
    return errors


def validate(path, mode, index=None, plan=None):
    errors = []
    if mode == RELEASE and plan is None:
        return ["release validation requires an explicit ReleasePlan"], 0
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        return [f"{path}: cannot be read as JSON: {exc}"], 0

    if not isinstance(data, list):
        return [f"{path}: expected a JSON array of transform entries"], 0

    seen = set()
    for index_position, entry in enumerate(data):
        label = (
            entry.get("name", f"#{index_position}")
            if isinstance(entry, dict)
            else f"#{index_position}"
        )
        if not isinstance(entry, dict):
            errors.append(f"{label}: entry is not a JSON object")
            continue

        key = (entry.get("name", ""), entry.get("version", ""))
        if key in seen:
            errors.append(f"{label}: duplicate name/version pair {key}")
        seen.add(key)

        errors.extend(validate_entry(entry, label, mode, index, plan))

    return errors, len(data)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "paths",
        nargs="*",
        help="catalog files (default: registry/transforms.json)",
    )
    parser.add_argument("--mode", choices=MODES, default=STRUCTURAL)
    parser.add_argument(
        "--artifacts",
        action="append",
        default=[],
        metavar="DIR",
        help=(
            "directory of release artifacts staged for this release; required in "
            "release mode and repeatable"
        ),
    )
    parser.add_argument(
        "--expected-tag",
        help="release tag whose selected artifacts are being published (for example v0.4.0)",
    )
    parser.add_argument(
        "--selection",
        metavar="FILE",
        help="JSON file keyed by release tag with explicit name/version/asset selections",
    )
    parser.add_argument(
        "--ship",
        action="append",
        default=[],
        metavar="NAME@VERSION=ASSET",
        help="inline shipping selection; repeatable and mutually exclusive with --selection",
    )
    args = parser.parse_args(argv)

    if args.mode == RELEASE and not args.artifacts:
        parser.error("--mode release requires at least one --artifacts DIR")
    if args.mode != RELEASE and args.artifacts:
        parser.error(f"--artifacts is only meaningful with --mode {RELEASE}")
    if args.mode == RELEASE and not args.expected_tag:
        parser.error("--mode release requires --expected-tag vX.Y.Z")
    if args.mode == RELEASE and not args.selection and not args.ship:
        parser.error("--mode release requires --selection FILE or at least one --ship value")
    if args.selection and args.ship:
        parser.error("--selection and --ship are mutually exclusive")
    if args.mode != RELEASE and (args.expected_tag or args.selection or args.ship):
        parser.error(
            f"--expected-tag/--selection/--ship are only meaningful with --mode {RELEASE}"
        )

    repo_root = Path(__file__).resolve().parent.parent
    paths = [Path(p) for p in (args.paths or [repo_root / "registry" / "transforms.json"])]

    index = None
    plan = None
    if args.mode == RELEASE:
        plan = (
            ReleasePlan.from_file(args.selection, args.expected_tag)
            if args.selection
            else ReleasePlan.from_specs(args.expected_tag, args.ship)
        )
        if plan.errors:
            for error in plan.errors:
                print(f"ERROR: {error}", file=sys.stderr)
            return 1

        index = ArtifactIndex(args.artifacts)
        if index.errors:
            for error in index.errors:
                print(f"ERROR: {error}", file=sys.stderr)
            return 1
        if not index.by_name:
            print(
                f"ERROR: no release artifacts found under {index.describe_roots()}",
                file=sys.stderr,
            )
            return 1

    failed = False
    results = []
    for path in paths:
        errors, count = validate(path, args.mode, index, plan)
        results.append((path, count))
        if errors:
            failed = True
            for error in errors:
                print(f"ERROR: {error}", file=sys.stderr)

    # Reverse binding runs once, after every catalog has had a chance to claim
    # a staged asset name, so splitting the catalog across files stays valid.
    if args.mode == RELEASE:
        for error in plan.missing_errors():
            failed = True
            print(f"ERROR: {error}", file=sys.stderr)
        for error in index.unreferenced_errors():
            failed = True
            print(f"ERROR: {error}", file=sys.stderr)

    if failed:
        return 1

    for path, count in results:
        print(f"{path}: valid ({args.mode} mode, {count} transforms)")

    if args.mode == RELEASE:
        staged_modules = sum(
            1 for name in index.by_name if name.lower().endswith(CATALOG_ARTIFACT_SUFFIX)
        )
        print(
            f"release binding for {plan.expected_tag}: {index.bound_entries}/"
            f"{len(plan.by_key)} explicitly selected entries bound to staged artifact "
            f"bytes under {index.describe_roots()}, {staged_modules} staged WASM artifacts "
            "all referenced by the shipping selection"
        )

    return 0


if __name__ == "__main__":
    sys.exit(main())
