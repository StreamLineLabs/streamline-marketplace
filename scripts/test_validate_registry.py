#!/usr/bin/env python3
"""Unit tests for scripts/validate_registry.py.

Covers the two-way artifact-binding contract of ``--mode release``: an explicit
name/version/asset shipping selection, canonical URL and expected-tag binding,
hashing staged bytes, ignoring entries not selected for this release, rejecting
selected ``pending`` entries, and rejecting staged WASM modules that no selected
catalog entry references — plus missing, ambiguous, malformed, and
syntactically valid but incorrect digests.

Run with:  python3 -m unittest discover -s scripts
"""

from __future__ import annotations

import hashlib
import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import validate_registry as vr  # noqa: E402
import stage_release_artifacts as stage  # noqa: E402
import check_release_version as release_version  # noqa: E402
import verify_published_registry as published  # noqa: E402

REPO_ROOT = Path(__file__).resolve().parent.parent
FIXTURES = REPO_ROOT / "scripts" / "fixtures"
FIXTURE_ARTIFACTS = FIXTURES / "artifacts"

RELEASE_URL = "https://github.com/streamlinelabs/streamline-marketplace/releases/download/v9.9.9"


def digest_of(data):
    return f"sha256:{hashlib.sha256(data).hexdigest()}"


def entry(name="unit-transform", asset="unit_transform.wasm", checksum="pending", **overrides):
    base = {
        "name": name,
        "version": "0.1.0",
        "description": "unit fixture",
        "author": "streamline-ci",
        "wasm_url": f"{RELEASE_URL}/{asset}",
        "categories": ["filtering"],
        "min_streamline_version": "0.1.0",
        "checksum": checksum,
    }
    base.update(overrides)
    return base


def release_plan(*records, tag="v9.9.9"):
    return vr.ReleasePlan(tag, list(records))


def selected(name="unit-transform", version="0.1.0", asset="unit_transform.wasm"):
    return {"name": name, "version": version, "asset": asset}


def published_record(
    checksum,
    name="unit-transform",
    version="0.1.0",
    asset="unit_transform.wasm",
    tag="v9.9.9",
):
    return {
        **selected(name=name, version=version, asset=asset),
        "url": (
            "https://github.com/streamlinelabs/streamline-marketplace/"
            f"releases/download/{tag}/{asset}"
        ),
        "checksum": checksum,
    }


class ValidatorTestCase(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.tmp = Path(self._tmp.name)
        self.addCleanup(self._tmp.cleanup)

    def write_catalog(self, entries, name="catalog.json"):
        path = self.tmp / name
        path.write_text(json.dumps(entries), encoding="utf-8")
        return path

    def write_artifact(self, name, data, subdir="dist"):
        directory = self.tmp / subdir
        directory.mkdir(parents=True, exist_ok=True)
        path = directory / name
        path.write_bytes(data)
        return path

    def write_selection(self, releases, name="releases.json"):
        path = self.tmp / name
        path.write_text(json.dumps(releases), encoding="utf-8")
        return path

    def run_validate(self, catalog, mode, artifact_dirs=(), plan=None):
        """Validate one catalog the way ``main`` does.

        In release mode that includes the reverse-binding pass, which runs once
        after every catalog has had a chance to claim a staged asset name.
        """
        index = vr.ArtifactIndex([str(d) for d in artifact_dirs]) if artifact_dirs else None
        if mode == vr.RELEASE and plan is None:
            entries = json.loads(Path(catalog).read_text(encoding="utf-8"))
            staged_names = set(index.by_name) if index is not None else set()
            records = {}
            tags = set()
            for entry_value in entries:
                if not isinstance(entry_value, dict):
                    continue
                asset, asset_error = vr.artifact_name_for(entry_value)
                if asset_error is not None:
                    continue
                checksum = entry_value.get("checksum")
                checksum_is_digest = isinstance(checksum, str) and bool(
                    vr.SHA256_RE.match(checksum)
                )
                if not checksum_is_digest and asset not in staged_names:
                    continue
                key = (entry_value.get("name"), entry_value.get("version"))
                records.setdefault(
                    key,
                    {
                        "name": key[0],
                        "version": key[1],
                        "asset": asset,
                    },
                )
                tag, _, identity_error = vr.release_coordinates(entry_value)
                if identity_error is None:
                    tags.add(tag)
            expected_tag = next(iter(tags)) if len(tags) == 1 else "v9.9.9"
            plan = vr.ReleasePlan(expected_tag, list(records.values()))

        errors = list(plan.errors) if mode == vr.RELEASE else []
        validation_errors, count = vr.validate(catalog, mode, index, plan)
        errors.extend(validation_errors)
        if mode == vr.RELEASE and index is not None:
            errors.extend(plan.missing_errors())
            errors.extend(index.unreferenced_errors())
        return errors, count

    def assertNoErrors(self, errors):
        self.assertEqual(errors, [], f"unexpected validation errors: {errors}")

    def assertErrorContains(self, errors, needle):
        self.assertTrue(
            any(needle in error for error in errors),
            f"expected an error containing {needle!r}; got {errors}",
        )


class ArtifactNameTests(ValidatorTestCase):
    def test_basename_is_taken_from_the_release_asset_path(self):
        name, error = vr.artifact_name_for(entry(asset="json_filter.wasm"))
        self.assertIsNone(error)
        self.assertEqual(name, "json_filter.wasm")

    def test_query_and_fragment_are_not_part_of_the_asset_name(self):
        name, error = vr.artifact_name_for(
            {"wasm_url": f"{RELEASE_URL}/json_filter.wasm?token=abc#frag"}
        )
        self.assertIsNone(error)
        self.assertEqual(name, "json_filter.wasm")

    def test_percent_encoding_is_decoded(self):
        name, error = vr.artifact_name_for({"wasm_url": f"{RELEASE_URL}/json%5Ffilter.wasm"})
        self.assertIsNone(error)
        self.assertEqual(name, "json_filter.wasm")

    def test_extensionless_binary_assets_are_supported(self):
        name, error = vr.artifact_name_for(
            {"wasm_url": f"{RELEASE_URL}/streamline-marketplace-cli"}
        )
        self.assertIsNone(error)
        self.assertEqual(name, "streamline-marketplace-cli")

    def test_missing_url_yields_an_error(self):
        name, error = vr.artifact_name_for({})
        self.assertIsNone(name)
        self.assertIn("wasm_url is missing", error)

    def test_directory_url_yields_an_error(self):
        name, error = vr.artifact_name_for({"wasm_url": f"{RELEASE_URL}/"})
        self.assertIsNone(name)
        self.assertIn("does not end in a release asset name", error)

    def test_traversal_segment_is_rejected(self):
        name, error = vr.artifact_name_for({"wasm_url": f"{RELEASE_URL}/.."})
        self.assertIsNone(name)
        self.assertIn("does not end in a release asset name", error)


class ReleaseIdentityTests(ValidatorTestCase):
    def test_canonical_release_url_yields_tag_and_asset(self):
        tag, asset, error = vr.release_coordinates(entry())
        self.assertIsNone(error)
        self.assertEqual(tag, "v9.9.9")
        self.assertEqual(asset, "unit_transform.wasm")

    def test_noncanonical_host_is_rejected(self):
        tag, asset, error = vr.release_coordinates(
            entry(wasm_url="https://example.com/releases/download/v9.9.9/unit_transform.wasm")
        )
        self.assertIsNone(tag)
        self.assertIsNone(asset)
        self.assertIn("must use https://github.com", error)

    def test_query_and_fragment_are_rejected_for_release_identity(self):
        _, _, error = vr.release_coordinates(
            entry(wasm_url=f"{RELEASE_URL}/unit_transform.wasm?download=1")
        )
        self.assertIn("must not contain a query or fragment", error)

    def test_malformed_release_tag_is_rejected(self):
        _, _, error = vr.release_coordinates(
            entry(
                wasm_url=(
                    "https://github.com/streamlinelabs/streamline-marketplace/"
                    "releases/download/latest/unit_transform.wasm"
                )
            )
        )
        self.assertIn("not a canonical vX.Y.Z tag", error)


class ReleasePlanTests(ValidatorTestCase):
    def test_selected_entry_binds_tag_version_asset_and_digest(self):
        payload = b"\x00asm\x01\x00\x00\x00selected"
        self.write_artifact("unit_transform.wasm", payload)
        catalog = self.write_catalog([entry(checksum=digest_of(payload))])
        plan = release_plan(selected())
        index = vr.ArtifactIndex([self.tmp / "dist"])

        errors, _ = vr.validate(catalog, vr.RELEASE, index, plan)
        errors += plan.missing_errors() + index.unreferenced_errors()
        self.assertNoErrors(errors)

    def test_selected_entry_rejects_wrong_url_tag(self):
        payload = b"\x00asm\x01\x00\x00\x00"
        self.write_artifact("unit_transform.wasm", payload)
        catalog = self.write_catalog(
            [
                entry(
                    checksum=digest_of(payload),
                    wasm_url=(
                        "https://github.com/streamlinelabs/streamline-marketplace/"
                        "releases/download/v8.8.8/unit_transform.wasm"
                    ),
                )
            ]
        )
        plan = release_plan(selected())
        index = vr.ArtifactIndex([self.tmp / "dist"])
        errors, _ = vr.validate(catalog, vr.RELEASE, index, plan)
        self.assertErrorContains(errors, "selected for v9.9.9")
        self.assertErrorContains(errors, "v8.8.8")

    def test_selected_entry_rejects_wrong_url_basename(self):
        payload = b"\x00asm\x01\x00\x00\x00"
        self.write_artifact("unit_transform.wasm", payload)
        catalog = self.write_catalog(
            [entry(asset="other.wasm", checksum=digest_of(payload))]
        )
        plan = release_plan(selected())
        index = vr.ArtifactIndex([self.tmp / "dist"])
        errors, _ = vr.validate(catalog, vr.RELEASE, index, plan)
        self.assertErrorContains(errors, "selection expects asset 'unit_transform.wasm'")

    def test_selection_requires_the_exact_catalog_version(self):
        payload = b"\x00asm\x01\x00\x00\x00"
        self.write_artifact("unit_transform.wasm", payload)
        catalog = self.write_catalog(
            [entry(version="0.2.0", checksum=digest_of(payload))]
        )
        plan = release_plan(selected(version="0.1.0"))
        index = vr.ArtifactIndex([self.tmp / "dist"])
        errors, _ = vr.validate(catalog, vr.RELEASE, index, plan)
        errors += plan.missing_errors()
        self.assertErrorContains(errors, "unit-transform@0.1.0")
        self.assertErrorContains(errors, "catalog entry was not found")

    def test_selected_pending_entry_is_rejected(self):
        self.write_artifact("unit_transform.wasm", b"\x00asm\x01\x00\x00\x00")
        catalog = self.write_catalog([entry(checksum="pending")])
        plan = release_plan(selected())
        index = vr.ArtifactIndex([self.tmp / "dist"])
        errors, _ = vr.validate(catalog, vr.RELEASE, index, plan)
        self.assertErrorContains(errors, "selected for v9.9.9")
        self.assertErrorContains(errors, "needs its real digest")

    def test_unselected_older_entry_is_not_republished(self):
        current = b"\x00asm\x01\x00\x00\x00current"
        self.write_artifact("current.wasm", current)
        catalog = self.write_catalog(
            [
                entry(
                    name="old",
                    version="0.1.0",
                    asset="old.wasm",
                    checksum=digest_of(b"old"),
                    wasm_url=(
                        "https://github.com/streamlinelabs/streamline-marketplace/"
                        "releases/download/v1.0.0/old.wasm"
                    ),
                ),
                entry(
                    name="current",
                    version="0.2.0",
                    asset="current.wasm",
                    checksum=digest_of(current),
                ),
            ]
        )
        plan = release_plan(selected(name="current", version="0.2.0", asset="current.wasm"))
        index = vr.ArtifactIndex([self.tmp / "dist"])
        errors, _ = vr.validate(catalog, vr.RELEASE, index, plan)
        errors += plan.missing_errors() + index.unreferenced_errors()
        self.assertNoErrors(errors)
        self.assertEqual(index.bound_entries, 1)

    def test_staging_an_unselected_older_asset_fails_reverse_binding(self):
        payload = b"\x00asm\x01\x00\x00\x00"
        self.write_artifact("old.wasm", payload)
        catalog = self.write_catalog(
            [
                entry(
                    name="old",
                    asset="old.wasm",
                    checksum=digest_of(payload),
                    wasm_url=(
                        "https://github.com/streamlinelabs/streamline-marketplace/"
                        "releases/download/v1.0.0/old.wasm"
                    ),
                )
            ]
        )
        plan = release_plan()
        index = vr.ArtifactIndex([self.tmp / "dist"])
        errors, _ = vr.validate(catalog, vr.RELEASE, index, plan)
        errors += index.unreferenced_errors()
        self.assertErrorContains(errors, "old.wasm")
        self.assertErrorContains(errors, "not referenced by any catalog entry")


class ArtifactIndexTests(ValidatorTestCase):
    def test_missing_directory_is_reported(self):
        index = vr.ArtifactIndex([str(self.tmp / "absent")])
        self.assertTrue(any("does not exist" in error for error in index.errors))

    def test_file_instead_of_directory_is_reported(self):
        path = self.tmp / "not-a-dir"
        path.write_bytes(b"x")
        index = vr.ArtifactIndex([str(path)])
        self.assertTrue(any("is not a directory" in error for error in index.errors))

    def test_nested_artifacts_are_indexed(self):
        self.write_artifact("json_filter.wasm", b"a", subdir="dist/nested")
        index = vr.ArtifactIndex([str(self.tmp / "dist")])
        path, error = index.resolve("json_filter.wasm")
        self.assertIsNone(error)
        self.assertEqual(path.name, "json_filter.wasm")

    def test_duplicate_basenames_are_ambiguous(self):
        self.write_artifact("json_filter.wasm", b"a", subdir="dist")
        self.write_artifact("json_filter.wasm", b"b", subdir="dist/nested")
        index = vr.ArtifactIndex([str(self.tmp / "dist")])
        path, error = index.resolve("json_filter.wasm")
        self.assertIsNone(path)
        self.assertIn("is ambiguous", error)

    def test_identical_duplicates_are_still_ambiguous(self):
        # Fail closed: two candidates mean the mapping is not deterministic,
        # even when today's bytes happen to agree.
        self.write_artifact("json_filter.wasm", b"same", subdir="dist")
        self.write_artifact("json_filter.wasm", b"same", subdir="dist/nested")
        index = vr.ArtifactIndex([str(self.tmp / "dist")])
        _, error = index.resolve("json_filter.wasm")
        self.assertIn("is ambiguous", error)

    def test_digest_matches_hashlib(self):
        path = self.write_artifact("json_filter.wasm", b"payload")
        index = vr.ArtifactIndex([str(self.tmp / "dist")])
        self.assertEqual(index.digest(path), digest_of(b"payload"))


class StructuralModeTests(ValidatorTestCase):
    def test_pending_is_accepted(self):
        catalog = self.write_catalog([entry(checksum="pending")])
        errors, count = self.run_validate(catalog, vr.STRUCTURAL)
        self.assertNoErrors(errors)
        self.assertEqual(count, 1)

    def test_missing_field_is_rejected(self):
        bad = entry()
        del bad["author"]
        catalog = self.write_catalog([bad])
        errors, _ = self.run_validate(catalog, vr.STRUCTURAL)
        self.assertErrorContains(errors, "missing required field 'author'")

    def test_malformed_digest_is_rejected(self):
        catalog = self.write_catalog([entry(checksum="sha256:zz")])
        errors, _ = self.run_validate(catalog, vr.STRUCTURAL)
        self.assertErrorContains(errors, "is neither 'sha256:<64 hex>'")

    def test_uppercase_digest_is_rejected(self):
        catalog = self.write_catalog([entry(checksum=digest_of(b"x").upper())])
        errors, _ = self.run_validate(catalog, vr.STRUCTURAL)
        self.assertErrorContains(errors, "is neither 'sha256:<64 hex>'")

    def test_non_string_checksum_is_rejected(self):
        catalog = self.write_catalog([entry(checksum=1234)])
        errors, _ = self.run_validate(catalog, vr.STRUCTURAL)
        self.assertErrorContains(errors, "checksum must be a string")

    def test_duplicate_name_version_is_rejected(self):
        catalog = self.write_catalog([entry(), entry()])
        errors, _ = self.run_validate(catalog, vr.STRUCTURAL)
        self.assertErrorContains(errors, "duplicate name/version pair")

    def test_non_array_catalog_is_rejected(self):
        path = self.tmp / "object.json"
        path.write_text('{"name": "x"}', encoding="utf-8")
        errors, _ = self.run_validate(path, vr.STRUCTURAL)
        self.assertErrorContains(errors, "expected a JSON array")

    def test_unreadable_catalog_is_rejected(self):
        errors, _ = self.run_validate(self.tmp / "absent.json", vr.STRUCTURAL)
        self.assertErrorContains(errors, "cannot be read as JSON")


class DigestsModeTests(ValidatorTestCase):
    def test_pending_is_rejected(self):
        catalog = self.write_catalog([entry(checksum="pending")])
        errors, _ = self.run_validate(catalog, vr.DIGESTS)
        self.assertErrorContains(errors, "the digest audit requires the real sha256 digest")

    def test_sha256_pending_sentinel_is_rejected(self):
        catalog = self.write_catalog([entry(checksum="sha256:pending")])
        errors, _ = self.run_validate(catalog, vr.DIGESTS)
        self.assertErrorContains(errors, "the digest audit requires the real sha256 digest")

    def test_wrong_digest_is_accepted_because_syntax_is_all_it_can_see(self):
        catalog = self.write_catalog([entry(checksum=digest_of(b"not the artifact"))])
        errors, _ = self.run_validate(catalog, vr.DIGESTS)
        self.assertNoErrors(errors)


class ReleaseModeTests(ValidatorTestCase):
    def test_matching_digest_passes(self):
        payload = b"\x00asm\x01\x00\x00\x00release"
        self.write_artifact("unit_transform.wasm", payload)
        catalog = self.write_catalog([entry(checksum=digest_of(payload))])
        errors, _ = self.run_validate(catalog, vr.RELEASE, [self.tmp / "dist"])
        self.assertNoErrors(errors)

    def test_wrong_digest_is_rejected(self):
        self.write_artifact("unit_transform.wasm", b"real bytes")
        catalog = self.write_catalog([entry(checksum=digest_of(b"other bytes"))])
        errors, _ = self.run_validate(catalog, vr.RELEASE, [self.tmp / "dist"])
        self.assertErrorContains(errors, "does not match staged release artifact")

    def test_single_flipped_byte_is_rejected(self):
        payload = b"\x00asm\x01\x00\x00\x00release"
        tampered = payload[:-1] + bytes([payload[-1] ^ 0x01])
        self.write_artifact("unit_transform.wasm", tampered)
        catalog = self.write_catalog([entry(checksum=digest_of(payload))])
        errors, _ = self.run_validate(catalog, vr.RELEASE, [self.tmp / "dist"])
        self.assertErrorContains(errors, "does not match staged release artifact")

    def test_unrelated_artifact_under_the_expected_name_is_rejected(self):
        self.write_artifact("unit_transform.wasm", b"hello world\n")
        catalog = self.write_catalog([entry(checksum=digest_of(b"\x00asm\x01\x00\x00\x00"))])
        errors, _ = self.run_validate(catalog, vr.RELEASE, [self.tmp / "dist"])
        self.assertErrorContains(errors, "does not match staged release artifact")

    def test_unrelated_artifact_under_another_name_cannot_substitute(self):
        # The digest is correct for the bytes present, but those bytes are not
        # published under the catalog's release asset name.
        payload = b"\x00asm\x01\x00\x00\x00"
        self.write_artifact("example_transform.wasm", payload)
        catalog = self.write_catalog([entry(checksum=digest_of(payload))])
        errors, _ = self.run_validate(catalog, vr.RELEASE, [self.tmp / "dist"])
        self.assertErrorContains(errors, "expected release artifact 'unit_transform.wasm'")

    def test_missing_artifact_is_rejected(self):
        self.write_artifact("something_else.wasm", b"x")
        catalog = self.write_catalog([entry(checksum=digest_of(b"x"))])
        errors, _ = self.run_validate(catalog, vr.RELEASE, [self.tmp / "dist"])
        self.assertErrorContains(errors, "was not found under")

    def test_malformed_digest_is_rejected_before_comparison(self):
        self.write_artifact("unit_transform.wasm", b"x")
        catalog = self.write_catalog([entry(checksum="sha256:not-hex")])
        errors, _ = self.run_validate(catalog, vr.RELEASE, [self.tmp / "dist"])
        self.assertErrorContains(errors, "is neither 'sha256:<64 hex>'")

    def test_ambiguous_artifact_is_rejected_even_when_a_candidate_matches(self):
        payload = b"\x00asm\x01\x00\x00\x00"
        self.write_artifact("unit_transform.wasm", payload, subdir="dist")
        self.write_artifact("unit_transform.wasm", b"different", subdir="dist/nested")
        catalog = self.write_catalog([entry(checksum=digest_of(payload))])
        errors, _ = self.run_validate(catalog, vr.RELEASE, [self.tmp / "dist"])
        self.assertErrorContains(errors, "is ambiguous")

    def test_duplicate_entries_are_rejected(self):
        payload = b"\x00asm\x01\x00\x00\x00"
        self.write_artifact("unit_transform.wasm", payload)
        catalog = self.write_catalog(
            [entry(checksum=digest_of(payload)), entry(checksum=digest_of(payload))]
        )
        errors, _ = self.run_validate(catalog, vr.RELEASE, [self.tmp / "dist"])
        self.assertErrorContains(errors, "duplicate name/version pair")

    def test_every_digest_entry_must_bind_to_an_artifact(self):
        payload = b"\x00asm\x01\x00\x00\x00"
        self.write_artifact("first.wasm", payload)
        catalog = self.write_catalog(
            [
                entry(name="first", asset="first.wasm", checksum=digest_of(payload)),
                entry(name="second", asset="second.wasm", checksum=digest_of(payload)),
            ]
        )
        errors, _ = self.run_validate(catalog, vr.RELEASE, [self.tmp / "dist"])
        self.assertErrorContains(errors, "expected release artifact 'second.wasm'")


class ReleaseModePendingTests(ValidatorTestCase):
    """`pending` is honest only for a transform this release does not ship."""

    def test_pending_entry_without_a_staged_artifact_is_allowed(self):
        # The catalog may list transforms that have no crate yet; the gate must
        # stay satisfiable instead of demanding digests for artifacts that
        # cannot exist.
        payload = b"\x00asm\x01\x00\x00\x00"
        self.write_artifact("shipped.wasm", payload)
        catalog = self.write_catalog(
            [
                entry(name="shipped", asset="shipped.wasm", checksum=digest_of(payload)),
                entry(name="not-built-yet", asset="not_built_yet.wasm", checksum="pending"),
            ]
        )
        errors, _ = self.run_validate(catalog, vr.RELEASE, [self.tmp / "dist"])
        self.assertNoErrors(errors)

    def test_pending_only_catalog_passes_when_nothing_it_names_is_staged(self):
        # The staged CLI binary is out of catalog scope, so a release that ships
        # no WASM module at all is still coherent.
        self.write_artifact("streamline-marketplace", b"native binary")
        catalog = self.write_catalog([entry(checksum="pending")])
        errors, _ = self.run_validate(catalog, vr.RELEASE, [self.tmp / "dist"])
        self.assertNoErrors(errors)

    def test_pending_entry_for_a_staged_artifact_is_rejected(self):
        payload = b"\x00asm\x01\x00\x00\x00"
        self.write_artifact("unit_transform.wasm", payload)
        catalog = self.write_catalog([entry(checksum="pending")])
        errors, _ = self.run_validate(catalog, vr.RELEASE, [self.tmp / "dist"])
        self.assertErrorContains(errors, "every shipping artifact needs its real digest")

    def test_sha256_pending_sentinel_for_a_staged_artifact_is_rejected(self):
        payload = b"\x00asm\x01\x00\x00\x00"
        self.write_artifact("unit_transform.wasm", payload)
        catalog = self.write_catalog([entry(checksum="sha256:pending")])
        errors, _ = self.run_validate(catalog, vr.RELEASE, [self.tmp / "dist"])
        self.assertErrorContains(errors, "every shipping artifact needs its real digest")

    def test_pending_entry_for_an_ambiguously_staged_artifact_is_rejected(self):
        self.write_artifact("unit_transform.wasm", b"a", subdir="dist")
        self.write_artifact("unit_transform.wasm", b"b", subdir="dist/nested")
        catalog = self.write_catalog([entry(checksum="pending")])
        errors, _ = self.run_validate(catalog, vr.RELEASE, [self.tmp / "dist"])
        self.assertErrorContains(errors, "every shipping artifact needs its real digest")

    def test_every_entry_naming_a_staged_asset_must_carry_a_real_digest(self):
        # Two versions of the same asset name: one released, one still pending.
        # The staged bytes make the pending one a hard failure.
        payload = b"\x00asm\x01\x00\x00\x00"
        self.write_artifact("unit_transform.wasm", payload)
        catalog = self.write_catalog(
            [
                entry(version="0.1.0", checksum=digest_of(payload)),
                entry(version="0.2.0", checksum="pending"),
            ]
        )
        errors, _ = self.run_validate(catalog, vr.RELEASE, [self.tmp / "dist"])
        self.assertErrorContains(errors, "is selected by both")


class ReleaseModeReverseBindingTests(ValidatorTestCase):
    """No staged WASM module may ship without a catalog entry pinning it."""

    def test_staged_wasm_without_a_catalog_entry_is_rejected(self):
        payload = b"\x00asm\x01\x00\x00\x00"
        self.write_artifact("unit_transform.wasm", payload)
        self.write_artifact("surprise_module.wasm", b"\x00asm\x01\x00\x00\x00extra")
        catalog = self.write_catalog([entry(checksum=digest_of(payload))])
        errors, _ = self.run_validate(catalog, vr.RELEASE, [self.tmp / "dist"])
        self.assertErrorContains(errors, "staged release artifact 'surprise_module.wasm'")
        self.assertErrorContains(errors, "is not referenced by any catalog entry")

    def test_staged_native_binary_without_a_catalog_entry_is_allowed(self):
        # The CLI is published alongside the catalog, not through it.
        payload = b"\x00asm\x01\x00\x00\x00"
        self.write_artifact("unit_transform.wasm", payload)
        self.write_artifact("streamline-marketplace", b"native binary")
        catalog = self.write_catalog([entry(checksum=digest_of(payload))])
        errors, _ = self.run_validate(catalog, vr.RELEASE, [self.tmp / "dist"])
        self.assertNoErrors(errors)

    def test_a_pending_entry_still_counts_as_a_reference(self):
        # The artifact is claimed by the catalog, so the failure is the pending
        # checksum on a shipped asset, not an unbound artifact.
        self.write_artifact("unit_transform.wasm", b"\x00asm\x01\x00\x00\x00")
        catalog = self.write_catalog([entry(checksum="pending")])
        errors, _ = self.run_validate(catalog, vr.RELEASE, [self.tmp / "dist"])
        self.assertEqual(len(errors), 1, errors)
        self.assertErrorContains(errors, "every shipping artifact needs its real digest")

    def test_reverse_binding_is_satisfied_across_multiple_catalogs(self):
        payload = b"\x00asm\x01\x00\x00\x00"
        other = b"\x00asm\x01\x00\x00\x00second"
        self.write_artifact("first.wasm", payload)
        self.write_artifact("second.wasm", other)
        first = self.write_catalog(
            [entry(name="first", asset="first.wasm", checksum=digest_of(payload))],
            name="first.json",
        )
        second = self.write_catalog(
            [entry(name="second", asset="second.wasm", checksum=digest_of(other))],
            name="second.json",
        )
        dist = str(self.tmp / "dist")
        self.assertEqual(
            vr.main(
                [
                    str(first),
                    str(second),
                    "--mode",
                    "release",
                    "--artifacts",
                    dist,
                    "--expected-tag",
                    "v9.9.9",
                    "--ship",
                    "first@0.1.0=first.wasm",
                    "--ship",
                    "second@0.1.0=second.wasm",
                ]
            ),
            0,
        )
        # Validating only one of them leaves the other module unbound.
        self.assertEqual(
            vr.main(
                [
                    str(first),
                    "--mode",
                    "release",
                    "--artifacts",
                    dist,
                    "--expected-tag",
                    "v9.9.9",
                    "--ship",
                    "first@0.1.0=first.wasm",
                ]
            ),
            1,
        )


class CommandLineTests(ValidatorTestCase):
    def test_release_mode_requires_artifacts(self):
        catalog = self.write_catalog([entry()])
        with self.assertRaises(SystemExit) as raised:
            vr.main([str(catalog), "--mode", "release"])
        self.assertNotEqual(raised.exception.code, 0)

    def test_artifacts_are_rejected_outside_release_mode(self):
        catalog = self.write_catalog([entry()])
        with self.assertRaises(SystemExit) as raised:
            vr.main([str(catalog), "--mode", "structural", "--artifacts", str(self.tmp)])
        self.assertNotEqual(raised.exception.code, 0)

    def test_empty_artifact_directory_fails(self):
        empty = self.tmp / "empty"
        empty.mkdir()
        catalog = self.write_catalog([entry(checksum=digest_of(b"x"))])
        self.assertEqual(
            vr.main(
                [
                    str(catalog),
                    "--mode",
                    "release",
                    "--artifacts",
                    str(empty),
                    "--expected-tag",
                    "v9.9.9",
                    "--ship",
                    "unit-transform@0.1.0=unit_transform.wasm",
                ]
            ),
            1,
        )

    def test_exit_codes_track_validation_outcome(self):
        payload = b"\x00asm\x01\x00\x00\x00"
        self.write_artifact("unit_transform.wasm", payload)
        good = self.write_catalog([entry(checksum=digest_of(payload))], name="good.json")
        bad = self.write_catalog([entry(checksum=digest_of(b"other"))], name="bad.json")
        dist = str(self.tmp / "dist")
        release_args = [
            "--mode",
            "release",
            "--artifacts",
            dist,
            "--expected-tag",
            "v9.9.9",
            "--ship",
            "unit-transform@0.1.0=unit_transform.wasm",
        ]
        self.assertEqual(vr.main([str(good), *release_args]), 0)
        self.assertEqual(vr.main([str(bad), *release_args]), 1)

    def test_release_mode_requires_expected_tag(self):
        catalog = self.write_catalog([entry()])
        self.write_artifact("unit_transform.wasm", b"x")
        with self.assertRaises(SystemExit) as raised:
            vr.main(
                [
                    str(catalog),
                    "--mode",
                    "release",
                    "--artifacts",
                    str(self.tmp / "dist"),
                    "--ship",
                    "unit-transform@0.1.0=unit_transform.wasm",
                ]
            )
        self.assertNotEqual(raised.exception.code, 0)

    def test_release_mode_requires_explicit_selection(self):
        catalog = self.write_catalog([entry()])
        self.write_artifact("unit_transform.wasm", b"x")
        with self.assertRaises(SystemExit) as raised:
            vr.main(
                [
                    str(catalog),
                    "--mode",
                    "release",
                    "--artifacts",
                    str(self.tmp / "dist"),
                    "--expected-tag",
                    "v9.9.9",
                ]
            )
        self.assertNotEqual(raised.exception.code, 0)


class ReleaseStagingTests(ValidatorTestCase):
    def test_stage_copies_only_entries_selected_for_the_requested_tag(self):
        old = b"\x00asm\x01\x00\x00\x00old"
        current = b"\x00asm\x01\x00\x00\x00current"
        build = self.tmp / "build"
        build.mkdir()
        (build / "old.wasm").write_bytes(old)
        (build / "current.wasm").write_bytes(current)
        catalog = self.write_catalog(
            [
                entry(
                    name="old",
                    asset="old.wasm",
                    checksum=digest_of(old),
                    wasm_url=(
                        "https://github.com/streamlinelabs/streamline-marketplace/"
                        "releases/download/v1.0.0/old.wasm"
                    ),
                ),
                entry(
                    name="current",
                    version="0.2.0",
                    asset="current.wasm",
                    checksum=digest_of(current),
                ),
            ]
        )
        selection = self.write_selection(
            {
                "v1.0.0": [selected(name="old", asset="old.wasm")],
                "v9.9.9": [
                    selected(name="current", version="0.2.0", asset="current.wasm")
                ],
            }
        )
        output = self.tmp / "stage"

        errors, count = stage.stage_release(
            catalog, selection, "v9.9.9", build, output
        )
        self.assertNoErrors(errors)
        self.assertEqual(count, 1)
        self.assertEqual([path.name for path in output.iterdir()], ["current.wasm"])
        self.assertEqual((output / "current.wasm").read_bytes(), current)

    def test_stage_rejects_a_selected_entry_whose_url_targets_another_tag(self):
        payload = b"\x00asm\x01\x00\x00\x00"
        build = self.tmp / "build"
        build.mkdir()
        (build / "unit_transform.wasm").write_bytes(payload)
        catalog = self.write_catalog(
            [
                entry(
                    checksum=digest_of(payload),
                    wasm_url=(
                        "https://github.com/streamlinelabs/streamline-marketplace/"
                        "releases/download/v1.0.0/unit_transform.wasm"
                    ),
                )
            ]
        )
        selection = self.write_selection({"v9.9.9": [selected()]})
        errors, count = stage.stage_release(
            catalog, selection, "v9.9.9", build, self.tmp / "stage"
        )
        self.assertEqual(count, 0)
        self.assertErrorContains(errors, "wasm_url targets v1.0.0")

    def test_stage_requires_an_explicit_tag_key_even_for_cli_only_releases(self):
        selection = self.write_selection({"v1.0.0": []})
        errors, count = stage.stage_release(
            self.write_catalog([]),
            selection,
            "v9.9.9",
            self.tmp / "build",
            self.tmp / "stage",
        )
        self.assertEqual(count, 0)
        self.assertErrorContains(errors, "no explicit shipping selection exists")


class PublishedRegistryTests(ValidatorTestCase):
    def test_published_validation_uses_downloaded_artifacts_not_current_builds(self):
        payload = b"\x00asm\x01\x00\x00\x00live"
        artifacts = self.tmp / "published"
        artifacts.mkdir()
        (artifacts / "unit_transform.wasm").write_bytes(payload)
        catalog = self.write_catalog([entry(checksum=digest_of(payload))])
        manifest = self.write_selection(
            {"v9.9.9": [published_record(digest_of(payload))]}
        )

        errors = published.verify_published(
            catalog,
            manifest,
            artifacts=artifacts,
        )
        self.assertNoErrors(errors)

        mutated = json.loads(catalog.read_text(encoding="utf-8"))
        mutated[0]["checksum"] = digest_of(b"syntactically valid but wrong")
        catalog.write_text(json.dumps(mutated), encoding="utf-8")
        errors = published.verify_published(
            catalog,
            manifest,
            artifacts=artifacts,
        )
        self.assertErrorContains(errors, "differs from the published manifest")

        manifest_data = json.loads(manifest.read_text(encoding="utf-8"))
        manifest_data["v9.9.9"][0]["checksum"] = mutated[0]["checksum"]
        manifest.write_text(json.dumps(manifest_data), encoding="utf-8")
        errors = published.verify_published(
            catalog,
            manifest,
            artifacts=artifacts,
        )
        self.assertErrorContains(errors, "does not match staged release artifact")

    def test_published_manifest_matches_live_catalog_identities(self):
        manifest_path = REPO_ROOT / "registry" / "published-releases.json"
        shipping_path = REPO_ROOT / "registry" / "shipping.json"
        catalog = json.loads(
            (REPO_ROOT / "registry" / "transforms.json").read_text(encoding="utf-8")
        )
        by_key = {(entry["name"], entry["version"]): entry for entry in catalog}
        manifests = json.loads(manifest_path.read_text(encoding="utf-8"))
        shipping = json.loads(shipping_path.read_text(encoding="utf-8"))

        self.assertEqual(set(manifests), {"v0.3.0"})
        self.assertEqual(len(manifests["v0.3.0"]), 6)
        self.assertEqual(
            shipping,
            {"v0.4.0": []},
            "current source must declare only the truthful CLI-only shipping plan",
        )
        released_entries = [
            entry_value
            for entry_value in catalog
            if vr.SHA256_RE.match(entry_value.get("checksum", ""))
        ]
        self.assertEqual(len(released_entries), 6)
        for entry_value in released_entries:
            url_tag, _, error = vr.release_coordinates(entry_value)
            self.assertIsNone(error)
            self.assertEqual(
                url_tag,
                "v0.3.0",
                f"{entry_value['name']} must not imply a nonexistent older asset",
            )
        for tag, records in manifests.items():
            plan = vr.ReleasePlan.from_file(manifest_path, tag)
            self.assertNoErrors(plan.errors)
            for record in records:
                entry_value = by_key[(record["name"], record["version"])]
                url_tag, asset, error = vr.release_coordinates(entry_value)
                self.assertIsNone(error)
                self.assertEqual(url_tag, tag)
                self.assertEqual(asset, record["asset"])
                self.assertRegex(entry_value["checksum"], vr.SHA256_RE)
                self.assertEqual(record["url"], entry_value["wasm_url"])
                self.assertEqual(record["checksum"], entry_value["checksum"])


class ReleaseVersionTests(unittest.TestCase):
    def test_version_helper_accepts_matching_workspace_and_cli_versions(self):
        metadata = {
            "packages": [
                {"name": "streamline-marketplace-cli", "version": "0.4.0"}
            ]
        }
        self.assertEqual(
            release_version.release_versions("v0.4.0", metadata, "0.4.0"),
            [],
        )

    def test_version_helper_rejects_tag_workspace_and_cli_mismatches(self):
        metadata = {
            "packages": [
                {"name": "streamline-marketplace-cli", "version": "0.4.0"}
            ]
        }
        errors = release_version.release_versions("v0.5.0", metadata, "0.4.0")
        self.assertTrue(any("workspace version" in error for error in errors))
        self.assertTrue(any("CLI version" in error for error in errors))

    def test_actual_locked_metadata_matches_v0_4_0(self):
        self.assertEqual(
            release_version.check_release_version("v0.4.0", REPO_ROOT),
            [],
        )


class ReleaseWorkflowContractTests(unittest.TestCase):
    def test_ci_separates_current_build_reproducibility_from_published_assets(self):
        workflow = (REPO_ROOT / ".github" / "workflows" / "ci.yml").read_text(
            encoding="utf-8"
        )
        self.assertIn('toolchain: "1.85.1"', workflow)
        self.assertIn("runs-on: ubuntu-22.04", workflow)
        self.assertIn(
            "rust:1.85.1-bookworm@sha256:"
            "e51d0265072d2d9d5d320f6a44dde6b9ef13653b035098febd68cce8fa7c0bc4",
            workflow,
        )
        self.assertIn("scripts/check_reproducible_wasm.sh", workflow)
        self.assertIn("scripts/verify_published_registry.py", workflow)
        published_script = (
            REPO_ROOT / "scripts" / "verify_published_registry.py"
        ).read_text(encoding="utf-8")
        self.assertIn("registry/published-releases.json", published_script)
        self.assertNotIn("current build", published_script.lower())

    def test_tag_release_fails_before_build_without_version_and_future_plan(self):
        workflow = (REPO_ROOT / ".github" / "workflows" / "release.yml").read_text(
            encoding="utf-8"
        )
        version_gate = workflow.index("scripts/check_release_version.py")
        shipping_gate = workflow.index("scripts/check_shipping_plan.py")
        build = workflow.index("scripts/build_release_wasm.sh")
        self.assertLess(version_gate, build)
        self.assertLess(shipping_gate, build)
        self.assertIn("scripts/stage_release_artifacts.py", workflow)
        self.assertIn('--expected-tag "${GITHUB_REF_NAME}"', workflow)
        self.assertIn("--selection registry/shipping.json", workflow)
        self.assertNotIn("cp target/wasm32-wasip1/release/*.wasm dist/", workflow)

    def test_release_builder_is_exactly_pinned_and_locked(self):
        script = (REPO_ROOT / "scripts" / "build_release_wasm.sh").read_text(
            encoding="utf-8"
        )
        self.assertIn("rustc 1.85.1 (4eb161250 2025-03-15)", script)
        self.assertIn('EXPECTED_HOST="x86_64-unknown-linux-gnu"', script)
        self.assertIn("--remap-path-prefix=$(pwd -P)=/workspace", script)
        self.assertIn("cargo build --locked --release --target wasm32-wasip1", script)
        self.assertNotRegex(script, r"(?m)^\s*cargo clean\b")

        makefile = (REPO_ROOT / "Makefile").read_text(encoding="utf-8")
        self.assertIn(
            "cargo build --locked -p streamline-marketplace-cli --release",
            makefile,
        )


class RepositoryFixtureTests(ValidatorTestCase):
    """The committed fixtures must keep meaning what their filenames claim."""

    FIXTURE_CATALOGS = (
        "catalog_released.json",
        "catalog_pending_absent.json",
        "catalog_pending_staged.json",
        "catalog_wrong_digest.json",
        "catalog_missing_artifact.json",
        "catalog_duplicate_entry.json",
    )

    def stage(self, *artifacts):
        """Stage exactly the named fixture artifacts, as a release job would."""
        staged = self.tmp / "staged"
        staged.mkdir(parents=True, exist_ok=True)
        for name in artifacts:
            (staged / name).write_bytes((FIXTURE_ARTIFACTS / name).read_bytes())
        return staged

    def test_released_fixture_digest_matches_its_artifact_bytes(self):
        catalog = json.loads((FIXTURES / "catalog_released.json").read_text(encoding="utf-8"))
        artifact = FIXTURE_ARTIFACTS / "fixture_released.wasm"
        self.assertEqual(catalog[0]["checksum"], vr.sha256_of(artifact))

    def test_wrong_digest_fixture_is_valid_syntax_but_wrong_bytes(self):
        catalog = json.loads((FIXTURES / "catalog_wrong_digest.json").read_text(encoding="utf-8"))
        checksum = catalog[0]["checksum"]
        self.assertRegex(checksum, vr.SHA256_RE)
        self.assertNotEqual(checksum, vr.sha256_of(FIXTURE_ARTIFACTS / "fixture_released.wasm"))

    def test_released_fixture_passes_release_mode(self):
        staged = self.stage("fixture_released.wasm")
        errors, _ = self.run_validate(FIXTURES / "catalog_released.json", vr.RELEASE, [staged])
        self.assertNoErrors(errors)

    def test_pending_absent_fixture_passes_release_mode(self):
        staged = self.stage("fixture_released.wasm")
        errors, _ = self.run_validate(
            FIXTURES / "catalog_pending_absent.json", vr.RELEASE, [staged]
        )
        self.assertNoErrors(errors)

    def test_pending_staged_fixture_fails_release_mode(self):
        staged = self.stage("fixture_pending.wasm")
        errors, _ = self.run_validate(
            FIXTURES / "catalog_pending_staged.json", vr.RELEASE, [staged]
        )
        self.assertErrorContains(errors, "every shipping artifact needs its real digest")

    def test_missing_artifact_fixture_fails_release_mode(self):
        staged = self.stage("fixture_released.wasm")
        errors, _ = self.run_validate(
            FIXTURES / "catalog_missing_artifact.json", vr.RELEASE, [staged]
        )
        self.assertErrorContains(errors, "expected release artifact 'fixture_absent.wasm'")

    def test_wrong_digest_fixture_fails_release_mode(self):
        staged = self.stage("fixture_released.wasm")
        errors, _ = self.run_validate(
            FIXTURES / "catalog_wrong_digest.json", vr.RELEASE, [staged]
        )
        self.assertErrorContains(errors, "does not match staged release artifact")

    def test_duplicate_fixture_fails_release_mode(self):
        staged = self.stage("fixture_released.wasm")
        errors, _ = self.run_validate(
            FIXTURES / "catalog_duplicate_entry.json", vr.RELEASE, [staged]
        )
        self.assertErrorContains(errors, "duplicate name/version pair")

    def test_unreferenced_staged_fixture_artifact_fails_release_mode(self):
        staged = self.stage("fixture_released.wasm", "fixture_unrelated.wasm")
        errors, _ = self.run_validate(FIXTURES / "catalog_released.json", vr.RELEASE, [staged])
        self.assertErrorContains(errors, "staged release artifact 'fixture_unrelated.wasm'")

    def test_every_fixture_catalog_is_structurally_valid_or_a_declared_negative(self):
        for name in self.FIXTURE_CATALOGS:
            with self.subTest(fixture=name):
                errors, count = self.run_validate(FIXTURES / name, vr.STRUCTURAL)
                self.assertGreater(count, 0)
                if name == "catalog_duplicate_entry.json":
                    self.assertErrorContains(errors, "duplicate name/version pair")
                else:
                    self.assertNoErrors(errors)

    def test_fixtures_contain_no_placeholder_identifiers(self):
        # Placeholder hosts and demo modules are not evidence of anything; the
        # fixtures must stay real release-asset names with real bytes.
        for name in self.FIXTURE_CATALOGS:
            text = (FIXTURES / name).read_text(encoding="utf-8")
            for placeholder in ("example.invalid", "hello-world", "hello_world"):
                self.assertNotIn(
                    placeholder, text, f"{name} still uses the placeholder {placeholder!r}"
                )
        for artifact in FIXTURE_ARTIFACTS.iterdir():
            for placeholder in ("hello-world", "hello_world"):
                self.assertNotIn(
                    placeholder,
                    artifact.name,
                    f"{artifact.name} is a placeholder fixture artifact",
                )

    def test_live_catalog_is_structurally_valid(self):
        errors, count = vr.validate(REPO_ROOT / "registry" / "transforms.json", vr.STRUCTURAL)
        self.assertNoErrors(errors)
        self.assertGreater(count, 0)

    def test_live_catalog_distinguishes_released_and_pending_entries(self):
        # Implemented transforms carry real digests and therefore require their
        # exact artifacts in release mode. Unimplemented entries stay pending:
        # staging one of those is still a hard failure, while not staging it is
        # allowed. Keep these assertions independent of a local Rust build; the
        # control script's --built-artifacts path proves the real byte binding.
        catalog = REPO_ROOT / "registry" / "transforms.json"
        entries = json.loads(catalog.read_text(encoding="utf-8"))
        released = [e for e in entries if vr.SHA256_RE.match(e["checksum"])]
        pending = [e for e in entries if e["checksum"] in vr.PENDING_VALUES]
        self.assertGreater(len(released), 0)
        self.assertGreater(len(pending), 0)

        missing_released = self.tmp / "missing-released"
        missing_released.mkdir()
        (missing_released / "streamline-marketplace").write_bytes(b"native binary")
        errors, _ = self.run_validate(catalog, vr.RELEASE, [missing_released])
        for entry_value in released:
            asset = entry_value["wasm_url"].rsplit("/", 1)[-1]
            self.assertErrorContains(errors, f"expected release artifact '{asset}'")

        pending_entry = next(e for e in pending if e["wasm_url"].endswith(".wasm"))
        staged_name = pending_entry["wasm_url"].rsplit("/", 1)[-1]
        pending_catalog = self.write_catalog([pending_entry], name="live-pending-entry.json")
        blocked = self.tmp / "blocked"
        blocked.mkdir()
        (blocked / staged_name).write_bytes(b"\x00asm\x01\x00\x00\x00")
        errors, _ = self.run_validate(pending_catalog, vr.RELEASE, [blocked])
        self.assertErrorContains(errors, "every shipping artifact needs its real digest")

        unrelated = self.tmp / "unrelated"
        unrelated.mkdir()
        (unrelated / "streamline-marketplace").write_bytes(b"native binary")
        errors, _ = self.run_validate(pending_catalog, vr.RELEASE, [unrelated])
        self.assertNoErrors(errors)


if __name__ == "__main__":
    unittest.main()
