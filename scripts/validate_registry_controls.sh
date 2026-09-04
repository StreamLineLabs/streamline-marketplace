#!/usr/bin/env bash
# Prove that release-mode catalog validation is meaningful, using hermetic
# fixtures instead of the live catalog's current (and changing) state.
#
# Release validation is authoritative only if it binds an explicit shipping
# selection to catalog name/version, the expected release tag, asset basename,
# and staged bytes in both directions. These controls must hold whether or not
# the live catalog still carries pending checksums:
#
#   * a selected catalog entry with coherent identity/tag/asset/digest passes;
#   * an unselected `pending` entry is ignored by this release;
#   * a selected `pending` entry fails;
#   * a selected entry targeting another release tag fails;
#   * a syntactically valid but wrong digest fails;
#   * a real digest with no staged artifact fails;
#   * a staged WASM artifact that no catalog entry references fails;
#   * a duplicated catalog entry fails;
#   * an unrelated artifact published under the expected asset name fails;
#   * an ambiguous asset name (same basename in two trees) fails;
#   * release mode refuses to run at all without artifacts.
#
# With `--built-artifacts DIR` the same byte-level checks are extended to real,
# locally built outputs using a generated selection. Separately,
# verify_published_registry.py separately binds the live catalog and immutable
# published manifests to downloaded GitHub release bytes.
#
# Because release mode also rejects staged-but-unreferenced WASM artifacts,
# each scenario stages exactly the artifacts its catalog claims. The committed
# fixture bytes under `fixtures/artifacts/` are the source those staging
# directories are composed from.
#
# No network access and no published release artifacts are required.
set -euo pipefail

cd "$(dirname "$0")/.."

BUILT_ARTIFACTS=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    --built-artifacts)
      [[ $# -ge 2 ]] || { echo "--built-artifacts requires a directory" >&2; exit 2; }
      BUILT_ARTIFACTS="$2"
      shift 2
      ;;
    *)
      echo "usage: $0 [--built-artifacts DIR]" >&2
      exit 2
      ;;
  esac
done

VALIDATOR="scripts/validate_registry.py"
FIXTURES="scripts/fixtures"
ARTIFACTS="${FIXTURES}/artifacts"
RELEASED="${FIXTURES}/catalog_released.json"
PENDING_ABSENT="${FIXTURES}/catalog_pending_absent.json"
PENDING_STAGED="${FIXTURES}/catalog_pending_staged.json"
WRONG_DIGEST="${FIXTURES}/catalog_wrong_digest.json"
MISSING="${FIXTURES}/catalog_missing_artifact.json"
DUPLICATE="${FIXTURES}/catalog_duplicate_entry.json"
FIXTURE_TAG="v0.0.0-ci-fixture"
RELEASED_SELECTION=(
  --expected-tag "${FIXTURE_TAG}"
  --ship "fixture-released@0.1.0=fixture_released.wasm"
)

WORK="target/validate-registry-controls"
rm -rf "${WORK}"
mkdir -p "${WORK}"

# Compose a staging directory holding exactly the named fixture artifacts, the
# way a release job stages exactly what it is about to publish.
stage() { # $1: directory name under WORK, rest: fixture artifact basenames
  local name="$1"
  shift
  local dir="${WORK}/${name}"
  rm -rf "${dir}"
  mkdir -p "${dir}"
  local artifact
  for artifact in "$@"; do
    cp "${ARTIFACTS}/${artifact}" "${dir}/"
  done
  echo "${dir}"
}

# Run a validation that must fail, and assert the exact reason it failed for.
# Guards against a control passing because validation broke for some unrelated
# reason (bad path, syntax error, wrong flag).
expect_failure() { # $1: label, $2: expected substring, rest: validator args
  local label="$1" expected="$2"
  shift 2
  local output status=0
  output="$(python3 "${VALIDATOR}" "$@" 2>&1)" || status=$?
  if [[ "${status}" == "0" ]]; then
    echo "FAIL: ${label}: validation succeeded but must have failed" >&2
    echo "${output}" >&2
    exit 1
  fi
  # `-e` keeps expectations that begin with '-' (CLI usage errors) from being
  # parsed as grep options.
  if ! grep -Fq -e "${expected}" <<<"${output}"; then
    echo "FAIL: ${label}: validation failed for an unexpected reason" >&2
    echo "       expected to find: ${expected}" >&2
    echo "--- captured output ---" >&2
    echo "${output}" >&2
    exit 1
  fi
}

echo "==> Fixture artifacts are present"
for artifact in fixture_released.wasm fixture_pending.wasm fixture_unrelated.wasm; do
  test -s "${ARTIFACTS}/${artifact}" || {
    echo "FAIL: missing fixture artifact ${ARTIFACTS}/${artifact}" >&2
    exit 1
  }
done

STAGED_RELEASED="$(stage staged-released fixture_released.wasm)"
STAGED_PENDING="$(stage staged-pending fixture_pending.wasm)"
STAGED_UNREFERENCED="$(stage staged-unreferenced fixture_released.wasm fixture_unrelated.wasm)"

echo "==> Structural validation accepts every fixture catalog"
python3 "${VALIDATOR}" --mode structural \
  "${RELEASED}" "${PENDING_ABSENT}" "${PENDING_STAGED}" "${WRONG_DIGEST}" "${MISSING}"

echo "==> Structural validation rejects a duplicated entry"
expect_failure "duplicate entry (structural mode)" \
  "duplicate name/version pair" \
  --mode structural "${DUPLICATE}"

echo "==> Syntax-only (digests) validation accepts digests it cannot verify"
# Exactly the blind spot artifact binding closes: a wrong digest and a digest
# for an artifact that was never built are both syntactically valid.
python3 "${VALIDATOR}" --mode digests "${RELEASED}" "${WRONG_DIGEST}" "${MISSING}"

echo "==> Syntax-only (digests) validation is an audit, not a gate: pending fails"
expect_failure "pending (digests mode)" \
  "the digest audit requires the real sha256 digest" \
  --mode digests "${PENDING_STAGED}"

echo "==> Release validation accepts a digest bound to the staged artifact's bytes"
python3 "${VALIDATOR}" --mode release --artifacts "${STAGED_RELEASED}" \
  "${RELEASED_SELECTION[@]}" "${RELEASED}"

echo "==> Release validation accepts 'pending' when no such artifact is staged"
# The gate must stay satisfiable while the catalog still lists transforms this
# release does not ship.
python3 "${VALIDATOR}" --mode release --artifacts "${STAGED_RELEASED}" \
  "${RELEASED_SELECTION[@]}" "${PENDING_ABSENT}"

echo "==> Release validation rejects 'pending' for an artifact that IS staged"
expect_failure "pending for a staged artifact" \
  "every shipping artifact needs its real digest" \
  --mode release --artifacts "${STAGED_PENDING}" \
  --expected-tag "${FIXTURE_TAG}" \
  --ship "fixture-pending-staged@0.1.0=fixture_pending.wasm" \
  "${PENDING_STAGED}"

echo "==> Release validation rejects a syntactically valid but wrong digest"
expect_failure "wrong digest" \
  "does not match staged release artifact" \
  --mode release --artifacts "${STAGED_RELEASED}" \
  --expected-tag "${FIXTURE_TAG}" \
  --ship "fixture-wrong-digest@0.1.0=fixture_released.wasm" \
  "${WRONG_DIGEST}"

echo "==> Release validation rejects an entry targeting another release tag"
expect_failure "wrong release tag" \
  "selected for v0.0.1, but wasm_url targets older/different release tag" \
  --mode release --artifacts "${STAGED_RELEASED}" \
  --expected-tag v0.0.1 \
  --ship "fixture-released@0.1.0=fixture_released.wasm" \
  "${RELEASED}"

echo "==> Release validation rejects a real digest with no staged artifact"
expect_failure "missing artifact" \
  "expected release artifact 'fixture_absent.wasm' was not found under" \
  --mode release --artifacts "${STAGED_RELEASED}" \
  --expected-tag "${FIXTURE_TAG}" \
  --ship "fixture-released@0.1.0=fixture_released.wasm" \
  --ship "fixture-missing-artifact@0.1.0=fixture_absent.wasm" \
  "${MISSING}"

echo "==> Release validation rejects a staged WASM artifact nothing references"
expect_failure "unreferenced staged artifact" \
  "staged release artifact 'fixture_unrelated.wasm'" \
  --mode release --artifacts "${STAGED_UNREFERENCED}" \
  "${RELEASED_SELECTION[@]}" "${RELEASED}"

echo "==> Release validation rejects a duplicated catalog entry"
expect_failure "duplicate entry" \
  "duplicate name/version pair" \
  --mode release --artifacts "${STAGED_RELEASED}" \
  "${RELEASED_SELECTION[@]}" "${DUPLICATE}"

echo "==> An unrelated artifact under the expected name cannot satisfy validation"
IMPOSTOR="${WORK}/impostor"
mkdir -p "${IMPOSTOR}"
cp "${ARTIFACTS}/fixture_unrelated.wasm" "${IMPOSTOR}/fixture_released.wasm"
expect_failure "impostor artifact" \
  "does not match staged release artifact" \
  --mode release --artifacts "${IMPOSTOR}" \
  "${RELEASED_SELECTION[@]}" "${RELEASED}"

echo "==> Ambiguous artifact names are rejected instead of silently resolved"
AMBIGUOUS_A="$(stage ambiguous-a fixture_released.wasm)"
AMBIGUOUS_B="$(stage ambiguous-b fixture_released.wasm)"
expect_failure "ambiguous artifact" \
  "is ambiguous" \
  --mode release --artifacts "${AMBIGUOUS_A}" --artifacts "${AMBIGUOUS_B}" \
  "${RELEASED_SELECTION[@]}" "${RELEASED}"

echo "==> Release validation refuses to run without artifacts"
expect_failure "no --artifacts" \
  "--mode release requires at least one --artifacts DIR" \
  --mode release --expected-tag "${FIXTURE_TAG}" \
  --ship "fixture-released@0.1.0=fixture_released.wasm" "${RELEASED}"

echo "==> Release validation refuses a missing artifact directory"
expect_failure "absent artifact directory" \
  "does not exist" \
  --mode release --artifacts "${WORK}/not-a-directory" \
  "${RELEASED_SELECTION[@]}" "${RELEASED}"

echo "==> Release validation refuses an empty artifact directory"
EMPTY="${WORK}/empty"
mkdir -p "${EMPTY}"
expect_failure "empty artifact directory" \
  "no release artifacts found under" \
  --mode release --artifacts "${EMPTY}" \
  "${RELEASED_SELECTION[@]}" "${RELEASED}"

echo "==> Validator unit tests"
python3 -m unittest discover -s scripts -p 'test_*.py' -v

if [[ -n "${BUILT_ARTIFACTS}" ]]; then
  echo "==> Binding controls over real build outputs in ${BUILT_ARTIFACTS}"
  test -d "${BUILT_ARTIFACTS}" || {
    echo "FAIL: ${BUILT_ARTIFACTS} is not a directory" >&2
    exit 1
  }

  GENERATED="${WORK}/generated_catalog.json"
  PARTIAL="${WORK}/partial_catalog.json"
  GENERATED_SELECTION="${WORK}/generated_releases.json"
  PARTIAL_SELECTION="${WORK}/partial_releases.json"
  BUILT_STAGE="${WORK}/built-stage"
  TAMPERED_DIR="${WORK}/tampered"
  rm -rf "${BUILT_STAGE}" "${TAMPERED_DIR}"
  mkdir -p "${BUILT_STAGE}" "${TAMPERED_DIR}"
  for artifact in "${BUILT_ARTIFACTS}"/*; do
    [[ -f "${artifact}" ]] || continue
    case "$(basename "${artifact}")" in
      *.wasm|streamline-marketplace)
        cp "${artifact}" "${BUILT_STAGE}/"
        cp "${artifact}" "${TAMPERED_DIR}/"
        ;;
    esac
  done

  # Build a catalog from the real digests of the built artifacts, then flip a
  # single byte in a copy of the first artifact. Same catalog, same asset names:
  # only the bytes differ, so only byte-level binding can tell them apart. A
  # second catalog drops one built module's entry, exercising the reverse
  # binding (no staged WASM artifact may go unreferenced) over real outputs.
  python3 - "${BUILT_STAGE}" "${GENERATED}" "${TAMPERED_DIR}" "${PARTIAL}" \
    "${GENERATED_SELECTION}" "${PARTIAL_SELECTION}" <<'PY'
import hashlib
import json
import sys
from pathlib import Path

source, catalog_path, tampered_dir, partial_path, selection_path, partial_selection_path = (
    Path(a) for a in sys.argv[1:7]
)
artifacts = sorted(
    p
    for p in source.iterdir()
    if p.is_file() and (p.suffix == ".wasm" or p.name == "streamline-marketplace")
)
if not artifacts:
    sys.exit(f"no built artifacts in {source}")

entries = []
for artifact in artifacts:
    digest = hashlib.sha256(artifact.read_bytes()).hexdigest()
    entries.append(
        {
            "name": artifact.stem.replace("_", "-"),
            "version": "0.0.0-built",
            "description": f"generated control for {artifact.name}",
            "author": "streamline-ci",
            "wasm_url": (
                "https://github.com/streamlinelabs/streamline-marketplace/"
                f"releases/download/v0.0.0-built/{artifact.name}"
            ),
            "categories": ["filtering"],
            "min_streamline_version": "0.1.0",
            "checksum": f"sha256:{digest}",
        }
    )
catalog_path.write_text(json.dumps(entries, indent=2), encoding="utf-8")

wasm_names = [a.name for a in artifacts if a.name.endswith(".wasm")]
if not wasm_names:
    sys.exit(f"no built WASM modules in {source}")
selection = {
    "v0.0.0-built": [
        {
            "name": entry["name"],
            "version": entry["version"],
            "asset": entry["wasm_url"].rsplit("/", 1)[-1],
        }
        for entry in entries
        if entry["wasm_url"].endswith(".wasm")
    ]
}
selection_path.write_text(json.dumps(selection, indent=2), encoding="utf-8")

dropped = wasm_names[0]
partial = [e for e in entries if not e["wasm_url"].endswith(f"/{dropped}")]
partial_path.write_text(json.dumps(partial, indent=2), encoding="utf-8")
partial_selection = {
    "v0.0.0-built": [
        item for item in selection["v0.0.0-built"] if item["asset"] != dropped
    ]
}
partial_selection_path.write_text(
    json.dumps(partial_selection, indent=2), encoding="utf-8"
)

target = tampered_dir / wasm_names[0]
data = bytearray(target.read_bytes())
data[-1] ^= 0x01
target.write_bytes(bytes(data))
print(f"generated {len(entries)} entries; dropped {dropped}; tampered with {target.name}")
PY

  echo "==> Real build outputs satisfy their generated digests"
  python3 "${VALIDATOR}" --mode release --artifacts "${BUILT_STAGE}" \
    --expected-tag v0.0.0-built --selection "${GENERATED_SELECTION}" "${GENERATED}"

  echo "==> A single flipped byte in a built artifact fails validation"
  expect_failure "tampered build output" \
    "does not match staged release artifact" \
    --mode release --artifacts "${TAMPERED_DIR}" \
    --expected-tag v0.0.0-built --selection "${GENERATED_SELECTION}" "${GENERATED}"

  echo "==> A built WASM module missing from the catalog fails validation"
  expect_failure "unreferenced build output" \
    "is not referenced by any catalog entry" \
    --mode release --artifacts "${BUILT_STAGE}" \
    --expected-tag v0.0.0-built --selection "${PARTIAL_SELECTION}" "${PARTIAL}"
fi

echo "==> Release validation controls passed"
