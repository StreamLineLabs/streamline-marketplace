#!/usr/bin/env bash
# Prove two clean Rust 1.85.1 release builds produce byte-identical WASM.
#
# Only the dedicated target and comparison directories are removed. Shared
# Cargo targets and caches are never cleaned.
set -euo pipefail

cd "$(dirname "$0")/.."

TARGET_ROOT="${CARGO_TARGET_DIR:-target/reproducible-release}"
FIRST_ROOT="${TARGET_ROOT}-first"
MODULES=(
  json_filter.wasm
  timestamp_enricher.wasm
  pii_redactor.wasm
  schema_validator.wasm
  field_router.wasm
  ai_classifier.wasm
)

rm -rf "${TARGET_ROOT}" "${FIRST_ROOT}"

CARGO_TARGET_DIR="${TARGET_ROOT}" bash scripts/build_release_wasm.sh
mkdir -p "${FIRST_ROOT}"
for module in "${MODULES[@]}"; do
  cp "${TARGET_ROOT}/wasm32-wasip1/release/${module}" "${FIRST_ROOT}/${module}"
done

rm -rf "${TARGET_ROOT}"
CARGO_TARGET_DIR="${TARGET_ROOT}" bash scripts/build_release_wasm.sh

for module in "${MODULES[@]}"; do
  cmp "${FIRST_ROOT}/${module}" \
    "${TARGET_ROOT}/wasm32-wasip1/release/${module}" || {
      echo "non-reproducible release artifact: ${module}" >&2
      exit 1
    }
done

rm -rf "${FIRST_ROOT}"
echo "Two clean Rust 1.85.1 release builds produced byte-identical WASM modules."
