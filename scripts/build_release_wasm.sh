#!/usr/bin/env bash
# Build the release WASM modules with the exact toolchain used to derive the
# live catalog digests. The caller chooses CARGO_TARGET_DIR; this script never
# runs cargo clean or removes shared build state.
set -euo pipefail

cd "$(dirname "$0")/.."

EXPECTED_RUSTC="rustc 1.85.1 (4eb161250 2025-03-15)"
EXPECTED_HOST="x86_64-unknown-linux-gnu"
ACTUAL_RUSTC="$(rustc --version)"
if [[ "${ACTUAL_RUSTC}" != "${EXPECTED_RUSTC}" ]]; then
  echo "release WASM builds require ${EXPECTED_RUSTC}; found ${ACTUAL_RUSTC}" >&2
  exit 1
fi
ACTUAL_HOST="$(rustc -vV | sed -n 's/^host: //p')"
if [[ "${ACTUAL_HOST}" != "${EXPECTED_HOST}" ]]; then
  echo "release WASM builds require host ${EXPECTED_HOST}; found ${ACTUAL_HOST}" >&2
  echo "Use the pinned linux/amd64 release container documented in README.md." >&2
  exit 1
fi

if [[ -n "${RUSTFLAGS:-}" || -n "${CARGO_ENCODED_RUSTFLAGS:-}" ]]; then
  echo "release WASM builds refuse ambient RUSTFLAGS/CARGO_ENCODED_RUSTFLAGS" >&2
  exit 1
fi

export CARGO_INCREMENTAL=0
export SOURCE_DATE_EPOCH=0
export RUSTFLAGS="--remap-path-prefix=$(pwd -P)=/workspace"

CRATES=(
  json-filter
  timestamp-enricher
  pii-redactor
  schema-validator
  field-router
  ai-classifier
)
MODULES=(
  json_filter.wasm
  timestamp_enricher.wasm
  pii_redactor.wasm
  schema_validator.wasm
  field_router.wasm
  ai_classifier.wasm
)

for crate in "${CRATES[@]}"; do
  echo "Building ${crate} with ${EXPECTED_RUSTC}..."
  cargo build --locked --release --target wasm32-wasip1 -p "${crate}"
done

TARGET_ROOT="${CARGO_TARGET_DIR:-target}"
OUTPUT_DIR="${TARGET_ROOT}/wasm32-wasip1/release"
for module in "${MODULES[@]}"; do
  test -s "${OUTPUT_DIR}/${module}" || {
    echo "missing release module ${OUTPUT_DIR}/${module}" >&2
    exit 1
  }
done

echo "Pinned release WASM build completed under ${OUTPUT_DIR}"
