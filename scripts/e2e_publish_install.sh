#!/usr/bin/env bash
# Hermetic end-to-end integrity check for the marketplace.
#
# Publishes an artifact to a loopback-bound registry, installs it with the CLI,
# and asserts that authentication, checksum verification, path validation, and
# tamper detection all behave as expected. CLI-side checksum policy (pending and
# mismatch) is exercised against a controlled static endpoint that performs no
# serve-time verification, so those assertions cannot be short-circuited by the
# registry's own integrity check, which is asserted separately.
# No network access and no published release artifacts are required.
set -euo pipefail

cd "$(dirname "$0")/.."
ROOT="$(pwd)"
WORK="${ROOT}/target/e2e"
DATA="${WORK}/data"
INSTALL="${WORK}/install"
TOKEN="e2e-publish-token-0123456789"
PORT="${E2E_PORT:-18080}"
BASE="http://127.0.0.1:${PORT}"

CARGO_PROFILE="debug"
BIN_DIR="target/debug"
if [[ "${E2E_RELEASE:-0}" == "1" ]]; then
  CARGO_PROFILE="release"
  BIN_DIR="target/release"
fi

# Upper bound for a registry process that is expected to fail closed at startup.
# Generous enough for a cold CI runner, short enough that a regression which
# lets the server come up fails the run in seconds instead of hanging.
STARTUP_TIMEOUT="${E2E_STARTUP_TIMEOUT:-20}"

FIXTURE_PORT="${E2E_FIXTURE_PORT:-$((PORT + 1))}"
FIXTURE_DIR="${WORK}/fixtures"
FIXTURE_BASE="http://127.0.0.1:${FIXTURE_PORT}"

rm -rf "${WORK}"
mkdir -p "${DATA}" "${INSTALL}" "${FIXTURE_DIR}"

sha256_of() { # $1: file path, prints "sha256:<hex>"
  printf 'sha256:%s' "$(python3 -c \
    "import hashlib,sys;print(hashlib.sha256(open(sys.argv[1],'rb').read()).hexdigest())" "$1")"
}

# Assert an exact diagnostic is present, printing the captured log on failure.
assert_log() { # $1: log file, $2: expected substring, $3: failure message
  grep -Fq "$2" "$1" || {
    echo "FAIL: $3" >&2
    echo "       expected to find: $2" >&2
    echo "--- captured output ---" >&2
    cat "$1" >&2
    exit 1
  }
}

refute_log() { # $1: log file, $2: forbidden substring, $3: failure message
  if grep -Fq "$2" "$1"; then
    echo "FAIL: $3" >&2
    echo "       unexpected output: $2" >&2
    echo "--- captured output ---" >&2
    cat "$1" >&2
    exit 1
  fi
}

wait_for_url() { # $1: url
  for _ in $(seq 1 60); do
    if curl -fsS "$1" >/dev/null 2>&1; then return 0; fi
    sleep 0.5
  done
  return 1
}

# Run a command that must exit on its own, with a hard upper bound.
#
# The registry's fail-closed startup checks are asserted by running the server
# itself; if a regression let it start, a foreground run would block forever and
# the job would only end at the CI step timeout. Bounding it here turns that
# regression into a fast, explicit failure. Implemented with plain job control
# rather than timeout(1)/gtimeout(1), which are not present by default on macOS.
#
# Prints nothing; returns the command's exit status, or 124 if it had to be
# killed (matching timeout(1)'s convention).
run_bounded() { # $1: seconds, $2: log file, rest: command
  local limit="$1" log="$2"
  shift 2

  "$@" >"${log}" 2>&1 &
  local pid=$!

  local waited=0
  local deadline=$((limit * 10)) # tenths of a second
  while ((waited < deadline)); do
    kill -0 "${pid}" 2>/dev/null || break
    sleep 0.1
    waited=$((waited + 1))
  done

  if kill -0 "${pid}" 2>/dev/null; then
    kill "${pid}" 2>/dev/null || true
    sleep 0.2
    kill -9 "${pid}" 2>/dev/null || true
    wait "${pid}" 2>/dev/null || true
    return 124
  fi

  local status=0
  wait "${pid}" || status=$?
  return "${status}"
}

# Assert that the registry refuses to start under the given environment.
assert_registry_refuses_to_start() { # $1: label, $2: log, $3: expected substring, rest: command
  local label="$1" log="$2" expected="$3"
  shift 3

  local status=0
  run_bounded "${STARTUP_TIMEOUT}" "${log}" "$@" || status=$?

  if [[ "${status}" == "124" ]]; then
    echo "FAIL: ${label}: registry was still running after ${STARTUP_TIMEOUT}s;" \
      "it must fail closed at startup" >&2
    echo "--- captured output ---" >&2
    cat "${log}" >&2
    exit 1
  fi
  if [[ "${status}" == "0" ]]; then
    echo "FAIL: ${label}: registry exited successfully instead of failing closed" >&2
    echo "--- captured output ---" >&2
    cat "${log}" >&2
    exit 1
  fi
  assert_log "${log}" "${expected}" "${label}: missing the expected startup diagnostic"
}

echo "==> Building registry and CLI"
# Spelled out per profile: an empty array expansion under `set -u` is an error
# in bash 3.2, which is what macOS ships as /bin/bash.
if [[ "${CARGO_PROFILE}" == "release" ]]; then
  cargo build --release -p streamline-marketplace-registry -p streamline-marketplace-cli
else
  cargo build -p streamline-marketplace-registry -p streamline-marketplace-cli
fi

REGISTRY_BIN="${ROOT}/${BIN_DIR}/streamline-registry"
CLI_BIN="${ROOT}/${BIN_DIR}/streamline-marketplace"

# A minimal, valid WASM module header.
printf '\x00\x61\x73\x6d\x01\x00\x00\x00' > "${WORK}/e2e_transform.wasm"
EXPECTED="$(sha256_of "${WORK}/e2e_transform.wasm")"
echo "    artifact digest: ${EXPECTED}"

echo "==> Registry refuses to start without REGISTRY_AUTH_TOKEN"
assert_registry_refuses_to_start "no token" "${WORK}/no-token.log" "REGISTRY_AUTH_TOKEN" \
  env -u REGISTRY_AUTH_TOKEN "REGISTRY_DATA_DIR=${DATA}" "REGISTRY_BIND=127.0.0.1:${PORT}" \
  "${REGISTRY_BIN}"

echo "==> Registry refuses invalid CORS configuration"
assert_registry_refuses_to_start "wildcard origin" "${WORK}/bad-cors.log" \
  "REGISTRY_ALLOWED_ORIGINS" \
  env "REGISTRY_AUTH_TOKEN=${TOKEN}" "REGISTRY_ALLOWED_ORIGINS=*" "REGISTRY_DATA_DIR=${DATA}" \
  "REGISTRY_BIND=127.0.0.1:${PORT}" "${REGISTRY_BIN}"

echo "==> Starting registry on ${BASE}"
REGISTRY_AUTH_TOKEN="${TOKEN}" \
REGISTRY_DATA_DIR="${DATA}" \
REGISTRY_BIND="127.0.0.1:${PORT}" \
  "${REGISTRY_BIN}" >"${WORK}/registry.log" 2>&1 &
REGISTRY_PID=$!
FIXTURE_PID=""
cleanup() {
  kill "${REGISTRY_PID}" 2>/dev/null || true
  [[ -n "${FIXTURE_PID}" ]] && kill "${FIXTURE_PID}" 2>/dev/null || true
}
trap cleanup EXIT

wait_for_url "${BASE}/healthz" || { echo "FAIL: registry never became ready" >&2; exit 1; }

echo "==> Starting static fixture endpoint on ${FIXTURE_BASE}"
# A controlled, loopback-only static endpoint. Unlike the registry it performs
# no serve-time integrity check, so artifacts served here reach the CLI verbatim
# and exercise the CLI's own checksum validation.
: > "${FIXTURE_DIR}/index.html"
python3 -m http.server "${FIXTURE_PORT}" --bind 127.0.0.1 --directory "${FIXTURE_DIR}" \
  >"${WORK}/fixture-server.log" 2>&1 &
FIXTURE_PID=$!
wait_for_url "${FIXTURE_BASE}/index.html" \
  || { echo "FAIL: fixture endpoint never became ready" >&2; exit 1; }

META='{"name":"e2e-transform","version":"0.1.0","description":"e2e fixture","author":"ci","categories":["filter"],"min_streamline_version":"0.1.0"}'

publish() { # $1: extra curl args (auth), prints status code
  curl -s -o "${WORK}/publish.out" -w '%{http_code}' -X POST "${BASE}/api/v1/transforms" \
    "$@" \
    -F "metadata=${META}" \
    -F "wasm=@${WORK}/e2e_transform.wasm"
}

echo "==> Publish is rejected without credentials"
[[ "$(publish)" == "401" ]]
echo "==> Publish is rejected with a wrong token"
[[ "$(publish -H "Authorization: Bearer wrong-token-000000") " == "401 " ]]
echo "==> Publish is rejected with a malformed scheme"
[[ "$(publish -H "Authorization: Bearer")" == "401" ]]
echo "==> Publish is rejected with a non-ASCII header"
[[ "$(publish -H "Authorization: Bearer tökén")" == "401" ]]

echo "==> Publish succeeds with the configured token"
[[ "$(publish -H "Authorization: Bearer ${TOKEN}")" == "201" ]]
PUBLISHED="$(python3 -c "import json,sys;print(json.load(open(sys.argv[1]))['checksum'])" "${WORK}/publish.out")"
[[ "${PUBLISHED}" == "${EXPECTED}" ]] || {
  echo "FAIL: published checksum ${PUBLISHED} != ${EXPECTED}" >&2; exit 1; }

echo "==> Duplicate publish is rejected"
[[ "$(publish -H "Authorization: Bearer ${TOKEN}")" == "409" ]]

echo "==> Path traversal is rejected"
TRAVERSAL="$(curl -s -o /dev/null -w '%{http_code}' --path-as-is \
  "${BASE}/api/v1/transforms/..%2F..%2Fetc/0.1.0/download")"
[[ "${TRAVERSAL}" == "400" || "${TRAVERSAL}" == "404" ]] || {
  echo "FAIL: traversal returned ${TRAVERSAL}" >&2; exit 1; }

echo "==> CLI installs and verifies the artifact"
"${CLI_BIN}" --registry-url "${BASE}" --transforms-dir "${INSTALL}" install e2e-transform
INSTALLED="${INSTALL}/e2e-transform/0.1.0/e2e_transform.wasm"
INSTALLED_DIGEST="$(sha256_of "${INSTALLED}")"
[[ "${INSTALLED_DIGEST}" == "${EXPECTED}" ]] || {
  echo "FAIL: installed digest ${INSTALLED_DIGEST} != ${EXPECTED}" >&2; exit 1; }

# The two checksum-policy tests below run against pristine, downloadable bytes,
# so the CLI always reaches checksum validation instead of failing earlier on a
# transport error. Registry serve-time integrity is asserted separately, last,
# because it deliberately corrupts the stored artifact.

echo "==> Pending catalog checksums are never installable (CLI-side)"
PENDING_DIR="${WORK}/pending"
mkdir -p "${PENDING_DIR}"
cat > "${PENDING_DIR}/transforms.json" <<JSON
[{"name":"pending-transform","version":"0.1.0","description":"pending fixture","author":"ci",
  "checksum":"pending","categories":["filter"],"min_streamline_version":"0.1.0",
  "wasm_url":"${BASE}/api/v1/transforms/e2e-transform/0.1.0/download"}]
JSON
if "${CLI_BIN}" --registry-url "${PENDING_DIR}/transforms.json" --transforms-dir "${INSTALL}" \
    install --force pending-transform >"${WORK}/pending.log" 2>&1; then
  echo "FAIL: pending checksum was installed" >&2
  cat "${WORK}/pending.log" >&2
  exit 1
fi
# The download must have succeeded; only checksum policy may reject the install.
refute_log "${WORK}/pending.log" "Download failed" \
  "pending test short-circuited on a transport error instead of checksum policy"
# Exact diagnostic emitted only by ChecksumError::Pending (the transform's own
# name also contains "pending", so a loose match would be vacuous).
assert_log "${WORK}/pending.log" \
  "checksum is 'pending': the artifact has not been released yet" \
  "pending checksum was not rejected by checksum validation"
[[ ! -e "${INSTALL}/pending-transform" ]] || {
  echo "FAIL: pending transform left artifacts on disk" >&2; exit 1; }

echo "==> CLI rejects a downloadable artifact whose digest does not match"
# Served by the static fixture endpoint, which has no serve-time integrity
# check, so the mismatch is detected by the CLI (ChecksumError::Mismatch) and
# not masked by the registry's 500.
printf '\x00\x61\x73\x6d\x01\x00\x00\x02' > "${FIXTURE_DIR}/mismatch_transform.wasm"
MISMATCH_DIGEST="$(sha256_of "${FIXTURE_DIR}/mismatch_transform.wasm")"
[[ "${MISMATCH_DIGEST}" != "${EXPECTED}" ]] || {
  echo "FAIL: mismatch fixture digest collides with the expected digest" >&2; exit 1; }
MISMATCH_DIR="${WORK}/mismatch"
mkdir -p "${MISMATCH_DIR}"
cat > "${MISMATCH_DIR}/transforms.json" <<JSON
[{"name":"mismatch-transform","version":"0.1.0","description":"mismatch fixture","author":"ci",
  "checksum":"${EXPECTED}","categories":["filter"],"min_streamline_version":"0.1.0",
  "wasm_url":"${FIXTURE_BASE}/mismatch_transform.wasm"}]
JSON
if "${CLI_BIN}" --registry-url "${MISMATCH_DIR}/transforms.json" --transforms-dir "${INSTALL}" \
    install --force mismatch-transform >"${WORK}/mismatch.log" 2>&1; then
  echo "FAIL: artifact with a mismatching digest was installed" >&2
  cat "${WORK}/mismatch.log" >&2
  exit 1
fi
refute_log "${WORK}/mismatch.log" "Download failed" \
  "mismatch test short-circuited on a transport error instead of checksum validation"
assert_log "${WORK}/mismatch.log" \
  "checksum mismatch: expected ${EXPECTED}, computed ${MISMATCH_DIGEST}" \
  "CLI did not report ChecksumError::Mismatch with the exact digests"
assert_log "${WORK}/mismatch.log" "The download may be corrupted or tampered with." \
  "CLI did not emit the tamper hint that accompanies a checksum mismatch"
[[ ! -e "${INSTALL}/mismatch-transform" ]] || {
  echo "FAIL: mismatching transform left artifacts on disk" >&2; exit 1; }

echo "==> Registry refuses to serve tampered artifacts (server-side)"
STORED="${DATA}/wasm/e2e-transform/0.1.0/e2e_transform.wasm"
printf '\x00\x61\x73\x6d\x01\x00\x00\x01' > "${STORED}"
TAMPERED_STATUS="$(curl -s -o /dev/null -w '%{http_code}' \
  "${BASE}/api/v1/transforms/e2e-transform/0.1.0/download")"
[[ "${TAMPERED_STATUS}" == "500" ]] || {
  echo "FAIL: tampered artifact served with status ${TAMPERED_STATUS}" >&2; exit 1; }
assert_log "${WORK}/registry.log" "Refusing to serve e2e-transform v0.1.0" \
  "registry did not log a serve-time integrity refusal"

echo "==> Tampered artifacts are rejected end to end"
if "${CLI_BIN}" --registry-url "${BASE}" --transforms-dir "${INSTALL}" install --force e2e-transform \
    >"${WORK}/tampered.log" 2>&1; then
  echo "FAIL: tampered artifact was installed" >&2
  cat "${WORK}/tampered.log" >&2
  exit 1
fi
assert_log "${WORK}/tampered.log" "Download failed with status 500" \
  "CLI did not surface the registry's serve-time integrity refusal"
# The previously installed, verified artifact is untouched.
[[ "$(sha256_of "${INSTALLED}")" == "${EXPECTED}" ]] || {
  echo "FAIL: verified installation was overwritten by a rejected download" >&2; exit 1; }

echo "==> End-to-end integrity check passed"
