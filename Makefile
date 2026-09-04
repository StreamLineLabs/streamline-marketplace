.PHONY: build test lint fmt check clean help build-transforms build-transforms-release \
	check-reproducible-wasm build-sinks build-cli stage-release verify-published-registry \
	validate-registry validate-registry-digests validate-registry-release \
	validate-registry-controls

WASM_TARGET = wasm32-wasip1

# Directory of locally built release artifacts used by the artifact-bound
# release gate. Override with `make validate-registry-release ARTIFACTS_DIR=...`.
ARTIFACTS_DIR = dist
RELEASE_TAG ?=
REPRO_TARGET_DIR ?= target/reproducible-release
RELEASE_WASM_DIR ?= target/wasm32-wasip1/release

# WASM transforms (compile to wasm32-wasip1)
WASM_TRANSFORMS = json-filter timestamp-enricher pii-redactor schema-validator field-router ai-classifier

# Sink connectors (standard Rust library crates)
SINK_TRANSFORMS = streamline-http-webhook-sink streamline-redis-sink streamline-postgres-connector \
	streamline-elasticsearch-sink streamline-mongodb-sink streamline-slack-sink \
	streamline-s3-sink streamline-snowflake-sink streamline-bigquery-sink streamline-mysql-sink

help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-20s\033[0m %s\n", $$1, $$2}'

build: build-cli build-transforms build-sinks ## Build everything

build-cli: ## Build the marketplace CLI
	cargo build --locked -p streamline-marketplace-cli --release

build-transforms: ## Build all WASM transforms
	@for t in $(WASM_TRANSFORMS); do \
		echo "Building $$t (WASM)..."; \
		cargo build -p $$t --target $(WASM_TARGET) --release; \
	done

build-transforms-release: ## Build WASM with the exact release Rust 1.85.1 toolchain
	bash scripts/build_release_wasm.sh

check-reproducible-wasm: ## Compare two clean, pinned Rust 1.85.1 release builds
	CARGO_TARGET_DIR=$(REPRO_TARGET_DIR) bash scripts/check_reproducible_wasm.sh

build-sinks: ## Build all sink connectors (native)
	@for t in $(SINK_TRANSFORMS); do \
		echo "Building $$t..."; \
		cargo build -p $$t --release; \
	done

test: ## Run all tests
	cargo test -p streamline-marketplace-cli
	@for t in $(WASM_TRANSFORMS); do \
		echo "Testing $$t..."; \
		cargo test -p $$t; \
	done
	@for t in $(SINK_TRANSFORMS); do \
		echo "Testing $$t..."; \
		cargo test -p $$t; \
	done

fmt: ## Format all code
	cargo fmt --all

check: ## Check formatting and lints
	cargo fmt --all -- --check
	cargo clippy -p streamline-marketplace-cli --all-targets -- -D warnings
	@for t in $(WASM_TRANSFORMS); do \
		cargo clippy -p $$t --target $(WASM_TARGET) -- -D warnings; \
	done
	@for t in $(SINK_TRANSFORMS); do \
		cargo clippy -p $$t --all-targets -- -D warnings; \
	done

lint: check ## Alias for check

validate-registry: ## Validate the transform registry (structural / pre-artifact)
	python3 scripts/validate_registry.py --mode structural

validate-registry-digests: ## Advisory audit: report entries that still carry 'pending' (never a release gate)
	python3 scripts/validate_registry.py --mode digests

stage-release: ## Stage only entries explicitly selected for RELEASE_TAG
	@test -n "$(RELEASE_TAG)" || (echo "Usage: make stage-release RELEASE_TAG=vX.Y.Z" && exit 1)
	python3 scripts/stage_release_artifacts.py --tag $(RELEASE_TAG) \
		--selection registry/shipping.json \
		--build-dir $(RELEASE_WASM_DIR) --output-dir $(ARTIFACTS_DIR)

verify-published-registry: ## Download and verify actual published assets against the live catalog
	python3 scripts/verify_published_registry.py --download

validate-registry-release: ## Strict current-tag gate (RELEASE_TAG=vX.Y.Z, ARTIFACTS_DIR=dist)
	@test -n "$(RELEASE_TAG)" || (echo "Usage: make validate-registry-release RELEASE_TAG=vX.Y.Z" && exit 1)
	python3 scripts/validate_registry.py --mode release --artifacts $(ARTIFACTS_DIR) \
		--expected-tag $(RELEASE_TAG) --selection registry/shipping.json

validate-registry-controls: ## Prove release validation rejects pending-on-staged, wrong, missing, ambiguous, impostor, and unreferenced artifacts
	bash scripts/validate_registry_controls.sh

clean: ## Clean build artifacts
	cargo clean
