.PHONY: build test lint fmt check clean help build-transforms build-cli

WASM_TARGET = wasm32-wasip1
TRANSFORMS = json-filter timestamp-enricher pii-redactor schema-validator field-router

help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-20s\033[0m %s\n", $$1, $$2}'

build: build-cli build-transforms ## Build everything

build-cli: ## Build the marketplace CLI
	cargo build -p streamline-marketplace-cli --release

build-transforms: ## Build all WASM transforms
	@for t in $(TRANSFORMS); do \
		echo "Building $$t..."; \
		cargo build -p $$t --target $(WASM_TARGET) --release; \
	done

test: ## Run all tests
	cargo test -p streamline-marketplace-cli
	@for t in $(TRANSFORMS); do \
		cargo test -p $$t; \
	done

fmt: ## Format all code
	cargo fmt --all

check: ## Check formatting and lints
	cargo fmt --all -- --check
	cargo clippy -p streamline-marketplace-cli --all-targets -- -D warnings
	@for t in $(TRANSFORMS); do \
		cargo clippy -p $$t --target $(WASM_TARGET) -- -D warnings; \
	done

lint: check ## Alias for check

validate-registry: ## Validate the transform registry
	python3 -c "\
	import json, sys; \
	data = json.load(open('registry/transforms.json')); \
	required = ['name','version','description','author','wasm_url','categories','min_streamline_version','checksum']; \
	[sys.exit(f'ERROR: {e.get(\"name\",\"?\")} missing {f}') for e in data for f in required if f not in e or not e[f]]; \
	print(f'Registry valid: {len(data)} transforms')"

clean: ## Clean build artifacts
	cargo clean
