.PHONY: build test lint fmt install-hooks build-agent build-controller build-ui

build:
	cargo build --workspace
	pnpm build

test:
	cargo test --workspace

lint:
	cargo fmt --all --check
	cargo clippy --workspace --all-targets --all-features -- -D warnings
	pnpm lint
	pnpm typecheck

fmt:
	cargo fmt --all
	pnpm --filter @netqmon/controller-ui exec eslint . --fix

install-hooks:
	git config core.hooksPath .githooks
	@echo "Git hooks installed. Rust formatting will be checked before each commit."

build-agent:
	cargo build --package netqmon-agent

build-controller:
	cargo build --package netqmon-collector

build-ui:
	pnpm build
