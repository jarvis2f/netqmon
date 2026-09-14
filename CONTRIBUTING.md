# Contributing to NetQmon

Thank you for your interest in contributing to NetQmon! We welcome community contributions, bug reports, documentation enhancements, and feature suggestions.

## Development Setup

NetQmon consists of three primary components:
1. **Agent (`crates/agent`)**: Rust eBPF agent designed for OpenWrt (requires Linux and `clang` for eBPF bytecode compilation).
2. **Collector (`crates/collector`)**: Rust ingestion and query engine (supports SQLite and ClickHouse backends).
3. **Controller UI (`apps/controller-ui`)**: Next.js web application built with TypeScript, Tailwind CSS, and shadcn/ui.

### Prerequisites

* **Rust**: Current stable toolchain (`rustup default stable`).
* **Node.js**: v20+ and **pnpm** (`npm install -g pnpm`).
* **Docker & Docker Compose**: For local controller testing.

### Local Development

1. **Format verification hook**:
   Install the repository pre-commit hook:
   ```bash
   make hooks
   ```

2. **Check Rust crates**:
   ```bash
   cargo check --workspace
   cargo test --workspace
   cargo fmt --all -- --check
   cargo clippy --workspace --all-targets
   ```

3. **Check Controller UI**:
   ```bash
   pnpm install
   pnpm --filter @netqmon/controller-ui lint
   pnpm --filter @netqmon/controller-ui typecheck
   ```

## Pull Request Guidelines

1. **Create a topic branch**: Fork the repository and branch from `main` (or `dev` for in-progress features).
2. **Commit messages**: Use conventional commit messages (`feat:`, `fix:`, `docs:`, `perf:`, `refactor:`, `test:`, `ci:`).
3. **Run checks locally**: Ensure all tests, linter checks, and formatting pass before opening a PR.
4. **Keep PRs focused**: Small, single-purpose pull requests are much easier to review and merge quickly.
5. **Update documentation**: When adding new features or configuration options, update relevant docs in `docs/` and `README.md`.

## Reporting Issues

* Check existing issues to see if your problem or suggestion has already been discussed.
* Use the appropriate issue template (Bug Report or Feature Request).
* For security-sensitive issues, please follow our [Security Policy](SECURITY.md) instead of public issue trackers.
