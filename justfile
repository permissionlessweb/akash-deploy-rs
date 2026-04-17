# akash-deploy-rs justfile
# Standalone Akash deployment workflow engine

# Show available commands
default:
    @just --list

# ═══════════════════════════════════════════════════════════════
# Build & Check
# ═══════════════════════════════════════════════════════════════

# Check code compiles (fast JSON output)
chec:
    @cargo chec

# Build the library
build:
    @cargo build

# Build with release optimizations
build-release:
    @cargo build --release

# Format code
fmt:
    @cargo fmt

# Run clippy lints
lint:
    @cargo clippy -- -D warnings

# ═══════════════════════════════════════════════════════════════
# Testing
# ═══════════════════════════════════════════════════════════════

# Run all tests (unit + e2e)
test: test-unit test-e2e
    @echo ""
    @echo "✅ All tests passed (unit + e2e)"

# Run tests with coverage report (excludes generated proto files)
coverage:
    rm -rf carp.json
    @cargo carpulin --all-features --ignore-filename-regex 'src/gen/.*\.rs' >> carp.json

# Run unit tests only
test-unit:
    @cargo test

# Run unit tests with output
test-verbose:
    @cargo test -- --nocapture

# Run integration tests (Rust → Go provider validation)
test-e2e:
    @cd tests && just test

# Run only JWT verification test
test-jwt:
    @cd tests && just test-jwt-only

# Run only manifest hash verification
test-manifest:
    @cd tests && just test-sdl

# Test a single SDL file
test-one SDL:
    @cd tests && just test-one {{SDL}}

# Live demonstration deploying a simple sd to akash network
demo:
    @cargo run --example deploy --features default-client

# Alias for test
test-all: test

# ═══════════════════════════════════════════════════════════════
# Maintenance
# ═══════════════════════════════════════════════════════════════

# Clean build artifacts
clean:
    @cargo clean
    @cd tests && just clean

# Clean and rebuild everything
rebuild: clean build test-all

# Update dependencies
update:
    @cargo update

# Check for outdated dependencies
outdated:
    @cargo outdated

# ═══════════════════════════════════════════════════════════════
# Publishing
# ═══════════════════════════════════════════════════════════════

# Dry run of publish
publish-dry:
    @cargo publish --dry-run

# Publish to crates.io
publish:
    @cargo publish

# ═══════════════════════════════════════════════════════════════
# Proto Generation — Rust types from .proto files
# ═══════════════════════════════════════════════════════════════

# Compile all .proto files under proto/ and regenerate src/gen/mod.rs.
# Auto-discovers every proto file — no manual listing required.
gen-proto:
    @echo ">>> Compiling proto files and regenerating src/gen/..."
    cargo run --manifest-path proto/Cargo.toml --bin proto-gen
    @echo "Done — src/gen/ updated."

# Clean generated Rust proto types.
clean-gen:
    rm -rf src/gen/*.rs
    @echo "Cleaned src/gen/"

# ═══════════════════════════════════════════════════════════════
# Proto Generation — Console API (Zod → proto3)
# ═══════════════════════════════════════════════════════════════

# Install JS deps for the console-api proto generator (idempotent).
console-api-install:
    @echo "Installing console-api script deps..."
    cd scripts && npm install

# Generate proto/console/*.proto from Zod schemas.
# Installs npm deps first if node_modules is missing.
console-api-proto:
    #!/usr/bin/env bash
    set -euo pipefail
    if [[ ! -d scripts/node_modules ]]; then
        echo ">>> Installing script dependencies..."
        cd scripts && npm install && cd ..
    fi
    echo ">>> Generating console-api proto files..."
    cd scripts && npm run generate
    echo "Done — proto files written to proto/console/"

# List all Zod schemas registered in the console-api schema registry.
console-api-schemas:
    #!/usr/bin/env bash
    set -euo pipefail
    if [[ ! -d scripts/node_modules ]]; then
        cd scripts && npm install && cd ..
    fi
    cd scripts && npm run schemas

# ═══════════════════════════════════════════════════════════════
# Development
# ═══════════════════════════════════════════════════════════════

# Run pre-commit checks
pre-commit: fmt lint chec test

# Watch for changes and run checks
watch:
    @cargo watch -x check -x test

# Generate docs and open in browser
docs:
    @cargo doc --open --no-deps

# ═══════════════════════════════════════════════════════════════
# Utility
# ═══════════════════════════════════════════════════════════════

# Show dependency tree
tree:
    @cargo tree

# Show package info
info:
    @cargo metadata --no-deps --format-version 1 | jq -r '.packages[0]'

# Compile console API protos into Rust gRPC clients (src/gen/console.*.rs)
gen-console:
    @echo ">>> Compiling console API protos..."
    cargo run --manifest-path proto/Cargo.toml --bin console-gen
    @echo "Done — console clients generated in src/gen/"

# Full proto rebuild: chain protos + console API
gen-all: gen-proto gen-console
