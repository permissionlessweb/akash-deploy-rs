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
