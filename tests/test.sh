#!/bin/bash
# Integration test: Rust client output → Go provider validation
#
# Tests BOTH JWT signing AND manifest hashing against the
# actual provider code. Either it works or it doesn't.
#
# The Rust binary uses the ACTUAL engine code (ManifestBuilder,
# to_canonical_json) to generate manifests and hashes.
# The Go binary uses the ACTUAL provider code (AuthProcess,
# Manifest.Version) to verify them.

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
BINARY="$SCRIPT_DIR/provider-validate"
SDL_FILE="${SDL_FILE:-$SCRIPT_DIR/testdata/simple.yaml}"

echo "🧪 Provider Compatibility Test"
echo "================================"
echo ""

if [ ! -f "$SDL_FILE" ]; then
    echo "❌ SDL file not found: $SDL_FILE"
    echo "   Set SDL_FILE env var to point to a valid SDL file"
    exit 1
fi

# Build Go validator
echo "📦 Building provider validator..."
cd "$SCRIPT_DIR"
go build -o provider-validate . || {
    echo "❌ Go build failed"
    exit 1
}

# ── RUST GENERATION ─────────────────────────────────────────────

echo "🦀 Generating JWT + manifest with Rust engine..."
cd "$SCRIPT_DIR/rust-jwt-gen"

OUTPUT=$(cargo run --quiet -- "$SDL_FILE" 2>/dev/null) || {
    echo "❌ Rust generation failed"
    exit 1
}

JWT=$(echo "$OUTPUT" | grep "^JWT=" | cut -d= -f2)
PUBKEY=$(echo "$OUTPUT" | grep "^PUBKEY=" | cut -d= -f2)
ISSUER=$(echo "$OUTPUT" | grep "^ISSUER=" | cut -d= -f2)
MANIFEST_HASH=$(echo "$OUTPUT" | grep "^MANIFEST_HASH=" | cut -d= -f2)

# Extract multi-line MANIFEST_JSON (everything between MANIFEST_JSON= and MANIFEST_HASH=)
MANIFEST_JSON=$(echo "$OUTPUT" | sed -n '/^MANIFEST_JSON=/,/^MANIFEST_HASH=/{ /^MANIFEST_JSON=/s/^MANIFEST_JSON=//p; /^MANIFEST_JSON=/!{ /^MANIFEST_HASH=/!p; } }')

if [ -z "$JWT" ] || [ -z "$PUBKEY" ]; then
    echo "❌ Failed to parse Rust JWT output"
    echo "Output was:"
    echo "$OUTPUT"
    exit 1
fi

if [ -z "$MANIFEST_JSON" ] || [ -z "$MANIFEST_HASH" ]; then
    echo "❌ Failed to parse Rust manifest output"
    echo "Output was:"
    echo "$OUTPUT"
    exit 1
fi

echo "   Issuer: $ISSUER"
echo "   Pubkey: ${PUBKEY:0:16}..."
echo "   JWT:    ${JWT:0:32}..."
echo "   Hash:   ${MANIFEST_HASH:0:16}..."
echo ""

# Write Rust-generated fixtures for Go to verify
mkdir -p "$SCRIPT_DIR/testdata/fixtures"
echo "$MANIFEST_JSON" > "$SCRIPT_DIR/testdata/fixtures/manifest.json"
echo -n "$MANIFEST_HASH" > "$SCRIPT_DIR/testdata/fixtures/manifest-hash.txt"

# ── JWT TEST ─────────────────────────────────────────────────────

echo "🔍 Verifying Rust JWT with provider AuthProcess()..."
"$BINARY" jwt "$JWT" "$PUBKEY" || {
    echo ""
    echo "❌ JWT VERIFICATION FAILED"
    echo "   Rust JWT rejected by provider AuthProcess()"
    exit 1
}

echo ""

# ── MANIFEST TEST ─────────────────────────────────────────────────

echo "🔍 Verifying Rust manifest hash with provider Manifest.Version()..."
"$BINARY" manifest "$SCRIPT_DIR/testdata/fixtures/manifest.json" "$MANIFEST_HASH" || {
    echo ""
    echo "❌ MANIFEST HASH VERIFICATION FAILED"
    echo "   Rust manifest hash doesn't match provider Manifest.Version()"
    echo "   This means our Rust engine produces different output than Go providers expect"
    exit 1
}

echo ""

# ── RESULT ───────────────────────────────────────────────────────

echo "✅ ALL INTEGRATION TESTS PASSED"
echo "   Rust JWT    → accepted by provider AuthProcess()"
echo "   Rust manifest → hash matches provider Manifest.Version()"
echo ""
