// Provider-compatible validation tool for Rust client output.
//
// Validates JWT authentication, manifest hashing, and generates
// test fixtures - all using ACTUAL provider code.
//
// Usage:
//   provider-validate jwt      <token> <pubkey_hex>
//   provider-validate manifest  <manifest.json> <expected_hash_hex>
//   provider-validate all       <token> <pubkey_hex> <manifest.json> <expected_hash_hex>
//   provider-validate gen-fixture <sdl_file> [output_dir]
package main

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"github.com/cosmos/cosmos-sdk/crypto/keys/secp256k1"
	cryptotypes "github.com/cosmos/cosmos-sdk/crypto/types"
	sdk "github.com/cosmos/cosmos-sdk/types"

	// ACTUAL provider JWT verification
	gwutils "github.com/akash-network/provider/gateway/utils"
	"github.com/akash-network/provider/tools/fromctx"
	providertypes "github.com/akash-network/provider/types"

	ajwt "pkg.akt.dev/go/util/jwt"

	// ACTUAL provider manifest validation
	maniv2beta3 "pkg.akt.dev/go/manifest/v2beta3"

	// ACTUAL provider SDL parsing (for fixture generation)
	"pkg.akt.dev/go/sdl"
)

func init() {
	// Providers use akash bech32 prefix
	config := sdk.GetConfig()
	config.SetBech32PrefixForAccount("akash", "akashpub")
}

// mockAccountQuerier returns the pubkey we provide instead of querying the chain.
type mockAccountQuerier struct {
	pubkey cryptotypes.PubKey
}

func (m *mockAccountQuerier) GetAccountPublicKey(_ context.Context, _ sdk.Address) (cryptotypes.PubKey, error) {
	return m.pubkey, nil
}

func main() {
	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}

	cmd := os.Args[1]

	var err error
	switch cmd {
	case "jwt":
		if len(os.Args) < 4 {
			fmt.Fprintf(os.Stderr, "Usage: %s jwt <token> <pubkey_hex>\n", os.Args[0])
			os.Exit(1)
		}
		err = verifyJWT(os.Args[2], os.Args[3])

	case "manifest":
		if len(os.Args) < 4 {
			fmt.Fprintf(os.Stderr, "Usage: %s manifest <manifest.json> <expected_hash_hex>\n", os.Args[0])
			os.Exit(1)
		}
		err = verifyManifest(os.Args[2], os.Args[3])

	case "all":
		if len(os.Args) < 6 {
			fmt.Fprintf(os.Stderr, "Usage: %s all <token> <pubkey_hex> <manifest.json> <expected_hash_hex>\n", os.Args[0])
			os.Exit(1)
		}
		err = verifyAll(os.Args[2], os.Args[3], os.Args[4], os.Args[5])

	case "gen-fixture":
		if len(os.Args) < 3 {
			fmt.Fprintf(os.Stderr, "Usage: %s gen-fixture <sdl_file> [output_dir]\n", os.Args[0])
			os.Exit(1)
		}
		outputDir := "fixtures"
		if len(os.Args) >= 4 {
			outputDir = os.Args[3]
		}
		err = genFixture(os.Args[2], outputDir)

	default:
		printUsage()
		os.Exit(1)
	}

	if err != nil {
		fmt.Fprintf(os.Stderr, "\n❌ FAILED: %v\n", err)
		os.Exit(1)
	}
}

func printUsage() {
	fmt.Fprintf(os.Stderr, `Provider Validation Tool

Validates Rust client output using ACTUAL Akash provider code.

COMMANDS:
  jwt          Verify JWT signature (uses provider gateway/utils.AuthProcess)
  manifest     Verify manifest hash (uses provider manifest/v2beta3.Manifest.Version)
  all          Verify both JWT and manifest
  gen-fixture  Generate manifest fixtures from SDL file

USAGE:
  %[1]s jwt          <token> <pubkey_hex>
  %[1]s manifest     <manifest.json> <expected_hash_hex>
  %[1]s all          <token> <pubkey_hex> <manifest.json> <expected_hash_hex>
  %[1]s gen-fixture  <sdl_file> [output_dir]

EXAMPLES:
  %[1]s jwt eyJhbGc... 02a1b2c3...
  %[1]s manifest manifest.json abc123...
  %[1]s all eyJhbGc... 02a1b2c3... manifest.json abc123...
  %[1]s gen-fixture simple.yaml fixtures/

PROVIDER CODE USED:
  JWT:      github.com/akash-network/provider/gateway/utils.AuthProcess()
  Manifest: pkg.akt.dev/go/manifest/v2beta3.Manifest.Version()
  SDL:      pkg.akt.dev/go/sdl.ReadFile()
`, os.Args[0])
}

// ═══════════════════════════════════════════════════════════════════
// JWT VERIFICATION - uses gateway/utils.AuthProcess()
// ═══════════════════════════════════════════════════════════════════

func verifyJWT(tokenStr, pubkeyHex string) error {
	fmt.Println("═══════════════════════════════════════════")
	fmt.Println("  JWT VERIFICATION")
	fmt.Println("  gateway/utils.AuthProcess()")
	fmt.Println("═══════════════════════════════════════════")
	fmt.Println()

	// Parse token without verification to display claims
	parser := jwt.NewParser(jwt.WithoutClaimsValidation())
	token, _, err := parser.ParseUnverified(tokenStr, &ajwt.Claims{})
	if err != nil {
		return fmt.Errorf("failed to parse JWT: %w", err)
	}

	claims, ok := token.Claims.(*ajwt.Claims)
	if !ok {
		return fmt.Errorf("invalid claims type")
	}

	fmt.Printf("  Issuer:    %s\n", claims.Issuer)
	fmt.Printf("  Version:   %s\n", claims.Version)
	fmt.Printf("  IssuedAt:  %s\n", claims.IssuedAt.Time.Format(time.RFC3339))
	fmt.Printf("  NotBefore: %s\n", claims.NotBefore.Time.Format(time.RFC3339))
	fmt.Printf("  ExpiresAt: %s\n", claims.ExpiresAt.Time.Format(time.RFC3339))
	fmt.Printf("  Access:    %s\n", claims.Leases.Access)
	fmt.Println()

	// Decode public key
	pubkeyBytes, err := hex.DecodeString(pubkeyHex)
	if err != nil {
		return fmt.Errorf("invalid pubkey hex: %w", err)
	}
	if len(pubkeyBytes) != 33 {
		return fmt.Errorf("pubkey must be 33 bytes (compressed secp256k1), got %d", len(pubkeyBytes))
	}
	pubkey := &secp256k1.PubKey{Key: pubkeyBytes}

	fmt.Printf("  PubKey:    %x\n\n", pubkeyBytes)

	// Mock account querier - returns our pubkey instead of chain query
	mockQuerier := &mockAccountQuerier{pubkey: pubkey}
	ctx := context.WithValue(context.Background(), fromctx.CtxKeyAccountQuerier, providertypes.AccountQuerier(mockQuerier))

	// Call ACTUAL provider verification
	verifiedClaims, err := gwutils.AuthProcess(ctx, nil, tokenStr)
	if err != nil {
		return fmt.Errorf("provider AuthProcess() rejected: %w", err)
	}

	if verifiedClaims.Issuer != claims.Issuer {
		return fmt.Errorf("issuer mismatch after verification: got %s, expected %s", verifiedClaims.Issuer, claims.Issuer)
	}

	fmt.Println("  ✅ JWT: provider AuthProcess() accepted")
	return nil
}

// ═══════════════════════════════════════════════════════════════════
// MANIFEST VERIFICATION - uses manifest/v2beta3.Manifest.Version()
// ═══════════════════════════════════════════════════════════════════

func verifyManifest(manifestFile, expectedHash string) error {
	fmt.Println("═══════════════════════════════════════════")
	fmt.Println("  MANIFEST HASH VERIFICATION")
	fmt.Println("  manifest/v2beta3.Manifest.Version()")
	fmt.Println("═══════════════════════════════════════════")
	fmt.Println()

	// Read manifest JSON
	manifestJSON, err := os.ReadFile(manifestFile)
	if err != nil {
		return fmt.Errorf("failed to read %s: %w", manifestFile, err)
	}

	// Parse into the ACTUAL provider manifest type
	var manifest maniv2beta3.Manifest
	if err := json.Unmarshal(manifestJSON, &manifest); err != nil {
		return fmt.Errorf("failed to parse manifest JSON: %w", err)
	}

	fmt.Printf("  Groups: %d\n", len(manifest))
	for i, group := range manifest.GetGroups() {
		fmt.Printf("  Group[%d]: %s (%d services)\n", i, group.Name, len(group.Services))
	}
	fmt.Println()

	// Validate manifest structure (same as provider)
	if err := manifest.Validate(); err != nil {
		return fmt.Errorf("manifest.Validate() failed: %w", err)
	}
	fmt.Println("  ✅ Manifest structure valid")

	// Compute version hash using the ACTUAL provider method
	// This is what manifest/manager.go:421 calls
	version, err := manifest.Version()
	if err != nil {
		return fmt.Errorf("manifest.Version() failed: %w", err)
	}

	computedHash := hex.EncodeToString(version)
	fmt.Printf("  Hash:  %s\n", computedHash)

	fmt.Printf("  Expected: %s\n", expectedHash)

	if computedHash != expectedHash {
		fmt.Println()

		// Show where they diverge
		for i := 0; i < len(expectedHash) && i < len(computedHash); i++ {
			if expectedHash[i] != computedHash[i] {
				fmt.Printf("  First diff at byte %d: expected '%c', got '%c'\n", i, expectedHash[i], computedHash[i])
				break
			}
		}

		// Show the sorted JSON so you can debug field ordering
		normalized, _ := json.Marshal(manifest)
		sortedJSON, _ := sdk.SortJSON(normalized)
		fmt.Printf("\n  Sorted JSON (what gets hashed):\n  %s\n", string(sortedJSON))

		return fmt.Errorf("hash mismatch: computed %s, expected %s", computedHash, expectedHash)
	}

	fmt.Println("  ✅ Manifest hash matches expected")

	return nil
}

// ═══════════════════════════════════════════════════════════════════
// COMBINED VERIFICATION - both JWT and manifest
// ═══════════════════════════════════════════════════════════════════

func verifyAll(tokenStr, pubkeyHex, manifestFile, expectedHash string) error {
	// JWT first
	if err := verifyJWT(tokenStr, pubkeyHex); err != nil {
		return err
	}
	fmt.Println()

	// Then manifest
	if err := verifyManifest(manifestFile, expectedHash); err != nil {
		return err
	}

	fmt.Println()
	fmt.Println("═══════════════════════════════════════════")
	fmt.Println("  ✅ ALL VALIDATIONS PASSED")
	fmt.Println("═══════════════════════════════════════════")
	return nil
}

// ═══════════════════════════════════════════════════════════════════
// FIXTURE GENERATION - uses pkg.akt.dev/go/sdl + Manifest.Version()
// ═══════════════════════════════════════════════════════════════════

func genFixture(sdlFile, outputDir string) error {
	fmt.Println("═══════════════════════════════════════════")
	fmt.Println("  FIXTURE GENERATION")
	fmt.Println("  sdl.ReadFile() → Manifest.Version()")
	fmt.Println("═══════════════════════════════════════════")
	fmt.Println()

	// Parse SDL using ACTUAL provider SDK
	sdlObj, err := sdl.ReadFile(sdlFile)
	if err != nil {
		return fmt.Errorf("sdl.ReadFile(%s) failed: %w", sdlFile, err)
	}
	fmt.Printf("  SDL:  %s\n", sdlFile)

	// Get manifest from SDL
	manifest, err := sdlObj.Manifest()
	if err != nil {
		return fmt.Errorf("sdl.Manifest() failed: %w", err)
	}

	fmt.Printf("  Groups: %d\n", len(manifest))
	for i, group := range manifest.GetGroups() {
		fmt.Printf("  Group[%d]: %s (%d services)\n", i, group.Name, len(group.Services))
	}
	fmt.Println()

	// Compute version hash
	version, err := manifest.Version()
	if err != nil {
		return fmt.Errorf("manifest.Version() failed: %w", err)
	}
	computedHash := hex.EncodeToString(version)
	fmt.Printf("  Hash: %s\n\n", computedHash)

	// Create output directory
	if err := os.MkdirAll(outputDir, 0755); err != nil {
		return fmt.Errorf("failed to create %s: %w", outputDir, err)
	}

	// Write manifest JSON
	manifestJSON, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return fmt.Errorf("json.Marshal failed: %w", err)
	}
	manifestPath := filepath.Join(outputDir, "manifest.json")
	if err := os.WriteFile(manifestPath, manifestJSON, 0644); err != nil {
		return fmt.Errorf("failed to write %s: %w", manifestPath, err)
	}
	fmt.Printf("  Wrote: %s\n", manifestPath)

	// Write hash
	hashPath := filepath.Join(outputDir, "manifest-hash.txt")
	if err := os.WriteFile(hashPath, []byte(computedHash), 0644); err != nil {
		return fmt.Errorf("failed to write %s: %w", hashPath, err)
	}
	fmt.Printf("  Wrote: %s\n", hashPath)

	fmt.Println()
	fmt.Println("  ✅ Fixtures generated")
	return nil
}
