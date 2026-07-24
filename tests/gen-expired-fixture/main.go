package main

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"time"

	secp "github.com/decred/dcrd/dcrec/secp256k1/v4"
	secpecdsa "github.com/decred/dcrd/dcrec/secp256k1/v4/ecdsa"
)

func main() {
	// Use the same pubkey as the fixture
	pubHex := "024f4e2ad99c34d60b9ba6283c9431a8418af8673212961f97a77b6377fcd05b62"

	// Generate signing key (we don't have the private key, so generate a random one)
	// and produce a JWT signed by a DIFFERENT key than the fixture - this simulates
	// expired JWT signed by the same provider but with exp in the past
	priv, err := secp.GeneratePrivateKey()
	if err != nil {
		panic(err)
	}
	pub := priv.PubKey()
	_ = pubHex // not used for signing but kept for reference

	now := time.Date(2024, 1, 15, 0, 0, 0, 0, time.UTC) // far in the past
	claims := map[string]any{
		"iss":     "akash19rl4cm2hmr8afy4kldpxz3fka4jguq0a3mq6x0",
		"iat":     now.Unix(),
		"exp":     now.Add(15 * time.Minute).Unix(),
		"nbf":     now.Unix(),
		"version": "v1",
		"leases":  map[string]any{"access": "full"},
	}

	header := map[string]string{"alg": "ES256K", "typ": "JWT"}
	headerBytes, _ := json.Marshal(header)
	headerB64 := base64.RawURLEncoding.EncodeToString(headerBytes)
	payloadBytes, _ := json.Marshal(claims)
	payloadB64 := base64.RawURLEncoding.EncodeToString(payloadBytes)
	signingInput := headerB64 + "." + payloadB64
	hash := sha256.Sum256([]byte(signingInput))
	sig := secpecdsa.Sign(priv, hash[:])
	r := sig.R()
	s := sig.S()
	rBytes := (&r).Bytes()
	sBytes := (&s).Bytes()
	sigBytes := make([]byte, 64)
	copy(sigBytes[0:32], rBytes[:])
	copy(sigBytes[32:64], sBytes[:])
	sigB64 := base64.RawURLEncoding.EncodeToString(sigBytes)
	jwt := headerB64 + "." + payloadB64 + "." + sigB64

	pubHexStr := hex.EncodeToString(pub.SerializeCompressed())
	fmt.Fprintln(os.Stdout, jwt)
	fmt.Fprintln(os.Stderr, "EXPIRED JWT:", jwt[:40]+"...")
	fmt.Fprintln(os.Stderr, "PUBKEY:", pubHexStr)
}