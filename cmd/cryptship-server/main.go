// Command cryptship-server is a reference license / key-broker server for the
// online and attested binding modes. It derives each per-license secret from a
// master secret and signs responses with the vendor key.
//
// For attested mode, --require-attestation fails closed: this build has no
// attestation verifier (SEV-SNP and TDX verification are not implemented yet),
// so the server refuses to start with the flag rather than release secrets
// against unverified evidence. An integrator who has a verifier implements
// attest.Verifier and sets licenseserver.Server.Verifier, or fronts the
// key broker with one (e.g. Confidential Containers Trustee).
package main

import (
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"flag"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/AI2TH/cryptship/pkg/attest"
	"github.com/AI2TH/cryptship/pkg/license"
	"github.com/AI2TH/cryptship/pkg/licenseserver"
)

func main() {
	masterPath := flag.String("master", "master.key", "master secret (base64), from `cryptship master-key`")
	signPath := flag.String("sign", "vendor.key", "vendor Ed25519 private key that signs responses")
	keyID := flag.String("key-id", "v1", "signing key id advertised in responses")
	addr := flag.String("addr", ":8080", "listen address")
	ttl := flag.Duration("ttl", 24*time.Hour, "validity of each key answer")
	revoke := flag.String("revoke", "", "comma-separated license ids to deny (static)")
	revokeFile := flag.String("revoke-file", "", "path to a live denylist (one license id per line); edit it to revoke without restarting")
	noLegacy := flag.Bool("no-legacy-secrets", false, "refuse licenses issued without binding.secret_v 2 (their secret does not bind the policy, so this server could release attested secrets)")
	enforceSeats := flag.Bool("enforce-seats", false, "enforce binding.max distinct machines per license (loaders send their signed license and machine fingerprint)")
	seatLease := flag.Duration("seat-lease", 30*24*time.Hour, "with --enforce-seats: how long a machine keeps its seat after its last start")
	seatsFile := flag.String("seats-file", "", "with --enforce-seats: persist seats in this JSON file")
	licenseKeys := flag.String("license-keys", "", "with --enforce-seats: vendor public key / key ring that signs licenses (default: the public half of --sign)")
	requireAtt := flag.Bool("require-attestation", false, "require verified TEE attestation (fails to start: no verifier is built in yet)")
	flag.Parse()

	master, err := readB64(*masterPath)
	must(err, "read master key")
	priv, err := readB64(*signPath)
	must(err, "read signing key")
	if len(priv) != ed25519.PrivateKeySize {
		must(errors.New("not an ed25519 private key"), "signing key")
	}

	revoked := map[string]bool{}
	for _, id := range strings.Split(*revoke, ",") {
		if id = strings.TrimSpace(id); id != "" {
			revoked[id] = true
		}
	}

	srv := &licenseserver.Server{
		Master:      master,
		SignKey:     ed25519.PrivateKey(priv),
		KeyID:       *keyID,
		TTL:         *ttl,
		Revoked:     revoked,
		RevokedFile: *revokeFile,

		NoLegacySecrets: *noLegacy,
	}
	if *enforceSeats {
		srv.Seats = &licenseserver.SeatTracker{Lease: *seatLease, Path: *seatsFile}
		if *licenseKeys != "" {
			b, err := os.ReadFile(*licenseKeys)
			must(err, "read --license-keys")
			srv.LicenseKeys, err = license.ParseKeyRing(b)
			must(err, "parse --license-keys")
		}
	}
	verifier, err := attestationVerifier(*requireAtt, builtinVerifier())
	must(err, "--require-attestation")
	srv.Verifier = verifier

	fmt.Fprintf(os.Stderr, "cryptship-server listening on %s (attestation required: %v, seats enforced: %v)\n", *addr, *requireAtt, *enforceSeats)
	if err := http.ListenAndServe(*addr, srv.Handler()); err != nil {
		must(err, "serve")
	}
}

// builtinVerifier returns the attestation verifier compiled into this server.
// There is none yet: SEV-SNP and TDX verifiers are planned.
func builtinVerifier() attest.Verifier { return nil }

// attestationVerifier fails closed: when attestation is required and no
// verifier is available it returns an error, never a verifier that accepts
// unverified evidence.
func attestationVerifier(require bool, v attest.Verifier) (attest.Verifier, error) {
	if !require {
		return nil, nil
	}
	if v == nil {
		return nil, fmt.Errorf("%w: this build cannot verify SEV-SNP or TDX evidence, so it refuses to start rather than release secrets to unverified clients", attest.ErrNoVerifier)
	}
	return v, nil
}

func readB64(path string) ([]byte, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return base64.StdEncoding.DecodeString(strings.TrimSpace(string(b)))
}

func must(err error, what string) {
	if err != nil {
		fmt.Fprintf(os.Stderr, "cryptship-server: %s: %v\n", what, err)
		os.Exit(1)
	}
}
