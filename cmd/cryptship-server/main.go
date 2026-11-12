// Command cryptship-server is a reference license / key-broker server for the
// online and attested binding modes. It derives each per-license secret from a
// master secret and signs responses with the vendor key.
//
// For attested mode, --require-attestation currently accepts any non-empty
// evidence — a PLACEHOLDER for real SEV-SNP/TDX quote verification, which an
// integrator plugs in (e.g. by fronting this with Confidential Containers
// Trustee or calling a verifier such as Veraison/MAA).
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

	"github.com/cryptship/cryptship/pkg/licenseserver"
)

func main() {
	masterPath := flag.String("master", "master.key", "master secret (base64), from `cryptship master-key`")
	signPath := flag.String("sign", "vendor.key", "vendor Ed25519 private key that signs responses")
	keyID := flag.String("key-id", "v1", "signing key id advertised in responses")
	addr := flag.String("addr", ":8080", "listen address")
	ttl := flag.Duration("ttl", 24*time.Hour, "validity of each key answer")
	revoke := flag.String("revoke", "", "comma-separated license ids to deny")
	requireAtt := flag.Bool("require-attestation", false, "require (placeholder) attestation evidence")
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
		Master:  master,
		SignKey: ed25519.PrivateKey(priv),
		KeyID:   *keyID,
		TTL:     *ttl,
		Revoked: revoked,
	}
	if *requireAtt {
		srv.Verify = func(evidence []byte) error {
			if len(evidence) == 0 {
				return errors.New("missing attestation evidence")
			}
			// PLACEHOLDER: verify a real SEV-SNP/TDX quote here.
			return nil
		}
	}

	fmt.Fprintf(os.Stderr, "cryptship-server listening on %s (attestation required: %v)\n", *addr, *requireAtt)
	if err := http.ListenAndServe(*addr, srv.Handler()); err != nil {
		must(err, "serve")
	}
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
