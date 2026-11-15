// Package attest defines how a key broker checks TEE attestation evidence
// before it releases a binding secret for the attested binding mode.
//
// Only the interface lives here. cryptship does not ship a production
// verifier yet: SEV-SNP and TDX verifiers (signature chain, nonce in
// REPORT_DATA, measurement allow-list) are planned. attesttest has a
// verifier for tests that proves nothing about the runtime environment.
package attest

import "errors"

// Measurement is what a verifier extracted from evidence it accepted.
type Measurement struct {
	// Platform names the TEE, e.g. "sev-snp" or "tdx".
	Platform string
	// Digest is the launch measurement that was matched against the
	// verifier's allow-list.
	Digest []byte
}

// Verifier checks attestation evidence. nonce is the value the evidence must
// commit to in REPORT_DATA (online.AttestationBinding of the license id, the
// server's challenge and the loader's ephemeral public key), so evidence made
// for another challenge, license or key is rejected. Verify returns an error for any
// evidence it cannot fully verify; it never accepts by default.
type Verifier interface {
	Verify(evidence, nonce []byte) (Measurement, error)
}

// ErrNoVerifier is returned where attestation is required but no verifier is
// configured.
var ErrNoVerifier = errors.New("attest: no attestation verifier is configured")
