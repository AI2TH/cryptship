package main

import (
	"errors"
	"testing"

	"github.com/AI2TH/cryptship/pkg/attest"
	"github.com/AI2TH/cryptship/pkg/attest/attesttest"
)

func TestRequireAttestationFailsClosed(t *testing.T) {
	// This build has no verifier, so --require-attestation must refuse.
	if v, err := attestationVerifier(true, builtinVerifier()); !errors.Is(err, attest.ErrNoVerifier) || v != nil {
		t.Fatalf("require with no verifier: v=%v err=%v, want ErrNoVerifier", v, err)
	}
	// Not required: no verifier, no error.
	if v, err := attestationVerifier(false, nil); err != nil || v != nil {
		t.Fatalf("not required: v=%v err=%v", v, err)
	}
	// Required with a verifier: that verifier is used.
	if v, err := attestationVerifier(true, attesttest.Verifier{}); err != nil || v == nil {
		t.Fatalf("require with verifier: v=%v err=%v", v, err)
	}
}
