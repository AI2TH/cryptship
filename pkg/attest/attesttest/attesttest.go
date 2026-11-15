// Package attesttest provides an attester and verifier pair for tests and
// local demos. The evidence is a fixed prefix followed by the nonce: it is
// bound to the request but proves NOTHING about the runtime environment.
// Never wire these into a production server or loader.
package attesttest

import (
	"bytes"
	"context"
	"errors"

	"github.com/AI2TH/cryptship/pkg/attest"
)

const prefix = "cryptship-attesttest-evidence/v1\x00"

// Attester produces test evidence that commits to bindData. It satisfies
// keyprovider.Attester.
type Attester struct{}

// Name implements keyprovider.Attester.
func (Attester) Name() string { return "attesttest" }

// Evidence implements keyprovider.Attester.
func (Attester) Evidence(_ context.Context, bindData []byte) ([]byte, error) {
	return append([]byte(prefix), bindData...), nil
}

// Verifier accepts only evidence produced by Attester for the same nonce.
type Verifier struct{}

// Verify implements attest.Verifier.
func (Verifier) Verify(evidence, nonce []byte) (attest.Measurement, error) {
	if len(nonce) == 0 {
		return attest.Measurement{}, errors.New("attesttest: empty nonce")
	}
	if !bytes.Equal(evidence, append([]byte(prefix), nonce...)) {
		return attest.Measurement{}, errors.New("attesttest: evidence does not match the nonce")
	}
	return attest.Measurement{Platform: "attesttest"}, nil
}
