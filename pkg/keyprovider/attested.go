package keyprovider

import (
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/json"
	"errors"
	"time"

	"github.com/AI2TH/cryptship/pkg/crypto"
	"github.com/AI2TH/cryptship/pkg/license"
	"github.com/AI2TH/cryptship/pkg/machine"
	"github.com/AI2TH/cryptship/pkg/online"
)

// Attester produces TEE attestation evidence (e.g. an AMD SEV-SNP report or an
// Intel TDX quote). Real implementations read /dev/sev-guest or /dev/tdx_guest
// and put bindData (online.AttestationBinding of the license id, the server's
// challenge and the loader's ephemeral public key) into the report's
// REPORT_DATA field. ErrNoTEE is returned where no TEE is available.
// pkg/attest/attesttest has a test-only implementation.
type Attester interface {
	Name() string
	Evidence(ctx context.Context, bindData []byte) ([]byte, error)
}

// ErrNoTEE indicates the host is not a confidential VM, so attested binding
// cannot be satisfied here.
var ErrNoTEE = errors.New("attested: no confidential-compute TEE available on this host")

// Attested releases the content key only after the key broker verifies TEE
// attestation evidence. The flow (see pkg/online/attested.go):
//
//  1. fetch a single-use challenge from the server (POST /v1/challenge);
//  2. make an ephemeral X25519 key pair in this process (inside the TEE);
//  3. ask the Attester for evidence committing to
//     online.AttestationBinding(license id, challenge, ephemeral public key);
//  4. POST /v1/key with the challenge, evidence and ephemeral public key;
//  5. verify the signed answer and decrypt the secret with the ephemeral key.
//
// A captured request cannot be replayed (the challenge is spent), and a
// captured answer is useless without the ephemeral private key.
//
// NOTE: real SEV-SNP/TDX evidence needs confidential-compute hardware.
// DefaultAttester() reports ErrNoTEE on ordinary hosts; integrators supply a
// platform Attester (and a server-side attest.Verifier). See
// docs/ARCHITECTURE.md.
type Attested struct {
	Keys     license.KeyRing
	Client   HTTPClient
	Attester Attester
}

// Name implements Provider.
func (Attested) Name() string { return "attested" }

// Handles implements Provider.
func (Attested) Handles(p license.BindingPolicy) bool { return p == license.BindAttested }

// ContentKey implements Provider. Attested never uses the outage grace cache:
// every start re-attests.
func (a Attested) ContentKey(ctx context.Context, lic *license.License) ([]byte, error) {
	if a.Attester == nil {
		return nil, ErrNoTEE
	}
	c := lic.Claims

	chBody, err := postJSON(ctx, a.Client, c, "/v1/challenge", online.ChallengeRequest{LicenseID: c.LicenseID})
	if err != nil {
		return nil, err
	}
	var ch online.ChallengeResponse
	if err := json.Unmarshal(chBody, &ch); err != nil || len(ch.Challenge) == 0 {
		return nil, errors.New("attested: bad challenge from server")
	}

	eph, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	ephPub := eph.PublicKey().Bytes()
	evidence, err := a.Attester.Evidence(ctx, online.AttestationBinding(c.LicenseID, ch.Challenge, ephPub))
	if err != nil {
		return nil, err
	}

	m, _ := machine.ID()
	body, err := postJSON(ctx, a.Client, c, "/v1/key", online.KeyRequest{
		LicenseID: c.LicenseID, Machine: m, Nonce: ch.Challenge,
		Attestation: evidence, EphemeralPub: ephPub,
		Policy: string(c.Binding.Policy), SecretVersion: c.Binding.SecretVersion,
	})
	if err != nil {
		return nil, err
	}
	kr, err := online.VerifyAttestedKeyResponse(body, a.Keys, c.LicenseID, ch.Challenge, ephPub, time.Now())
	if err != nil {
		return nil, err
	}
	secret, err := online.OpenFromServer(eph, kr.ServerPub, c.LicenseID, ch.Challenge, kr.SealedSecret)
	if err != nil {
		return nil, err
	}
	defer crypto.Wipe(secret)
	if len(secret) != online.SecretSize {
		return nil, errors.New("attested: secret has the wrong size")
	}
	return Unwrap(c, secret)
}

// noTEE is the default attester on hosts without confidential-compute hardware.
type noTEE struct{}

func (noTEE) Name() string                                     { return "none" }
func (noTEE) Evidence(context.Context, []byte) ([]byte, error) { return nil, ErrNoTEE }

// DefaultAttester returns the attester for the current host. On non-CC hardware
// it reports ErrNoTEE; swap in an SEV-SNP/TDX attester to enable attested mode.
func DefaultAttester() Attester { return noTEE{} }
