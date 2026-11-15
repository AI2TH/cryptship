package keyprovider

import (
	"context"
	"errors"

	"github.com/AI2TH/cryptship/pkg/license"
	"github.com/AI2TH/cryptship/pkg/online"
)

// Attester produces TEE attestation evidence (e.g. an AMD SEV-SNP report or an
// Intel TDX quote). Real implementations read /dev/sev-guest or /dev/tdx_guest
// and commit bindData (online.AttestationNonce of the license id and request
// nonce) into the report's REPORT_DATA field. ErrNoTEE is returned where no
// TEE is available. pkg/attest/attesttest has a test-only implementation.
type Attester interface {
	Name() string
	Evidence(ctx context.Context, bindData []byte) ([]byte, error)
}

// ErrNoTEE indicates the host is not a confidential VM, so attested binding
// cannot be satisfied here.
var ErrNoTEE = errors.New("attested: no confidential-compute TEE available on this host")

// Attested releases the content key only after the loader sends TEE attestation
// evidence that the key broker verifies before returning the binding secret.
// The network flow reuses the online request (with the evidence attached).
//
// NOTE: real SEV-SNP/TDX quote generation requires confidential-compute
// hardware. DefaultAttester() reports ErrNoTEE on ordinary hosts; integrators
// supply a platform Attester (and run a key broker that verifies the quote,
// e.g. Confidential Containers Trustee). See docs/ARCHITECTURE.md.
type Attested struct {
	Keys     license.KeyRing
	Client   HTTPClient
	Attester Attester
}

// Name implements Provider.
func (Attested) Name() string { return "attested" }

// Handles implements Provider.
func (Attested) Handles(p license.BindingPolicy) bool { return p == license.BindAttested }

// ContentKey implements Provider.
func (a Attested) ContentKey(ctx context.Context, lic *license.License) ([]byte, error) {
	if a.Attester == nil {
		return nil, ErrNoTEE
	}
	return fetchAndUnwrap(ctx, a.Keys, a.Client, lic, func(nonce []byte) ([]byte, error) {
		return a.Attester.Evidence(ctx, online.AttestationNonce(lic.Claims.LicenseID, nonce))
	})
}

// noTEE is the default attester on hosts without confidential-compute hardware.
type noTEE struct{}

func (noTEE) Name() string                                     { return "none" }
func (noTEE) Evidence(context.Context, []byte) ([]byte, error) { return nil, ErrNoTEE }

// DefaultAttester returns the attester for the current host. On non-CC hardware
// it reports ErrNoTEE; swap in an SEV-SNP/TDX attester to enable attested mode.
func DefaultAttester() Attester { return noTEE{} }
