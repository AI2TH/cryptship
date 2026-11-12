package keyprovider

import (
	"context"
	"errors"

	"github.com/cryptship/cryptship/pkg/license"
)

// Attester produces TEE attestation evidence (e.g. an AMD SEV-SNP report or an
// Intel TDX quote). Real implementations read /dev/sev-guest or /dev/tdx_guest
// and commit bindData (e.g. license id + an ephemeral key) into the report's
// REPORT_DATA field. ErrNoTEE is returned where no TEE is available.
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
	evidence, err := a.Attester.Evidence(ctx, []byte(lic.Claims.LicenseID))
	if err != nil {
		return nil, err
	}
	return fetchAndUnwrap(ctx, a.Keys, a.Client, lic, evidence)
}

// noTEE is the default attester on hosts without confidential-compute hardware.
type noTEE struct{}

func (noTEE) Name() string                                     { return "none" }
func (noTEE) Evidence(context.Context, []byte) ([]byte, error) { return nil, ErrNoTEE }

// DefaultAttester returns the attester for the current host. On non-CC hardware
// it reports ErrNoTEE; swap in an SEV-SNP/TDX attester to enable attested mode.
func DefaultAttester() Attester { return noTEE{} }

// MockAttester returns fixed evidence. For tests and local demos only — it
// proves nothing about the runtime environment.
type MockAttester struct{ Token []byte }

// Name implements Attester.
func (MockAttester) Name() string { return "mock" }

// Evidence implements Attester.
func (m MockAttester) Evidence(context.Context, []byte) ([]byte, error) {
	if len(m.Token) == 0 {
		return []byte("mock-evidence"), nil
	}
	return m.Token, nil
}
