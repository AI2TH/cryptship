package keyprovider

import (
	"context"
	"errors"
	"fmt"

	"github.com/cryptship/cryptship/pkg/license"
	"github.com/cryptship/cryptship/pkg/machine"
)

// Offline resolves the content key with no network access, for none/strict/pool
// bindings. Revocation is by expiry only.
type Offline struct{}

// Name implements Provider.
func (Offline) Name() string { return "offline" }

// Handles implements Provider.
func (Offline) Handles(p license.BindingPolicy) bool {
	return p == license.BindNone || p == license.BindStrict || p == license.BindPool
}

// ContentKey implements Provider.
func (Offline) ContentKey(_ context.Context, lic *license.License) ([]byte, error) {
	c := lic.Claims
	switch c.Binding.Policy {
	case license.BindNone:
		if len(c.UnboundSecret) == 0 {
			return nil, errors.New("offline: none-binding license is missing its unbound secret")
		}
		return Unwrap(c, c.UnboundSecret)

	case license.BindStrict, license.BindPool:
		cands, err := machine.Candidates()
		if err != nil {
			return nil, fmt.Errorf("offline: %w", err)
		}
		for _, cand := range cands {
			if key, err := Unwrap(c, []byte(cand.ID)); err == nil {
				return key, nil
			}
		}
		return nil, fmt.Errorf("offline: %w (checked %d fingerprint(s) for license %s)", ErrNotBound, len(cands), c.LicenseID)

	default:
		return nil, fmt.Errorf("offline: unsupported policy %q", c.Binding.Policy)
	}
}
