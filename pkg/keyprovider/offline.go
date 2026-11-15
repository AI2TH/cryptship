package keyprovider

import (
	"context"
	"errors"
	"fmt"

	"github.com/AI2TH/cryptship/pkg/license"
	"github.com/AI2TH/cryptship/pkg/machine"
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
func (o Offline) ContentKey(ctx context.Context, lic *license.License) ([]byte, error) {
	return contentKeyOnly(o.Unlock(ctx, lic))
}

// Unlock implements Unlocker.
func (Offline) Unlock(_ context.Context, lic *license.License) (Unlocked, error) {
	c := lic.Claims
	switch c.Binding.Policy {
	case license.BindNone:
		if len(c.UnboundSecret) == 0 {
			return Unlocked{}, errors.New("offline: none-binding license is missing its unbound secret")
		}
		return UnwrapKeys(c, c.UnboundSecret)

	case license.BindStrict, license.BindPool:
		cands, err := machine.Candidates()
		if err != nil {
			return Unlocked{}, fmt.Errorf("offline: %w", err)
		}
		for _, cand := range cands {
			if u, err := UnwrapKeys(c, []byte(cand.ID)); err == nil {
				return u, nil
			}
		}
		return Unlocked{}, fmt.Errorf("offline: %w (checked %d fingerprint(s) for license %s)", ErrNotBound, len(cands), c.LicenseID)

	default:
		return Unlocked{}, fmt.Errorf("offline: unsupported policy %q", c.Binding.Policy)
	}
}
