// Package keyprovider abstracts how the loader obtains the content key. Every
// deployment mode — air-gapped, on-prem, cloud, confidential-compute — is a
// Provider that differs only in where the binding material comes from; the
// unwrap is shared (Unwrap).
package keyprovider

import (
	"context"
	"errors"
	"fmt"

	"github.com/AI2TH/cryptship/pkg/crypto"
	"github.com/AI2TH/cryptship/pkg/license"
)

// Provider acquires the content key for a verified license.
type Provider interface {
	Name() string
	Handles(license.BindingPolicy) bool
	ContentKey(ctx context.Context, lic *license.License) ([]byte, error)
}

var (
	// ErrNotBound means no wrapped key could be unwrapped on this machine.
	ErrNotBound = errors.New("keyprovider: not bound to the license")
	// ErrRevoked means the server reported the license revoked (410 Gone).
	ErrRevoked = errors.New("keyprovider: license revoked by server")
	// ErrDenied means the server refused to release the key for another
	// reason (403 Forbidden), such as rejected attestation evidence.
	ErrDenied = errors.New("keyprovider: server refused to release the key (e.g. attestation rejected)")
)

// Unlocked is what a provider recovers for a license.
type Unlocked struct {
	// ContentKey decrypts the payload.
	ContentKey []byte
	// StateKey seals the loader's local state (crypto.DeriveStateKey of the
	// binding material that unwrapped the content key). Nil if the provider
	// does not implement Unlocker.
	StateKey []byte
}

// Wipe zeroes both keys.
func (u Unlocked) Wipe() {
	crypto.Wipe(u.ContentKey)
	crypto.Wipe(u.StateKey)
}

// Unlocker is implemented by providers that also return a state key. All the
// built-in providers do.
type Unlocker interface {
	Unlock(ctx context.Context, lic *license.License) (Unlocked, error)
}

// Unlock uses p's Unlock if it has one, and ContentKey otherwise (with no
// state key).
func Unlock(ctx context.Context, p Provider, lic *license.License) (Unlocked, error) {
	if u, ok := p.(Unlocker); ok {
		return u.Unlock(ctx, lic)
	}
	k, err := p.ContentKey(ctx, lic)
	return Unlocked{ContentKey: k}, err
}

// contentKeyOnly adapts an Unlock result to ContentKey.
func contentKeyOnly(u Unlocked, err error) ([]byte, error) {
	crypto.Wipe(u.StateKey)
	return u.ContentKey, err
}

// Select returns the first provider that handles the license's binding policy.
func Select(lic *license.License, providers ...Provider) (Provider, error) {
	for _, p := range providers {
		if p.Handles(lic.Claims.Binding.Policy) {
			return p, nil
		}
	}
	return nil, fmt.Errorf("keyprovider: no provider for binding policy %q", lic.Claims.Binding.Policy)
}

// Unwrap derives the KEK from binding material plus the claims context, and
// tries every wrapped key until one authenticates. A returned key is genuine
// (a wrong KEK fails the AEAD tag).
func Unwrap(c license.Claims, material []byte) ([]byte, error) {
	return contentKeyOnly(UnwrapKeys(c, material))
}

// UnwrapKeys is Unwrap that also derives the state key from the binding
// material that unwrapped the content key.
func UnwrapKeys(c license.Claims, material []byte) (Unlocked, error) {
	bctx, err := c.BindingContext()
	if err != nil {
		return Unlocked{}, err
	}
	kek, err := crypto.DeriveKEK(material, []byte(c.LicenseID), bctx)
	if err != nil {
		return Unlocked{}, err
	}
	defer crypto.Wipe(kek)
	for _, wk := range c.WrappedKeys {
		key, err := crypto.UnwrapKey(kek, wk)
		if err != nil {
			continue
		}
		sk, err := crypto.DeriveStateKey(material, []byte(c.LicenseID), bctx)
		if err != nil {
			crypto.Wipe(key)
			return Unlocked{}, err
		}
		return Unlocked{ContentKey: key, StateKey: sk}, nil
	}
	return Unlocked{}, ErrNotBound
}
