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
	bctx, err := c.BindingContext()
	if err != nil {
		return nil, err
	}
	kek, err := crypto.DeriveKEK(material, []byte(c.LicenseID), bctx)
	if err != nil {
		return nil, err
	}
	defer crypto.Wipe(kek)
	for _, wk := range c.WrappedKeys {
		if key, err := crypto.UnwrapKey(kek, wk); err == nil {
			return key, nil
		}
	}
	return nil, ErrNotBound
}
