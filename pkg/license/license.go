// Package license defines cryptship's license format: signed claims plus a
// detached Ed25519 signature over the stored claim bytes. The signed claims
// carry the wrapped content key, so a valid signature and a successful
// key-unwrap are the same event — there is no separate "is valid" boolean for
// an attacker to patch.
package license

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
)

// FormatVersion is the current license schema version.
const FormatVersion = 1

// ClockSkew is the tolerance (seconds) applied to issued_at so a slightly slow
// client clock does not reject a fresh license.
const ClockSkew = 300

// BindingPolicy controls how a license is tied to an environment.
type BindingPolicy string

const (
	// BindNone: content key recoverable from the signed license alone.
	BindNone BindingPolicy = "none"
	// BindStrict: content key wrapped to exactly one machine fingerprint.
	BindStrict BindingPolicy = "strict"
	// BindPool: content key wrapped to each of up to Max fingerprints.
	BindPool BindingPolicy = "pool"
	// BindOnline: binding secret fetched from Binding.Server at run time.
	BindOnline BindingPolicy = "online"
	// BindAttested: binding secret released by a key broker after the loader
	// proves it runs in a genuine TEE (confidential computing).
	BindAttested BindingPolicy = "attested"
)

// Binding describes how a license is bound.
type Binding struct {
	Policy            BindingPolicy `json:"policy"`
	Max               int           `json:"max,omitempty"`
	FingerprintHashes []string      `json:"fingerprint_hashes,omitempty"`
	// Server is the base URL of the license / key-broker server (online, attested).
	Server string `json:"server,omitempty"`
	// ProviderData is opaque, provider-defined bytes (e.g. attestation policy id).
	ProviderData []byte `json:"provider_data,omitempty"`
}

// Claims is the signed portion of a license. Field order is significant.
type Claims struct {
	Version    int    `json:"v"`
	LicenseID  string `json:"license_id"`
	CustomerID string `json:"customer_id"`
	Product    string `json:"product"`
	Edition    string `json:"edition,omitempty"`

	// PayloadID identifies the encrypted build this license unlocks.
	PayloadID string `json:"payload_id"`

	Entitlements []string `json:"entitlements,omitempty"`

	IssuedAt int64 `json:"issued_at"`
	NotAfter int64 `json:"not_after"`

	Binding Binding `json:"binding"`

	WrappedKeys [][]byte `json:"wrapped_keys"`

	// UnboundSecret is present only for BindNone.
	UnboundSecret []byte `json:"unbound_secret,omitempty"`

	RevocationURL string `json:"revocation_url,omitempty"`
	SigningKeyID  string `json:"signing_key_id"`
}

// License is the complete artifact. ClaimsRaw holds the exact claim bytes that
// were signed; Claims is decoded from them and is a read view.
type License struct {
	ClaimsRaw json.RawMessage `json:"claims"`
	SigAlg    string          `json:"sig_alg"`
	Sig       []byte          `json:"sig"`

	Claims Claims `json:"-"`
}

// BindingContext is the fixed, language-independent byte layout of the claims
// the KEK is bound to. Editing any of them changes the KEK, so a tampered
// license cannot unwrap the content key even if signature checks are patched.
func (c Claims) BindingContext() []byte {
	var b []byte
	put := func(s string) { b = append(b, s...); b = append(b, 0) }
	put("cryptship/kek-ctx/v1")
	put(strconv.Itoa(c.Version))
	put(c.LicenseID)
	put(c.CustomerID)
	put(c.Product)
	put(c.PayloadID)
	put(string(c.Binding.Policy))
	b = binary.BigEndian.AppendUint64(b, uint64(c.IssuedAt))
	return binary.BigEndian.AppendUint64(b, uint64(c.NotAfter))
}

// Expired reports whether the license is outside its validity window at now.
func (c Claims) Expired(now int64) bool {
	if c.NotAfter != 0 && now > c.NotAfter {
		return true
	}
	if c.IssuedAt != 0 && now+ClockSkew < c.IssuedAt {
		return true
	}
	return false
}

// Validate checks structural invariants for the binding policy. It is called at
// issue time; the loader relies on key-unwrap failing for malformed licenses.
func (c Claims) Validate() error {
	if c.LicenseID == "" {
		return errors.New("cryptship/license: empty license_id")
	}
	if c.PayloadID == "" {
		return errors.New("cryptship/license: empty payload_id")
	}
	if c.NotAfter != 0 && c.NotAfter <= c.IssuedAt {
		return errors.New("cryptship/license: not_after <= issued_at")
	}
	switch c.Binding.Policy {
	case BindNone:
		if len(c.UnboundSecret) != 32 || len(c.WrappedKeys) != 1 {
			return errors.New("cryptship/license: none binding needs a 32-byte unbound_secret and one wrapped key")
		}
	case BindStrict, BindPool:
		if len(c.UnboundSecret) != 0 || len(c.WrappedKeys) < 1 {
			return errors.New("cryptship/license: machine binding needs wrapped keys and no unbound_secret")
		}
	case BindOnline, BindAttested:
		if c.Binding.Server == "" {
			return errors.New("cryptship/license: online/attested binding needs binding.server")
		}
		if len(c.UnboundSecret) != 0 || len(c.WrappedKeys) < 1 {
			return errors.New("cryptship/license: online/attested binding needs wrapped keys and no unbound_secret")
		}
	default:
		return fmt.Errorf("cryptship/license: unknown binding policy %q", c.Binding.Policy)
	}
	return nil
}

// Marshal serialises a license for storage. It must stay compact: the signature
// covers ClaimsRaw byte-for-byte, and Sign produces compact bytes.
func (l *License) Marshal() ([]byte, error) { return json.Marshal(l) }

// Parse decodes a license and its claims view.
func Parse(b []byte) (*License, error) {
	var l License
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&l); err != nil {
		return nil, err
	}
	if len(l.ClaimsRaw) == 0 {
		return nil, errors.New("cryptship/license: missing claims")
	}
	cd := json.NewDecoder(bytes.NewReader(l.ClaimsRaw))
	cd.DisallowUnknownFields()
	if err := cd.Decode(&l.Claims); err != nil {
		return nil, fmt.Errorf("cryptship/license: claims: %w", err)
	}
	if l.Claims.Version == 0 {
		return nil, errors.New("cryptship/license: missing version")
	}
	if l.Claims.Version > FormatVersion {
		return nil, fmt.Errorf("cryptship/license: version %d newer than supported %d", l.Claims.Version, FormatVersion)
	}
	return &l, nil
}
