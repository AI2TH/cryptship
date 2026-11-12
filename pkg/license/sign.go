package license

import (
	"crypto/ed25519"
	"encoding/json"
	"errors"
)

// SigAlgEd25519 is the only signature algorithm currently supported.
const SigAlgEd25519 = "ed25519"

var (
	// ErrBadSignature is returned when a license signature does not verify.
	ErrBadSignature = errors.New("cryptship/license: signature verification failed")
	// ErrUnsupportedAlg is returned for an unknown signature algorithm.
	ErrUnsupportedAlg = errors.New("cryptship/license: unsupported signature algorithm")
	// ErrKeySize is returned for a wrong-size key; ed25519 panics otherwise.
	ErrKeySize = errors.New("cryptship/license: wrong key size")
)

// sigDomain domain-separates the signature; the algorithm is bound into the
// signed input so it cannot be swapped (alg-confusion) without breaking the sig.
const sigDomain = "cryptship/license-sig/v1\x00"

func signingInput(alg string, raw []byte) []byte {
	b := make([]byte, 0, len(sigDomain)+len(alg)+1+len(raw))
	b = append(b, sigDomain...)
	b = append(b, alg...)
	b = append(b, 0)
	return append(b, raw...)
}

// Sign signs the claims and returns a License whose ClaimsRaw is the exact
// signed bytes (a detached signature over opaque bytes, JWS-style).
func Sign(priv ed25519.PrivateKey, c Claims) (*License, error) {
	if len(priv) != ed25519.PrivateKeySize {
		return nil, ErrKeySize
	}
	if c.Version == 0 {
		c.Version = FormatVersion
	}
	raw, err := json.Marshal(c)
	if err != nil {
		return nil, err
	}
	return &License{
		ClaimsRaw: raw,
		SigAlg:    SigAlgEd25519,
		Sig:       ed25519.Sign(priv, signingInput(SigAlgEd25519, raw)),
		Claims:    c,
	}, nil
}

// Verify checks the signature over the stored claim bytes. It does not check
// expiry or binding — callers do that separately.
func (l *License) Verify(pub ed25519.PublicKey) error {
	if l.SigAlg != SigAlgEd25519 {
		return ErrUnsupportedAlg
	}
	if len(pub) != ed25519.PublicKeySize {
		return ErrKeySize
	}
	if len(l.Sig) != ed25519.SignatureSize {
		return ErrBadSignature
	}
	if !ed25519.Verify(pub, signingInput(l.SigAlg, l.ClaimsRaw), l.Sig) {
		return ErrBadSignature
	}
	return nil
}
