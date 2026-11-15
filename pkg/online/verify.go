package online

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"time"
)

// MaxResponseBytes caps how much of a server response the loader reads.
const MaxResponseBytes = 64 << 10

var (
	// ErrUnsigned means the body is not a signed response at all (not JSON, or
	// no signature). Callers decide whether an unsigned answer is acceptable.
	ErrUnsigned = errors.New("online: response is not signed")
	// ErrBadSignature means the response is signed by an unknown key or the
	// signature does not verify.
	ErrBadSignature = errors.New("online: bad response signature")
	// ErrMismatch means a correctly signed response answers a different
	// license or nonce (for example a replayed answer).
	ErrMismatch = errors.New("online: response does not match the request")
	// ErrExpired means the response's not_after has passed.
	ErrExpired = errors.New("online: response already expired")
)

// SigningKey looks up the public key for a signing key id in keys, falling
// back to the wildcard id "*" (license.KeyRing has this shape).
func SigningKey(keys map[string]ed25519.PublicKey, id string) (ed25519.PublicKey, error) {
	pub, ok := keys[id]
	if !ok {
		pub, ok = keys["*"]
	}
	if !ok || len(pub) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("%w: unknown signing key %q", ErrBadSignature, id)
	}
	return pub, nil
}

// SignCheck fills in SigningKeyID and Sig for a revocation answer. The server
// signs check answers with the same vendor key and the same envelope (license
// id, nonce, not_after, key id, detached Ed25519 signature) as key answers;
// the signing inputs carry different domain labels, so one can never be
// passed off as the other.
func SignCheck(priv ed25519.PrivateKey, keyID string, r *CheckResponse) {
	r.SigningKeyID = keyID
	r.Sig = ed25519.Sign(priv, CheckSigningInput(*r))
}

// VerifyCheckResponse decodes a revocation answer and accepts it only if it is
// signed by a key in keys, answers licenseID and the nonce the caller sent, and
// has not expired at now. A body that is not a signed response returns
// ErrUnsigned so the caller can apply its policy for unsigned endpoints.
func VerifyCheckResponse(body []byte, keys map[string]ed25519.PublicKey, licenseID string, nonce []byte, now time.Time) (CheckResponse, error) {
	var r CheckResponse
	if err := json.Unmarshal(body, &r); err != nil || len(r.Sig) == 0 {
		return CheckResponse{}, ErrUnsigned
	}
	pub, err := SigningKey(keys, r.SigningKeyID)
	if err != nil {
		return CheckResponse{}, err
	}
	if !ed25519.Verify(pub, CheckSigningInput(r), r.Sig) {
		return CheckResponse{}, ErrBadSignature
	}
	if r.LicenseID != licenseID || len(nonce) == 0 || !bytes.Equal(r.Nonce, nonce) {
		return CheckResponse{}, ErrMismatch
	}
	if r.NotAfter != 0 && now.Unix() > r.NotAfter {
		return CheckResponse{}, ErrExpired
	}
	return r, nil
}

// VerifyKeyResponse decodes a key answer and accepts it only if it is signed by
// a key in keys, answers licenseID and nonce, carries a secret of the expected
// shape, and has not expired at now.
func VerifyKeyResponse(body []byte, keys map[string]ed25519.PublicKey, licenseID string, nonce []byte, now time.Time) (KeyResponse, error) {
	var r KeyResponse
	if err := json.Unmarshal(body, &r); err != nil {
		return KeyResponse{}, fmt.Errorf("online: bad response: %w", err)
	}
	if len(r.Sig) == 0 {
		return KeyResponse{}, ErrUnsigned
	}
	pub, err := SigningKey(keys, r.SigningKeyID)
	if err != nil {
		return KeyResponse{}, err
	}
	if !ed25519.Verify(pub, ResponseSigningInput(r), r.Sig) {
		return KeyResponse{}, ErrBadSignature
	}
	if r.LicenseID != licenseID || len(nonce) == 0 || !bytes.Equal(r.Nonce, nonce) || len(r.Secret) != SecretSize {
		return KeyResponse{}, ErrMismatch
	}
	if r.NotAfter != 0 && now.Unix() > r.NotAfter {
		return KeyResponse{}, ErrExpired
	}
	return r, nil
}
