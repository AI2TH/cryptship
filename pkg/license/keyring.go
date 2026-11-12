package license

import (
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
)

// KeyRing maps a signing-key id to its public key. The special id "*" matches
// any license, so a single plain base64 public key stays backward compatible.
type KeyRing map[string]ed25519.PublicKey

// ParseKeyRing accepts either a single base64 public key (stored under "*"), or
// lines of "<key_id> <base64>" (comments with # ignored), enabling rotation by
// concatenating keys.
func ParseKeyRing(b []byte) (KeyRing, error) {
	kr := KeyRing{}
	for _, line := range strings.Split(string(b), "\n") {
		f := strings.Fields(line)
		if len(f) == 0 || strings.HasPrefix(f[0], "#") {
			continue
		}
		id, enc := "*", f[0]
		if len(f) >= 2 {
			id, enc = f[0], f[1]
		}
		k, err := base64.StdEncoding.DecodeString(enc)
		if err != nil || len(k) != ed25519.PublicKeySize {
			return nil, fmt.Errorf("cryptship/license: bad public key for id %q", id)
		}
		kr[id] = ed25519.PublicKey(k)
	}
	if len(kr) == 0 {
		return nil, errors.New("cryptship/license: empty key ring")
	}
	return kr, nil
}

// VerifyWith selects the key named by the license's signing_key_id (falling back
// to "*") and verifies. An unknown id is refused rather than tried against all.
func (l *License) VerifyWith(kr KeyRing) error {
	pub, ok := kr[l.Claims.SigningKeyID]
	if !ok {
		pub, ok = kr["*"]
	}
	if !ok {
		return fmt.Errorf("cryptship/license: unknown signing key id %q", l.Claims.SigningKeyID)
	}
	return l.Verify(pub)
}
