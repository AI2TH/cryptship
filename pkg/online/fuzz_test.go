package online

import (
	"bytes"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"testing"
	"time"
)

var (
	fuzzPub, fuzzPriv, _ = ed25519.GenerateKey(rand.Reader)
	fuzzKeys             = map[string]ed25519.PublicKey{"v1": fuzzPub}
	fuzzNonce            = []byte("0123456789abcdef")
)

// FuzzVerifyKeyResponse: the online answer decoder never panics, and anything
// it accepts answers this license and nonce with a well-formed secret.
func FuzzVerifyKeyResponse(f *testing.F) {
	r := KeyResponse{LicenseID: "lic", Nonce: fuzzNonce, Secret: make([]byte, SecretSize), NotAfter: time.Now().Add(time.Hour).Unix(), SigningKeyID: "v1"}
	r.Sig = ed25519.Sign(fuzzPriv, ResponseSigningInput(r))
	good, _ := json.Marshal(r)
	f.Add(good)
	f.Add([]byte(`{"license_id":"lic","nonce":"MDEyMzQ1Njc4OWFiY2RlZg==","secret":"","sig":"AA=="}`))
	f.Add([]byte(`null`))
	f.Fuzz(func(t *testing.T, body []byte) {
		got, err := VerifyKeyResponse(body, fuzzKeys, "lic", fuzzNonce, time.Now())
		if err != nil {
			return
		}
		if got.LicenseID != "lic" || !bytes.Equal(got.Nonce, fuzzNonce) || len(got.Secret) != SecretSize ||
			!ed25519.Verify(fuzzPub, ResponseSigningInput(got), got.Sig) {
			t.Fatalf("accepted a non-matching answer: %+v", got)
		}
	})
}

// FuzzVerifyCheckResponse: same for revocation answers.
func FuzzVerifyCheckResponse(f *testing.F) {
	r := CheckResponse{LicenseID: "lic", Nonce: fuzzNonce, NotAfter: time.Now().Add(time.Hour).Unix()}
	SignCheck(fuzzPriv, "v1", &r)
	good, _ := json.Marshal(r)
	f.Add(good)
	f.Add([]byte(`OK`))
	f.Fuzz(func(t *testing.T, body []byte) {
		got, err := VerifyCheckResponse(body, fuzzKeys, "lic", fuzzNonce, time.Now())
		if err != nil {
			return
		}
		if got.LicenseID != "lic" || !bytes.Equal(got.Nonce, fuzzNonce) || !ed25519.Verify(fuzzPub, CheckSigningInput(got), got.Sig) {
			t.Fatalf("accepted a non-matching answer: %+v", got)
		}
	})
}

// FuzzVerifyAttestedKeyResponse: the attested decoder never panics, and what
// it accepts never carries a plaintext secret.
func FuzzVerifyAttestedKeyResponse(f *testing.F) {
	client, _ := ecdh.X25519().GenerateKey(rand.Reader)
	cpub := client.PublicKey().Bytes()
	sp, sealed, _ := SealToEphemeral(cpub, "lic", fuzzNonce, make([]byte, SecretSize))
	r := KeyResponse{LicenseID: "lic", Nonce: fuzzNonce, NotAfter: time.Now().Add(time.Hour).Unix(), SigningKeyID: "v1", ServerPub: sp, SealedSecret: sealed}
	r.Sig = ed25519.Sign(fuzzPriv, AttestedSigningInput(r, cpub))
	good, _ := json.Marshal(r)
	f.Add(good)
	f.Fuzz(func(t *testing.T, body []byte) {
		got, err := VerifyAttestedKeyResponse(body, fuzzKeys, "lic", fuzzNonce, cpub, time.Now())
		if err != nil {
			return
		}
		if len(got.Secret) != 0 || len(got.ServerPub) != EphemeralKeySize || !ed25519.Verify(fuzzPub, AttestedSigningInput(got, cpub), got.Sig) {
			t.Fatalf("accepted a malformed attested answer: %+v", got)
		}
		_, _ = OpenFromServer(client, got.ServerPub, "lic", fuzzNonce, got.SealedSecret)
	})
}

// FuzzCheckChallenge: arbitrary bytes do not crash the check, and a
// challenge that passes is bound to its license and server key: it never also
// passes for another license or under another server's key.
func FuzzCheckChallenge(f *testing.F) {
	key, _ := ChallengeKey([]byte("fuzz-master-fuzz-master-fuzz-mas"))
	other, _ := ChallengeKey([]byte("other-master-other-master-other-"))
	ch, _ := NewChallenge(key, "lic", time.Now().Add(time.Hour))
	f.Add(ch)
	f.Add(make([]byte, ChallengeSize))
	f.Fuzz(func(t *testing.T, c []byte) {
		now := time.Now()
		if CheckChallenge(key, "lic", c, now) != nil {
			return
		}
		if CheckChallenge(key, "lic2", c, now) == nil || CheckChallenge(other, "lic", c, now) == nil {
			t.Fatalf("challenge not bound to its license and key: %x", c)
		}
	})
}
