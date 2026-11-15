package online

import (
	"bytes"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"testing"
	"time"
)

func TestChallenge(t *testing.T) {
	key, err := ChallengeKey([]byte("master-secret-master-secret-1234"))
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	ch, err := NewChallenge(key, "lic", now.Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if len(ch) != ChallengeSize {
		t.Fatalf("size %d", len(ch))
	}
	if err := CheckChallenge(key, "lic", ch, now); err != nil {
		t.Fatalf("fresh challenge: %v", err)
	}
	other, _ := ChallengeKey([]byte("another-master-another-master-12"))
	tampered := bytes.Clone(ch)
	tampered[5] ^= 1
	extended := bytes.Clone(ch)
	extended[1+challengeRandSize] ^= 0x40 // push the expiry out
	ch2, _ := NewChallenge(key, "lic", now.Add(time.Minute))
	cases := map[string]error{
		"other license": CheckChallenge(key, "lic_other", ch, now),
		"other server":  CheckChallenge(other, "lic", ch, now),
		"tampered":      CheckChallenge(key, "lic", tampered, now),
		"extended":      CheckChallenge(key, "lic", extended, now),
		"expired":       CheckChallenge(key, "lic", ch, now.Add(2*time.Minute)),
		"truncated":     CheckChallenge(key, "lic", ch[:10], now),
		"empty":         CheckChallenge(key, "lic", nil, now),
	}
	for name, err := range cases {
		if !errors.Is(err, ErrBadChallenge) {
			t.Errorf("%s: err = %v", name, err)
		}
	}
	if bytes.Equal(ch, ch2) {
		t.Fatal("two challenges are equal")
	}
}

func TestAttestationBindingIsUnambiguous(t *testing.T) {
	pub := make([]byte, 32)
	a := AttestationBinding("ab", []byte("c"), pub)
	b := AttestationBinding("a", []byte("bc"), pub)
	c := AttestationBinding("ab", []byte("c"), append(make([]byte, 31), 1))
	if bytes.Equal(a, b) || bytes.Equal(a, c) {
		t.Fatal("binding collides across fields")
	}
	if len(a) != 32 {
		t.Fatalf("binding is %d bytes; REPORT_DATA holds 64", len(a))
	}
}

func TestSealToEphemeral(t *testing.T) {
	client, _ := ecdh.X25519().GenerateKey(rand.Reader)
	secret := bytes.Repeat([]byte{7}, SecretSize)
	ch := []byte("challenge")
	serverPub, sealed, err := SealToEphemeral(client.PublicKey().Bytes(), "lic", ch, secret)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(sealed, secret) {
		t.Fatal("secret in clear")
	}
	got, err := OpenFromServer(client, serverPub, "lic", ch, sealed)
	if err != nil || !bytes.Equal(got, secret) {
		t.Fatalf("open: %v", err)
	}
	// An eavesdropper with its own key, or the right key in another context,
	// cannot open it.
	eve, _ := ecdh.X25519().GenerateKey(rand.Reader)
	if _, err := OpenFromServer(eve, serverPub, "lic", ch, sealed); err == nil {
		t.Fatal("opened with another private key")
	}
	if _, err := OpenFromServer(client, serverPub, "lic_other", ch, sealed); err == nil {
		t.Fatal("opened for another license")
	}
	if _, err := OpenFromServer(client, serverPub, "lic", []byte("other"), sealed); err == nil {
		t.Fatal("opened for another challenge")
	}
	// Low-order / all-zero keys are refused.
	if _, _, err := SealToEphemeral(make([]byte, 32), "lic", ch, secret); err == nil {
		t.Fatal("sealed to the all-zero point")
	}
	if _, _, err := SealToEphemeral([]byte("short"), "lic", ch, secret); err == nil {
		t.Fatal("sealed to a short key")
	}
}

func TestVerifyAttestedKeyResponse(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	keys := map[string]ed25519.PublicKey{"v1": pub}
	client, _ := ecdh.X25519().GenerateKey(rand.Reader)
	cpub := client.PublicKey().Bytes()
	ch := []byte("challenge-bytes")
	sp, sealed, _ := SealToEphemeral(cpub, "lic", ch, make([]byte, SecretSize))
	now := time.Now()
	sign := func(r KeyResponse, forPub []byte) []byte {
		r.SigningKeyID = "v1"
		r.Sig = ed25519.Sign(priv, AttestedSigningInput(r, forPub))
		b, _ := json.Marshal(r)
		return b
	}
	good := KeyResponse{LicenseID: "lic", Nonce: ch, NotAfter: now.Add(time.Hour).Unix(), ServerPub: sp, SealedSecret: sealed}
	if _, err := VerifyAttestedKeyResponse(sign(good, cpub), keys, "lic", ch, cpub, now); err != nil {
		t.Fatalf("good answer: %v", err)
	}
	leaky := good
	leaky.Secret = make([]byte, SecretSize)
	other, _ := ecdh.X25519().GenerateKey(rand.Reader)
	cases := []struct {
		name string
		body []byte
		want error
	}{
		{"signed for another ephemeral key", sign(good, other.PublicKey().Bytes()), ErrBadSignature},
		{"plaintext secret", sign(leaky, cpub), ErrMismatch},
		{"unsigned", []byte(`{}`), ErrUnsigned},
	}
	for _, tc := range cases {
		if _, err := VerifyAttestedKeyResponse(tc.body, keys, "lic", ch, cpub, now); !errors.Is(err, tc.want) {
			t.Errorf("%s: err = %v, want %v", tc.name, err, tc.want)
		}
	}
	if _, err := VerifyAttestedKeyResponse(sign(good, cpub), keys, "lic", []byte("other"), cpub, now); !errors.Is(err, ErrMismatch) {
		t.Errorf("other challenge: err = %v", err)
	}
}
