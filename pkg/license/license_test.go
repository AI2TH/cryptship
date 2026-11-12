package license

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"testing"
	"time"
)

func genKey(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	return pub, priv
}

func sampleClaims() Claims {
	now := time.Now().Unix()
	return Claims{
		Version:       FormatVersion,
		LicenseID:     "lic_test",
		CustomerID:    "acme",
		Product:       "widget",
		Edition:       "enterprise",
		PayloadID:     "payload-123",
		Entitlements:  []string{"a", "b"},
		IssuedAt:      now,
		NotAfter:      now + 3600,
		Binding:       Binding{Policy: BindNone},
		WrappedKeys:   [][]byte{{1, 2, 3, 4}},
		UnboundSecret: []byte("secret"),
		SigningKeyID:  "v1",
	}
}

func TestSignThenVerify(t *testing.T) {
	pub, priv := genKey(t)
	lic, err := Sign(priv, sampleClaims())
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if lic.SigAlg != SigAlgEd25519 {
		t.Fatalf("SigAlg = %q", lic.SigAlg)
	}
	if err := lic.Verify(pub); err != nil {
		t.Fatalf("Verify: %v", err)
	}

	// Round-trip through JSON (what the loader does) and verify again.
	b, err := lic.Marshal()
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	parsed, err := Parse(b)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if err := parsed.Verify(pub); err != nil {
		t.Fatalf("Verify after Parse: %v", err)
	}
}

func TestVerifyFailsAfterClaimMutation(t *testing.T) {
	pub, priv := genKey(t)
	lic, err := Sign(priv, sampleClaims())
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}

	cases := map[string]func(*Claims){
		"customer_id":    func(c *Claims) { c.CustomerID = "mallory" },
		"not_after":      func(c *Claims) { c.NotAfter += 86400 * 365 },
		"payload_id":     func(c *Claims) { c.PayloadID = "other-build" },
		"binding":        func(c *Claims) { c.Binding.Policy = BindStrict },
		"wrapped_keys":   func(c *Claims) { c.WrappedKeys[0][0] ^= 1 },
		"entitlements":   func(c *Claims) { c.Entitlements = append(c.Entitlements, "root") },
		"unbound_secret": func(c *Claims) { c.UnboundSecret = []byte("x") },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			b, _ := lic.Marshal()
			cp, err := Parse(b) // fresh deep copy
			if err != nil {
				t.Fatal(err)
			}
			mutate(&cp.Claims)
			// Raw-bytes signing: re-encode the claims the attacker edited, so
			// the stored signed bytes now differ from the original signature.
			cp.ClaimsRaw, _ = json.Marshal(cp.Claims)
			if err := cp.Verify(pub); !errors.Is(err, ErrBadSignature) {
				t.Fatalf("Verify after mutating %s: err = %v, want ErrBadSignature", name, err)
			}
		})
	}
}

func TestVerifyFailsWithDifferentPublicKey(t *testing.T) {
	_, priv := genKey(t)
	otherPub, _ := genKey(t)
	lic, err := Sign(priv, sampleClaims())
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if err := lic.Verify(otherPub); !errors.Is(err, ErrBadSignature) {
		t.Fatalf("Verify with other key: err = %v, want ErrBadSignature", err)
	}
}

func TestVerifyRejectsUnsupportedAlg(t *testing.T) {
	pub, priv := genKey(t)
	lic, _ := Sign(priv, sampleClaims())
	lic.SigAlg = "rsa"
	if err := lic.Verify(pub); !errors.Is(err, ErrUnsupportedAlg) {
		t.Fatalf("err = %v, want ErrUnsupportedAlg", err)
	}
}

func TestParseRequiresVersion(t *testing.T) {
	if _, err := Parse([]byte(`{"claims":{},"sig_alg":"ed25519","sig":""}`)); err == nil {
		t.Fatalf("Parse accepted a license with no version")
	}
}

func TestExpired(t *testing.T) {
	c := Claims{IssuedAt: 1000, NotAfter: 2000}
	if c.Expired(1500) {
		t.Fatalf("inside window reported expired")
	}
	if !c.Expired(2001) {
		t.Fatalf("past not_after not reported expired")
	}
	// Within clock-skew tolerance of issued_at: NOT expired (slow client clock).
	if c.Expired(1000 - ClockSkew + 1) {
		t.Fatalf("within clock skew before issued_at reported expired")
	}
	// Well before issued_at (beyond skew): expired.
	if !c.Expired(1000 - ClockSkew - 1) {
		t.Fatalf("well before issued_at not reported expired")
	}
	if (Claims{}).Expired(1 << 40) {
		t.Fatalf("no-expiry license reported expired")
	}
}
