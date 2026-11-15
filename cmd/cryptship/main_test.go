package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"testing"

	"github.com/AI2TH/cryptship/pkg/crypto"
	"github.com/AI2TH/cryptship/pkg/keyprovider"
	"github.com/AI2TH/cryptship/pkg/license"
)

// Each fingerprint of a pool license must unwrap the content key after a
// sign / marshal / parse round trip, for both format versions. Under v2 the
// context covers binding.fingerprint_hashes, so all hashes must be recorded
// before the first wrap.
func TestWrapIntoPoolEveryFingerprintUnwraps(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	contentKey, _ := crypto.RandomKey()
	fps := []string{"fp-one", "fp-two", "fp-three"}

	for _, v := range []int{license.FormatVersion1, license.FormatVersion2} {
		c := license.Claims{Version: v, LicenseID: "lic_pool", CustomerID: "acme", Product: "w", PayloadID: "p", SigningKeyID: "v1"}
		if err := wrapInto(&c, license.BindPool, contentKey, fps, "", nil); err != nil {
			t.Fatal(err)
		}
		if err := c.Validate(); err != nil {
			t.Fatal(err)
		}
		lic, err := license.Sign(priv, c)
		if err != nil {
			t.Fatal(err)
		}
		b, _ := lic.Marshal()
		parsed, err := license.Parse(b)
		if err != nil {
			t.Fatal(err)
		}
		for _, fp := range fps {
			got, err := keyprovider.Unwrap(parsed.Claims, []byte(fp))
			if err != nil || !bytes.Equal(got, contentKey) {
				t.Fatalf("v%d fingerprint %s: err = %v", v, fp, err)
			}
		}
		if _, err := keyprovider.Unwrap(parsed.Claims, []byte("fp-other")); err == nil {
			t.Fatalf("v%d: an unlisted fingerprint unwrapped", v)
		}
	}
}

func TestWrapIntoNoneAndOnline(t *testing.T) {
	contentKey, _ := crypto.RandomKey()
	master, _ := crypto.RandomKey()

	c := license.Claims{Version: license.FormatVersion, LicenseID: "lic_none", PayloadID: "p"}
	if err := wrapInto(&c, license.BindNone, contentKey, nil, "", nil); err != nil {
		t.Fatal(err)
	}
	if got, err := keyprovider.Unwrap(c, c.UnboundSecret); err != nil || !bytes.Equal(got, contentKey) {
		t.Fatalf("none: err = %v", err)
	}

	c = license.Claims{Version: license.FormatVersion, LicenseID: "lic_online", PayloadID: "p"}
	if err := wrapInto(&c, license.BindOnline, contentKey, nil, "https://keys.example", master); err != nil {
		t.Fatal(err)
	}
	if err := c.Validate(); err != nil {
		t.Fatal(err)
	}
}
