package online

import (
	"bytes"
	"encoding/hex"
	"errors"
	"testing"
)

func TestDeriveSecretFor(t *testing.T) {
	master := bytes.Repeat([]byte{9}, 32)
	legacy, _ := DeriveSecret(master, "lic")
	for _, p := range []string{"online", "attested", ""} {
		if got, err := DeriveSecretFor(master, "lic", p, 0); err != nil || !bytes.Equal(got, legacy) {
			t.Fatalf("version 0 must equal the legacy derivation (policy %q): %v", p, err)
		}
	}
	on, err := DeriveSecretFor(master, "lic", "online", 2)
	if err != nil {
		t.Fatal(err)
	}
	at, _ := DeriveSecretFor(master, "lic", "attested", 2)
	other, _ := DeriveSecretFor(master, "lic2", "online", 2)
	if bytes.Equal(on, at) || bytes.Equal(on, legacy) || bytes.Equal(at, legacy) || bytes.Equal(on, other) {
		t.Fatal("v2 secrets must differ by policy, license and from the legacy secret")
	}
	if _, err := DeriveSecretFor(master, "lic", "strict", 2); !errors.Is(err, ErrSecretVersion) {
		t.Fatalf("v2 strict: %v", err)
	}
	if _, err := DeriveSecretFor(master, "lic", "online", 1); !errors.Is(err, ErrSecretVersion) {
		t.Fatalf("version 1: %v", err)
	}
	// Golden vector, cross-checked with an independent HKDF (Python hmac):
	// changing the v2 derivation strands every v2 license.
	if got := hex.EncodeToString(on); got != "9282a9fef672b608e50e3bc0e4f301febad1373b6df28d1c3870ae44f7cf9338" {
		t.Fatalf("v2 derivation changed: %s", got)
	}
}
