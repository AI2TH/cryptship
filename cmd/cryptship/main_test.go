package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"os"
	"path/filepath"
	"testing"

	"github.com/AI2TH/cryptship/pkg/crypto"
	"github.com/AI2TH/cryptship/pkg/keyprovider"
	"github.com/AI2TH/cryptship/pkg/license"
	"github.com/AI2TH/cryptship/pkg/online"
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
		if err := wrapInto(&c, license.BindPool, contentKey, fps, serverBinding{}); err != nil {
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
	if err := wrapInto(&c, license.BindNone, contentKey, nil, serverBinding{}); err != nil {
		t.Fatal(err)
	}
	if got, err := keyprovider.Unwrap(c, c.UnboundSecret); err != nil || !bytes.Equal(got, contentKey) {
		t.Fatalf("none: err = %v", err)
	}

	for _, policy := range []license.BindingPolicy{license.BindOnline, license.BindAttested} {
		for _, sv := range []int{license.SecretVersionLegacy, license.SecretVersion2} {
			c = license.Claims{Version: license.FormatVersion, LicenseID: "lic_srv", PayloadID: "p"}
			if err := wrapInto(&c, policy, contentKey, nil, serverBinding{URL: "https://keys.example", Master: master, SecretVersion: sv, MaxMachines: 3}); err != nil {
				t.Fatal(err)
			}
			if err := c.Validate(); err != nil {
				t.Fatal(err)
			}
			if c.Binding.SecretVersion != sv || c.Binding.Max != 3 {
				t.Fatalf("%s: secret_v = %d, want %d", policy, c.Binding.SecretVersion, sv)
			}
			want, _ := online.DeriveSecretFor(master, "lic_srv", string(policy), sv)
			if got, err := keyprovider.Unwrap(c, want); err != nil || !bytes.Equal(got, contentKey) {
				t.Fatalf("%s v%d: err = %v", policy, sv, err)
			}
			// Under v2 the other policy's secret does not unwrap.
			if sv == license.SecretVersion2 {
				otherPolicy := license.BindOnline
				if policy == license.BindOnline {
					otherPolicy = license.BindAttested
				}
				wrong, _ := online.DeriveSecretFor(master, "lic_srv", string(otherPolicy), sv)
				if _, err := keyprovider.Unwrap(c, wrong); err == nil {
					t.Fatalf("%s: the %s secret unwrapped it", policy, otherPolicy)
				}
			}
		}
	}
	c = license.Claims{Version: license.FormatVersion, LicenseID: "lic_x", PayloadID: "p"}
	if err := wrapInto(&c, license.BindOnline, contentKey, nil, serverBinding{URL: "https://keys.example", Master: master, SecretVersion: 7}); err == nil {
		t.Fatal("unknown secret version accepted")
	}
}

func TestMasterKeyRefusesOverwrite(t *testing.T) {
	path := filepath.Join(t.TempDir(), "master.key")
	if err := cmdMasterKey([]string{"--out", path}); err != nil {
		t.Fatal(err)
	}
	first, _ := os.ReadFile(path)
	if err := cmdMasterKey([]string{"--out", path}); err == nil {
		t.Fatal("master-key overwrote an existing key without --force")
	}
	if again, _ := os.ReadFile(path); !bytes.Equal(first, again) {
		t.Fatal("existing master key changed")
	}
	if err := cmdMasterKey([]string{"--out", path, "--force"}); err != nil {
		t.Fatalf("--force: %v", err)
	}
}
