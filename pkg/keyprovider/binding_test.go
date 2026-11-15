package keyprovider

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/AI2TH/cryptship/pkg/crypto"
	"github.com/AI2TH/cryptship/pkg/license"
)

// issueNone builds and serialises a signed binding-"none" license of the given
// format version, with claims that v1 leaves outside the KEK context.
func issueNone(t *testing.T, version int, contentKey []byte) []byte {
	t.Helper()
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	secret, _ := crypto.RandomKey()
	now := time.Now().Unix()
	c := license.Claims{
		Version: version, LicenseID: "lic_tamper", CustomerID: "acme", Product: "widget",
		Edition: "basic", PayloadID: "build-1", Entitlements: []string{"reports"},
		IssuedAt: now, NotAfter: now + 3600,
		Binding:       license.Binding{Policy: license.BindNone},
		UnboundSecret: secret,
		RevocationURL: "https://vendor.example/v1/check",
		SigningKeyID:  "v1",
	}
	c.WrappedKeys = [][]byte{wrapForTest(t, c, secret, contentKey)}
	if err := c.Validate(); err != nil {
		t.Fatal(err)
	}
	lic, err := license.Sign(priv, c)
	if err != nil {
		t.Fatal(err)
	}
	b, err := lic.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// editClaims edits the claims JSON of a serialised license, keeps the now
// invalid signature, and parses the result: what a loader with the signature
// check patched out would go on to unwrap.
func editClaims(t *testing.T, licBytes []byte, edit func(map[string]any)) *license.License {
	t.Helper()
	var outer map[string]json.RawMessage
	if err := json.Unmarshal(licBytes, &outer); err != nil {
		t.Fatal(err)
	}
	var claims map[string]any
	if err := json.Unmarshal(outer["claims"], &claims); err != nil {
		t.Fatal(err)
	}
	edit(claims)
	raw, err := json.Marshal(claims)
	if err != nil {
		t.Fatal(err)
	}
	outer["claims"] = raw
	b, err := json.Marshal(outer)
	if err != nil {
		t.Fatal(err)
	}
	lic, err := license.Parse(b)
	if err != nil {
		t.Fatalf("Parse edited license: %v", err)
	}
	return lic
}

var signatureBypassEdits = map[string]func(map[string]any){
	"revocation_url removed": func(c map[string]any) { delete(c, "revocation_url") },
	"revocation_url changed": func(c map[string]any) { c["revocation_url"] = "http://127.0.0.1:1/ok" },
	"entitlement added":      func(c map[string]any) { c["entitlements"] = []string{"reports", "admin"} },
	"entitlements removed":   func(c map[string]any) { delete(c, "entitlements") },
	"edition changed":        func(c map[string]any) { c["edition"] = "enterprise" },
	"signing_key_id changed": func(c map[string]any) { c["signing_key_id"] = "v9" },
	"binding.max added": func(c map[string]any) {
		c["binding"].(map[string]any)["max"] = 50
	},
}

// Issue #1: with v2, editing a claim outside the v1 subset breaks the unwrap
// even when the signature check is bypassed.
func TestV2EditedClaimsDoNotUnwrap(t *testing.T) {
	contentKey, _ := crypto.RandomKey()
	b := issueNone(t, license.FormatVersion2, contentKey)

	// Unedited: unwraps.
	lic := editClaims(t, b, func(map[string]any) {})
	got, err := Offline{}.ContentKey(context.Background(), lic)
	if err != nil || !bytes.Equal(got, contentKey) {
		t.Fatalf("unedited v2 license: key=%x err=%v", got, err)
	}

	for name, edit := range signatureBypassEdits {
		t.Run(name, func(t *testing.T) {
			lic := editClaims(t, b, edit)
			if _, err := (Offline{}).ContentKey(context.Background(), lic); !errors.Is(err, ErrNotBound) {
				t.Fatalf("edited v2 license unwrapped (err = %v)", err)
			}
		})
	}
}

// v1 licenses still load. The same edits still unwrap under v1: this is the
// gap v2 closes, recorded here so the behaviour is explicit.
func TestV1StillUnwrapsAndKeepsItsLimits(t *testing.T) {
	contentKey, _ := crypto.RandomKey()
	b := issueNone(t, license.FormatVersion1, contentKey)

	lic := editClaims(t, b, func(map[string]any) {})
	got, err := Offline{}.ContentKey(context.Background(), lic)
	if err != nil || !bytes.Equal(got, contentKey) {
		t.Fatalf("unedited v1 license: key=%x err=%v", got, err)
	}
	for name, edit := range signatureBypassEdits {
		lic := editClaims(t, b, edit)
		if _, err := (Offline{}).ContentKey(context.Background(), lic); err != nil {
			t.Errorf("%s: v1 behaviour changed, edit now breaks the unwrap: %v", name, err)
		}
	}
	// A v1-bound claim still breaks a v1 unwrap.
	lic = editClaims(t, b, func(c map[string]any) { c["not_after"] = float64(time.Now().Unix() + 1e8) })
	if _, err := (Offline{}).ContentKey(context.Background(), lic); !errors.Is(err, ErrNotBound) {
		t.Fatalf("v1 not_after edit unwrapped (err = %v)", err)
	}
}

// Changing "v" moves the license to the other context: neither a downgrade to
// the weaker v1 nor an upgrade unwraps.
func TestVersionEditDoesNotUnwrap(t *testing.T) {
	contentKey, _ := crypto.RandomKey()
	for _, tc := range []struct{ from, to int }{{2, 1}, {1, 2}} {
		b := issueNone(t, tc.from, contentKey)
		lic := editClaims(t, b, func(c map[string]any) { c["v"] = tc.to })
		if _, err := (Offline{}).ContentKey(context.Background(), lic); !errors.Is(err, ErrNotBound) {
			t.Fatalf("v%d -> v%d edit unwrapped (err = %v)", tc.from, tc.to, err)
		}
	}
}

// An unknown version never reaches a KEK derivation.
func TestUnwrapRejectsUnknownVersion(t *testing.T) {
	c := license.Claims{Version: 7, LicenseID: "l", WrappedKeys: [][]byte{{1}}}
	if _, err := Unwrap(c, []byte("material")); err == nil || errors.Is(err, ErrNotBound) {
		t.Fatalf("Unwrap(v7) err = %v, want a version error", err)
	}
}
